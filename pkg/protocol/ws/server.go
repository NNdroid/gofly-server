package ws

import (
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/lesismal/nbio/logging"
	"github.com/lesismal/nbio/nbhttp"
	"github.com/lesismal/nbio/nbhttp/websocket"
	"github.com/patrickmn/go-cache"
	"go.uber.org/zap"
	"gofly/pkg/cipher"
	"gofly/pkg/config"
	"gofly/pkg/layers"
	"gofly/pkg/layers/ipv4"
	"gofly/pkg/layers/ipv6"
	"gofly/pkg/logger"
	"gofly/pkg/statistics"
	"gofly/pkg/utils"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/golang/snappy"

	"github.com/lesismal/llib/std/crypto/tls"
)

const AuthFieldKey = "key"

type Server struct {
	Layer           *layers.Layer
	Config          *config.Config
	ReadFunc        func([]byte) (int, error)
	WriteFunc       func([]byte) int
	WriteToTunFunc  func(buf []byte) (int, error)
	CTX             context.Context
	connectionCache *cache.Cache
	Statistics      *statistics.Statistics
}

func (x *Server) newUpgrade() *websocket.Upgrader {
	u := websocket.NewUpgrader()
	u.CheckOrigin = func(r *http.Request) bool { return true }
	u.SetPingHandler(func(c *websocket.Conn, s string) {
		logger.Logger.Sugar().Debugf("received ping message <%v> from %s\n", s, c.Conn.RemoteAddr().String())
		err := c.WriteMessage(websocket.PongMessage, []byte(s))
		if err != nil {
			logger.Logger.Sugar().Errorf("try to send pong error: %v\n", err)
			c.CloseWithError(errors.New("try to send pong error"))
		}
	})
	u.SetPongHandler(func(c *websocket.Conn, s string) {
		logger.Logger.Sugar().Debugf("received pong message <%v> from %s\n", s, c.Conn.RemoteAddr().String())
	})
	u.OnMessage(func(c *websocket.Conn, messageType websocket.MessageType, data []byte) {
		if messageType == websocket.BinaryMessage {
			n := len(data)
			x.Statistics.IncrReceivedBytes(n)
			if x.Config.VTun.Compress {
				data, _ = snappy.Decode(nil, data)
			}
			if x.Config.VTun.Obfs {
				data = cipher.XOR(data)
			}
			if key := utils.GetSrcKey(data); key != "" {
				x.connectionCache.Set(key, c, 24*time.Hour)
				x.convertSrcAddr(data)
				x.WriteFunc(data)
				x.Statistics.IncrClientTransportBytes(c.RemoteAddr(), n)
			}
		}
	})

	u.OnClose(func(c *websocket.Conn, err error) {
		x.Statistics.Remove(c.RemoteAddr())
		logger.Logger.Sugar().Debugf("closed: %s -> %v", c.RemoteAddr().String(), zap.Error(err))
	})
	return u
}

func (x *Server) onWebsocket(w http.ResponseWriter, r *http.Request) {
	if !x.checkPermission(r) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
		return
	}
	upgrade := x.newUpgrade()
	conn, err := upgrade.Upgrade(w, r, nil)
	if err != nil {
		logger.Logger.Sugar().Errorf("upgrade error: %v", zap.Error(err))
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
		return
	}
	conn.SetReadDeadline(time.Time{})
	x.Statistics.Push(conn.RemoteAddr())
	logger.Logger.Sugar().Debugf("open: %s", conn.RemoteAddr().String())
}

// StartServerForApi starts the ws server
func (x *Server) StartServerForApi() {
	if !x.Config.VTun.Verbose {
		logging.SetLevel(logging.LevelNone)
		gin.SetMode(gin.ReleaseMode)
	}
	x.connectionCache = cache.New(15*time.Minute, 24*time.Hour)
	cipher.SetKey(x.Config.VTun.Key)
	// server -> client
	go x.toClient()
	// client -> server
	mux := &http.ServeMux{}
	mux.HandleFunc(x.Config.VTun.Path, x.onWebsocket)
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "6")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("CF-Cache-Status", "DYNAMIC")
		w.Header().Set("Server", "cloudflare")
		w.Write([]byte(`follow`))
	})

	var svr *nbhttp.Server
	if x.Config.VTun.Protocol == "wss" {
		cert, err := tls.LoadX509KeyPair(x.Config.VTun.TLSCertificateFilePath, x.Config.VTun.TLSCertificateKeyFilePath)
		if err != nil {
			log.Panic(err)
		}
		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: x.Config.VTun.TLSInsecureSkipVerify,
		}
		if x.Config.VTun.TLSSni != "" {
			tlsConfig.ServerName = x.Config.VTun.TLSSni
		}
		svr = nbhttp.NewServer(nbhttp.Config{
			Network:   "tcp",
			AddrsTLS:  []string{x.Config.VTun.LocalAddr},
			TLSConfig: tlsConfig,
			Handler:   mux,
		})
	} else {
		svr = nbhttp.NewServer(nbhttp.Config{
			Network: "tcp",
			Addrs:   []string{x.Config.VTun.LocalAddr},
			Handler: mux,
		})
	}

	err := svr.Start()
	if err != nil {
		logger.Logger.Sugar().Errorf("nbio.Start failed: %v", zap.Error(err))
		return
	}
	defer svr.Stop()

	logger.Logger.Sugar().Infof("gofly %s server started on %v", x.Config.VTun.Protocol, x.Config.VTun.LocalAddr)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	<-interrupt
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	svr.Shutdown(ctx)
}

// checkPermission checks the permission of the request
// Validation is successful if the header or request parameters contain specific data.
func (x *Server) checkPermission(req *http.Request) bool {
	if x.Config.VTun.Key == "" {
		return true
	}
	key1 := req.Header.Get(AuthFieldKey)
	key2 := req.URL.Query().Get(AuthFieldKey)
	if key1 != x.Config.VTun.Key && key2 != x.Config.VTun.Key {
		return false
	}
	return true
}

// toClient WireGuard to GateWay - ReadFunc
func (x *Server) toClient() {
	packet := make([]byte, x.Config.VTun.BufferSize)
	for contextOpened(x.CTX) {
		n, err := x.ReadFunc(packet)
		if err != nil {
			logger.Logger.Error("getData Error", zap.Error(err))
			break
		}
		if n == 0 {
			continue
		}
		b := packet[:n]
		x.convertDstAddr(b)
		if key := utils.GetDstKey(b); key != "" {
			if v, ok := x.connectionCache.Get(key); ok {
				if x.Config.VTun.Obfs {
					b = cipher.XOR(b)
				}
				if x.Config.VTun.Compress {
					b = snappy.Encode(nil, b)
				}
				ns := len(b)
				conn := v.(*websocket.Conn)
				err = conn.WriteMessage(websocket.BinaryMessage, b)
				if err != nil {
					logger.Logger.Error("write data error", zap.Error(err))
					x.connectionCache.Delete(key)
					continue
				}
				x.Statistics.IncrTransportBytes(ns)
				x.Statistics.IncrClientReceivedBytes(conn.RemoteAddr(), ns)
			}
		}
	}
}

func (x *Server) convertDstAddr(packet []byte) {
	if ok, _ := x.Layer.IsLocalSrcPacket(packet); ok {
		return
	}
	version := packet[0] >> 4
	if version == 4 {
		p := ipv4.GetProtocol(packet)
		if p == "tcp" {
			dstAddr := ipv4.ParseDstTcp(packet)
			x.Layer.V4Layer.ReplaceDstAddrTcp(packet, dstAddr)
			ipv4.CalcIPCheckSum(packet)
			ipv4.CalcTCPCheckSum(packet)
		} else if p == "udp" {
			dstAddr := ipv4.ParseDstUdp(packet)
			x.Layer.V4Layer.ReplaceDstAddrUdp(packet, dstAddr)
			ipv4.CalcIPCheckSum(packet)
			ipv4.CalcUDPCheckSum(packet)
		} else if p == "icmp" {
			srcAddr := ipv4.ParseSrcIcmpTag(packet, true) // dst ip
			dstAddr := ipv4.ParseDstIcmpTag(packet, true) // gateway ip
			x.Layer.V4Layer.ReplaceDstAddrIcmp(packet, dstAddr, srcAddr)
			ipv4.CalcIPCheckSum(packet)
			ipv4.CalcICMPCheckSum(packet)
		}
	} else if version == 6 {
		p := ipv6.GetProtocol(packet)
		if p == "tcp" {
			dstAddr := ipv6.ParseDstTcp(packet)
			x.Layer.V6Layer.ReplaceDstAddrTcp(packet, dstAddr)
			ipv6.CalcTCPCheckSum(packet)
		} else if p == "udp" {
			dstAddr := ipv6.ParseDstUdp(packet)
			x.Layer.V6Layer.ReplaceDstAddrUdp(packet, dstAddr)
			ipv6.CalcUDPCheckSum(packet)
		} else if p == "icmp" {
			srcAddr := ipv6.ParseSrcIcmpTag(packet, true) // dst ip
			dstAddr := ipv6.ParseDstIcmpTag(packet, true) // gateway ip
			x.Layer.V6Layer.ReplaceDstAddrIcmp(packet, dstAddr, srcAddr)
			ipv6.CalcICMPCheckSum(packet)
		}
	}
}

func (x *Server) convertSrcAddr(packet []byte) {
	if ok, _ := x.Layer.IsLocalDstPacket(packet); ok {
		_, err := x.WriteToTunFunc(packet)
		if err != nil {
			logger.Logger.Sugar().Errorf("write to tun error, %v\n", zap.Error(err))
			return
		}
		return
	}
	version := packet[0] >> 4
	if version == 4 {
		p := ipv4.GetProtocol(packet)
		if p == "tcp" {
			srcAddr := ipv4.ParseSrcTcp(packet)
			x.Layer.V4Layer.ReplaceSrcAddrTcp(packet, srcAddr)
			ipv4.CalcIPCheckSum(packet)
			ipv4.CalcTCPCheckSum(packet)
		} else if p == "udp" {
			srcAddr := ipv4.ParseSrcUdp(packet)
			x.Layer.V4Layer.ReplaceSrcAddrUdp(packet, srcAddr)
			ipv4.CalcIPCheckSum(packet)
			ipv4.CalcUDPCheckSum(packet)
		} else if p == "icmp" {
			srcAddr := ipv4.ParseSrcIcmpTag(packet, false) // client ip
			dstAddr := ipv4.ParseDstIcmpTag(packet, false) // dst ip
			x.Layer.V4Layer.ReplaceSrcAddrIcmp(packet, dstAddr, srcAddr)
			ipv4.CalcIPCheckSum(packet)
			ipv4.CalcICMPCheckSum(packet)
		}
	} else if version == 6 {
		p := ipv6.GetProtocol(packet)
		if p == "tcp" {
			srcAddr := ipv6.ParseSrcTcp(packet)
			x.Layer.V6Layer.ReplaceSrcAddrTcp(packet, srcAddr)
			ipv6.CalcTCPCheckSum(packet)
		} else if p == "udp" {
			srcAddr := ipv6.ParseSrcUdp(packet)
			x.Layer.V6Layer.ReplaceSrcAddrUdp(packet, srcAddr)
			ipv6.CalcUDPCheckSum(packet)
		} else if p == "icmp" {
			srcAddr := ipv6.ParseSrcIcmpTag(packet, false) // client ip
			dstAddr := ipv6.ParseDstIcmpTag(packet, false) // dst ip
			x.Layer.V6Layer.ReplaceSrcAddrIcmp(packet, dstAddr, srcAddr)
			ipv6.CalcICMPCheckSum(packet)
		}
	}
}

func contextOpened(_ctx context.Context) bool {
	select {
	case <-_ctx.Done():
		return false
	default:
		return true
	}
}
