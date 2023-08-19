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
	"gofly/pkg/logger"
	"gofly/pkg/protocol/basic"
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
	basic.Server
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
			if x.Config.VTunSettings.Compress {
				data, _ = snappy.Decode(nil, data)
			}
			if x.Config.VTunSettings.Obfs {
				data = cipher.XOR(data)
			}
			if key := utils.GetSrcKey(data); key != "" {
				x.ConnectionCache.Set(key, c, 24*time.Hour)
				x.ConvertSrcAddr(data)
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
	if !x.Config.VTunSettings.Verbose {
		logging.SetLevel(logging.LevelNone)
		gin.SetMode(gin.ReleaseMode)
	}
	x.ConnectionCache = cache.New(15*time.Minute, 24*time.Hour)
	cipher.SetKey(x.Config.VTunSettings.Key)
	// server -> client
	go x.toClient()
	// client -> server
	mux := &http.ServeMux{}
	mux.HandleFunc(x.Config.WebSocketSettings.Path, x.onWebsocket)
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
	if x.Config.VTunSettings.Protocol == "wss" {
		if x.Config.WebSocketSettings.TLSCertificateFilePath == "" || x.Config.WebSocketSettings.TLSCertificateKeyFilePath == "" {
			log.Panic(errors.New("tls certificate file location not set"))
		}
		cert, err := tls.LoadX509KeyPair(x.Config.WebSocketSettings.TLSCertificateFilePath, x.Config.WebSocketSettings.TLSCertificateKeyFilePath)
		if err != nil {
			log.Panic(err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		svr = nbhttp.NewServer(nbhttp.Config{
			Network:   "tcp",
			AddrsTLS:  []string{x.Config.VTunSettings.LocalAddr},
			TLSConfig: tlsConfig,
			Handler:   mux,
		})
	} else {
		svr = nbhttp.NewServer(nbhttp.Config{
			Network: "tcp",
			Addrs:   []string{x.Config.VTunSettings.LocalAddr},
			Handler: mux,
		})
	}

	err := svr.Start()
	if err != nil {
		logger.Logger.Sugar().Errorf("nbio.Start failed: %v", zap.Error(err))
		return
	}
	defer svr.Stop()

	logger.Logger.Sugar().Infof("gofly %s server started on %v", x.Config.VTunSettings.Protocol, x.Config.VTunSettings.LocalAddr)

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
	if x.Config.VTunSettings.Key == "" {
		return true
	}
	key1 := req.Header.Get(AuthFieldKey)
	key2 := req.URL.Query().Get(AuthFieldKey)
	if key1 != x.Config.VTunSettings.Key && key2 != x.Config.VTunSettings.Key {
		return false
	}
	return true
}

// toClient WireGuard to GateWay - ReadFunc
func (x *Server) toClient() {
	buffer := make([]byte, x.Config.VTunSettings.BufferSize)
	for basic.ContextOpened(x.CTX) {
		n, err := x.ReadFunc(buffer)
		if err != nil {
			logger.Logger.Error("getData Error", zap.Error(err))
			break
		}
		if n == 0 {
			continue
		}
		b := buffer[:n]
		x.ConvertDstAddr(b)
		if key := utils.GetDstKey(b); key != "" {
			if v, ok := x.ConnectionCache.Get(key); ok {
				if x.Config.VTunSettings.Obfs {
					b = cipher.XOR(b)
				}
				if x.Config.VTunSettings.Compress {
					b = snappy.Encode(nil, b)
				}
				ns := len(b)
				conn := v.(*websocket.Conn)
				err = conn.WriteMessage(websocket.BinaryMessage, b)
				if err != nil {
					logger.Logger.Error("write data error", zap.Error(err))
					x.ConnectionCache.Delete(key)
					continue
				}
				x.Statistics.IncrTransportBytes(ns)
				x.Statistics.IncrClientReceivedBytes(conn.RemoteAddr(), ns)
			}
		}
	}
}
