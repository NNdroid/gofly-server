package ws

import (
	"context"
	"github.com/net-byte/vtun/common/netutil"
	"go.uber.org/zap"
	"gofly/pkg/config"
	"gofly/pkg/layers"
	"gofly/pkg/layers/ipv4"
	"gofly/pkg/layers/ipv6"
	"gofly/pkg/logger"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/golang/snappy"

	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
)

type Server struct {
	Layer *layers.Layer
}

func New(layer *layers.Layer) *Server {
	return &Server{
		Layer: layer,
	}
}

// StartServerForApi starts the ws server
func (x *Server) StartServerForApi(config *config.Config, readFunc func([]byte) (int, error), readCallback func(int), writeFunc func([]byte) int, writeCallback func(int), _ctx context.Context) {
	// server -> client
	go x.toClient(config, readFunc, readCallback, _ctx)
	// client -> server
	srv := http.NewServeMux()
	srv.HandleFunc(config.VTun.Path, func(w http.ResponseWriter, r *http.Request) {
		if !x.checkPermission(w, r, config) {
			logger.Logger.Error("[server] authentication failed")
			return
		}
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			logger.Logger.Error("[server] failed to upgrade http", zap.Error(err))
			return
		}
		x.toServer(config, conn, writeFunc, writeCallback, _ctx)
	})

	srv.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "6")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("CF-Cache-Status", "DYNAMIC")
		w.Header().Set("Server", "cloudflare")
		w.Write([]byte(`follow`))
	})

	log.Printf("vtun websocket server started on %v", config.VTun.LocalAddr)
	if config.VTun.Protocol == "wss" && config.VTun.TLSCertificateFilePath != "" && config.VTun.TLSCertificateKeyFilePath != "" {
		err := http.ListenAndServeTLS(config.VTun.LocalAddr, config.VTun.TLSCertificateFilePath, config.VTun.TLSCertificateKeyFilePath, srv)
		if err != nil {
			logger.Logger.Fatal("http listen Error", zap.Error(err))
		}
	} else {
		err := http.ListenAndServe(config.VTun.LocalAddr, srv)
		if err != nil {
			logger.Logger.Fatal("http listen Error", zap.Error(err))
		}
	}
}

// checkPermission checks the permission of the request
func (x *Server) checkPermission(w http.ResponseWriter, req *http.Request, config *config.Config) bool {
	if config.VTun.Key == "" {
		return true
	}
	key := req.Header.Get("key")
	if key != config.VTun.Key {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("No permission"))
		return false
	}
	return true
}

// toClient sends data to client
func (x *Server) toClient(config *config.Config, readFunc func([]byte) (int, error), callback func(int), _ctx context.Context) {
	packet := make([]byte, config.VTun.BufferSize)
	for contextOpened(_ctx) {
		n, err := readFunc(packet)
		if err != nil {
			logger.Logger.Error("getData Error", zap.Error(err))
			break
		}
		if n == 0 {
			continue
		}
		b := packet[:n]
		x.convertDstAddr(b)
		if key := netutil.GetDstKey(b); key != "" {
			if v, ok := cache.GetCache().Get(key); ok {
				if config.VTun.Obfs {
					b = cipher.XOR(b)
				}
				if config.VTun.Compress {
					b = snappy.Encode(nil, b)
				}
				err := wsutil.WriteServerBinary(v.(net.Conn), b)
				if err != nil {
					cache.GetCache().Delete(key)
					continue
				}
				callback(n)
			}
		}
	}
}

func (x *Server) convertDstAddr(packet []byte) {
	version := packet[0] >> 4
	if version == 4 {
		//if layers.IsPrivate(packet[12:16]) {
		//	return
		//}
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
	version := packet[0] >> 4
	if version == 4 {
		//if layers.IsPrivate(packet[16:20]) {
		//	return
		//}
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

// toServer sends data to server
func (x *Server) toServer(config *config.Config, conn net.Conn, writeFunc func([]byte) int, callback func(int), _ctx context.Context) {
	defer conn.Close()
	for contextOpened(_ctx) {
		b, op, err := wsutil.ReadClientData(conn)
		if err != nil {
			logger.Logger.Error("ReadClientData Error", zap.Error(err))
			break
		}
		if op == ws.OpText {
			err := wsutil.WriteServerMessage(conn, op, b)
			if err != nil {
				logger.Logger.Error("WriteServerMessage Error", zap.Error(err))
				return
			}
		} else if op == ws.OpBinary {
			if config.VTun.Compress {
				b, _ = snappy.Decode(nil, b)
			}
			if config.VTun.Obfs {
				b = cipher.XOR(b)
			}
			if key := netutil.GetSrcKey(b); key != "" {
				cache.GetCache().Set(key, conn, 24*time.Hour)
				x.convertSrcAddr(b)
				callback(len(b))
				writeFunc(b)
			}
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
