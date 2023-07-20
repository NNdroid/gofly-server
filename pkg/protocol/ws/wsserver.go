package ws

import (
	"context"
	"github.com/net-byte/vtun/common/netutil"
	"go.uber.org/zap"
	"gofly/pkg/config"
	"gofly/pkg/layers"
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

// StartServerForApi starts the ws server
func StartServerForApi(config *config.Config, readFunc func([]byte) (int, error), readCallback func(int), writeFunc func([]byte) int, writeCallback func(int), _ctx context.Context) {
	// server -> client
	go toClient(config, readFunc, readCallback, _ctx)
	// client -> server
	http.HandleFunc(config.VTun.Path, func(w http.ResponseWriter, r *http.Request) {
		if !checkPermission(w, r, config) {
			logger.Logger.Error("[server] authentication failed")
			return
		}
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			logger.Logger.Error("[server] failed to upgrade http", zap.Error(err))
			return
		}
		toServer(config, conn, writeFunc, writeCallback, _ctx)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
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
		err := http.ListenAndServeTLS(config.VTun.LocalAddr, config.VTun.TLSCertificateFilePath, config.VTun.TLSCertificateKeyFilePath, nil)
		if err != nil {
			logger.Logger.Fatal("http listen Error", zap.Error(err))
		}
	} else {
		err := http.ListenAndServe(config.VTun.LocalAddr, nil)
		if err != nil {
			logger.Logger.Fatal("http listen Error", zap.Error(err))
		}
	}
}

// checkPermission checks the permission of the request
func checkPermission(w http.ResponseWriter, req *http.Request, config *config.Config) bool {
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
func toClient(config *config.Config, readFunc func([]byte) (int, error), callback func(int), _ctx context.Context) {
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
		convertDstAddr(b)
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

func convertDstAddr(packet []byte) {
	version := packet[0] >> 4
	if version == 4 {
		//if layers.IsPrivate(packet[12:16]) {
		//	return
		//}
		p := layers.GetProtocol(packet)
		//log.Printf("Dst -0: %v\n", p)
		if p == "tcp" {
			//log.Printf("DstT -a: %v\n", packet)
			dstAddr := layers.ParseDstTcp(packet)
			layers.ReplaceDstAddrTcp(packet, dstAddr)
			layers.CalcIPCheckSum(packet)
			layers.CalcTCPCheckSum(packet)
			//log.Printf("DstT -b: %v\n", packet)
		} else if p == "udp" {
			//log.Printf("DstU -a: %v\n", packet)
			dstAddr := layers.ParseDstUdp(packet)
			layers.ReplaceDstAddrUdp(packet, dstAddr)
			layers.CalcIPCheckSum(packet)
			layers.CalcUDPCheckSum(packet)
			//log.Printf("DstU -b: %v\n", packet)
		} else if p == "icmp" {
			//log.Printf("DstU -a: %v\n", packet)
			srcAddr := layers.ParseSrcIcmpTag(packet, true) // client ip
			dstAddr := layers.ParseDstIcmpTag(packet, true) // dst ip
			layers.ReplaceDstAddrIcmp(packet, dstAddr, srcAddr)
			layers.CalcIPCheckSum(packet)
			layers.CalcICMPCheckSum(packet)
			//log.Printf("DstU -b: %v\n", packet)
		}
	} else if version == 6 {
		p := layers.GetProtocolV6(packet)
		srcAddr := layers.GetSrcAddrV6(packet)
		dstAddr := layers.GetDstAddrV6(packet)
		log.Printf("DST => p: %s, src: %s -> dst: %s\n", p, srcAddr.String(), dstAddr.String())
	}
}

func convertSrcAddr(packet []byte) {
	version := packet[0] >> 4
	if version == 4 {
		//if layers.IsPrivate(packet[16:20]) {
		//	return
		//}
		p := layers.GetProtocol(packet)
		//log.Printf("Src -0: %v\n", p)
		if p == "tcp" {
			//log.Printf("SrcT -a: %v\n", packet)
			dstAddr := layers.ParseSrcTcp(packet)
			layers.ReplaceSrcAddrTcp(packet, dstAddr)
			layers.CalcIPCheckSum(packet)
			layers.CalcTCPCheckSum(packet)
			//log.Printf("SrcT -b: %v\n", packet)
		} else if p == "udp" {
			//log.Printf("SrcU -a: %v\n", packet)
			dstAddr := layers.ParseSrcUdp(packet)
			layers.ReplaceSrcAddrUdp(packet, dstAddr)
			layers.CalcIPCheckSum(packet)
			layers.CalcUDPCheckSum(packet)
			//log.Printf("SrcU -b: %v\n", packet)
		} else if p == "icmp" {
			//log.Printf("SrcU -a: %v\n", packet)
			srcAddr := layers.ParseSrcIcmpTag(packet, false) // client ip
			dstAddr := layers.ParseDstIcmpTag(packet, false) // dst ip
			layers.ReplaceSrcAddrIcmp(packet, dstAddr, srcAddr)
			layers.CalcIPCheckSum(packet)
			layers.CalcICMPCheckSum(packet)
			//log.Printf("SrcU -b: %v\n", packet)
		}
	} else if version == 6 {
		p := layers.GetProtocolV6(packet)
		srcAddr := layers.GetSrcAddrV6(packet)
		dstAddr := layers.GetDstAddrV6(packet)
		log.Printf("SRC => p: %s, src: %s -> dst: %s\n", p, srcAddr.String(), dstAddr.String())
	}
}

// toServer sends data to server
func toServer(config *config.Config, conn net.Conn, writeFunc func([]byte) int, callback func(int), _ctx context.Context) {
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
				convertSrcAddr(b)
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
