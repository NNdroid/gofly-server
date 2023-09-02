package basic

import (
	"context"
	"github.com/klauspost/compress/snappy"
	"github.com/patrickmn/go-cache"
	"go.uber.org/zap"
	"gofly/pkg/cipher"
	"gofly/pkg/config"
	"gofly/pkg/layers"
	"gofly/pkg/layers/ipv4"
	"gofly/pkg/layers/ipv6"
	"gofly/pkg/logger"
	"gofly/pkg/statistics"
	"gofly/pkg/x/xcrypto"
	"gofly/pkg/x/xproto"
	"time"
)

type ServerForApi interface {
	Init()
	StartServerForApi()
}

func ContextOpened(_ctx context.Context) bool {
	select {
	case <-_ctx.Done():
		return false
	default:
		return true
	}
}

type Server struct {
	Layer           *layers.Layer
	Config          *config.Config
	ReadFunc        func([]byte) (int, error)
	WriteFunc       func([]byte) int
	WriteToTunFunc  func(buf []byte) (int, error)
	CTX             context.Context
	ConnectionCache *cache.Cache
	Statistics      *statistics.Statistics
	xp              *xcrypto.XCrypto
	authKey         *xproto.AuthKey
}

func (x *Server) Init() {
	cipher.SetKey(x.Config.VTunSettings.Key)
	x.authKey = xproto.ParseAuthKeyFromString(x.Config.VTunSettings.Key)
	x.xp = &xcrypto.XCrypto{}
	err := x.xp.Init(x.Config.VTunSettings.Key)
	if err != nil {
		logger.Logger.Sugar().Panicf("Init XCrypto failed: %s", err)
	}
}

func (x *Server) ConvertDstAddr(packet []byte) {
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

func (x *Server) ConvertSrcAddr(packet []byte) {
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

func (x *Server) BasicEncode(b []byte) ([]byte, error) {
	if x.Config.VTunSettings.Obfs {
		b = cipher.XOR(b)
	}
	if x.Config.VTunSettings.Compress {
		b = snappy.Encode(nil, b)
	}
	return b, nil
}

func (x *Server) BasicDecode(b []byte) ([]byte, error) {
	var err error
	if x.Config.VTunSettings.Compress {
		b, err = snappy.Decode(nil, b)
		if err != nil {
			return nil, err
		}
	}
	if x.Config.VTunSettings.Obfs {
		b = cipher.XOR(b)
	}
	return b, nil
}

func (x *Server) ExtendEncode(b []byte) ([]byte, error) {
	var err error
	if x.Config.VTunSettings.Obfs {
		b = cipher.XOR(b)
	}
	b, err = x.xp.Encode(b)
	if err != nil {
		return nil, err
	}
	if x.Config.VTunSettings.Compress {
		b = snappy.Encode(nil, b)
	}
	return b, nil
}

func (x *Server) ExtendDecode(b []byte) ([]byte, error) {
	var err error
	if x.Config.VTunSettings.Compress {
		b, err = snappy.Decode(nil, b)
		if err != nil {
			return nil, err
		}
	}
	b, err = x.xp.Decode(b)
	if err != nil {
		return nil, err
	}
	if x.Config.VTunSettings.Obfs {
		b = cipher.XOR(b)
	}
	return b, nil
}

func (x *Server) AuthKey() *xproto.AuthKey {
	return x.authKey
}

func GetTimeout() time.Time {
	return time.Now().Add(time.Second * 9)
}
