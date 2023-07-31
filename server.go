package gofly

import (
	"context"
	"errors"
	"go.uber.org/zap"
	"gofly/pkg/config"
	"gofly/pkg/layers"
	"gofly/pkg/layers/ipv4"
	"gofly/pkg/layers/ipv6"
	"gofly/pkg/logger"
	"gofly/pkg/protocol/basic"
	"gofly/pkg/protocol/reality"
	"gofly/pkg/protocol/ws"
	"gofly/pkg/statistics"
	ct "gofly/pkg/tun"
	"gofly/pkg/utils"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	tun2 "golang.zx2c4.com/wireguard/tun"
	"log"
)

var _ctx context.Context
var cancel context.CancelFunc
var ti tun2.Device
var tNet *ct.Net
var layer *layers.Layer
var stats *statistics.Statistics

func StartServer(config *config.Config) {
	_ctx, cancel = context.WithCancel(context.Background())
	ipv4Addr := utils.FindAIPv4Address(config.WireGuardSettings.Address)
	if ipv4Addr == "" {
		logger.Logger.Fatal("can not find a ipv4 address from configuration.")
		return
	}
	ipv6Addr := utils.FindAIPv6Address(config.WireGuardSettings.Address)
	if ipv6Addr == "" {
		logger.Logger.Fatal("can not find a ipv6 address from configuration.")
		return
	}
	layer = &layers.Layer{
		V4Layer: ipv4.New(ipv4Addr),
		V6Layer: ipv6.New(ipv6Addr),
	}
	layer.LoadAddress(config.WireGuardSettings.Address)
	ct.Init(_ctx)
	var err error
	ti, tNet, err = ct.CreateNetTUN(
		utils.ParseAddr(config.WireGuardSettings.Address),
		utils.ParseAddr(config.WireGuardSettings.DNS),
		config.WireGuardSettings.MTU,
	)
	if err != nil {
		log.Panic(err)
	}
	logLevel := device.LogLevelSilent
	if config.VTunSettings.Verbose {
		logLevel = device.LogLevelVerbose
	}
	dev := device.NewDevice(ti, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))
	ClientConfig := createIPCRequest(config)
	err = dev.IpcSet(ClientConfig)
	if err != nil {
		log.Panic(err)
	}
	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}
	go ReadTunSync(config)
	//go RunHttpClient()
	go RunLocalHttpServer()
	stats = &statistics.Statistics{}
	go stats.AutoUpdateChartData()
	bs := basic.Server{
		Layer:          layer,
		Config:         config,
		ReadFunc:       ReadFromWireGuard,
		WriteFunc:      WriteToWireGuard,
		WriteToTunFunc: WriteToTun,
		CTX:            _ctx,
		Statistics:     stats,
	}
	var server basic.ServerForApi
	switch config.VTunSettings.Protocol {
	case "ws", "wss":
		err = config.WebSocketSettings.Check()
		if err != nil {
			logger.Logger.Sugar().Errorf("error: %v\n", zap.Error(err))
			return
		}
		server = &ws.Server{
			Server: bs,
		}
		break
	case "reality":
		err = config.RealitySettings.Check()
		if err != nil {
			logger.Logger.Sugar().Errorf("error: %v\n", zap.Error(err))
			return
		}
		server = &reality.Server{
			Server: bs,
		}
		break
	default:
		log.Panic(errors.New("unsupported protocol"))
	}
	//start server
	server.StartServerForApi()
}

func ReadTunSync(config *config.Config) {
	buffer := make([]byte, config.VTunSettings.BufferSize)
	for contextOpened(_ctx) {
		n, err := ReadFromTun(buffer)
		if err != nil {
			logger.Logger.Sugar().Errorf("ReadFromTun error %v\n", zap.Error(err))
		}
		b := make([]byte, n)
		copy(b, buffer[:n])
		tNet.WaitRecvCh.In <- b
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

func ReadFromWireGuard(bts []byte) (int, error) {
	a := <-tNet.WaitRecvCh.Out
	n := len(a)
	copy(bts[:n], a)
	return n, nil
}

func WriteToWireGuard(bts []byte) int {
	n := len(bts)
	tNet.WaitSendCh.In <- bts
	return n
}

func ReadFromTun(buf []byte) (int, error) {
	return ti.(*ct.NetTun).ReadFromTun(buf, 0)
}

func WriteToTun(buf []byte) (int, error) {
	return ti.(*ct.NetTun).WriteToTun(buf, 0)
}

func Close() {
	cancel()
}
