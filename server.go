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

type AppContainer struct {
	CTX       context.Context
	CANCEL    context.CancelFunc
	TunDevice tun2.Device
	TunNet    *ct.Net
	Layer     *layers.Layer
	Stats     *statistics.Statistics
	Device    *device.Device
}

func StartServer(config *config.Config) {
	app := &AppContainer{}
	app.CTX, app.CANCEL = context.WithCancel(context.Background())
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
	app.Layer = &layers.Layer{
		V4Layer: ipv4.New(ipv4Addr),
		V6Layer: ipv6.New(ipv6Addr),
	}
	app.Layer.LoadAddress(config.WireGuardSettings.Address)
	ct.Init(app.CTX)
	var err error
	app.TunDevice, app.TunNet, err = ct.CreateNetTUN(
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
	dev := device.NewDevice(app.TunDevice, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))
	ClientConfig := createIPCRequest(config)
	err = dev.IpcSet(ClientConfig)
	if err != nil {
		log.Panic(err)
	}
	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}
	go app.ReadTunSync(config)
	//go app.RunHttpClient()
	go app.RunLocalHttpServer()
	app.Stats = &statistics.Statistics{}
	go app.Stats.AutoUpdateChartData()
	app.Stats.EnableCronTask()
	bs := basic.Server{
		Layer:          app.Layer,
		Config:         config,
		ReadFunc:       app.ReadFromWireGuard,
		WriteFunc:      app.WriteToWireGuard,
		WriteToTunFunc: app.WriteToTun,
		CTX:            app.CTX,
		Statistics:     app.Stats,
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
	//init server
	server.Init()
	//start server
	server.StartServerForApi()
}

func (u *AppContainer) ReadTunSync(config *config.Config) {
	buffer := make([]byte, config.VTunSettings.BufferSize)
	for contextOpened(u.CTX) {
		n, err := u.ReadFromTun(buffer)
		if err != nil {
			logger.Logger.Sugar().Errorf("ReadFromTun error %v\n", zap.Error(err))
		}
		b := make([]byte, n)
		copy(b, buffer[:n])
		u.TunNet.WaitRecvCh.In <- b
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

func (u *AppContainer) ReadFromWireGuard(bts []byte) (int, error) {
	a := <-u.TunNet.WaitRecvCh.Out
	n := len(a)
	copy(bts[:n], a)
	return n, nil
}

func (u *AppContainer) WriteToWireGuard(bts []byte) int {
	n := len(bts)
	u.TunNet.WaitSendCh.In <- bts
	return n
}

func (u *AppContainer) ReadFromTun(buf []byte) (int, error) {
	return u.TunDevice.(*ct.NetTun).ReadFromTun(buf, 0)
}

func (u *AppContainer) WriteToTun(buf []byte) (int, error) {
	return u.TunDevice.(*ct.NetTun).WriteToTun(buf, 0)
}

func (u *AppContainer) Close() {
	u.CANCEL()
}
