package gofly

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"gofly/pkg/config"
	"gofly/pkg/layers"
	"gofly/pkg/layers/ipv4"
	"gofly/pkg/layers/ipv6"
	"gofly/pkg/logger"
	"gofly/pkg/protocol/ws"
	ct "gofly/pkg/tun"
	"gofly/pkg/utils"
	tun2 "golang.zx2c4.com/wireguard/tun"
	"log"
	"net"
	"net/http"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

var _ctx context.Context
var cancel context.CancelFunc
var tun tun2.Device
var tnet *ct.Net
var layer *layers.Layer

func parseAddr(address []string) []netip.Addr {
	var result []netip.Addr
	for _, addr := range address {
		result = append(result, netip.MustParseAddr(addr))
	}
	return result
}

func StartServer(config *config.Config) {
	_ctx, cancel = context.WithCancel(context.Background())
	ipv4Addr := utils.FindAIPv4Address(config.Wg.Address)
	if ipv4Addr == "" {
		logger.Logger.Fatal("can not find a ipv4 address from configuration.")
		return
	}
	ipv6Addr := utils.FindAIPv6Address(config.Wg.Address)
	if ipv6Addr == "" {
		logger.Logger.Fatal("can not find a ipv6 address from configuration.")
		return
	}
	layer = &layers.Layer{
		V4Layer: ipv4.New(ipv4Addr),
		V6Layer: ipv6.New(ipv6Addr),
	}
	ct.Init(_ctx)
	var err error
	tun, tnet, err = ct.CreateNetTUN(
		parseAddr(config.Wg.Address),
		parseAddr(config.Wg.DNS),
		config.Wg.MTU,
	)
	if err != nil {
		log.Panic(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	ClientConfig := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25\nendpoint=%s", config.Wg.SecretKey, config.Wg.Peers[0].PublicKey, config.Wg.Peers[0].PreSharedKey, config.Wg.Peers[0].EndPoint)
	err = dev.IpcSet(ClientConfig)
	if err != nil {
		log.Panic(err)
	}
	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}
	go RunLocalHttpServer()
	server := ws.New(layer)
	//websocket server
	server.StartServerForApi(
		config,
		func(bts []byte) (int, error) {
			a := <-tnet.WaitRecvCh.Out
			n := len(a)
			copy(bts[:n], a)
			return n, nil
		},
		func(i int) {},
		func(bts []byte) int {
			n := len(bts)
			tnet.WaitSendCh.In <- bts
			return n
		},
		func(i int) {},
		_ctx)
}

func RunLocalHttpServer() {
	listener, err := tnet.ListenTCP(&net.TCPAddr{Port: 80})
	if err != nil {
		log.Panicln(err)
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.GET("/myip", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"ip":         c.Request.RemoteAddr,
			"user-agent": c.Request.UserAgent(),
		})
	})
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, ":)   this is vpn gateway!")
	})
	err = r.RunListener(listener)
	if err != nil {
		log.Panicln(err)
	}
}

func Close() {
	cancel()
}
