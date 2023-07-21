package gofly

import (
	"bytes"
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gofly/pkg/config"
	"gofly/pkg/layers"
	"gofly/pkg/layers/ipv4"
	"gofly/pkg/layers/ipv6"
	"gofly/pkg/logger"
	"gofly/pkg/protocol/ws"
	ct "gofly/pkg/tun"
	"gofly/pkg/utils"
	tun2 "golang.zx2c4.com/wireguard/tun"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

var _ctx context.Context
var cancel context.CancelFunc
var ti tun2.Device
var tNet *ct.Net
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
	layer.LoadAddress(config.Wg.Address)
	ct.Init(_ctx)
	var err error
	ti, tNet, err = ct.CreateNetTUN(
		parseAddr(config.Wg.Address),
		parseAddr(config.Wg.DNS),
		config.Wg.MTU,
	)
	if err != nil {
		log.Panic(err)
	}
	dev := device.NewDevice(ti, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
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
	go RunHttpClient()
	go RunLocalHttpServer()
	server := &ws.Server{
		Layer:          layer,
		Config:         config,
		ReadFunc:       ReadFromWireGuard,
		ReadCallback:   func(i int) {},
		WriteFunc:      WriteToWireGuard,
		WriteCallback:  func(i int) {},
		WriteToTunFunc: WriteToTun,
		CTX:            _ctx,
	}
	//websocket server
	server.StartServerForApi()
}

func ReadTunSync(config *config.Config) {
	buffer := make([]byte, config.VTun.BufferSize)
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

func RunLocalHttpServer() {
	listener, err := tNet.ListenTCP(&net.TCPAddr{Port: 80})
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

func RunHttpClient() {
	client := http.Client{
		Transport: &http.Transport{
			DialContext: tNet.DialContext,
		},
	}
	resp, err := client.Get("http://172.16.222.1/")
	if err != nil {
		log.Panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Panic(err)
	}
	log.Println(string(body))
}

func Close() {
	cancel()
}

// serialize the config into an IPC request
func createIPCRequest(config *config.Config) string {
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", config.Wg.SecretKey))

	for _, peer := range config.Wg.Peers {
		endpoint, err := parseEndpoints(peer.EndPoint)
		if err != nil {
			logger.Logger.Sugar().Error(zap.Error(err))
			os.Exit(-1)
		}
		var appendPSKText = ""
		if peer.PreSharedKey != "" {
			appendPSKText = fmt.Sprintf("preshared_key=%s\n", peer.PreSharedKey)
		}
		request.WriteString(fmt.Sprintf("public_key=%s\nendpoint=%s\npersistent_keepalive_interval=%d\n%s",
			peer.PublicKey, endpoint.String(), peer.KeepAlive, appendPSKText))
		for _, ip := range peer.AllowedIPs {
			request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip))
		}
	}
	return request.String()[:request.Len()]
}

// convert endpoint string to netip.Addr
func parseEndpoints(endpoint string) (*netip.AddrPort, error) {
	var addr netip.Addr
	var port uint16 = 2080
	var err error
	if strings.Contains(endpoint, ":") {
		sp := strings.Split(endpoint, ":")
		_port, err := strconv.Atoi(sp[1])
		if err != nil {
			return nil, err
		}
		endpoint = sp[0]
		port = uint16(_port)
	}
	if IsDomainName(endpoint) {
		ip, err := LookupDomainFirst(endpoint)
		if err != nil {
			return nil, err
		}
		endpoint = ip.String()
	}
	addr, err = netip.ParseAddr(endpoint)
	if err != nil {
		return nil, err
	}
	result := netip.AddrPortFrom(addr, port)
	return &result, nil
}

func LookupDomain(domain string) ([]net.IP, error) {
	return net.LookupIP(domain)
}

func LookupDomainFirst(domain string) (net.IP, error) {
	ips, err := LookupDomain(domain)
	if err != nil {
		return nil, err
	}
	return ips[0], nil
}

func IsDomainName(s string) bool {
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}
	last := byte('.')
	nonNumeric := false
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			partlen++
		case c == '-':
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}
	return nonNumeric
}
