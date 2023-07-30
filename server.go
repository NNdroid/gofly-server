package gofly

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
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
	"gofly/pkg/web"
	tun2 "golang.zx2c4.com/wireguard/tun"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
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
var stats *statistics.Statistics

func parseAddr(address []string) []netip.Addr {
	var result []netip.Addr
	for _, addr := range address {
		result = append(result, netip.MustParseAddr(addr))
	}
	return result
}

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
		parseAddr(config.WireGuardSettings.Address),
		parseAddr(config.WireGuardSettings.DNS),
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

func RunLocalHttpServer() {
	listener, err := tNet.ListenTCP(&net.TCPAddr{Port: 80})
	if err != nil {
		log.Panicln(err)
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.StaticFS("/dashboard/", http.FS(web.StaticFS))
	g1 := r.Group("/api/v1")
	g1.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	g1.GET("/myinfo", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"connection": c.Request.RemoteAddr,
			"user-agent": c.Request.UserAgent(),
			"ip":         c.ClientIP(),
		})
	})
	g1.GET("/online/count", func(c *gin.Context) {
		c.String(http.StatusOK, strconv.Itoa(stats.OnlineClientCount))
	})
	g1.GET("/traffic", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"rx": stats.RX,
			"tx": stats.TX,
		})
	})
	g1.GET("/traffic/chart", func(c *gin.Context) {
		tbx, rbx, labels, count := stats.ChartData.GetData()
		c.JSON(http.StatusOK, gin.H{
			"receive":   rbx,
			"transport": tbx,
			"labels":    labels,
			"count":     count,
		})
	})
	g1.GET("/clients", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"data": stats.ClientList,
		})
	})
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, ":)   this is vpn gateway!\ndashboard at /dashboard\ncopyright follow 2023")
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

	request.WriteString(fmt.Sprintf("private_key=%s\n", config.WireGuardSettings.SecretKey))

	for _, peer := range config.WireGuardSettings.Peers {
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

var IPv6AddrPortRegex = regexp.MustCompile("^\\[([a-f0-9A-F:]{2,})\\]\\:([0-9]{1,})$")

// convert endpoint string to netip.AddrPort
func parseEndpoints(endpoint string) (*netip.AddrPort, error) {
	var addr netip.Addr
	var port uint16 = 2080
	var err error
	if strings.Count(endpoint, ":") > 1 {
		//ipv6
		matchArr := IPv6AddrPortRegex.FindStringSubmatch(endpoint)
		if len(matchArr) < 3 {
			return nil, errors.New("it not is ipv6 address")
		}
		_port, err := strconv.Atoi(matchArr[2])
		if err != nil {
			return nil, err
		}
		endpoint = matchArr[1]
		port = uint16(_port)
	} else {
		//ipv4 or domain
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
	partLen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partLen++
		case '0' <= c && c <= '9':
			partLen++
		case c == '-':
			if last == '.' {
				return false
			}
			partLen++
			nonNumeric = true
		case c == '.':
			if last == '.' || last == '-' {
				return false
			}
			if partLen > 63 || partLen == 0 {
				return false
			}
			partLen = 0
		}
		last = c
	}
	if last == '-' || partLen > 63 {
		return false
	}
	return nonNumeric
}
