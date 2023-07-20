package gofly

import (
	"context"
	"fmt"
	"gofly/pkg/config"
	"gofly/pkg/layers"
	"gofly/pkg/protocol/ws"
	ct "gofly/pkg/tun"
	tun2 "golang.zx2c4.com/wireguard/tun"
	"io"
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

func parseAddr(address []string) []netip.Addr {
	var result []netip.Addr
	for _, addr := range address {
		result = append(result, netip.MustParseAddr(addr))
	}
	return result
}

func StartServer(config *config.Config) {
	_ctx, cancel = context.WithCancel(context.Background())
	layers.SetReverseIP(config.Wg.Address[0])
	layers.SetReverseIPv6(config.Wg.Address[1])
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
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	ClientConfig := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25\nendpoint=%s", config.Wg.SecretKey, config.Wg.Peers[0].PublicKey, config.Wg.Peers[0].PreSharedKey, config.Wg.Peers[0].EndPoint)
	err = dev.IpcSet(ClientConfig)
	if err != nil {
		log.Panic(err)
	}
	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}
	//pr, _ := hex.DecodeString(config.Wg.Peers[0].PublicKey)
	//pk := device.NoisePublicKey{}
	//pk.FromHex(config.Wg.Peers[0].PublicKey)
	//peer := dev.LookupPeer(pk)
	//go peer.RoutineSequentialReceiver(1)
	//go peer.RoutineSequentialReceiver(1)
	go func() {
		listener, err := tnet.ListenTCP(&net.TCPAddr{Port: 80})
		if err != nil {
			log.Panicln(err)
		}
		http.HandleFunc("/vvvv", func(writer http.ResponseWriter, request *http.Request) {
			log.Printf("> %s - %s - %s", request.RemoteAddr, request.URL.String(), request.UserAgent())
			io.WriteString(writer, "Hello from userspace TCP!")
		})
		err = http.Serve(listener, nil)
		if err != nil {
			log.Panicln(err)
		}
	}()
	//bts, _ := hex.DecodeString("4500003eddb0400040111234ac10de02c0a8649fc3580035002a0272799201000001000000000000056374766d34063331303331300378797a00001c0001")
	//tun.Write([][]byte{bts}, 0)
	ws.StartServerForApi(config,
		func(bts []byte) (int, error) {
			a := <-tnet.WaitRecvCh.Out
			n := len(a)
			copy(bts[:n], a)
			return n, nil
		},
		func(i int) {
		},
		func(bts []byte) int {
			n := len(bts)
			tnet.WaitSendCh.In <- bts
			return n
		},
		func(i int) {
		},
		_ctx)
}
