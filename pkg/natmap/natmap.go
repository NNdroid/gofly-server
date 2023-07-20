package natmap

import (
	"fmt"
	"net"
)

var _tcpPort = 1024
var _udpPort = 1024
var _cacheTcpP = make(map[string]*net.TCPAddr, 65535)
var _cacheTcpN = make(map[string]*net.TCPAddr, 65535)
var _cacheUdpP = make(map[string]*net.UDPAddr, 65535)
var _cacheUdpN = make(map[string]*net.UDPAddr, 65535)
var _cacheICMPP = make(map[string]*ICMPPair, 65535) // client ip:tag1 => dst ip:tag2
var _cacheICMPN = make(map[string]*ICMPPair, 65535) // dst ip:tag2 => client ip:tag1

type ICMPPair struct {
	IP  net.IP
	Tag int
}

func (i *ICMPPair) String() string {
	return fmt.Sprintf("%s:%d", i.IP.String(), i.Tag)
}

func ReserveIcmp(it *ICMPPair) *ICMPPair {
	var key = it.String()
	if _, ok := _cacheICMPP[key]; ok {
		return _cacheICMPP[key]
	}
	if _, ok := _cacheICMPN[key]; ok {
		return _cacheICMPN[key]
	}
	return nil
}

func ReserveTcp(addr *net.TCPAddr) *net.TCPAddr {
	var key = addr.String()
	if _, ok := _cacheTcpP[key]; ok {
		return _cacheTcpP[key]
	}
	if _, ok := _cacheTcpN[key]; ok {
		return _cacheTcpN[key]
	}
	return nil
}

func ReserveUdp(addr *net.UDPAddr) *net.UDPAddr {
	var key = addr.String()
	if _, ok := _cacheUdpP[key]; ok {
		return _cacheUdpP[key]
	}
	if _, ok := _cacheUdpN[key]; ok {
		return _cacheUdpN[key]
	}
	return nil
}

func AppendIcmp(srcAddr *ICMPPair, dstAddr *ICMPPair) {
	var keyP = srcAddr.String()
	var keyN = dstAddr.String()
	_cacheICMPP[keyP] = dstAddr
	_cacheICMPN[keyN] = srcAddr
}

func AppendTcp(srcAddr *net.TCPAddr, dstAddr *net.TCPAddr) {
	var keyP = srcAddr.String()
	var keyN = dstAddr.String()
	_cacheTcpP[keyP] = dstAddr
	_cacheTcpN[keyN] = srcAddr
}

func AppendUdp(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr) {
	var keyP = srcAddr.String()
	var keyN = dstAddr.String()
	_cacheUdpP[keyP] = dstAddr
	_cacheUdpN[keyN] = srcAddr
}

func NewIcmp(ip net.IP, tag int) *ICMPPair {
	return &ICMPPair{
		IP:  ip,
		Tag: tag,
	}
}

func NewTcp(ip net.IP, port int) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}
}

func NewUdp(ip net.IP, port int) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   ip,
		Port: port,
	}
}

func CreateIcmp(srcAddr *ICMPPair, dstAddr *ICMPPair) *ICMPPair {
	AppendIcmp(srcAddr, dstAddr)
	return dstAddr
}

func CreateTcp(srcAddr *net.TCPAddr, ip net.IP) *net.TCPAddr {
	var dstAddr = NewTcp(ip, _tcpPort)
	AppendTcp(srcAddr, dstAddr)
	_tcpPort = (_tcpPort + 1) % 65535
	return dstAddr
}

func CreateUdp(srcAddr *net.UDPAddr, ip net.IP) *net.UDPAddr {
	var dstAddr = NewUdp(ip, _udpPort)
	AppendUdp(srcAddr, dstAddr)
	_udpPort = (_udpPort + 1) % 65535
	return dstAddr
}

func CreateCheckIcmp(srcAddr *ICMPPair, dstAddr *ICMPPair) *ICMPPair {
	reverseAddr := ReserveIcmp(srcAddr)
	if reverseAddr == nil {
		reverseAddr = CreateIcmp(srcAddr, dstAddr)
	}
	return reverseAddr
}

func CreateCheckTcp(srcAddr *net.TCPAddr, ip net.IP, dstMode bool) *net.TCPAddr {
	if srcAddr.IP.String() == ip.String() && !dstMode {
		return nil
	}
	reverseAddr := ReserveTcp(srcAddr)
	if reverseAddr == nil {
		reverseAddr = CreateTcp(srcAddr, ip)
	}
	return reverseAddr
}

func CreateCheckUdp(srcAddr *net.UDPAddr, ip net.IP, dstMode bool) *net.UDPAddr {
	//log.Printf("srcAddr: %s, ip: %s\n", srcAddr.String(), ip.String())
	if srcAddr.IP.String() == ip.String() && !dstMode {
		return nil
	}
	reverseAddr := ReserveUdp(srcAddr)
	if reverseAddr == nil {
		reverseAddr = CreateUdp(srcAddr, ip)
	}
	return reverseAddr
}
