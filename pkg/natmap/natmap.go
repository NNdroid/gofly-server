package natmap

import (
	"fmt"
	"net"
)

type NatMap struct {
	_tcpPort    int
	_udpPort    int
	_cacheTcpP  map[string]*net.TCPAddr
	_cacheTcpN  map[string]*net.TCPAddr
	_cacheUdpP  map[string]*net.UDPAddr
	_cacheUdpN  map[string]*net.UDPAddr
	_cacheICMPP map[string]*ICMPPair // client ip:tag1 => dst ip:tag2
	_cacheICMPN map[string]*ICMPPair // dst ip:tag2 => client ip:tag1
}

func New() *NatMap {
	return &NatMap{
		_tcpPort:    1024,
		_udpPort:    1024,
		_cacheTcpP:  make(map[string]*net.TCPAddr, 65535),
		_cacheTcpN:  make(map[string]*net.TCPAddr, 65535),
		_cacheUdpP:  make(map[string]*net.UDPAddr, 65535),
		_cacheUdpN:  make(map[string]*net.UDPAddr, 65535),
		_cacheICMPP: make(map[string]*ICMPPair, 65535), // client ip:tag1 => dst ip:tag2
		_cacheICMPN: make(map[string]*ICMPPair, 65535), // dst ip:tag2 => client ip:tag1
	}
}

type ICMPPair struct {
	IP  net.IP
	Tag int
}

func (i *ICMPPair) String() string {
	return fmt.Sprintf("%s:%d", i.IP.String(), i.Tag)
}

func (x *NatMap) ReserveIcmp(it *ICMPPair) *ICMPPair {
	var key = it.String()
	if _, ok := x._cacheICMPP[key]; ok {
		return x._cacheICMPP[key]
	}
	if _, ok := x._cacheICMPN[key]; ok {
		return x._cacheICMPN[key]
	}
	return nil
}

func (x *NatMap) ReserveTcp(addr *net.TCPAddr) *net.TCPAddr {
	var key = addr.String()
	if _, ok := x._cacheTcpP[key]; ok {
		return x._cacheTcpP[key]
	}
	if _, ok := x._cacheTcpN[key]; ok {
		return x._cacheTcpN[key]
	}
	return nil
}

func (x *NatMap) ReserveUdp(addr *net.UDPAddr) *net.UDPAddr {
	var key = addr.String()
	if _, ok := x._cacheUdpP[key]; ok {
		return x._cacheUdpP[key]
	}
	if _, ok := x._cacheUdpN[key]; ok {
		return x._cacheUdpN[key]
	}
	return nil
}

func (x *NatMap) AppendIcmp(srcAddr *ICMPPair, dstAddr *ICMPPair) {
	var keyP = srcAddr.String()
	var keyN = dstAddr.String()
	x._cacheICMPP[keyP] = dstAddr
	x._cacheICMPN[keyN] = srcAddr
}

func (x *NatMap) AppendTcp(srcAddr *net.TCPAddr, dstAddr *net.TCPAddr) {
	var keyP = srcAddr.String()
	var keyN = dstAddr.String()
	x._cacheTcpP[keyP] = dstAddr
	x._cacheTcpN[keyN] = srcAddr
}

func (x *NatMap) AppendUdp(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr) {
	var keyP = srcAddr.String()
	var keyN = dstAddr.String()
	x._cacheUdpP[keyP] = dstAddr
	x._cacheUdpN[keyN] = srcAddr
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

func (x *NatMap) CreateIcmp(srcAddr *ICMPPair, dstAddr *ICMPPair) *ICMPPair {
	x.AppendIcmp(srcAddr, dstAddr)
	return dstAddr
}

func (x *NatMap) CreateTcp(srcAddr *net.TCPAddr, ip net.IP) *net.TCPAddr {
	var dstAddr = NewTcp(ip, x._tcpPort)
	x.AppendTcp(srcAddr, dstAddr)
	x._tcpPort = (x._tcpPort + 1) % 65535
	return dstAddr
}

func (x *NatMap) CreateUdp(srcAddr *net.UDPAddr, ip net.IP) *net.UDPAddr {
	var dstAddr = NewUdp(ip, x._udpPort)
	x.AppendUdp(srcAddr, dstAddr)
	x._udpPort = (x._udpPort + 1) % 65535
	return dstAddr
}

func (x *NatMap) CreateCheckIcmp(srcAddr *ICMPPair, dstAddr *ICMPPair) *ICMPPair {
	reverseAddr := x.ReserveIcmp(srcAddr)
	if reverseAddr == nil {
		reverseAddr = x.CreateIcmp(srcAddr, dstAddr)
	}
	return reverseAddr
}

func (x *NatMap) CreateCheckTcp(srcAddr *net.TCPAddr, ip net.IP, dstMode bool) *net.TCPAddr {
	// Do not update NAT table in src mode when source address is same as local IP address
	if srcAddr.IP.String() == ip.String() && !dstMode {
		return nil
	}
	reverseAddr := x.ReserveTcp(srcAddr)
	if reverseAddr == nil {
		reverseAddr = x.CreateTcp(srcAddr, ip)
	}
	return reverseAddr
}

func (x *NatMap) CreateCheckUdp(srcAddr *net.UDPAddr, ip net.IP, dstMode bool) *net.UDPAddr {
	// Do not update NAT table in src mode when source address is same as local IP address
	if srcAddr.IP.String() == ip.String() && !dstMode {
		return nil
	}
	reverseAddr := x.ReserveUdp(srcAddr)
	if reverseAddr == nil {
		reverseAddr = x.CreateUdp(srcAddr, ip)
	}
	return reverseAddr
}
