package natmap

import (
	"fmt"
	"github.com/patrickmn/go-cache"
	"net"
	"time"
)

type NatMap struct {
	_tcpPort    int
	_udpPort    int
	_cacheTcpP  *cache.Cache //key: string, value: *net.TCPAddr
	_cacheTcpN  *cache.Cache //key: string, value: *net.TCPAddr
	_cacheUdpP  *cache.Cache //key: string, value: *net.UDPAddr
	_cacheUdpN  *cache.Cache //key: string, value: *net.UDPAddr
	_cacheICMPP *cache.Cache //key: string, value: *ICMPPair // client ip:tag1 => dst ip:tag2
	_cacheICMPN *cache.Cache //key: string, value: *ICMPPair // dst ip:tag2 => client ip:tag1
}

func New() *NatMap {
	return &NatMap{
		_tcpPort:    1024,
		_udpPort:    1024,
		_cacheTcpP:  cache.New(1*time.Minute, 15*time.Minute),
		_cacheTcpN:  cache.New(1*time.Minute, 15*time.Minute),
		_cacheUdpP:  cache.New(1*time.Minute, 15*time.Minute),
		_cacheUdpN:  cache.New(1*time.Minute, 15*time.Minute),
		_cacheICMPP: cache.New(1*time.Minute, 15*time.Minute), // client ip:tag1 => dst ip:tag2
		_cacheICMPN: cache.New(1*time.Minute, 15*time.Minute), // dst ip:tag2 => client ip:tag1
	}
}

func (x *NatMap) SearchTcpP(key string) (*net.TCPAddr, bool) {
	v, ok := x._cacheTcpP.Get(key)
	if ok {
		return v.(*net.TCPAddr), true
	}
	return nil, false
}

func (x *NatMap) SearchTcpN(key string) (*net.TCPAddr, bool) {
	v, ok := x._cacheTcpN.Get(key)
	if ok {
		return v.(*net.TCPAddr), true
	}
	return nil, false
}

func (x *NatMap) SearchUdpP(key string) (*net.UDPAddr, bool) {
	v, ok := x._cacheUdpP.Get(key)
	if ok {
		return v.(*net.UDPAddr), true
	}
	return nil, false
}

func (x *NatMap) SearchUdpN(key string) (*net.UDPAddr, bool) {
	v, ok := x._cacheUdpN.Get(key)
	if ok {
		return v.(*net.UDPAddr), true
	}
	return nil, false
}

func (x *NatMap) SearchIcmpP(key string) (*ICMPPair, bool) {
	v, ok := x._cacheICMPP.Get(key)
	if ok {
		return v.(*ICMPPair), true
	}
	return nil, false
}

func (x *NatMap) SearchIcmpN(key string) (*ICMPPair, bool) {
	v, ok := x._cacheICMPN.Get(key)
	if ok {
		return v.(*ICMPPair), true
	}
	return nil, false
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
	if v, ok := x.SearchIcmpP(key); ok {
		return v
	}
	if v, ok := x.SearchIcmpN(key); ok {
		return v
	}
	return nil
}

func (x *NatMap) ReserveTcp(addr *net.TCPAddr) *net.TCPAddr {
	var key = addr.String()
	if v, ok := x.SearchTcpP(key); ok {
		return v
	}
	if v, ok := x.SearchTcpN(key); ok {
		return v
	}
	return nil
}

func (x *NatMap) ReserveUdp(addr *net.UDPAddr) *net.UDPAddr {
	var key = addr.String()
	if v, ok := x.SearchUdpP(key); ok {
		return v
	}
	if v, ok := x.SearchUdpN(key); ok {
		return v
	}
	return nil
}

func (x *NatMap) AppendIcmp(srcAddr *ICMPPair, dstAddr *ICMPPair) {
	var keyP = srcAddr.String()
	var keyN = dstAddr.String()
	x._cacheICMPP.Set(keyP, dstAddr, cache.DefaultExpiration)
	x._cacheICMPN.Set(keyN, srcAddr, cache.DefaultExpiration)
}

func (x *NatMap) AppendTcp(srcAddr *net.TCPAddr, dstAddr *net.TCPAddr) {
	var keyP = srcAddr.String()
	var keyN = dstAddr.String()
	x._cacheTcpP.Set(keyP, dstAddr, cache.DefaultExpiration)
	x._cacheTcpN.Set(keyN, srcAddr, cache.DefaultExpiration)
}

func (x *NatMap) AppendUdp(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr) {
	var keyP = srcAddr.String()
	var keyN = dstAddr.String()
	x._cacheUdpP.Set(keyP, dstAddr, cache.DefaultExpiration)
	x._cacheUdpN.Set(keyN, srcAddr, cache.DefaultExpiration)
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
	if x.ReserveTcp(dstAddr) != nil {
		x._tcpPort = (x._tcpPort + 1) % 65535
		return x.CreateTcp(srcAddr, ip)
	}
	x.AppendTcp(srcAddr, dstAddr)
	x._tcpPort = (x._tcpPort + 1) % 65535
	return dstAddr
}

func (x *NatMap) CreateUdp(srcAddr *net.UDPAddr, ip net.IP) *net.UDPAddr {
	var dstAddr = NewUdp(ip, x._udpPort)
	if x.ReserveUdp(dstAddr) != nil {
		x._udpPort = (x._udpPort + 1) % 65535
		return x.CreateUdp(srcAddr, ip)
	}
	x.AppendUdp(srcAddr, dstAddr)
	x._udpPort = (x._udpPort + 1) % 65535
	return dstAddr
}

func (x *NatMap) CreateCheckIcmp(srcAddr *ICMPPair, dstAddr *ICMPPair) *ICMPPair {
	reverseAddr := x.ReserveIcmp(srcAddr)
	if reverseAddr == nil {
		reverseAddr = x.CreateIcmp(srcAddr, dstAddr)
	} else {
		x.AppendIcmp(srcAddr, reverseAddr)
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
	} else {
		x.AppendTcp(srcAddr, reverseAddr)
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
	} else {
		x.AppendUdp(srcAddr, reverseAddr)
	}
	return reverseAddr
}
