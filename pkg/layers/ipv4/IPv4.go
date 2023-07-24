package ipv4

import (
	"gofly/pkg/natmap"
	"net"
	"strconv"
)

type V4Layer struct {
	ReverseIP net.IP
	NatTable  *natmap.NatMap
}

func (x *V4Layer) SetReverseIP(ip string) {
	x.ReverseIP = net.ParseIP(ip)
}

func New(ip string) *V4Layer {
	return &V4Layer{
		ReverseIP: net.ParseIP(ip),
		NatTable:  natmap.New(),
	}
}

func ParseSrcTcp(b []byte) *net.TCPAddr {
	ip4HeaderLen := GetHeaderLength(b)
	ip4 := net.IP{b[12], b[13], b[14], b[15]}
	port := ReadPort(b[ip4HeaderLen+0 : ip4HeaderLen+2])
	return &net.TCPAddr{
		IP:   ip4,
		Port: port,
	}
}

func ParseSrcUdp(b []byte) *net.UDPAddr {
	ip4HeaderLen := GetHeaderLength(b)
	ip4 := net.IP{b[12], b[13], b[14], b[15]}
	port := ReadPort(b[ip4HeaderLen+0 : ip4HeaderLen+2])
	return &net.UDPAddr{
		IP:   ip4,
		Port: port,
	}
}

func ParseDstTcp(b []byte) *net.TCPAddr {
	ip4HeaderLen := GetHeaderLength(b)
	ip4 := net.IP{b[16], b[17], b[18], b[19]}
	port := ReadPort(b[ip4HeaderLen+2 : ip4HeaderLen+4])
	return &net.TCPAddr{
		IP:   ip4,
		Port: port,
	}
}

func ParseDstUdp(b []byte) *net.UDPAddr {
	ip4HeaderLen := GetHeaderLength(b)
	ip4 := net.IP{b[16], b[17], b[18], b[19]}
	port := ReadPort(b[ip4HeaderLen+2 : ip4HeaderLen+4])
	return &net.UDPAddr{
		IP:   ip4,
		Port: port,
	}
}

func (x *V4Layer) ReplaceSrcAddrIcmp(b []byte, srcAddr *natmap.ICMPPair, dstAddr *natmap.ICMPPair) {
	reverseAddr := x.NatTable.CreateCheckIcmp(srcAddr, dstAddr)
	if reverseAddr != nil {
		copy(b[12:16], x.ReverseIP.To4()[:])
	}
}

func (x *V4Layer) ReplaceDstAddrIcmp(b []byte, srcAddr *natmap.ICMPPair, dstAddr *natmap.ICMPPair) {
	reverseAddr := x.NatTable.CreateCheckIcmp(dstAddr, srcAddr)
	if reverseAddr != nil {
		copy(b[16:20], reverseAddr.IP.To4()[:])
	}
}

func (x *V4Layer) ReplaceSrcAddrTcp(b []byte, addr *net.TCPAddr) {
	ip4HeaderLen := GetHeaderLength(b)
	reverseAddr := x.NatTable.CreateCheckTcp(addr, x.ReverseIP, false)
	if reverseAddr != nil {
		copy(b[12:16], reverseAddr.IP.To4()[:])
		WritePort(b[ip4HeaderLen+0:ip4HeaderLen+2], reverseAddr.Port)
	}
}

func (x *V4Layer) ReplaceSrcAddrUdp(b []byte, addr *net.UDPAddr) {
	ip4HeaderLen := GetHeaderLength(b)
	reverseAddr := x.NatTable.CreateCheckUdp(addr, x.ReverseIP, false)
	if reverseAddr != nil {
		copy(b[12:16], reverseAddr.IP.To4()[:])
		WritePort(b[ip4HeaderLen+0:ip4HeaderLen+2], reverseAddr.Port)
	}
}

func (x *V4Layer) ReplaceDstAddrTcp(b []byte, addr *net.TCPAddr) {
	ip4HeaderLen := GetHeaderLength(b)
	reverseAddr := x.NatTable.CreateCheckTcp(addr, x.ReverseIP, true)
	if reverseAddr != nil {
		copy(b[16:20], reverseAddr.IP.To4()[:])
		WritePort(b[ip4HeaderLen+2:ip4HeaderLen+4], reverseAddr.Port)
	}
}

func (x *V4Layer) ReplaceDstAddrUdp(b []byte, addr *net.UDPAddr) {
	ip4HeaderLen := GetHeaderLength(b)
	reverseAddr := x.NatTable.CreateCheckUdp(addr, x.ReverseIP, true)
	if reverseAddr != nil {
		copy(b[16:20], reverseAddr.IP.To4()[:])
		WritePort(b[ip4HeaderLen+2:ip4HeaderLen+4], reverseAddr.Port)
	}
}

// ReadPort []byte length to int length
func ReadPort(header []byte) int {
	length := 0
	if len(header) >= 2 {
		length = ((length & 0x00) | int(header[0])) << 8
		length = length | int(header[1])
	}
	return length
}

func WritePort(header []byte, length int) {
	if len(header) >= 2 {
		header[0] = byte(length >> 8 & 0xff)
		header[1] = byte(length & 0xff)
	}
}

func GetProtocol(b []byte) string {
	if b[9] == 0x01 {
		return "icmp"
	} else if b[9] == 0x06 {
		return "tcp"
	} else if b[9] == 0x11 {
		return "udp"
	}
	return strconv.Itoa(int(b[9]))
}

func IsPrivate(ip []byte) bool {
	if len(ip) == 4 {
		return net.IP{ip[0], ip[1], ip[2], ip[3]}.IsPrivate()
	} else if len(ip) == 16 {
		return net.IP{ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]}.IsPrivate()
	}
	return false
}

func GetHeaderLength(b []byte) int {
	return int((b[0] & 0x0f) * 4)
}

func GetPayloadLength(b []byte) int {
	total := ReadPort(b[2:4])
	return total - GetHeaderLength(b)
}

func CalcUDPCheckSum(packet []byte) {
	if len(packet) < IPHeaderLengthMinimum {
		return
	}
	ip4HeaderLen := GetHeaderLength(packet)   // 20 v
	ip4PayloadLen := GetPayloadLength(packet) //116 v
	if len(packet) < ip4HeaderLen+ip4PayloadLen {
		return
	}
	packet[ip4HeaderLen+6] = 0x00
	packet[ip4HeaderLen+7] = 0x00
	result := 0
	result += ReadPort(packet[12:14])      // src address 49320
	result += ReadPort(packet[14:16])      // 74932
	result += ReadPort(packet[16:18])      // dst address 124252
	result += ReadPort(packet[18:20])      // 150011
	result += ReadPort([]byte{0x00, 0x11}) // 0, 6 //150017
	tl1 := byte((ip4PayloadLen & 0xff00) >> 8)
	tl2 := byte(ip4PayloadLen & 0x00ff)
	result += ReadPort([]byte{tl1, tl2})           // tcp length 150133
	l := ((ip4HeaderLen + ip4PayloadLen) % 2) == 1 // false
	n := ip4PayloadLen / 2
	for i := 0; i < n; i++ {
		result += ReadPort(packet[ip4HeaderLen+i*2 : ip4HeaderLen+i*2+2])
	}
	if l {
		result += (int(packet[ip4HeaderLen+ip4PayloadLen-1]) << 8) & 0xff00
	}
	hl := ((result & 0xffff0000) >> 16) & 0x0000ffff
	ll := result & 0x0000ffff
	x := hl + ll
	WritePort(packet[ip4HeaderLen+6:ip4HeaderLen+8], 0xffff-x)
}

func CalcTCPCheckSum(packet []byte) {
	if len(packet) < IPHeaderLengthMinimum {
		return
	}
	ip4HeaderLen := GetHeaderLength(packet)   // 20 v
	ip4PayloadLen := GetPayloadLength(packet) //116 v
	if len(packet) < ip4HeaderLen+ip4PayloadLen {
		return
	}
	packet[ip4HeaderLen+16] = 0x00
	packet[ip4HeaderLen+17] = 0x00
	result := 0
	result += ReadPort(packet[12:14])      // src address 49320
	result += ReadPort(packet[14:16])      // 74932
	result += ReadPort(packet[16:18])      // dst address 124252
	result += ReadPort(packet[18:20])      // 150011
	result += ReadPort([]byte{0x00, 0x06}) // 0, 6 //150017
	tl1 := byte((ip4PayloadLen & 0xff00) >> 8)
	tl2 := byte(ip4PayloadLen & 0x00ff)
	result += ReadPort([]byte{tl1, tl2})           // tcp length 150133
	l := ((ip4HeaderLen + ip4PayloadLen) % 2) == 1 // false
	n := ip4PayloadLen / 2
	for i := 0; i < n; i++ {
		result += ReadPort(packet[ip4HeaderLen+i*2 : ip4HeaderLen+i*2+2])
	}
	if l {
		result += (int(packet[ip4HeaderLen+ip4PayloadLen-1]) << 8) & 0xff00
	}
	hl := ((result & 0xffff0000) >> 16) & 0x0000ffff
	ll := result & 0x0000ffff
	x := hl + ll
	WritePort(packet[ip4HeaderLen+16:ip4HeaderLen+18], 0xffff-x)
}

const IPHeaderLengthMinimum = 20

func CalcIPCheckSum(packet []byte) {
	if len(packet) < IPHeaderLengthMinimum {
		return
	}
	packet[10] = 0x00
	packet[11] = 0x00
	result := ReadPort(packet[10:12])
	ip4HeaderLen := GetHeaderLength(packet)
	if len(packet) < ip4HeaderLen {
		return
	}
	l := (ip4HeaderLen % 2) == 1
	n := ip4HeaderLen / 2
	for i := 0; i < n; i++ {
		result += ReadPort(packet[i*2 : i*2+2])
	}
	if l {
		result += int(packet[ip4HeaderLen-1])
	}
	hl := ((result & 0xffff0000) >> 16) & 0x0000ffff
	ll := result & 0x0000ffff
	x := hl + ll
	WritePort(packet[10:12], 0xffff-x)
}

func CalcICMPCheckSum(packet []byte) {
	if len(packet) < IPHeaderLengthMinimum {
		return
	}
	result := 0
	ip4HeaderLen := GetHeaderLength(packet)
	ip4PayloadLen := GetPayloadLength(packet)
	if len(packet) < ip4HeaderLen+ip4PayloadLen {
		return
	}
	packet[ip4HeaderLen+2] = 0x00
	packet[ip4HeaderLen+3] = 0x00
	l := (ip4PayloadLen % 2) == 1
	n := ip4PayloadLen / 2
	for i := 0; i < n; i++ {
		result += ReadPort(packet[ip4HeaderLen+i*2 : ip4HeaderLen+i*2+2])
	}
	if l {
		result += (int(packet[ip4HeaderLen+ip4PayloadLen-1]) << 8) & 0xff00
	}
	hl := ((result & 0xffff0000) >> 16) & 0x0000ffff
	ll := result & 0x0000ffff
	x := hl + ll
	WritePort(packet[ip4HeaderLen+2:ip4HeaderLen+4], 0xffff-x)
}

func ParseSrcIcmpTag(b []byte, dstMode bool) *natmap.ICMPPair {
	ip4HeaderLen := GetHeaderLength(b)
	var result natmap.ICMPPair
	result.IP = net.IP{b[12], b[13], b[14], b[15]}
	if dstMode {
		result.Tag = ReadPort(b[ip4HeaderLen+4 : ip4HeaderLen+6])
	} else {
		result.Tag = ReadPort(b[ip4HeaderLen : ip4HeaderLen+2])
	}
	return &result
}

func ParseDstIcmpTag(b []byte, dstMode bool) *natmap.ICMPPair {
	ip4HeaderLen := GetHeaderLength(b)
	var result natmap.ICMPPair
	result.IP = net.IP{b[16], b[17], b[18], b[19]}
	if dstMode {
		result.Tag = ReadPort(b[ip4HeaderLen : ip4HeaderLen+2])
	} else {
		result.Tag = ReadPort(b[ip4HeaderLen+4 : ip4HeaderLen+6])
	}
	return &result
}
