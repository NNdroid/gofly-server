package ipv6

import (
	"gofly/pkg/natmap"
	"net"
	"strconv"
)

const IPHeaderLength = 40

var ProtocolMap = map[int]string{
	41: "ipv6",  //IPV6头部
	0:  "hop",   //逐跳选项
	60: "dst",   //目的地选项
	43: "route", //路由选项
	44: "split", //分片选项
	50: "esp",   //封装安全载荷
	51: "ah",    //认证
	59: "none",  //没有下一头部
	58: "icmp",  //icmpv6
	17: "udp",
	6:  "tcp",
}

type V6Layer struct {
	ReverseIP net.IP
	NatTable  *natmap.NatMap
}

func (x *V6Layer) SetReverseIPv6(ip string) {
	x.ReverseIP = net.ParseIP(ip)
}

func New(ip string) *V6Layer {
	return &V6Layer{
		ReverseIP: net.ParseIP(ip),
		NatTable:  natmap.New(),
	}
}

func GetSrcAddr(b []byte) net.IP {
	return net.IP{b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]}
}

func GetDstAddr(b []byte) net.IP {
	return net.IP{b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31], b[32], b[33], b[34], b[35], b[36], b[37], b[38], b[39]}
}

func GetProtocol(b []byte) string {
	if b[6] == 0x06 {
		return "tcp"
	} else if b[6] == 0x11 {
		return "udp"
	} else if b[6] == 0x3a {
		return "icmp"
	}
	v, ok := ProtocolMap[int(b[6])]
	if ok {
		return v
	}
	return strconv.Itoa(int(b[6]))
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

func ParseSrcTcp(b []byte) *net.TCPAddr {
	ip := GetSrcAddr(b)
	port := ReadPort(b[IPHeaderLength+0 : IPHeaderLength+2])
	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}
}

func ParseSrcUdp(b []byte) *net.UDPAddr {
	ip := GetSrcAddr(b)
	port := ReadPort(b[IPHeaderLength+0 : IPHeaderLength+2])
	return &net.UDPAddr{
		IP:   ip,
		Port: port,
	}
}

func ParseDstTcp(b []byte) *net.TCPAddr {
	ip := GetDstAddr(b)
	port := ReadPort(b[IPHeaderLength+2 : IPHeaderLength+4])
	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}
}

func ParseDstUdp(b []byte) *net.UDPAddr {
	ip := GetDstAddr(b)
	port := ReadPort(b[IPHeaderLength+2 : IPHeaderLength+4])
	return &net.UDPAddr{
		IP:   ip,
		Port: port,
	}
}

func (x *V6Layer) ReplaceSrcAddrIcmp(b []byte, srcAddr *natmap.ICMPPair, dstAddr *natmap.ICMPPair) {
	reverseAddr := x.NatTable.CreateCheckIcmp(srcAddr, dstAddr)
	if reverseAddr != nil {
		copy(b[8:24], x.ReverseIP.To16()[:])
	}
}

func (x *V6Layer) ReplaceDstAddrIcmp(b []byte, srcAddr *natmap.ICMPPair, dstAddr *natmap.ICMPPair) {
	reverseAddr := x.NatTable.CreateCheckIcmp(dstAddr, srcAddr)
	if reverseAddr != nil {
		copy(b[24:40], reverseAddr.IP.To16()[:])
	}
}

func (x *V6Layer) ReplaceSrcAddrTcp(b []byte, addr *net.TCPAddr) {
	reverseAddr := x.NatTable.CreateCheckTcp(addr, x.ReverseIP, false)
	if reverseAddr != nil {
		copy(b[8:24], reverseAddr.IP.To16()[:])
		WritePort(b[IPHeaderLength+0:IPHeaderLength+2], reverseAddr.Port)
	}
}

func (x *V6Layer) ReplaceSrcAddrUdp(b []byte, addr *net.UDPAddr) {
	reverseAddr := x.NatTable.CreateCheckUdp(addr, x.ReverseIP, false)
	if reverseAddr != nil {
		copy(b[8:24], reverseAddr.IP.To16()[:])
		WritePort(b[IPHeaderLength+0:IPHeaderLength+2], reverseAddr.Port)
	}
}

func (x *V6Layer) ReplaceDstAddrTcp(b []byte, addr *net.TCPAddr) {
	reverseAddr := x.NatTable.CreateCheckTcp(addr, x.ReverseIP, true)
	if reverseAddr != nil {
		copy(b[24:40], reverseAddr.IP.To16()[:])
		WritePort(b[IPHeaderLength+2:IPHeaderLength+4], reverseAddr.Port)
	}
}

func (x *V6Layer) ReplaceDstAddrUdp(b []byte, addr *net.UDPAddr) {
	reverseAddr := x.NatTable.CreateCheckUdp(addr, x.ReverseIP, true)
	if reverseAddr != nil {
		copy(b[24:40], reverseAddr.IP.To16()[:])
		WritePort(b[IPHeaderLength+2:IPHeaderLength+4], reverseAddr.Port)
	}
}

func GetPayloadLength(b []byte) int {
	total := ReadPort(b[4:6])
	return total
}

func CalcUDPCheckSum(packet []byte) {
	if len(packet) < IPHeaderLength {
		return
	}
	payloadLen := GetPayloadLength(packet) //116 v
	if len(packet) < IPHeaderLength+payloadLen {
		return
	}
	packet[IPHeaderLength+6] = 0x00
	packet[IPHeaderLength+7] = 0x00
	result := 0
	result += ReadPort(packet[8:10]) //src 16*8
	result += ReadPort(packet[10:12])
	result += ReadPort(packet[12:14])
	result += ReadPort(packet[14:16])
	result += ReadPort(packet[16:18])
	result += ReadPort(packet[18:20])
	result += ReadPort(packet[20:22])
	result += ReadPort(packet[22:24])
	result += ReadPort(packet[24:26]) //dst 16*8
	result += ReadPort(packet[26:28])
	result += ReadPort(packet[28:30])
	result += ReadPort(packet[30:32])
	result += ReadPort(packet[32:34])
	result += ReadPort(packet[34:36])
	result += ReadPort(packet[36:38])
	result += ReadPort(packet[38:40])
	result += ReadPort([]byte{0x00, 0x11}) // zero + PTCL
	tl1 := byte((payloadLen & 0xff00) >> 8)
	tl2 := byte(payloadLen & 0x00ff)
	result += ReadPort([]byte{tl1, tl2})          // udp length 150133
	l := ((IPHeaderLength + payloadLen) % 2) == 1 // false
	n := payloadLen / 2
	for i := 0; i < n; i++ {
		result += ReadPort(packet[IPHeaderLength+i*2 : IPHeaderLength+i*2+2])
	}
	if l {
		result += (int(packet[IPHeaderLength+payloadLen-1]) << 8) & 0xff00
	}
	hl := ((result & 0xffff0000) >> 16) & 0x0000ffff
	ll := result & 0x0000ffff
	x := hl + ll
	WritePort(packet[IPHeaderLength+6:IPHeaderLength+8], 0xffff-x)
}

func CalcTCPCheckSum(packet []byte) {
	if len(packet) < IPHeaderLength {
		return
	}
	payloadLen := GetPayloadLength(packet) //116 v
	if len(packet) < IPHeaderLength+payloadLen {
		return
	}
	packet[IPHeaderLength+16] = 0x00
	packet[IPHeaderLength+17] = 0x00
	result := 0
	result += ReadPort(packet[8:10]) //src 16*8
	result += ReadPort(packet[10:12])
	result += ReadPort(packet[12:14])
	result += ReadPort(packet[14:16])
	result += ReadPort(packet[16:18])
	result += ReadPort(packet[18:20])
	result += ReadPort(packet[20:22])
	result += ReadPort(packet[22:24])
	result += ReadPort(packet[24:26]) //dst 16*8
	result += ReadPort(packet[26:28])
	result += ReadPort(packet[28:30])
	result += ReadPort(packet[30:32])
	result += ReadPort(packet[32:34])
	result += ReadPort(packet[34:36])
	result += ReadPort(packet[36:38])
	result += ReadPort(packet[38:40])
	result += ReadPort([]byte{0x00, 0x06}) // zero + PTCL
	tl1 := byte((payloadLen & 0xff00) >> 8)
	tl2 := byte(payloadLen & 0x00ff)
	result += ReadPort([]byte{tl1, tl2})          // tcp length 150133
	l := ((IPHeaderLength + payloadLen) % 2) == 1 // false
	n := payloadLen / 2
	for i := 0; i < n; i++ {
		result += ReadPort(packet[IPHeaderLength+i*2 : IPHeaderLength+i*2+2])
	}
	if l {
		result += (int(packet[IPHeaderLength+payloadLen-1]) << 8) & 0xff00
	}
	hl := ((result & 0xffff0000) >> 16) & 0x0000ffff
	ll := result & 0x0000ffff
	x := hl + ll
	WritePort(packet[IPHeaderLength+16:IPHeaderLength+18], 0xffff-x)
}

func CalcICMPCheckSum(packet []byte) {
	if len(packet) < IPHeaderLength {
		return
	}
	payloadLen := GetPayloadLength(packet) //116 v
	if len(packet) < IPHeaderLength+payloadLen {
		return
	}
	packet[IPHeaderLength+2] = 0x00
	packet[IPHeaderLength+3] = 0x00
	result := 0
	result += ReadPort(packet[8:10]) //src 16*8
	result += ReadPort(packet[10:12])
	result += ReadPort(packet[12:14])
	result += ReadPort(packet[14:16])
	result += ReadPort(packet[16:18])
	result += ReadPort(packet[18:20])
	result += ReadPort(packet[20:22])
	result += ReadPort(packet[22:24])
	result += ReadPort(packet[24:26]) //dst 16*8
	result += ReadPort(packet[26:28])
	result += ReadPort(packet[28:30])
	result += ReadPort(packet[30:32])
	result += ReadPort(packet[32:34])
	result += ReadPort(packet[34:36])
	result += ReadPort(packet[36:38])
	result += ReadPort(packet[38:40])
	result += ReadPort([]byte{0x00, 0x3a}) // zero + PTCL
	tl1 := byte((payloadLen & 0xff00) >> 8)
	tl2 := byte(payloadLen & 0x00ff)
	result += ReadPort([]byte{tl1, tl2})          // icmpv6 length 150133
	l := ((IPHeaderLength + payloadLen) % 2) == 1 // false
	n := payloadLen / 2
	for i := 0; i < n; i++ {
		result += ReadPort(packet[IPHeaderLength+i*2 : IPHeaderLength+i*2+2])
	}
	if l {
		result += (int(packet[IPHeaderLength+payloadLen-1]) << 8) & 0xff00
	}
	hl := ((result & 0xffff0000) >> 16) & 0x0000ffff
	ll := result & 0x0000ffff
	x := hl + ll
	WritePort(packet[IPHeaderLength+2:IPHeaderLength+4], 0xffff-x)
}

func ParseSrcIcmpTag(b []byte, dstMode bool) *natmap.ICMPPair {
	var result natmap.ICMPPair
	result.IP = GetSrcAddr(b)
	if dstMode {
		result.Tag = ReadPort(b[IPHeaderLength+4 : IPHeaderLength+6])
	} else {
		result.Tag = ReadPort(b[IPHeaderLength : IPHeaderLength+2])
	}
	return &result
}

func ParseDstIcmpTag(b []byte, dstMode bool) *natmap.ICMPPair {
	var result natmap.ICMPPair
	result.IP = GetDstAddr(b)
	if dstMode {
		result.Tag = ReadPort(b[IPHeaderLength : IPHeaderLength+2])
	} else {
		result.Tag = ReadPort(b[IPHeaderLength+4 : IPHeaderLength+6])
	}
	return &result
}
