package layers

import (
	"gofly/pkg/natmap"
	"net"
)

var reverseIP net.IP

func SetReverseIP(ip string) {
	reverseIP = net.ParseIP(ip)
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

func ReplaceSrcAddrIcmp(b []byte, srcAddr *natmap.ICMPPair, dstAddr *natmap.ICMPPair) {
	reverseAddr := natmap.CreateCheckIcmp(srcAddr, dstAddr)
	if reverseAddr != nil {
		//log.Printf("ReplaceSrcAddrTcp %s => %s\n", ParseSrcTcp(b).String(), reverseAddr.String())
		copy(b[12:16], reverseIP.To4()[:])
	}
}

func ReplaceDstAddrIcmp(b []byte, srcAddr *natmap.ICMPPair, dstAddr *natmap.ICMPPair) {
	reverseAddr := natmap.CreateCheckIcmp(dstAddr, srcAddr)
	if reverseAddr != nil {
		//log.Printf("ReplaceSrcAddrTcp %s => %s\n", ParseSrcTcp(b).String(), reverseAddr.String())
		copy(b[16:20], reverseAddr.IP.To4()[:])
	}
}

func ReplaceSrcAddrTcp(b []byte, addr *net.TCPAddr) {
	ip4HeaderLen := GetHeaderLength(b)
	reverseAddr := natmap.CreateCheckTcp(addr, reverseIP, false)
	if reverseAddr != nil {
		//log.Printf("ReplaceSrcAddrTcp %s => %s\n", ParseSrcTcp(b).String(), reverseAddr.String())
		copy(b[12:16], reverseAddr.IP.To4()[:])
		WritePort(b[ip4HeaderLen+0:ip4HeaderLen+2], reverseAddr.Port)
	}
}

func ReplaceSrcAddrUdp(b []byte, addr *net.UDPAddr) {
	ip4HeaderLen := GetHeaderLength(b)
	reverseAddr := natmap.CreateCheckUdp(addr, reverseIP, false)
	if reverseAddr != nil {
		//log.Printf("ReplaceSrcAddrUdp %s => %s\n", ParseSrcUdp(b).String(), reverseAddr.String())
		copy(b[12:16], reverseAddr.IP.To4()[:])
		WritePort(b[ip4HeaderLen+0:ip4HeaderLen+2], reverseAddr.Port)
	}
}

func ReplaceDstAddrTcp(b []byte, addr *net.TCPAddr) {
	ip4HeaderLen := GetHeaderLength(b)
	reverseAddr := natmap.CreateCheckTcp(addr, reverseIP, true)
	//log.Printf("reverseAddr: %s\n", reverseAddr.String())
	if reverseAddr != nil {
		//log.Printf("ReplaceDstAddrTcp %s => %s\n", ParseDstTcp(b).String(), reverseAddr.String())
		copy(b[16:20], reverseAddr.IP.To4()[:])
		WritePort(b[ip4HeaderLen+2:ip4HeaderLen+4], reverseAddr.Port)
	}
}

func ReplaceDstAddrUdp(b []byte, addr *net.UDPAddr) {
	ip4HeaderLen := GetHeaderLength(b)
	reverseAddr := natmap.CreateCheckUdp(addr, reverseIP, true)
	//log.Printf("reverseAddr: %s\n", reverseAddr.String())
	if reverseAddr != nil {
		//log.Printf("ReplaceDstAddrUdp %s => %s\n", ParseDstUdp(b).String(), reverseAddr.String())
		copy(b[16:20], reverseAddr.IP.To4()[:])
		WritePort(b[ip4HeaderLen+2:ip4HeaderLen+4], reverseAddr.Port)
	}
}

const HeaderLength = 2

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
	return ""
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
	ip4HeaderLen := GetHeaderLength(packet)   // 20 v
	ip4PayloadLen := GetPayloadLength(packet) //116 v
	if len(packet) < ip4HeaderLen+ip4PayloadLen {
		return
	}
	packet[ip4HeaderLen+6] = 0x00
	packet[ip4HeaderLen+7] = 0x00
	result := 0
	//result += ReadPort(packet[12:14])
	//result += ReadPort(packet[14:16])
	//result += ReadPort(packet[16:18])
	//result += ReadPort(packet[18:20])
	result += ReadPort(packet[12:14])      // src address 49320
	result += ReadPort(packet[14:16])      // 74932
	result += ReadPort(packet[16:18])      // dst address 124252
	result += ReadPort(packet[18:20])      // 150011
	result += ReadPort([]byte{0x00, 0x11}) // 0, 6 //150017
	tl1 := byte((ip4PayloadLen & 0xff00) >> 8)
	tl2 := byte(ip4PayloadLen & 0x00ff)
	result += ReadPort([]byte{tl1, tl2})           // tcp length 150133
	l := ((ip4HeaderLen + ip4PayloadLen) % 2) == 1 // false
	//n := ip4PayloadLen / 2
	n := ip4PayloadLen / 2
	for i := 0; i < n; i++ {
		result += ReadPort(packet[ip4HeaderLen+i*2 : ip4HeaderLen+i*2+2])
		//log.Printf("result: %d\n", result)
	}
	if l {
		result += (int(packet[ip4HeaderLen+ip4PayloadLen-1]) << 8) & 0xff00
		//log.Printf("result ex: %d\n", result)
	}
	hl := ((result & 0xffff0000) >> 16) & 0x0000ffff
	ll := result & 0x0000ffff
	x := hl + ll
	//log.Printf("result: %d\n", 0xffff-x) //4137
	WritePort(packet[ip4HeaderLen+6:ip4HeaderLen+8], 0xffff-x)
}

func CalcTCPCheckSum(packet []byte) {
	ip4HeaderLen := GetHeaderLength(packet)   // 20 v
	ip4PayloadLen := GetPayloadLength(packet) //116 v
	if len(packet) < ip4HeaderLen+ip4PayloadLen {
		return
	}
	packet[ip4HeaderLen+16] = 0x00
	packet[ip4HeaderLen+17] = 0x00
	result := 0
	//result += ReadPort(packet[12:14])
	//result += ReadPort(packet[14:16])
	//result += ReadPort(packet[16:18])
	//result += ReadPort(packet[18:20])
	result += ReadPort(packet[12:14])      // src address 49320
	result += ReadPort(packet[14:16])      // 74932
	result += ReadPort(packet[16:18])      // dst address 124252
	result += ReadPort(packet[18:20])      // 150011
	result += ReadPort([]byte{0x00, 0x06}) // 0, 6 //150017
	tl1 := byte((ip4PayloadLen & 0xff00) >> 8)
	tl2 := byte(ip4PayloadLen & 0x00ff)
	result += ReadPort([]byte{tl1, tl2})           // tcp length 150133
	l := ((ip4HeaderLen + ip4PayloadLen) % 2) == 1 // false
	//n := ip4PayloadLen / 2
	n := ip4PayloadLen / 2
	for i := 0; i < n; i++ {
		result += ReadPort(packet[ip4HeaderLen+i*2 : ip4HeaderLen+i*2+2])
		//log.Printf("result: %d\n", result)
	}
	if l {
		result += (int(packet[ip4HeaderLen+ip4PayloadLen-1]) << 8) & 0xff00
		//log.Printf("result ex: %d\n", result)
	}
	hl := ((result & 0xffff0000) >> 16) & 0x0000ffff
	ll := result & 0x0000ffff
	x := hl + ll
	//log.Printf("result: %d\n", 0xffff-x) //4137
	WritePort(packet[ip4HeaderLen+16:ip4HeaderLen+18], 0xffff-x)
}

func CalcIPCheckSum(packet []byte) {
	packet[10] = 0x00
	packet[11] = 0x00
	result := ReadPort(packet[10:12])
	ip4HeaderLen := GetHeaderLength(packet)
	//log.Printf("headerlen: %d\n", ip4HeaderLen)
	l := (ip4HeaderLen % 2) == 1
	n := ip4HeaderLen / 2
	for i := 0; i < n; i++ {
		result += ReadPort(packet[i*2 : i*2+2])
		//log.Printf("result: %d\n", result)
	}
	if l {
		result += int(packet[ip4HeaderLen-1])
		//log.Printf("result ex: %d\n", result)
	}
	hl := ((result & 0xffff0000) >> 16) & 0x0000ffff
	ll := result & 0x0000ffff
	x := hl + ll
	//log.Printf("result: %d\n", x)
	//log.Printf("result: %d\n", 0xffff-x)
	WritePort(packet[10:12], 0xffff-x)
}

func CalcICMPCheckSum(packet []byte) {
	result := 0
	ip4HeaderLen := GetHeaderLength(packet)
	packet[ip4HeaderLen+2] = 0x00
	packet[ip4HeaderLen+3] = 0x00
	ip4PayloadLen := GetPayloadLength(packet)
	//log.Printf("headerlen: %d\n", ip4HeaderLen)
	l := (ip4PayloadLen % 2) == 1
	n := ip4PayloadLen / 2
	for i := 0; i < n; i++ {
		result += ReadPort(packet[ip4HeaderLen+i*2 : ip4HeaderLen+i*2+2])
		//log.Printf("result: %d\n", result)
	}
	if l {
		result += (int(packet[ip4HeaderLen+ip4PayloadLen-1]) << 8) & 0xff00
		//log.Printf("result ex: %d\n", result)
	}
	hl := ((result & 0xffff0000) >> 16) & 0x0000ffff
	ll := result & 0x0000ffff
	x := hl + ll
	//log.Printf("result: %d\n", x)
	//log.Printf("result: %d\n", 0xffff-x)
	WritePort(packet[ip4HeaderLen+2:ip4HeaderLen+4], 0xffff-x)
}

func ParseSrcIcmpTag(b []byte, dstMode bool) *natmap.ICMPPair {
	ip4HeaderLen := GetHeaderLength(b)
	var result natmap.ICMPPair
	result.IP = net.IP{b[12], b[13], b[14], b[15]}
	result.Tag = ReadPort(b[ip4HeaderLen : ip4HeaderLen+2])
	if dstMode {
		result.Tag = ReadPort(b[ip4HeaderLen+4 : ip4HeaderLen+6])
	}
	return &result
}

func ParseDstIcmpTag(b []byte, dstMode bool) *natmap.ICMPPair {
	ip4HeaderLen := GetHeaderLength(b)
	var result natmap.ICMPPair
	result.IP = net.IP{b[16], b[17], b[18], b[19]}
	result.Tag = ReadPort(b[ip4HeaderLen+4 : ip4HeaderLen+6])
	if dstMode {
		result.Tag = ReadPort(b[ip4HeaderLen : ip4HeaderLen+2])
	}
	return &result
}
