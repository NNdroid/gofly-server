package layers

import "net"

var reverseIPv6 net.IP

func SetReverseIPv6(ip string) {
	reverseIPv6 = net.ParseIP(ip)
}

func GetSrcAddrV6(b []byte) net.IP {
	return net.IP{b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]}
}

func GetDstAddrV6(b []byte) net.IP {
	return net.IP{b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31], b[32], b[33], b[34], b[35], b[36], b[37], b[38], b[39]}
}

func GetProtocolV6(b []byte) string {
	if b[6] == 0x06 {
		return "tcp"
	} else if b[6] == 0x11 {
		return "udp"
	} else if b[6] == 0x3a {
		return "icmp"
	}
	return ""
}
