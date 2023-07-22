package utils

import (
	"net"
	"strings"
)

func IsIPv4(ip string) bool {
	return strings.Contains(ip, ".")
}

func IsIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}

func FindAIPv4Address(ips []string) string {
	for _, it := range ips {
		if IsIPv4(it) {
			return it
		}
	}
	return ""
}

func FindAIPv6Address(ips []string) string {
	for _, it := range ips {
		if IsIPv6(it) {
			return it
		}
	}
	return ""
}

func GetSrcKey(b []byte) string {
	version := b[0] >> 4
	if version == 4 {
		if len(b) < 20 {
			return ""
		}
		return net.IP{b[12], b[13], b[14], b[15]}.String()
	} else if version == 6 {
		if len(b) < 40 {
			return ""
		}
		return net.IP{b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]}.String()
	}
	return ""
}

func GetDstKey(b []byte) string {
	version := b[0] >> 4
	if version == 4 {
		if len(b) < 20 {
			return ""
		}
		return net.IP{b[16], b[17], b[18], b[19]}.String()
	} else if version == 6 {
		if len(b) < 40 {
			return ""
		}
		return net.IP{b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31], b[32], b[33], b[34], b[35], b[36], b[37], b[38], b[39]}.String()
	}
	return ""
}
