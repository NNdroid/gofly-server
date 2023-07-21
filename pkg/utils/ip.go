package utils

import "strings"

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
