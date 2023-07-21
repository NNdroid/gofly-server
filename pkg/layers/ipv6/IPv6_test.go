package ipv6

import (
	"encoding/hex"
	"testing"
)

func TestCalcTCPCheckSum(t *testing.T) {
	packet, _ := hex.DecodeString("600488ff0028063f240e037926cb4a040000000000000058200148380000001b0000000000000201e5600050ab0db01400000000a002fbb8ca840000020405980402080afccc413b0000000001030307")
	t.Logf("origin:%v\n", hex.EncodeToString(packet))
	CalcTCPCheckSum(packet)
	//0xca84
	t.Logf("result:%v\n", hex.EncodeToString(packet))
}

func TestCalcUDPCheckSum(t *testing.T) {
	packet, _ := hex.DecodeString("600b2f43002b1140fced0172001602010000000000000011200148604860000000000000000088886f4d0035002bda69c30a01000001000000000000037777770973746172747061676503636f6d00000100013d")
	t.Logf("corrent:%s\n", hex.EncodeToString(packet[46:48]))
	t.Logf("origin:%v\n", hex.EncodeToString(packet))
	CalcUDPCheckSum(packet)
	//0x7ed5
	t.Logf("result:%v\n", hex.EncodeToString(packet))
}

func TestCalcICMPCheckSum(t *testing.T) {
	packet, _ := hex.DecodeString("600b077600403a40fdffffffffffffff0000000000000001fdffffffffffffff000000000000000281006a2d087d041dacf6b96400000000e48c020000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	t.Logf("corrent:%s\n", hex.EncodeToString(packet[46:48]))
	t.Logf("origin:%v\n", hex.EncodeToString(packet))
	CalcICMPCheckSum(packet)
	//0x6a2d
	t.Logf("result:%v\n", hex.EncodeToString(packet))
}
