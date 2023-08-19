package reality

import (
	"gofly/pkg/protocol/basic"
	"net"
)

func splitRead(conn net.Conn, expectLen int, packet []byte) (int, error) {
	count := 0
	splitSize := 99
	for count < expectLen {
		receiveSize := splitSize
		if expectLen-count < splitSize {
			receiveSize = expectLen - count
		}
		err := conn.SetReadDeadline(basic.GetTimeout())
		if err != nil {
			return count, err
		}
		n, err := conn.Read(packet[count : count+receiveSize])
		if err != nil {
			return count, err
		}
		count += n
	}
	return count, nil
}
