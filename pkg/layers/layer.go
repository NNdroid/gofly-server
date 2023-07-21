package layers

import (
	"gofly/pkg/layers/ipv4"
	"gofly/pkg/layers/ipv6"
)

type Layer struct {
	V4Layer *ipv4.V4Layer
	V6Layer *ipv6.V6Layer
}
