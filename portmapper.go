// Implementation of NAT-PNP and PCP from RFC-6886
//
// https://datatracker.ietf.org/doc/html/rfc6886
package nebula

import (
	"net"
)

const (
	// This port is also used for something?
	//NAT_PNP_PORT_1 = 5350

	// NAT_PNP_PORT Use this port to figure out port mapping?
	NAT_PNP_PORT = 5351

	// BASE_REQUEST_TIMEOUT_MS How long to wait for a response. This is base timeout
	// and exponential backoff is used.
	//
	// This is used for creating port mappings, querying port mappings
	// and also deleting port mappings.
	BASE_REQUEST_TIMEOUT_MS = 250

	// MAX_ATTEMPTS The client should retry with exponential backoff up to 9 times
	// with a max request timeout of 64 seconds. Once the last attempt is
	// made and the server doesn't respond in 64 seconds then it is assumed
	// that NAT-PNP / PCP are unsupported.
	MAX_ATTEMPTS = 9

	PROTOCOL_VERSION_NATPNP = 1
	PROTOCOL_VERSION_PCP    = 2
)

// PortMapper Use port-mapping protocols such as UPNP, NAT-PMP and PCP to punch holes at the gateway.
type PortMapper interface {
	MapPort(localAddress net.IP, port uint16) chan interface{}
}

type portMapper struct {
}

func NewPortMapper() *PortMapper {
	return &portMapper{}
}

func (p *portMapper) MapPort(localAddress net.IP, port uint16) chan interface{} {
	return nil
}

// FIXME: Probe the gateway at port NAT_PNP_PORT_2 with ICMP. If it is
// unreachable then the gateway doesn't support NAT-PNP / PCP.

// FIXME: Cache that the gateway doesn't support NAT-PNP / PCP until
//
// - Hardware link changes
// - A new DHCP lease is acquired
// - The gateway's MAC address changes.
// - There is a NAT-PNP announcement from the gateway.
//
// Once this happens we are supposed to start probing the gateway again
// to see if NAT-PNP / PCP is supported.

// FIXME: Track when a port mapping is supposed to expire. Don't try to
// delete it after that point.

func IsLocalRange(ip net.IP) bool {
	return ip.IsPrivate()
}
