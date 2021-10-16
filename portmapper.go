// Package nebula Implementation of NAT-PNP and PCP from RFC-6886
//
// https://datatracker.ietf.org/doc/html/rfc6886
package nebula

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

const (
	// NAT_PNP_PORT Port used for client requests.
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

	// MULTICAST_ADDR Section 3.2.1.  Announcing Address Changes.
	//
	// The gateway is expected to announce to this link-local address and port any time the public IPv4 address changes
	// or the gateway reboots. It will broadcast to this address multiple times on an exponentially increasing interval.
	//
	// A message received on this address that isn't from the configured gateway should be ignored.
	//
	// If the SecondsSinceStartOfEpoch field is a plausible value that indicates that a state reset has actually
	// occurred on the gateway then the client is expected to re-create any port mappings as described in Section
	// 3.7, "Recreating Mappings on NAT Gateway Reboot".
	//
	// NOTE: When listening on this port it is required that SO_REUSEPORT is used because there may be multiple services
	// on the same system listening to announcements from the gateway.
	MULTICAST_ADDR = "224.0.0.1:5350"
)

// PortMapper Use port-mapping protocols such as UPNP, NAT-PMP and PCP to punch holes at the gateway.
type PortMapper interface {
	MapPort(localAddress net.IP, port uint16) chan interface{}
}

type portMapper struct {
}

func NewPortMapper() PortMapper {
	return &portMapper{}
}

func (p *portMapper) MapPort(localAddress net.IP, port uint16) chan interface{} {
	return nil
}

// ResultCode Section 3.5: Result Codes
type ResultCode uint16

const (
	// RESULT_CODE_SUCCESS Always indicates a successful operation.
	RESULT_CODE_SUCCESS = 0

	// RESULT_CODE_UNSUPPORTED_VERSION The version code set by the client is not supported by the gateway.
	RESULT_CODE_UNSUPPORTED_VERSION = 1

	// RESULT_CODE_NOT_AUTHORIZED Used when deleting a mapping that is statically configured on the gateway, or when the
	// gateway supports port mapping but the administrator has disabled that feature.
	RESULT_CODE_NOT_AUTHORIZED = 2

	// RESULT_CODE_NETWORK_FAILURE A network failure has occurred on the gateway.
	RESULT_CODE_NETWORK_FAILURE = 3

	// RESULT_CODE_OUT_OF_RESOURCES The gateway does not have the resources to create port mappings right now.
	RESULT_CODE_OUT_OF_RESOURCES = 4

	// RESULT_CODE_UNSUPPORTED_OPCODE The Op sent by the client in a request is not supported by the gateway.
	RESULT_CODE_UNSUPPORTED_OPCODE = 5
)

type OpCode uint8

const (
	OPCODE_CREATE_UDP_MAPPING = 1
	OPCODE_CREATE_TCP_MAPPING = 2
)

// FIXME
//
// If the version in the request is not zero, then the NAT-PMP server
// MUST return the following "Unsupported Version" error response to the
// client:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Vers = 0      | OP = 0        | Result Code = 1               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Seconds Since Start of Epoch (in network byte order)          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// If the opcode in the request is 128 or greater, then this is not a
// request; it's a response, and the NAT-PMP server MUST silently ignore
// it.  Otherwise, if the opcode in the request is less than 128, but is
// not a supported opcode (currently 0, 1, or 2), then the entire
// request MUST be returned to the sender, with the top bit of the
// opcode set (to indicate that this is a response) and the result code
// set to 5 (Unsupported opcode).
//
// For version 0 and a supported opcode (0, 1, or 2), if the operation
// fails for some reason (Not Authorized, Network Failure, or Out of
// resources), then a valid response MUST be sent to the client, with
// the top bit of the opcode set (to indicate that this is a response)
// and the result code set appropriately.  Other fields in the response
// MUST be set appropriately.  Specifically:
//
// o Seconds Since Start of Epoch MUST be set correctly
//
// o The External IPv4 Address should be set to the correct address, or
//   to 0.0.0.0, as appropriate.
//
// o The Internal Port MUST be set to the client's requested Internal
//   Port.  This is particularly important, because the client needs
//   this information to identify which request suffered the failure.
//
// o The Mapped External Port and Port Mapping Lifetime MUST be set
//   appropriately -- i.e., zero if no successful port mapping was
//   created.
//
// Should future NAT-PMP opcodes be defined, their error responses MUST
// similarly be specified to include sufficient information to identify
// which request suffered the failure.  By design, NAT-PMP messages do
// not contain any transaction identifiers.  All NAT-PMP messages are
// idempotent and self-describing; therefore, the specifications of
// future NAT-PMP messages need to include enough information for their
// responses to be self-describing.
//
// Clients MUST be able to properly handle result codes not defined in
// this document.  Undefined results codes MUST be treated as fatal
// errors of the request.

// FIXME
// 3.6.  Seconds Since Start of Epoch
//
//   Every packet sent by the NAT gateway includes a Seconds Since Start
//   of Epoch (SSSoE) field.  If the NAT gateway resets or loses the state
//   of its port mapping table, due to reboot, power failure, or any other
//   reason, it MUST reset its epoch time and begin counting SSSoE from
//   zero again.  Whenever a client receives any packet from the NAT
//   gateway, either unsolicited or in response to a client request, the
//   client computes its own conservative estimate of the expected SSSoE
//   value by taking the SSSoE value in the last packet it received from
//   the gateway and adding 7/8 (87.5%) of the time elapsed according to
//   the client's local clock since that packet was received.  If the
//   SSSoE in the newly received packet is less than the client's
//   conservative estimate by more than 2 seconds, then the client
//   concludes that the NAT gateway has undergone a reboot or other loss
//   of port mapping state, and the client MUST immediately renew all its
//   active port mapping leases as described in Section 3.7, "Recreating
//   Mappings on NAT Gateway Reboot".
//
// When a client renews its port mappings as the result of receiving a
//   packet where the Seconds Since Start of Epoch (SSSoE) field indicates
//   that a reboot or similar loss of state has occurred, the client MUST
//   first delay by a random amount of time selected with uniform random
//   distribution in the range 0 to 5 seconds, and then send its first
//   port mapping request.  After that request is acknowledged by the
//   gateway, the client may then send its second request, and so on, as
//   rapidly as the gateway allows.  The requests SHOULD be issued
//   serially, one at a time; the client SHOULD NOT issue multiple
//   concurrent requests.

// externalIPv4Announce This is the message sent by the gateway to MULTICAST_ADDR under certain circumstances to tell
// NAT-PMP/PCP clients the current external IPv4 address of the gateway. It is also the response sent from the gateway
// when it receives a request created by makeExternalIPv4Request.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Vers = 0      | OP = 128 + 0  | Result Code (net byte order)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Seconds Since Start of Epoch (in network byte order)          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | External IPv4 Address (a.b.c.d)                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
type externalIPv4Announce struct {
	// Specifies the protocol version supported by the gateway. 0 is NAT-PMP. 1 is PCP.
	Version uint8

	// This result code must be 128 + 0. If it is > 128 then something
	// went wrong and the rest of the response is undefined.
	Op uint8

	// TODO: Document this
	ResultCode uint16

	// Seconds since the gateway's port-mapping table was initialized. This can be considered the time since the last
	// reboot of the gateway. See section 3.6, "Seconds Since Start of Epoch"
	SecondsSinceStartOfEpoch uint32

	// The public IPv4 address of the gateway.
	ExternalIPv4Address net.IP
}

// createMappingRequest Sent to the gateway from a client to create a new port mapping.
//
// From section 3.3:  Requesting a Mapping
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Vers = 0      | OP = x        | Reserved                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Internal Port                 | Suggested External Port       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Requested Port Mapping Lifetime in Seconds                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// This request is also used to renew port mappings periodically. A client is expected to renew a mapping by re-sending
// the same request with the SuggestedExternalPort matching the port chosen by the gateway in response to the original
// createMappingRequest. This is because many low-cost gateways do not have any persistence for port mappings so they
// need to be told by the client which actual external port is associated with the renewal. This improves the stability
// of external ports across gateway reboots.
//
// Renewal should be sent half way through the TTL/lifetime of the port mapping, just like DHCP lease renewal.
//
// Deletion of mappings is also handled by this request. To delete a mapping, the client re-sends the same request but
// with RequestedLifetimeInSeconds and SuggestedExternalPort set to 0. If the mapping isn't deleted with such a request,
// then it will automatically get deleted when it expires or possibly when the client's DHCP lease expires. The gateway
// will always response do this request as if it were successful if such a mapping does not exist.
//
// Sending this request with all three of InternalPort, RequestedLifetimeInSeconds and SuggestedExternalPort set to 0
// will delete all port mappings associated with the client's IPv4 address. The gateway will delete as many mappings as
// possible, but will respond with a non-zero ResultCode if some subset of the port mappings were unable to be deleted.
//
// If deletion fails then the ResultCode is set to a non-zero value. If deletion fails because an attempt to delete a
// port mapping was made for a mapping that was set up by some static configuration on the gateway, then the result code
// will be 2 - Not authorized.
type createMappingRequest struct {
	// FIXME: Is this the same as the other version field?
	Version uint8

	// Opcodes supported:
	//   1 - Map UDP
	//   2 - Map TCP
	Op OpCode

	// The Reserved field MUST be set to zero on transmission and MUST be ignored on reception.
	Reserved uint16

	// The Internal Port is set to the local port on which the client is listening.
	InternalPort uint16

	// Can be set to a specific external port if, for example, the client desires the external port to match the actual
	// port it is using for its local service. If the desired port is unavailable then the gateway will choose a high
	// value port from the ephemeral range.
	//
	// If the client sets this to 0 the nan ephemeral port will be chosen by the gateway.
	SuggestedExternalPort uint16

	// The amount of time in seconds that the requested port mapping will be maintained. The recommended port mapping
	// lifetime is 7200 seconds (two hours).
	RequestedLifetimeInSeconds uint32
}

func (r createMappingRequest) Write(writer io.Writer) error {
	var buf [12]byte

	buf[0] = r.Version
	buf[1] = byte(r.Op)

	// NB: No need to set Reserved field since it is zero-initialized nad should always be two 0x00 bytes.

	binary.BigEndian.PutUint16(buf[4:6], r.InternalPort)

	binary.BigEndian.PutUint16(buf[6:8], r.SuggestedExternalPort)

	binary.BigEndian.PutUint32(buf[8:12], r.RequestedLifetimeInSeconds)

	bytesWritten, err := writer.Write(buf[:])
	if err != nil {
		return err
	}

	if bytesWritten != 12 {
		panic("Expected to have written 12 bytes")
	}

	return nil
}

// createMappingResponse The response sent by the gateway in response to createMappingResponse.
//
// From section 3.3:  Requesting a Mapping
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Vers = 0      | OP = 128 + x  | Result Code                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Seconds Since Start of Epoch                                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Internal Port                 | Mapped External Port          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Port Mapping Lifetime in Seconds                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
type createMappingResponse struct {
	// FIXME: Is this the same as the other version field?
	Version uint8

	// Must match the Op from the request. Op in requests starts from 0, but in responses it starts at 128.
	Op OpCode

	ResultCode uint16

	// Seconds since the gateway's port-mapping table was initialized. This can be considered the time since the last
	// reboot of the gateway. See section 3.6, "Seconds Since Start of Epoch"
	SecondsSinceStartOfEpoch uint32

	// The internal port used by the service.
	InternalPort uint16

	// The external port mapped to the internal port. This may not match the desired external port requested by the
	// client.
	MappedExternalPort uint16

	// The lifetime of the port mapping. It will expire after this many seconds. This may be a shorter period of time
	// than that requested by the client.
	LifetimeInSeconds uint32
}

func readCreateMappingResponse(reader io.Reader) (createMappingResponse, error) {
	return createMappingResponse{}, nil
}

type clientRequest struct {
	Version uint8
	Op      OpCode
}

//
func makeExternalIPv4Request() clientRequest {
	return clientRequest{
		Version: 0,
		Op:      0,
	}
}

func readExternalIPvAnnounce(reader io.Reader) (externalIPv4Announce, error) {
	var responseBuf [12]byte
	bytesRead, err := reader.Read(responseBuf[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to read response from socket: %v\n", err)
		return externalIPv4Announce{}, err
	}

	fmt.Printf("Read %d bytes from reader\n", bytesRead)

	msg := externalIPv4Announce{
		Version:                  responseBuf[0],
		Op:                       responseBuf[1],
		ResultCode:               binary.BigEndian.Uint16(responseBuf[2:4]),
		SecondsSinceStartOfEpoch: binary.BigEndian.Uint32(responseBuf[4:8]),
		ExternalIPv4Address:      net.IP(responseBuf[8:12]),
	}

	return msg, nil
}

// FIXME: Probe the gateway at port NAT_PNP_PORT_2 with ICMP. If it is
// unreachable then the gateway doesn't support NAT-PNP / PCP.
//
// Section 3.8:
//
//    If a network device not currently acting in the role of NAT gateway
//   receives UDP packets addressed to port 5351, it SHOULD respond
//   immediately with an "ICMP Port Unreachable" message to tell the
//   client that it needn't continue with timeouts and retransmissions,
//   and it should assume that NAT-PMP is not available and not needed on
//   this network.  Typically, this behavior can be achieved merely by not
//   having an open socket listening on UDP port 5351.

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
