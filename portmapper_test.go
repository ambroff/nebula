package nebula

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/jackpal/gateway"
)

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Vers = 0      | OP = 128 + 0  | Result Code (net byte order)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Seconds Since Start of Epoch (in network byte order)          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | External IPv4 Address (a.b.c.d)                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type externalIPv4Announce struct {
	// Specifies the protocol version supported by the gateway. 0 is NAT-PMP. 1 is PCP.
	Version uint8

	// This result code must be 128 + 0. If it is > 128 then something
	// went wrong and the rest of the response is undefined.
	Op uint8

	// TODO: Document this
	ResultCode uint16

	// Seconds since the gateway's port-mapping table was initialized. This can
	// be considered the time since the last reboot of the gateway.
	SecondsSinceStartOfEpoch uint32

	// The public IPv4 address of the gateway.
	ExternalIPv4Address net.IP
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

func TestRequestPublicIPFromGateway(t *testing.T) {
	gatewayAddress, err := gateway.DiscoverGateway()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to discover gateway: %v\n", err)
	}

	gateway := fmt.Sprintf("%s:%d", gatewayAddress, NAT_PNP_PORT)

	var gatewayAddr *net.UDPAddr
	gatewayAddr, err = net.ResolveUDPAddr("udp", gateway)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to resolve UDP address: %v\n", err)
		os.Exit(1)
	}

	var conn net.Conn
	conn, err = net.DialUDP("udp", nil, gatewayAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to create UDP socket: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	//doneChan := make(chan error, 1)
	//go func() {
	//
	//}

	//  0                   1
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Vers = 0      | OP = 0        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	var requestBuf [2]byte
	var bytesWritten int
	bytesWritten, err = conn.Write(requestBuf[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to write request to socket: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Wrote %d bytes to %s\n", bytesWritten, gateway)

	announce, deserializeErr := readExternalIPvAnnounce(conn)
	if deserializeErr != nil {
		t.Fail()
	}

	fmt.Printf("RESPONSE:\n")
	fmt.Printf(" - version:            %d\n", announce.Version)
	fmt.Printf(" - op:                 %d\n", announce.Op)
	fmt.Printf(" - result code:        %d\n", announce.ResultCode)
	fmt.Printf(" - secs since epoch:   %d\n", announce.SecondsSinceStartOfEpoch)
	fmt.Printf(" - Ext. IPv4           %v\n", announce.ExternalIPv4Address)
}
