package nebula

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/jackpal/gateway"
)

func TestRequestPublicIPFromGateway(t *testing.T) {
	gatewayAddress, err := gateway.DiscoverGateway()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to discover gateway: %v\n", err)
	}

	gateway := fmt.Sprintf("%s:%d", gatewayAddress, NAT_PNP_PORT)

	var conn net.Conn
	conn, err = net.Dial("udp", gateway)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to create UDP socket: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

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

	//  0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Vers = 0      | OP = 128 + 0  | Result Code (net byte order)  |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Seconds Since Start of Epoch (in network byte order)          |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | External IPv4 Address (a.b.c.d)                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	var responseBuf [12]byte
	var bytesRead int
	bytesRead, err = conn.Read(responseBuf[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to read response from socket: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Read %d bytes from %s\n", bytesRead, gateway)

	version := responseBuf[0]
	op := responseBuf[1]

	// This result code must be 128 + 0. If it is > 128 then something
	// went wrong and the rest of the response is undefined.
	resultCode := binary.BigEndian.Uint16(responseBuf[2:4])

	// Seconds since the gateway's port-mapping table was initialized. This can
	// be considered the time since the last reboot of the gateway.
	secondsSinceStartOfEpoch := binary.BigEndian.Uint32(responseBuf[4:8])

	// The public IPv4 address of the gateway.
	externalIPv4 := net.IP(responseBuf[8:12])

	fmt.Printf("RESPONSE:\n")
	fmt.Printf(" - version:            %d\n", version)
	fmt.Printf(" - op:                 %d\n", op)
	fmt.Printf(" - result code:        %d\n", resultCode)
	fmt.Printf(" - secs since epoch:   %d\n", secondsSinceStartOfEpoch)
	fmt.Printf(" - Ext. IPv4           %v\n", externalIPv4)
}
