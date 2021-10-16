package nebula

import (
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
