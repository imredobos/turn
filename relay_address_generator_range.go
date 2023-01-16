package turn

import (
	"fmt"
	"github.com/pion/turn/v2/internal/util"
	"net"

	"github.com/pion/randutil"
	"github.com/pion/transport/vnet"
)

// RelayAddressGeneratorPortRange can be used to only allocate connections inside a defined port range.
// Similar to the RelayAddressGeneratorStatic a static ip address can be set.
type RelayAddressGeneratorPortRange struct {
	// PublicRelayAddress is the IP returned to the user when the relay is created
	PublicRelayAddress  net.IP
	PrivateRelayAddress net.IP
	RelayAddress        net.IP

	// MinPort the minimum port to allocate
	MinPort uint16
	// MaxPort the maximum (inclusive) port to allocate
	MaxPort uint16

	// MaxRetries the amount of tries to allocate a random port in the defined range
	MaxRetries int

	// Rand the random source of numbers
	Rand randutil.MathRandomGenerator

	// Address is passed to Listen/ListenPacket when creating the Relay
	Address string

	Net *vnet.Net
}

// Validate is called on server startup and confirms the RelayAddressGenerator is properly configured
func (r *RelayAddressGeneratorPortRange) Validate() error {
	if r.Net == nil {
		r.Net = vnet.NewNet(nil)
	}

	if r.Rand == nil {
		r.Rand = randutil.NewMathRandomGenerator()
	}

	if r.MaxRetries == 0 {
		r.MaxRetries = 10
	}

	switch {
	case r.MinPort == 0:
		return errMinPortNotZero
	case r.MaxPort == 0:
		return errMaxPortNotZero
	case r.PublicRelayAddress == nil:
		return errRelayAddressInvalid
	case r.Address == "":
		return errListeningAddressInvalid
	default:
		return nil
	}
}

// AllocatePacketConn generates a new PacketConn to receive traffic on and the IP/Port to populate the allocation response with
func (r *RelayAddressGeneratorPortRange) AllocatePacketConn(network string, requestedPort int, srcAddr net.Addr, relayAddressType util.RelayAddressType) (net.PacketConn, net.Addr, error) {
	fmt.Println("key2", srcAddr)
	if requestedPort != 0 {
		fmt.Println("hello1 - %s, %s", network, requestedPort)
		conn, err := r.Net.ListenPacket(network, fmt.Sprintf("%s:%d", r.Address, requestedPort))
		if err != nil {
			return nil, nil, err
		}
		relayAddr, ok := conn.LocalAddr().(*net.UDPAddr)
		if !ok {
			return nil, nil, errNilConn
		}

		if relayAddressType == 0 {
			relayAddr.IP = r.PublicRelayAddress
		} else {
			relayAddr.IP = r.PrivateRelayAddress
		}

		return conn, relayAddr, nil
	}

	for try := 0; try < r.MaxRetries; try++ {
		port := r.MinPort + uint16(r.Rand.Intn(int((r.MaxPort+1)-r.MinPort)))
		conn, err := r.Net.ListenPacket(network, fmt.Sprintf("%s:%d", r.Address, port))
		if err != nil {
			continue
		}
		fmt.Println("hello2 - %s, %s", network, port)
		relayAddr, ok := conn.LocalAddr().(*net.UDPAddr)
		if !ok {
			return nil, nil, errNilConn
		}

		relayAddr.IP = r.getRelayAddress(relayAddressType)
		return conn, relayAddr, nil
	}

	return nil, nil, errMaxRetriesExceeded
}

func (r *RelayAddressGeneratorPortRange) getRelayAddress(relayAddressType util.RelayAddressType) net.IP {
	if r.RelayAddress != nil {
		return r.RelayAddress
	} else if relayAddressType == util.PrivateRelay {
		return r.PrivateRelayAddress
	} else if relayAddressType == util.PublicRelay {
		return r.PublicRelayAddress
	}
	panic("could not calculate relay address")
}

// AllocateConn generates a new Conn to receive traffic on and the IP/Port to populate the allocation response with
func (r *RelayAddressGeneratorPortRange) AllocateConn(network string, requestedPort int) (net.Conn, net.Addr, error) {
	return nil, nil, errTODO
}
