package turn

import (
	"crypto/md5" //nolint:gosec,gci
	"fmt"
	"github.com/pion/turn/v2/internal/util"
	"net"
	"strings"
	"time"

	"github.com/pion/logging"
)

// RelayAddressGenerator is used to generate a PublicRelayAddress when creating an allocation.
// You can use one of the provided ones or provide your own.
type RelayAddressGenerator interface {
	// Validate confirms that the RelayAddressGenerator is properly initialized
	Validate() error

	// Allocate a PacketConn (UDP) PublicRelayAddress
	AllocatePacketConn(network string, requestedPort int, srcAddr net.Addr, relayAddressType util.RelayAddressType) (net.PacketConn, net.Addr, error)

	// Allocate a Conn (TCP) PublicRelayAddress
	AllocateConn(network string, requestedPort int) (net.Conn, net.Addr, error)
}

// PacketConnConfig is a single net.PacketConn to listen/write on. This will be used for UDP listeners
type PacketConnConfig struct {
	PacketConn net.PacketConn

	// When an allocation is generated the RelayAddressGenerator
	// creates the net.PacketConn and returns the IP/Port it is available at
	RelayAddressGenerator RelayAddressGenerator
}

func (c *PacketConnConfig) validate() error {
	if c.PacketConn == nil {
		return errConnUnset
	}
	if c.RelayAddressGenerator == nil {
		return errRelayAddressGeneratorUnset
	}

	return c.RelayAddressGenerator.Validate()
}

// ListenerConfig is a single net.Listener to accept connections on. This will be used for TCP, TLS and DTLS listeners
type ListenerConfig struct {
	Listener net.Listener

	// When an allocation is generated the RelayAddressGenerator
	// creates the net.PacketConn and returns the IP/Port it is available at
	RelayAddressGenerator RelayAddressGenerator
}

func (c *ListenerConfig) validate() error {
	if c.Listener == nil {
		return errListenerUnset
	}

	if c.RelayAddressGenerator == nil {
		return errRelayAddressGeneratorUnset
	}

	return c.RelayAddressGenerator.Validate()
}

// AuthHandler is a callback used to handle incoming auth requests, allowing users to customize Pion TURN with custom behavior
type AuthHandler func(username string, realm string, srcAddr net.Addr) (key []byte, relayAddressType util.RelayAddressType, ok bool)

// GenerateAuthKey is a convenience function to easily generate keys in the format used by AuthHandler
func GenerateAuthKey(username, realm, password string) []byte {
	// #nosec
	h := md5.New()
	fmt.Fprint(h, strings.Join([]string{username, realm, password}, ":"))
	return h.Sum(nil)
}

// ServerConfig configures the Pion TURN Server
type ServerConfig struct {
	// PacketConnConfigs and ListenerConfigs are a list of all the turn listeners
	// Each listener can have custom behavior around the creation of Relays
	PacketConnConfigs []PacketConnConfig
	ListenerConfigs   []ListenerConfig

	// LoggerFactory must be set for logging from this server.
	LoggerFactory logging.LoggerFactory

	// Realm sets the realm for this server
	Realm string

	// AuthHandler is a callback used to handle incoming auth requests, allowing users to customize Pion TURN with custom behavior
	AuthHandler AuthHandler

	// ChannelBindTimeout sets the lifetime of channel binding. Defaults to 10 minutes.
	ChannelBindTimeout time.Duration

	// Sets the server inbound MTU(Maximum transmition unit). Defaults to 1600 bytes.
	InboundMTU int
}

func (s *ServerConfig) validate() error {
	if len(s.PacketConnConfigs) == 0 && len(s.ListenerConfigs) == 0 {
		return errNoAvailableConns
	}

	for _, s := range s.PacketConnConfigs {
		if err := s.validate(); err != nil {
			return err
		}
	}

	for _, s := range s.ListenerConfigs {
		if err := s.validate(); err != nil {
			return err
		}
	}

	return nil
}
