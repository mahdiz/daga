package daga

import (
	"github.com/dedis/crypto/abstract"
	daganet "github.com/mahdiz/daga/net"
	"net"
)

const (
	PROTOCOL_TYPE_DAGA = iota
)

type Protocol interface {
	Start() error
	HandleMessage(msg []byte, senderConn net.Conn) error
}

/////////////////

const (
	TRUSTEE_SETUP          = iota // Relay requesting DAGA setup (fresh authentication context)
	TRUSTEE_FINISHED_SETUP        // Trustee finished DAGA setup
	CLIENT_JOINING                // Client requests authentication from the relay
	CLIENT_CONTEXT_REQ            // Client requesting authentication context from the first trustee
)

type RelayProtocol struct {
	Initialized       bool
	TrusteeHosts      []string
	Trustees          []daganet.NodeRepresentation
	ClientPublicKeys  map[int]abstract.Point
	TrusteePublicKeys map[int]abstract.Point
}

type TrusteeProtocol struct {
	trusteeId          int
	trustees           []daganet.NodeRepresentation
	relay              daganet.NodeRepresentation
	relayConn          net.Conn
	publicKeyRoster    map[int]abstract.Point
	rand               int                    // r_j
	clientGenerators   map[int]abstract.Point // Clients' group generators (h_i's)
	trusteeCommitments map[int]abstract.Point
}
