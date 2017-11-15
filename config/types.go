package config

import "github.com/dedis/crypto/abstract"

const (
	NODE_TYPE_RELAY   = "Relay"
	NODE_TYPE_TRUSTEE = "Trustee"
	NODE_TYPE_CLIENT  = "Client"
)

// Node's personal information
type NodeInfo struct {
	Id    int    // Node id
	Name  string // Node name
	Type  string // Node type
	Suite string // Cipher suite name
	PubId string // My public key identifier. Used to validate the secret key file
}

// Node's public configuration information
// This type is marshaled into the node's .config file
type nodePubConfig struct {
	NodeInfo              // My public info
	NodesInfo  []NodeInfo // Other nodes' public info
	AuthMethod int        // Authentication method
}

// Node's configuration
// This type is marshaled into the node's config folder
type NodeConfig struct {
	nodePubConfig // Node's information

	PublicKey  abstract.Point
	PrivateKey abstract.Scalar

	PublicKeyRoster map[int]abstract.Point // Other nodes' public keys
}
