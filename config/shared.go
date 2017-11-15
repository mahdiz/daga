package config

import (
	"github.com/dedis/crypto/nist"
)

// Used to make sure everybody has the same version of the software. must be updated manually
const LLD_PROTOCOL_VERSION = 3

// Number of times to retry connecting to a node
const NUM_RETRY_CONNECT = 3

// Sets the crypto suite used
var CryptoSuite = nist.NewAES128SHA256P256()
