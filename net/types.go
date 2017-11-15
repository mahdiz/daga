package net

import (
	"github.com/dedis/crypto/abstract"
	"net"
)

type NodeRepresentation struct {
	Id        int
	Conn      net.Conn //classical TCP connection
	Connected bool
	PublicKey abstract.Point
}

type DataWithConnectionId struct {
	ConnectionId int    // connection number
	Data         []byte // data buffer
}

type DataWithMessageType struct {
	MessageType int
	Data        []byte
}

type DataWithMessageTypeAndConnId struct {
	MessageType  int
	ConnectionId int // connection number (SOCKS id)
	Data         []byte
}

const SOCKS_CONNECTION_ID_EMPTY = 0
const IPV4_BROADCAST_ADDR = "255.255.255.255"
const UDP_DATAGRAM_READING_MESSAGE_BUFFER_SIZE = 1024 //UDP max size is 65535. Should be BIGGER than the sent datagram (or data will be lost)

const (
	MESSAGE_TYPE_DATA = iota
	MESSAGE_TYPE_DATA_AND_RESYNC
	MESSAGE_TYPE_PUBLICKEYS
	MESSAGE_TYPE_LAST_UPLOAD_FAILED
)
