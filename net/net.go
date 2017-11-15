package net

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/mahdiz/daga/config"
	"io"
	"net"
	"strconv"
	"time"
)

func WriteMessage(conn net.Conn, message []byte) error {

	length := len(message)

	//compose new message
	buffer := make([]byte, length+6)
	binary.BigEndian.PutUint16(buffer[0:2], uint16(config.LLD_PROTOCOL_VERSION))
	binary.BigEndian.PutUint32(buffer[2:6], uint32(length))
	copy(buffer[6:], message)

	n, err := conn.Write(buffer)

	if n < length+6 {
		return errors.New("Couldn't write the full" + strconv.Itoa(length+6) + " bytes, only wrote " + strconv.Itoa(n))
	}

	if err != nil {
		return err
	}

	return nil
}

func ReadMessage(conn net.Conn) ([]byte, error) {

	header := make([]byte, 6)
	emptyMessage := make([]byte, 0)

	//read header
	n, err := io.ReadFull(conn, header)

	if err != nil {
		return emptyMessage, err
	}

	if n != 6 {
		return emptyMessage, errors.New("Couldn't read the full 6 header bytes, only read " + strconv.Itoa(n))
	}

	//parse header
	version := int(binary.BigEndian.Uint16(header[0:2]))
	bodySize := int(binary.BigEndian.Uint32(header[2:6]))

	if version != config.LLD_PROTOCOL_VERSION {

		return emptyMessage, errors.New("Read a message with protocol " + strconv.Itoa(version) + " bytes, but our version is " + strconv.Itoa(config.LLD_PROTOCOL_VERSION) + ".")
	}

	//read body
	body := make([]byte, bodySize)
	n2, err2 := io.ReadFull(conn, body)

	if err2 != nil {
		return emptyMessage, err2
	}

	if n2 != bodySize {
		return emptyMessage, errors.New("Couldn't read the full" + strconv.Itoa(bodySize) + " body bytes, only read " + strconv.Itoa(n2))
	}

	return body, nil
}

//tips : expectedSize could be UDP_DATAGRAM_READING_MESSAGE_BUFFER_SIZE
func ReadDatagram(conn net.Conn, expectedSize int) ([]byte, error) {

	buffer := make([]byte, expectedSize+6) //6 for application header
	emptyMessage := make([]byte, 0)

	//read header
	n, err := conn.Read(buffer)

	if err != nil {
		return emptyMessage, err
	}

	//parse header
	version := int(binary.BigEndian.Uint16(buffer[0:2]))
	bodySize := int(binary.BigEndian.Uint32(buffer[2:6]))

	if version != config.LLD_PROTOCOL_VERSION {
		return emptyMessage, errors.New("Read a datagram with protocol " + strconv.Itoa(version) + " bytes, but our version is " + strconv.Itoa(config.LLD_PROTOCOL_VERSION) + ".")
	}

	//read body
	body := make([]byte, bodySize) //here we should take N into account, and keep reading if it is smaller
	copy(body, buffer[6:])

	if n < bodySize+6 {
		return body, errors.New("Read a truncated datagram of " + strconv.Itoa(n-6) + " bytes, expected " + strconv.Itoa(bodySize) + ".")
	}

	return body, nil
}

// return data, error
func ReadMessageWithTimeOut(nodeId int, conn net.Conn, timeout time.Duration, chanForTimeoutNode chan int, chanForDisconnectedNode chan int) ([]byte, bool) {

	//read with timeout
	timeoutChan := make(chan bool, 1)
	errorChan := make(chan bool, 1)
	dataChan := make(chan []byte)

	go func() {
		time.Sleep(timeout)
		timeoutChan <- true
	}()

	go func() {
		dataHolder, err := ReadMessage(conn)

		if err != nil {
			errorChan <- true
		} else {
			dataChan <- dataHolder
		}
	}()

	var data []byte
	errorDuringRead := false
	select {
	case data = <-dataChan:

	case <-timeoutChan:
		errorDuringRead = true
		chanForTimeoutNode <- nodeId

	case <-errorChan:
		errorDuringRead = true
		chanForDisconnectedNode <- nodeId
	}

	return data, errorDuringRead
}

// return data, error
func ReadDatagramWithTimeOut(conn net.Conn, expectedSize int, timeout time.Duration) ([]byte, error) {

	//read with timeout
	timeoutChan := make(chan bool, 1)
	errorChan := make(chan error, 1)
	dataChan := make(chan []byte)

	go func() {
		time.Sleep(timeout)
		timeoutChan <- true
	}()

	go func() {
		dataHolder, err := ReadDatagram(conn, expectedSize)

		if err != nil {
			errorChan <- err
		} else {
			dataChan <- dataHolder
		}
	}()

	var data []byte
	var err error
	select {
	case err2 := <-errorChan:
		err = err2

	case data = <-dataChan:

	case <-timeoutChan:
		err = errors.New("ReadDatagramWithTimeOut - timeout")
	}

	return data, err
}

func ParseTranscript(conn net.Conn, nClients int, nTrustees int) ([]abstract.Point, [][]abstract.Point, [][]byte, error) {
	buffer, err := ReadMessage(conn)
	if err != nil {
		fmt.Println("couldn't read transcript from relay " + err.Error())
		return nil, nil, nil, err
	}

	G_s := make([]abstract.Point, nTrustees)
	ephPublicKeys_s := make([][]abstract.Point, nTrustees)
	proof_s := make([][]byte, nTrustees)

	//read the G_s
	currentByte := 0
	i := 0
	for {
		if currentByte+4 > len(buffer) {
			break //we reached the end of the array
		}

		length := int(binary.BigEndian.Uint32(buffer[currentByte : currentByte+4]))

		if length == 0 {
			break //we reached the end of the array
		}

		G_S_i_Bytes := buffer[currentByte+4 : currentByte+4+length]

		fmt.Println("G_S_", i)
		fmt.Println(hex.Dump(G_S_i_Bytes))

		base := config.CryptoSuite.Point()
		err2 := base.UnmarshalBinary(G_S_i_Bytes)
		if err2 != nil {
			fmt.Println(">>>>can't unmarshal base n°" + strconv.Itoa(i) + " ! " + err2.Error())
			return nil, nil, nil, err
		}

		G_s[i] = base
		fmt.Println("Read G_S[", i, "]")

		currentByte += 4 + length
		i += 1

		if i == nTrustees {
			break
		}
	}

	//read the ephemeral public keys
	i = 0
	for {
		if currentByte+4 > len(buffer) {
			break //we reached the end of the array
		}

		length := int(binary.BigEndian.Uint32(buffer[currentByte : currentByte+4]))

		if length == 0 {
			break //we reached the end of the array
		}

		ephPublicKeysBytes := buffer[currentByte+4 : currentByte+4+length]

		ephPublicKeys := make([]abstract.Point, 0)

		fmt.Println("Ephemeral_PKS_", i)
		fmt.Println(hex.Dump(ephPublicKeysBytes))

		currentByte2 := 0
		j := 0
		for {
			if currentByte2+4 > len(ephPublicKeysBytes) {
				break //we reached the end of the array
			}

			length := int(binary.BigEndian.Uint32(ephPublicKeysBytes[currentByte2 : currentByte2+4]))

			if length == 0 {
				break //we reached the end of the array
			}

			ephPublicKeyIJBytes := ephPublicKeysBytes[currentByte2+4 : currentByte2+4+length]
			ephPublicKey := config.CryptoSuite.Point()
			err2 := ephPublicKey.UnmarshalBinary(ephPublicKeyIJBytes)
			if err2 != nil {
				fmt.Println(">>>>can't unmarshal public key n°" + strconv.Itoa(i) + "," + strconv.Itoa(j) + " ! " + err2.Error())
				return nil, nil, nil, err
			}

			ephPublicKeys = append(ephPublicKeys, ephPublicKey)
			fmt.Println("Read EphemeralPublicKey[", i, "][", j, "]")

			currentByte2 += 4 + length
			j += 1

			if j == nClients {
				break
			}
		}

		fmt.Println("Read EphemeralPublicKey[", i, "]")
		ephPublicKeys_s[i] = ephPublicKeys

		currentByte += 4 + length
		i += 1

		if i == nTrustees {
			break
		}
	}

	//read the Proofs
	i = 0
	for {
		if currentByte+4 > len(buffer) {
			break //we reached the end of the array
		}

		length := int(binary.BigEndian.Uint32(buffer[currentByte : currentByte+4]))

		if length == 0 {
			break //we reached the end of the array
		}

		proofBytes := buffer[currentByte+4 : currentByte+4+length]
		fmt.Println("Read Proof[", i, "]")

		proof_s[i] = proofBytes

		currentByte += 4 + length
		i += 1

		if i == nTrustees {
			break
		}
	}

	return G_s, ephPublicKeys_s, proof_s, nil
}

func ParsePublicKeyFromConn(conn net.Conn) (abstract.Point, error) {
	buffer, err := ReadMessage(conn)

	fmt.Print("Trying to ParsePublicKeyFromConn")
	fmt.Println(hex.Dump(buffer))

	if err != nil {
		fmt.Println("ParsePublicKeyFromConn : Read error:" + err.Error())
		return nil, err
	}

	msgType := int(binary.BigEndian.Uint16(buffer[0:2]))

	if msgType != MESSAGE_TYPE_PUBLICKEYS {
		s := "ParsePublicKeyFromConn : Read error, type supposed to be " + strconv.Itoa(MESSAGE_TYPE_PUBLICKEYS) + " but is " + strconv.Itoa(msgType)
		fmt.Println(s)
		return nil, errors.New(s)
	}

	publicKey := config.CryptoSuite.Point()
	err2 := publicKey.UnmarshalBinary(buffer[2:])

	if err2 != nil {
		fmt.Println("ParsePublicKeyFromConn : can't unmarshal ephemeral client key ! " + err2.Error())
		return nil, err
	}

	return publicKey, nil
}

func ParseBaseAndPublicKeysFromConn(conn net.Conn) (abstract.Point, []abstract.Point, error) {
	buffer, err := ReadMessage(conn)

	if err != nil {
		fmt.Println("ParseBaseAndPublicKeysFromConn, couldn't read. " + err.Error())
		return nil, nil, err
	}

	baseSize := int(binary.BigEndian.Uint32(buffer[0:4]))
	keysSize := int(binary.BigEndian.Uint32(buffer[4+baseSize : 8+baseSize]))

	baseBytes := buffer[4 : 4+baseSize]
	keysBytes := buffer[8+baseSize : 8+baseSize+keysSize]

	base := config.CryptoSuite.Point()
	err2 := base.UnmarshalBinary(baseBytes)
	if err2 != nil {
		fmt.Println("ParseBaseAndPublicKeysFromConn : can't unmarshal client key ! " + err2.Error())
		return nil, nil, err2
	}

	publicKeys, err := UnMarshalPublicKeyArrayFromByteArray(keysBytes, config.CryptoSuite)
	if err != nil {
		return nil, nil, err
	}

	return base, publicKeys, nil
}

func IntToBA(x int) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf[0:4], uint32(x))
	return buf
}

func ParseBasePublicKeysAndProofFromConn(conn net.Conn) (abstract.Point, []abstract.Point, []byte, error) {
	buffer, err := ReadMessage(conn)
	if err != nil {
		fmt.Println("ParseBaseAndPublicKeysFromConn, couldn't read. " + err.Error())
		return nil, nil, nil, err
	}

	baseSize := int(binary.BigEndian.Uint32(buffer[0:4]))
	keysSize := int(binary.BigEndian.Uint32(buffer[4+baseSize : 8+baseSize]))
	proofSize := int(binary.BigEndian.Uint32(buffer[8+baseSize+keysSize : 12+baseSize+keysSize]))

	baseBytes := buffer[4 : 4+baseSize]
	keysBytes := buffer[8+baseSize : 8+baseSize+keysSize]
	proof := buffer[12+baseSize+keysSize : 12+baseSize+keysSize+proofSize]

	base := config.CryptoSuite.Point()
	err2 := base.UnmarshalBinary(baseBytes)
	if err2 != nil {
		fmt.Println("ParseBasePublicKeysAndProofFromConn : can't unmarshal client key ! " + err2.Error())
		return nil, nil, nil, err2
	}

	publicKeys, err := UnMarshalPublicKeyArrayFromByteArray(keysBytes, config.CryptoSuite)
	if err != nil {
		return nil, nil, nil, err
	}
	return base, publicKeys, proof, nil
}

func ParseBasePublicKeysAndTrusteeSignaturesFromConn(conn net.Conn) (abstract.Point, []abstract.Point, [][]byte, error) {
	buffer, err := ReadMessage(conn)
	if err != nil {
		fmt.Println("ParseBasePublicKeysAndTrusteeProofFromConn, couldn't read. " + err.Error())
		return nil, nil, nil, err
	}

	baseSize := int(binary.BigEndian.Uint32(buffer[0:4]))
	keysSize := int(binary.BigEndian.Uint32(buffer[4+baseSize : 8+baseSize]))
	signaturesSize := int(binary.BigEndian.Uint32(buffer[8+baseSize+keysSize : 12+baseSize+keysSize]))

	fmt.Println("Signature size", signaturesSize)

	baseBytes := buffer[4 : 4+baseSize]
	keysBytes := buffer[8+baseSize : 8+baseSize+keysSize]
	signaturesBytes := buffer[12+baseSize+keysSize : 12+baseSize+keysSize+signaturesSize]

	base := config.CryptoSuite.Point()
	err2 := base.UnmarshalBinary(baseBytes)
	if err2 != nil {
		fmt.Println("ParseBasePublicKeysAndProofFromConn : can't unmarshal client key ! " + err2.Error())
		return nil, nil, nil, err2
	}

	publicKeys, err := UnMarshalPublicKeyArrayFromByteArray(keysBytes, config.CryptoSuite)

	if err != nil {
		return nil, nil, nil, err
	}

	//now read the signatures
	currentByte := 0
	signatures := make([][]byte, 0)
	i := 0
	for {
		if currentByte+4 > len(signaturesBytes) {
			break //we reached the end of the array
		}

		length := int(binary.BigEndian.Uint32(signaturesBytes[currentByte : currentByte+4]))

		if length == 0 {
			break //we reached the end of the array
		}

		thisSig := signaturesBytes[currentByte+4 : currentByte+4+length]

		fmt.Println("thisSig_", i)
		fmt.Println(hex.Dump(thisSig))

		signatures = append(signatures, thisSig)

		currentByte += 4 + length
		i += 1
	}

	return base, publicKeys, signatures, nil
}

func WriteBaseAndPublicKeyToConn(conn net.Conn, base abstract.Point, keys []abstract.Point) error {

	baseBytes, err := base.MarshalBinary()

	if err != nil {
		fmt.Println("Marshall error:" + err.Error())
		return err
	}

	publicKeysBytes, err := MarshalPublicKeyArrayToByteArray(keys)

	if err != nil {
		return err
	}

	message := make([]byte, 8+len(baseBytes)+len(publicKeysBytes))

	binary.BigEndian.PutUint32(message[0:4], uint32(len(baseBytes)))
	copy(message[4:4+len(baseBytes)], baseBytes)
	binary.BigEndian.PutUint32(message[4+len(baseBytes):8+len(baseBytes)], uint32(len(publicKeysBytes)))
	copy(message[8+len(baseBytes):], publicKeysBytes)

	err2 := WriteMessage(conn, message)
	if err2 != nil {
		fmt.Println("Write error:" + err.Error())
		return err2
	}

	return nil
}

func WriteBasePublicKeysAndProofToConn(conn net.Conn, base abstract.Point, keys []abstract.Point, proof []byte) error {
	baseBytes, err := base.MarshalBinary()
	keysBytes, err := MarshalPublicKeyArrayToByteArray(keys)
	if err != nil {
		fmt.Println("Marshall error:" + err.Error())
		return err
	}

	//compose the message
	totalMessageLength := 12 + len(baseBytes) + len(keysBytes) + len(proof)
	message := make([]byte, totalMessageLength)

	binary.BigEndian.PutUint32(message[0:4], uint32(len(baseBytes)))
	binary.BigEndian.PutUint32(message[4+len(baseBytes):8+len(baseBytes)], uint32(len(keysBytes)))
	binary.BigEndian.PutUint32(message[8+len(baseBytes)+len(keysBytes):12+len(baseBytes)+len(keysBytes)], uint32(len(proof)))

	copy(message[4:4+len(baseBytes)], baseBytes)
	copy(message[8+len(baseBytes):8+len(baseBytes)+len(keysBytes)], keysBytes)
	copy(message[12+len(baseBytes)+len(keysBytes):12+len(baseBytes)+len(keysBytes)+len(proof)], proof)

	err2 := WriteMessage(conn, message)
	if err2 != nil {
		fmt.Println("Write error:" + err2.Error())
		return err2
	}

	return nil
}

func MarshalNodeRepresentations(nodes []NodeRepresentation) ([]byte, error) {
	var byteArray []byte

	msgType := make([]byte, 2)
	binary.BigEndian.PutUint16(msgType, uint16(MESSAGE_TYPE_PUBLICKEYS))
	byteArray = append(byteArray, msgType...)

	for i := 0; i < len(nodes); i++ {
		publicKeysBytes, err := nodes[i].PublicKey.MarshalBinary()
		publicKeyLength := make([]byte, 4)
		binary.BigEndian.PutUint32(publicKeyLength, uint32(len(publicKeysBytes)))

		byteArray = append(byteArray, publicKeyLength...)
		byteArray = append(byteArray, publicKeysBytes...)

		if err != nil {
			fmt.Println("can't marshal client public key n°" + strconv.Itoa(i))
			return nil, errors.New("Can't unmarshall")
		}
	}

	return byteArray, nil
}

func NUnicastMessageToNodes(nodes []NodeRepresentation, message []byte) {

	for i := 0; i < len(nodes); i++ {
		if nodes[i].Connected {
			err := WriteMessage(nodes[i].Conn, message)

			if err != nil {
				fmt.Println("Could not n*unicast to conn", i, "gonna set it to disconnected.")
				nodes[i].Connected = false
			}
		}
	}
}

func NUnicastMessage(conns []net.Conn, message []byte) error {
	for i := 0; i < len(conns); i++ {
		err := WriteMessage(conns[i], message)

		fmt.Println("[", conns[i].LocalAddr(), " - ", conns[i].RemoteAddr(), "]")

		if err != nil {
			fmt.Println("Could not n*unicast to conn", i)
			return err
		}
	}
	return nil
}

func TellPublicKey(conn net.Conn, publicKey abstract.Point) error {
	publicKeyBytes, _ := publicKey.MarshalBinary()

	err := WriteMessage(conn, publicKeyBytes)

	if err != nil {
		fmt.Println("Error writing to socket:" + err.Error())
		return err
	}

	return nil
}

func MarshalPublicKeyArrayToByteArray(publicKeys []abstract.Point) ([]byte, error) {
	var byteArray []byte

	msgType := make([]byte, 2)
	binary.BigEndian.PutUint16(msgType, uint16(MESSAGE_TYPE_PUBLICKEYS))
	byteArray = append(byteArray, msgType...)

	for i := 0; i < len(publicKeys); i++ {
		publicKeysBytes, err := publicKeys[i].MarshalBinary()
		publicKeyLength := make([]byte, 4)
		binary.BigEndian.PutUint32(publicKeyLength, uint32(len(publicKeysBytes)))

		byteArray = append(byteArray, publicKeyLength...)
		byteArray = append(byteArray, publicKeysBytes...)

		//fmt.Println(hex.Dump(publicKeysBytes))
		if err != nil {
			fmt.Println("can't marshal client public key n°" + strconv.Itoa(i))
			return nil, err
		}
	}

	return byteArray, nil
}

func UnMarshalPublicKeyArrayFromConnection(conn net.Conn, cryptoSuite abstract.Suite) ([]abstract.Point, error) {
	//collect the public keys from the trustees
	buffer, err := ReadMessage(conn)
	if err != nil {
		fmt.Println("Read error:" + err.Error())
		return nil, err
	}

	pks, err := UnMarshalPublicKeyArrayFromByteArray(buffer, cryptoSuite)
	if err != nil {
		return nil, err
	}
	return pks, nil
}

func UnMarshalPublicKeyArrayFromByteArray(buffer []byte, cryptoSuite abstract.Suite) ([]abstract.Point, error) {

	//will hold the public keys
	var publicKeys []abstract.Point

	//safety check
	messageType := int(binary.BigEndian.Uint16(buffer[0:2]))
	if messageType != MESSAGE_TYPE_PUBLICKEYS {
		fmt.Println("Trying to unmarshall an array, but does not start by 2")
		return nil, errors.New("Wrong message type")
	}

	//parse message
	currentByte := 2
	currentPkId := 0
	for {
		if currentByte+4 > len(buffer) {
			break //we reached the end of the array
		}

		keyLength := int(binary.BigEndian.Uint32(buffer[currentByte : currentByte+4]))

		if keyLength == 0 {
			break //we reached the end of the array
		}

		keyBytes := buffer[currentByte+4 : currentByte+4+keyLength]

		publicKey := cryptoSuite.Point()
		err2 := publicKey.UnmarshalBinary(keyBytes)
		if err2 != nil {
			fmt.Println(">>>>can't unmarshal key n°" + strconv.Itoa(currentPkId) + " ! " + err2.Error())
			return nil, err2
		}

		publicKeys = append(publicKeys, publicKey)

		currentByte += 4 + keyLength
		currentPkId += 1
	}

	return publicKeys, nil
}

// Marshals a sequence of byte arrays
// Each input array MUST have less than 65K bytes
func MarshalByteArrays(arrs ...[]byte) []byte {
	size := 0
	for _, arr := range arrs {
		size += len(arr) + 2
	}

	i := 0
	res := make([]byte, size)
	for _, arr := range arrs {
		arrlen := len(arr)
		if arrlen > 65535 {
			panic("Cannot marshal arrays with more than 65K bytes!")
		}
		binary.BigEndian.PutUint16(res[i:i+2], uint16(arrlen))
		copy(res[i+2:i+arrlen+2], arr)
		i += arrlen + 2
	}
	return res
}

// Unmarshals a sequence of byte arrays
func UnmarshalByteArrays(input []byte) [][]byte {
	var arrs [][]byte

	for i := 0; i < len(input); {
		len := int(binary.BigEndian.Uint16(input[i : i+2]))
		arr := make([]byte, len)
		copy(arr, input[i+2:i+2+len])
		arrs = append(arrs, arr)
		i += len + 2
	}
	return arrs
}
