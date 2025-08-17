package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

/*
*	15  14 13 12 11  10  9  8  7  6 5 4  3 2 1 0
*  |QR|   Opcode    |AA|TC|RD|RA|   Z   | RCODE |
*
*	QR      	Query/Response Indicator, 1 bit
* 	OPCODE  	Operation Code, 4 bit
* 	AA      	Authoritative Answer, 1 bit
* 	TC      	Truncation, 1 bit
* 	RD      	Recursion Desired, 1 bit
* 	RA      	Recursion Available, 1 bit
* 	Z       	Reserved, 3 bit
* 	RCODE   	Response Code, 4 bit
 */
type DNSHeader struct {
	ID      uint16 // Packet Identifier
	FLAGS   uint16 // Bits in the middle packed into a 2 byte flag
	QDCOUNT uint16 // Question Count
	ANCOUNT uint16 // Answer Record Count
	NSCOUNT uint16 // Authority Record Count
	ARCOUNT uint16 // Additional Record Count
}

func (h *DNSHeader) ToBytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, h)
	return buf.Bytes()
}

func main() {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		response := buf[:12] // send the header as response
		// Set QR bit to make it a response
		response[2] |= 0x80 // 10000000 in binary

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
