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
	ID      uint16 // Packet Identifier (bytes 0-1)
	FLAGS   uint16 // Bits in the middle packed into a 2 byte flag (bytes 2-3)
	QDCOUNT uint16 // Question Count (bytes 4-5)
	ANCOUNT uint16 // Answer Record Count (bytes 6-7)
	NSCOUNT uint16 // Authority Record Count (bytes 8-9)
	ARCOUNT uint16 // Additional Record Count (bytes 10-11)
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
		_, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		header := buf[:12]
		// Set QR bit to make it a response
		header[2] |= 0x80 // 10000000 in binary

		name, questionEnd := getQuestionEnd(buf)
		question := buf[12:questionEnd]

		binary.BigEndian.PutUint16(header[6:8], 1) // Set ANCOUNT to 1 (bytes 6-7)

		answer := append([]byte{}, name...)                // Copy name first
		answer = binary.BigEndian.AppendUint16(answer, 1)  // Type: 1 (A record)
		answer = binary.BigEndian.AppendUint16(answer, 1)  // Class: 1 (IN)
		answer = binary.BigEndian.AppendUint32(answer, 60) // TTL: 60
		answer = binary.BigEndian.AppendUint16(answer, 4)  // RDLENGTH: 4 bytes
		answer = append(answer, 8, 8, 8, 8)                // RDATA: 8.8.8.8

		response := bytes.Join([][]byte{header, question, answer}, nil)

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

func getQuestionEnd(buf []byte) ([]byte, int) {
	pos := 12 // start after header

	// iterate through domain labels till we get a null terminator
	for buf[pos] != 0 {
		labelLen := int(buf[pos])
		pos += labelLen + 1
	}

	pos += 1 // null terminator itself
	name := buf[12:pos]

	pos += 4 // QTYPE and QCLASS

	return name, pos
}
