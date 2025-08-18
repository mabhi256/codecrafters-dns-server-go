package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
)

/*
*    0   1 2 3 4    5  6  7  8   9 10 11   12 13 14 15
*  |QR|   Opcode   |AA|TC|RD|RA|    Z    |    RCODE   |
*
*   QR          Query/Response Indicator, 1 bit
*   OPCODE      Operation Code, 4 bit
*   AA          Authoritative Answer, 1 bit
*   TC          Truncation, 1 bit
*   RD          Recursion Desired, 1 bit
*   RA          Recursion Available, 1 bit
*   Z           Reserved, 3 bit
*   RCODE       Response Code, 4 bit
 */
type DNSHeader struct {
	ID      uint16 // Packet Identifier (bytes 0-1)
	FLAGS   uint16 // Bits in the middle packed into a 2 byte flag (bytes 2-3)
	QDCOUNT uint16 // Question Count (bytes 4-5)
	ANCOUNT uint16 // Answer Record Count (bytes 6-7)
	NSCOUNT uint16 // Authority Record Count (bytes 8-9)
	ARCOUNT uint16 // Additional Record Count (bytes 10-11)
}

type Question struct {
	Name  []byte
	Type  uint16
	Class uint16
}

func main() {
	udpConn, err := createDNSServer()
	if err != nil {
		fmt.Println("Failed to start DNS Server:", err)
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

		qdCount := binary.BigEndian.Uint16(buf[4:6])

		args := os.Args
		// Resolver only works with one question
		if qdCount == 1 && len(args) >= 2 && args[2] != "127.0.0.1:2053" {
			forwardAddress := args[2] // ip:port

			err := forwardDNSRequest(udpConn, buf[:size], forwardAddress, source)
			if err != nil {
				fmt.Printf("Error forwarding DNS request: %v\n", err)
			}
		} else {
			err := generateLocalResponse(buf, qdCount, udpConn, source)
			if err != nil {
				fmt.Printf("Error generating DNS response: %v\n", err)
			}
		}
	}
}

// Setup local DNS Server listening on port 2053
func createDNSServer() (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to address: %w", err)
	}

	return udpConn, nil
}

// Create local response
// - Create header and set QR, RCODE and ANCOUNT
// - Create question section and uncompress label pointers
// - Create answer section with uncompressed labels
func generateLocalResponse(buf []byte, qdCount uint16, udpConn *net.UDPConn, source *net.UDPAddr) error {
	header := setResponseHeader(buf, qdCount)

	questions, questionEnd := getQuestions(buf, qdCount)
	questionSection := buf[12:questionEnd]

	// Build answer section
	answerSection := []byte{}

	for _, q := range questions {
		answerSection = append(answerSection, q.Name...)                      // Copy name from question
		answerSection = binary.BigEndian.AppendUint16(answerSection, q.Type)  // Use actual question type
		answerSection = binary.BigEndian.AppendUint16(answerSection, q.Class) // Use actual question class
		answerSection = binary.BigEndian.AppendUint32(answerSection, 60)      // TTL: 60
		answerSection = binary.BigEndian.AppendUint16(answerSection, 4)       // RDLENGTH: 4 bytes
		answerSection = append(answerSection, 8, 8, 8, 8)                     // RDATA: 8.8.8.8
	}

	response := bytes.Join([][]byte{header, questionSection, answerSection}, nil)
	_, err := udpConn.WriteToUDP(response, source)
	if err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	return nil
}

func setResponseHeader(buf []byte, qdCount uint16) []byte {
	header := buf[:12]
	// Set QR bit to make it a response
	header[2] |= 0x80 // 10000000 in binary

	flags := binary.BigEndian.Uint16(header[2:4])
	opcode := (flags >> 11) & 0x0F // 0x0F = 0b1111 in binary, can also (flags >> 11) & 15

	if opcode != 0 {
		// Clear the bottom 4 bits (RCODE) and set to 4
		flags = (flags & 0xFFF0) | 4                   // 0xFFF0 = 0b1111111111110000
		binary.BigEndian.PutUint16(header[2:4], flags) // Write the updated flags back to the header
	}

	binary.BigEndian.PutUint16(header[6:8], qdCount) // Set ANCOUNT (bytes 6-7)

	return header
}

// Reads domain name and handles compression
func parseName(buf []byte, pos int) ([]byte, int) {
	name := []byte{}

	for {
		// Check if this is a compression pointer (first two bits are 11)
		if (buf[pos] & 0xc0) == 0xc0 {
			// 14 bits next to the compression marker
			offset := int(binary.BigEndian.Uint16(buf[pos:pos+2]) & 0x3fff)
			restOfName, _ := parseName(buf, offset)
			name = append(name, restOfName...)
			return name, pos + 2 // Return position after the pointer
		}

		// Append length or null terminator
		length := buf[pos]
		name = append(name, length)
		pos++

		if length == 0 {
			break // Null terminator - end of name
		}

		name = append(name, buf[pos:pos+int(length)]...)
		pos += int(length)
	}

	return name, pos
}

func getQuestions(buf []byte, qdCount uint16) ([]Question, int) {
	pos := 12 // start after header
	questions := []Question{}

	// Process each question
	for currQd := 0; currQd < int(qdCount); currQd++ {
		name, newPos := parseName(buf, pos)
		pos = newPos

		// Read QTYPE and QCLASS
		qtype := binary.BigEndian.Uint16(buf[pos : pos+2])
		qclass := binary.BigEndian.Uint16(buf[pos+2 : pos+4])
		pos += 4

		question := Question{
			Name:  name,
			Type:  qtype,
			Class: qclass,
		}

		questions = append(questions, question)
	}

	return questions, pos
}

func forwardDNSRequest(conn *net.UDPConn, buf []byte, forwardAddress string, source *net.UDPAddr) error {
	upstreamAddr, err := net.ResolveUDPAddr("udp", forwardAddress)
	if err != nil {
		return fmt.Errorf("failed to resolve upstream address: %w", err)
	}

	_, err = conn.WriteToUDP(buf, upstreamAddr)
	if err != nil {
		return fmt.Errorf("failed to send request to upstream: %w", err)
	}

	response := make([]byte, 512)
	_, err = conn.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read response from upstream: %w", err)
	}

	// Update the response ID to the original request ID
	originalID := binary.BigEndian.Uint16(buf[0:2])
	binary.BigEndian.PutUint16(response[0:2], originalID)

	_, err = conn.WriteToUDP(response, source)
	if err != nil {
		return fmt.Errorf("failed to send response to source: %w", err)
	}

	return nil
}
