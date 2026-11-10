package bedrock

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

var crc32IEEE = crc32.MakeTable(crc32.IEEE)

// EventStreamMessage represents a decoded AWS EventStream binary message.
type EventStreamMessage struct {
	Headers map[string]string
	Payload []byte
}

// DecodeEventStreamMessage decodes one message from the reader.
// Returns io.EOF when stream ends normally.
func DecodeEventStreamMessage(r io.Reader) (*EventStreamMessage, error) {
	// Read Prelude: 8 bytes
	prelude := make([]byte, 8)
	if _, err := io.ReadFull(r, prelude); err != nil {
		return nil, err
	}

	totalLength := binary.BigEndian.Uint32(prelude[0:4])
	headersLength := binary.BigEndian.Uint32(prelude[4:8])

	if totalLength < 16 {
		return nil, fmt.Errorf("invalid event stream total length: %d", totalLength)
	}

	// Read Prelude CRC: 4 bytes
	preludeCRCBytes := make([]byte, 4)
	if _, err := io.ReadFull(r, preludeCRCBytes); err != nil {
		return nil, fmt.Errorf("read prelude crc: %w", err)
	}
	expectedPreludeCRC := binary.BigEndian.Uint32(preludeCRCBytes)
	actualPreludeCRC := crc32.Checksum(prelude, crc32IEEE)
	if expectedPreludeCRC != actualPreludeCRC {
		return nil, fmt.Errorf("prelude crc mismatch: expected %d, got %d", expectedPreludeCRC, actualPreludeCRC)
	}

	// Read remaining bytes (headers + payload + message CRC)
	remainingLength := totalLength - 12
	remaining := make([]byte, remainingLength)
	if _, err := io.ReadFull(r, remaining); err != nil {
		return nil, fmt.Errorf("read message body: %w", err)
	}

	// Verify Message CRC (last 4 bytes)
	messageCRCBytes := remaining[remainingLength-4:]
	expectedMessageCRC := binary.BigEndian.Uint32(messageCRCBytes)

	// CRC is computed over prelude (8 bytes) + preludeCRC (4 bytes) + remaining up to remainingLength-4
	fullMsgForCRC := make([]byte, 0, totalLength-4)
	fullMsgForCRC = append(fullMsgForCRC, prelude...)
	fullMsgForCRC = append(fullMsgForCRC, preludeCRCBytes...)
	fullMsgForCRC = append(fullMsgForCRC, remaining[:remainingLength-4]...)
	actualMessageCRC := crc32.Checksum(fullMsgForCRC, crc32IEEE)
	if expectedMessageCRC != actualMessageCRC {
		return nil, fmt.Errorf("message crc mismatch: expected %d, got %d", expectedMessageCRC, actualMessageCRC)
	}

	// Parse Headers
	headersBytes := remaining[:headersLength]
	headers, err := parseHeaders(headersBytes)
	if err != nil {
		return nil, fmt.Errorf("parse headers: %w", err)
	}

	// Extract Payload
	payloadBytes := remaining[headersLength : remainingLength-4]

	return &EventStreamMessage{
		Headers: headers,
		Payload: payloadBytes,
	}, nil
}

func parseHeaders(data []byte) (map[string]string, error) {
	headers := make(map[string]string)
	offset := 0
	for offset < len(data) {
		if offset >= len(data) {
			break
		}
		nameLen := int(data[offset])
		offset++
		if offset+nameLen > len(data) {
			return nil, fmt.Errorf("header name out of bounds")
		}
		name := string(data[offset : offset+nameLen])
		offset += nameLen

		if offset >= len(data) {
			return nil, fmt.Errorf("header value type missing")
		}
		valType := data[offset]
		offset++

		// Header types: 7 is String
		switch valType {
		case 7: // String
			if offset+2 > len(data) {
				return nil, fmt.Errorf("header string length missing")
			}
			valLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2
			if offset+valLen > len(data) {
				return nil, fmt.Errorf("header string value out of bounds")
			}
			val := string(data[offset : offset+valLen])
			offset += valLen
			headers[name] = val
		case 0, 1: // bool true/false
			headers[name] = fmt.Sprintf("%v", valType == 1)
		case 2: // int8
			offset++
		case 3: // int16
			offset += 2
		case 4: // int32
			offset += 4
		case 5: // int64
			offset += 8
		case 6: // byte array
			if offset+2 > len(data) {
				return nil, fmt.Errorf("header bytes length missing")
			}
			valLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2 + valLen
		default:
			// Skip unknown header types if possible
			return headers, nil
		}
	}
	return headers, nil
}

// EncodeEventStreamMessage encodes a payload and headers into an AWS EventStream binary message.
// Used for test generation and mock servers.
func EncodeEventStreamMessage(headers map[string]string, payload []byte) []byte {
	var headersBuf []byte
	for k, v := range headers {
		headersBuf = append(headersBuf, byte(len(k)))
		headersBuf = append(headersBuf, []byte(k)...)
		headersBuf = append(headersBuf, 7) // String type
		valLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(valLenBytes, uint16(len(v)))
		headersBuf = append(headersBuf, valLenBytes...)
		headersBuf = append(headersBuf, []byte(v)...)
	}

	headersLen := uint32(len(headersBuf))
	totalLen := 12 + headersLen + uint32(len(payload)) + 4

	prelude := make([]byte, 8)
	binary.BigEndian.PutUint32(prelude[0:4], totalLen)
	binary.BigEndian.PutUint32(prelude[4:8], headersLen)

	preludeCRC := crc32.Checksum(prelude, crc32IEEE)
	preludeCRCBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(preludeCRCBytes, preludeCRC)

	msgForCRC := make([]byte, 0, totalLen-4)
	msgForCRC = append(msgForCRC, prelude...)
	msgForCRC = append(msgForCRC, preludeCRCBytes...)
	msgForCRC = append(msgForCRC, headersBuf...)
	msgForCRC = append(msgForCRC, payload...)

	msgCRC := crc32.Checksum(msgForCRC, crc32IEEE)
	msgCRCBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(msgCRCBytes, msgCRC)

	var fullMsg []byte
	fullMsg = append(fullMsg, msgForCRC...)
	fullMsg = append(fullMsg, msgCRCBytes...)
	return fullMsg
}
