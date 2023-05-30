package endian

import "encoding/binary"

func BigEndian16(x uint16) uint16 {
	xBe := make([]byte, 2)
	binary.LittleEndian.PutUint16(xBe, x)
	return binary.BigEndian.Uint16(xBe)
}

func BigEndian32(x uint32) uint32 {
	xBe := make([]byte, 4)
	binary.LittleEndian.PutUint32(xBe, x)
	return binary.BigEndian.Uint32(xBe)
}

func BigEndian64(x uint64) uint64 {
	xBe := make([]byte, 8)
	binary.LittleEndian.PutUint64(xBe, x)
	return binary.BigEndian.Uint64(xBe)
}
