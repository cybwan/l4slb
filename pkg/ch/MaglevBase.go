package ch

const (
	kHashSeed0 = uint32(0)
	kHashSeed1 = uint32(2307)
	kHashSeed2 = uint64(42)
	kHashSeed3 = uint64(2718281828)
)

type maglevBase struct {
}

func (m *maglevBase) genMaglevPermutation(permutation []uint32, endpoint Endpoint, pos int, ringSize uint32) {
	offset_hash := MurmurHash3(endpoint.Hash, kHashSeed2, kHashSeed0)
	offset := uint32(offset_hash % uint64(ringSize))
	skipHash := MurmurHash3(endpoint.Hash, kHashSeed3, kHashSeed1)
	skip := uint32(skipHash%(uint64(ringSize)-1) + 1)
	permutation[2*pos] = offset
	permutation[2*pos+1] = skip
}
