package ch

const (
	kDefaultChRingSize = uint32(65537)
)

// Endpoint struct which describes backend, each backend would have unique number,
// weight (the measurment of how often we would see this endpoint on CH ring) and hash value,
// which will be used as a seed value (it should be unique value per endpoint for CH to work as expected)
type Endpoint struct {
	Num    uint32
	Weight uint32
	Hash   uint64
}

type EndpointSlice []Endpoint

func (x EndpointSlice) Len() int {
	return len(x)
}
func (x EndpointSlice) Less(i, j int) bool {
	return x[i].Hash < x[j].Hash
}
func (x EndpointSlice) Swap(i, j int) {
	x[i], x[j] = x[j], x[i]
}

type HashFunction int

const (
	Maglev HashFunction = iota
	MaglevV2
)

type ConsistentHash interface {
	GenerateHashRing(endpoints []Endpoint, ringSize uint32) []int
}
