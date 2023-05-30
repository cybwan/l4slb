package ch

type maglevHashV2 struct {
	maglevBase
}

func (m *maglevHashV2) GenerateHashRing(endpoints []Endpoint, ringSize uint32) []int {
	if ringSize == 0 {
		ringSize = kDefaultChRingSize
	}

	result := make([]int, ringSize)
	for i := uint32(0); i < ringSize; i++ {
		result[i] = -1
	}

	if len(endpoints) == 0 {
		return result
	}

	if len(endpoints) == 1 {
		for i := uint32(0); i < ringSize; i++ {
			result[i] = int(endpoints[0].Num)
		}
		return result
	}

	maxWeight := uint32(0)
	for _, endpoint := range endpoints {
		if endpoint.Weight > maxWeight {
			maxWeight = endpoint.Weight
		}
	}

	runs := uint32(0)
	permutation := make([]uint32, len(endpoints)*2)
	next := make([]uint32, len(endpoints))
	cumWeight := make([]uint32, len(endpoints))

	for i := 0; i < len(endpoints); i++ {
		m.genMaglevPermutation(permutation, endpoints[i], i, ringSize)
	}

	for {
		for i := 0; i < len(endpoints); i++ {
			cumWeight[i] += endpoints[i].Weight
			if cumWeight[i] >= maxWeight {
				cumWeight[i] -= maxWeight
				offset := permutation[2*i]
				skip := permutation[2*i+1]
				cur := (offset + next[i]*skip) % ringSize
				for result[cur] >= 0 {
					next[i] += 1
					cur = (offset + next[i]*skip) % ringSize
				}
				result[cur] = int(endpoints[i].Num)
				next[i] += 1
				runs++
				if runs == ringSize {
					return result
				}
			}
		}
	}
}
