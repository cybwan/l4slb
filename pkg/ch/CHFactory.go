package ch

func Make(hfunc HashFunction) ConsistentHash {
	switch hfunc {
	case MaglevV2:
		return new(maglevHashV2)
	case Maglev:
		return new(maglevHashV1)
	default:
		return new(maglevHashV1)
	}
}
