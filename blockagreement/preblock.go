package blockagreement

import (
	"crypto/sha256"

	"github.com/niclabs/tcrsa"
)

type PreBlock struct {
	Vec []*PreBlockMessage
}

type PreBlockMessage struct {
	Message []byte
	Sig     *tcrsa.SigShare
}

// Adds a message to the pre-block at given node index
func (pre *PreBlock) AddMessage(node int, message *PreBlockMessage) {
	if pre.Vec[node] == nil {
		pre.Vec[node] = message
	}
}

// Returns the number of elements that are not nil
func (pre *PreBlock) Quality() (counter int) {
	for _, v := range pre.Vec {
		if v != nil {
			counter++
		}
	}
	return counter
}

// Concatenates all the messages and takes the hash of that byte array
// TODO: maybe hash with sig?
func (pre *PreBlock) Hash() [32]byte {
	var inp []byte
	for _, m := range pre.Vec {
		inp = append(inp, m.Message...)
	}
	hash := sha256.Sum256(inp)
	return hash
}

// Returns a new empty pre-block with given size
func NewPreBlock(n int) *PreBlock {
	var vec []*PreBlockMessage
	for i := 0; i < n; i++ {
		vec = append(vec, nil)
	}
	return &PreBlock{
		Vec: vec,
	}
}
