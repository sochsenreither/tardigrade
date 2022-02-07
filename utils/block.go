package utils

import (
	"crypto"
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

type BlockPointer struct {
	BlockHash []byte          // Hash of the large pre-block
	Sig       tcrsa.Signature // Combined signature of the committee members on the hash
}

type BlockShare struct {
	Block   *PreBlock
	Pointer *BlockPointer
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

// Concatenates all the messages and signatures and takes the hash of that byte array.
func (pre *PreBlock) Hash() [32]byte {
	var inp []byte
	for _, m := range pre.Vec {
		if m != nil {
			// append message and signature
			b := append(m.Message, m.Sig.Xi...)
			inp = append(inp, b...)
		}
	}
	hash := sha256.Sum256(inp)
	return hash
}

// Concatenates BlockHash and Sig which are both byte slices and returns the hash of the combined a
// slice.
func (ptr *BlockPointer) Hash() [32]byte {
	h := append(ptr.BlockHash, ptr.Sig...)
	hash := sha256.Sum256(h)
	return hash
}

// Concatenates the hashes of the block and block pointer and returns the hash of those combined
// byte slices.
func (bs *BlockShare) Hash() [32]byte {
	pointerHash := bs.Pointer.Hash()
	blockHash := bs.Block.Hash()
	h := append(pointerHash[:], blockHash[:]...)
	hash := sha256.Sum256(h)
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

// Returns a new block pointer
func NewBlockPointer(hash []byte, sig tcrsa.Signature) *BlockPointer {
	return &BlockPointer{
		BlockHash: hash,
		Sig:       sig,
	}
}

// Returns a new block share
func NewBlockShare(block *PreBlock, pointer *BlockPointer) *BlockShare {
	return &BlockShare{
		Block:   block,
		Pointer: pointer,
	}
}


// Returns a new pre-block message
func NewPreBlockMessage(mes []byte, keyShare *tcrsa.KeyShare, keyMeta *tcrsa.KeyMeta) (*PreBlockMessage, error) {
	mesHash := sha256.Sum256(mes)
	mesHashPadded, err := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, mesHash[:])
	if err != nil {
		return nil, err
	}
	sig, err := keyShare.Sign(mesHashPadded, crypto.SHA256, keyMeta)
	if err != nil {
		return nil, err
	}
	preBlockMes := &PreBlockMessage{
		Message: mes,
		Sig: sig,
	}
	return preBlockMes, nil
}