package utils

import (
	"testing"

	"github.com/niclabs/tcrsa"
)

func TestPreBlock(t *testing.T) {
	block := NewPreBlock(10)

	t.Run("Checks for correct size and initialization", func(t *testing.T) {
		if len(block.Vec) != 10 {
			t.Errorf("Got block length of %d, expected %d", len(block.Vec), 10)
		}
		for _, v := range block.Vec {
			if v != nil {
				t.Errorf("Expected nil, got %p", v)
			}
		}
	})

	t.Run("Checks if messages gets added and quality is correct", func(t *testing.T) {
		preBlockMessage := &PreBlockMessage{
			Message: []byte("TEST"),
			Sig:     nil,
		}
		block.AddMessage(0, preBlockMessage)

		if block.Vec[0] == nil {
			t.Errorf("Expected %s, got nil", []byte("TEST"))
		}
		if block.Quality() != 1 {
			t.Errorf("Expected a quality of %d, got %d", 1, block.Quality())
		}
	})

	t.Run("Check if pre-block gets hashed", func(t *testing.T) {
		keyShares, keyMeta, _ := tcrsa.NewKey(512, uint16(2), uint16(2), nil)
		preBlockMessage1, _ := NewPreBlockMessage([]byte("foo"), keyShares[0], keyMeta)
		preBlockMessage2, _ := NewPreBlockMessage([]byte("bar"), keyShares[1], keyMeta)

		block1 := NewPreBlock(3)
		block2 := NewPreBlock(3)


		for i := range block1.Vec {
			block1.AddMessage(i, preBlockMessage1)
			block2.AddMessage(i, preBlockMessage2)
		}

		hash1 := block1.Hash()
		hash2 := block2.Hash()

		if hash1 == hash2 {
			t.Errorf("Hashes of two different pre-block shouldn't match")
		}
	})
}
