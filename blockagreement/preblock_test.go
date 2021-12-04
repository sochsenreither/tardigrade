package blockagreement

import (
	"testing"
)

func TestPreBlock(t *testing.T) {
	block := NewPreBlock(10)

	t.Run("Checks for correct size and initialization", func(t *testing.T) {
		if len(block.vec) != 10 {
			t.Errorf("Got block length of %d, expected %d", len(block.vec), 10)
		}
		for _, v := range block.vec {
			if v != nil {
				t.Errorf("Expected nil, got %p", v)
			}
		}
	})

	t.Run("Checks if messages gets added and quality is correct", func(t *testing.T) {
		preBlockMessage := &preBlockMessage{
			message: []byte("TEST"),
			sig:     nil,
		}
		block.addMessage(0, preBlockMessage)

		if block.vec[0] == nil {
			t.Errorf("Expected %s, got nil", []byte("TEST"))
		}
		if block.Quality() != 1 {
			t.Errorf("Expected a quality of %d, got %d", 1, block.Quality())
		}
	})
}
