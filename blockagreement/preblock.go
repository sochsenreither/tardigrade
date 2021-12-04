package blockagreement

import "github.com/niclabs/tcrsa"

type preBlock struct {
	vec     []*preBlockMessage
}

type preBlockMessage struct {
	message []byte
	sig     *tcrsa.SigShare
}

func (pre *preBlock) addMessage(node int, message *preBlockMessage) {
	if pre.vec[node] == nil {
		pre.vec[node] = message
	}
}

func (pre *preBlock) Quality() (counter int) {
	for _, v := range pre.vec {
		if v != nil {
			counter++
		}
	}
	return counter
}

func NewPreBlock(n int) *preBlock {
	var vec []*preBlockMessage
	for i := 0; i < n; i++ {
		vec = append(vec, nil)
	}
	return &preBlock{
		vec: vec,
	}
}
