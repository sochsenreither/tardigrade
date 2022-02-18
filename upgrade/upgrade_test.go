package upgrade

import (
	"strconv"
	"testing"
)


func simpleTestInstance(n int) *Upgrade {
	buf := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		buf[i] = []byte(strconv.Itoa(i))
	}
	committee := make(map[int]bool)
	committee[0] = true
	cfg := &UpgradeConfig {
		n: 1,
		nodeId: 0,
		t: 0,
		tk: 0,
		kappa: 0,
		lambda: 200,
		committee: committee,
	}
	u := &Upgrade{
		cfg: cfg,
		acs: nil,
		ba: nil,
		tcs: nil,
		buf: buf,
	}
	return u
}

func TestProposeTxs(t *testing.T) {
	u := simpleTestInstance(1)

	r := u.proposeTxs(3, 10)
	if len(r) != 3 {
		t.Errorf("Expected %d elements, got %d", 3, len(r))
	}
	r = u.proposeTxs(10, 10)
	if len(r) != 10 {
		t.Errorf("Expected %d elements, got %d", 10, len(r))
	}
}