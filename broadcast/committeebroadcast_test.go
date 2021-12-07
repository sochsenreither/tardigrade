package broadcast

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/niclabs/tcrsa"
)

type testCBBInstance struct {
	n                   int
	t                   int
	kappa               int
	epsilon             int
	committee           map[int]bool
	bbNodeChans         []chan *broadcastMessage
	cbbNodeChans        []chan *committeeBroadcastMessage
	senderChans         []chan []byte
	outs                []chan []byte
	committeeBroadcasts []*CommitteeBroadcast
}

func NewTestCBBInstance(n, ts, sender, kappa int, committee map[int]bool) *testCBBInstance {
	testCBBInstance := &testCBBInstance{
		n:                   n,
		t:                   ts,
		kappa:               kappa,
		epsilon:             0,
		committee:           committee,
		bbNodeChans:         make([]chan *broadcastMessage, n),
		cbbNodeChans:        make([]chan *committeeBroadcastMessage, n),
		senderChans:         make([]chan []byte, n),
		outs:                make([]chan []byte, n),
		committeeBroadcasts: make([]*CommitteeBroadcast, n),
	}

	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(n-ts+1), uint16(n), nil)
	if err != nil {
		panic(err)
	}

	for i := 0; i < n; i++ {
		hash := sha256.Sum256([]byte(strconv.Itoa(i)))
		hashPadded, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
		// Dealer signs
		sig, _ := keyShares[len(keyShares)-1].Sign(hashPadded, crypto.SHA256, keyMeta)
		sigScheme := &signatureScheme{
			sig:     sig,
			keyMeta: keyMeta,
		}
		testCBBInstance.bbNodeChans[i] = make(chan *broadcastMessage, 100*n)
		testCBBInstance.cbbNodeChans[i] = make(chan *committeeBroadcastMessage, 100*n)
		testCBBInstance.senderChans[i] = make(chan []byte, 100*n)
		testCBBInstance.outs[i] = make(chan []byte, 100*n)
		testCBBInstance.committeeBroadcasts[i] = NewCommitteeBroadcast(n, i, ts, kappa, sender, 0, committee, testCBBInstance.bbNodeChans, testCBBInstance.cbbNodeChans, testCBBInstance.senderChans, testCBBInstance.outs[i], sigScheme)
	}

	return testCBBInstance
}

func TestCBBEveryoneAgreesOnInput(t *testing.T) {
	committee := make(map[int]bool)
	committee[0] = true
	committee[1] = true
	committee[2] = true

	testCBB := NewTestCBBInstance(10, 2, 0, 3, committee)
	var wg sync.WaitGroup

	inp := []byte("foo")
	testCBB.committeeBroadcasts[0].SetValue(inp)

	start := time.Now()
	for i := 0; i < testCBB.n-testCBB.t; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			testCBB.committeeBroadcasts[i].run()
		}()
	}
	wg.Wait()
	fmt.Println("Execution time:", time.Since(start))

	for i := 0; i < testCBB.n-testCBB.t; i++ {
		val := <- testCBB.outs[i]
		if !bytes.Equal(inp, val) {
			t.Errorf("Node %d returned %q, expected %q", i, val, inp)
		}
	}
}