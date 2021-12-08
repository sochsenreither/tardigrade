package blockagreement

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/niclabs/tcrsa"
)

type testGradedConsensusInstance struct {
	n               int
	ts              int
	round           int
	nodeChans       []chan *message
	tickers         []chan int
	outs            []chan *gradedConsensusResult
	gcs             []*gradedConsensus
	kills           []chan struct{}
	thresholdCrypto []*thresholdCrypto
	leaderChan      chan *leaderRequest
}

func newTestGradedConsensusInstance(n, ts, round int) *testGradedConsensusInstance {
	gc := &testGradedConsensusInstance{
		n:               n,
		ts:              ts,
		round:           round,
		nodeChans:       make([]chan *message, n),
		tickers:         make([]chan int, n),
		outs:            make([]chan *gradedConsensusResult, n),
		gcs:             make([]*gradedConsensus, n),
		kills:           make([]chan struct{}, n),
		thresholdCrypto: make([]*thresholdCrypto, n),
		leaderChan:      make(chan *leaderRequest, n),
	}

	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	if err != nil {
		panic(err)
	}

	// Fill pre-block with enough valid messages
	pre := NewPreBlock(n)
	for i := 0; i < n; i++ {
		// Create a test message with a corresponding signature by node i
		message := []byte("test")
		messageHash := sha256.Sum256(message)
		messageHashPadded, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, messageHash[:])
		sig, _ := keyShares[i].Sign(messageHashPadded, crypto.SHA256, keyMeta)

		preMes := &PreBlockMessage{
			Message: message,
			Sig:     sig,
		}
		pre.AddMessage(i, preMes)
	}

	// Set up individual graded consensus protocols
	for i := 0; i < n; i++ {
		vote := &vote{
			round:    0,
			preBlock: pre,
			commits:  nil,
		}
		gc.nodeChans[i] = make(chan *message, n*n)
		gc.tickers[i] = make(chan int, n*n*n)
		gc.outs[i] = make(chan *gradedConsensusResult, n)
		gc.kills[i] = make(chan struct{}, n)
		gc.thresholdCrypto[i] = &thresholdCrypto{
			keyShare: keyShares[i],
			keyMeta:  keyMeta,
		}
		gc.gcs[i] = NewGradedConsensus(n, i, ts, round, gc.nodeChans, gc.tickers[i], vote, gc.kills[i], gc.thresholdCrypto[i], gc.leaderChan, gc.outs[i])
	}

	return gc
}

func TestGCEveryoneAgreesOnSameOutputInRoundOneWithGrade2(t *testing.T) {
	testGC := newTestGradedConsensusInstance(4, 1, 0)

	go testLeader(testGC.leaderChan)
	go tickr(testGC.tickers, 25*time.Millisecond, 10)
	for i := 0; i < testGC.n-testGC.ts; i++ {
		go testGC.gcs[i].run()
	}
	start := time.Now()

	for i := 0; i < testGC.n-testGC.ts; i++ {
		grade := <-testGC.outs[i]
		if grade.grade != 2 {
			t.Errorf("Node %d got grade %d, expected %d", i, grade.grade, 2)
		}
		if len(grade.commits) < testGC.n-testGC.ts {
			t.Errorf("Set of commits is too small, got %d, expected %d", len(grade.commits), 2)
		}
	}
	fmt.Println("Execution time:", time.Since(start))
}

func TestGCFailedRoundButStillTerminates(t *testing.T) {
	test := newTestGradedConsensusInstance(4, 1, 0)
	timeout := time.After(200 * time.Millisecond)
	done := make(chan struct{})

	helper := func() {
		start := time.Now()
		var wg sync.WaitGroup
		// Start protocol with only 1 honest node
		for i := 0; i < 1; i++ {
			wg.Add(1)
			i := i
			go func() {
				defer wg.Done()
				test.gcs[i].run()
			}()
		}
		go testLeader(test.leaderChan)
		go tickr(test.tickers, 25*time.Millisecond, 6)
		wg.Wait()
		fmt.Println("Execution time:", time.Since(start))
	}

	go func() {
		helper()
		done <- struct{}{}
	}()

	select {
	case <-timeout:
		t.Errorf("Protocol didn't terminate")
	case <-done:
	}
}

// Dummy leader who just responds with 0
func testLeader(in chan *leaderRequest) {
	for request := range in {
		answer := &leaderAnswer{
			round:  request.round,
			leader: 0,
		}
		request.answer <- answer
	}
}
