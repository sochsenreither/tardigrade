package blockagreement

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/upgrade/utils"
)

type testGradedConsensusInstance struct {
	n               int
	ts              int
	round           int
	nodeChans       map[int][]chan *utils.Message
	tickers         []chan int
	gcs             []*gradedConsensus
	thresholdCrypto []*thresholdCrypto
}

func newTestGradedConsensusInstance(n, ts, round int) *testGradedConsensusInstance {
	gc := &testGradedConsensusInstance{
		n:               n,
		ts:              ts,
		round:           round,
		nodeChans:       make(map[int][]chan *utils.Message),
		tickers:         make([]chan int, n),
		gcs:             make([]*gradedConsensus, n),
		thresholdCrypto: make([]*thresholdCrypto, n),
	}

	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	if err != nil {
		panic(err)
	}

	// Fill pre-block with enough valid messages
	pre := utils.NewPreBlock(n)
	for i := 0; i < n; i++ {
		// Create a test message with a corresponding signature by node i
		message := []byte("test")
		messageHash := sha256.Sum256(message)
		messageHashPadded, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, messageHash[:])
		sig, _ := keyShares[i].Sign(messageHashPadded, crypto.SHA256, keyMeta)

		preMes := &utils.PreBlockMessage{
			Message: message,
			Sig:     sig,
		}
		pre.AddMessage(i, preMes)
	}

	var mu sync.Mutex
	multicast := func(msg *utils.Message, round int, params ...int) {
		go func() {
			var chans []chan *utils.Message
			mu.Lock()
			if gc.nodeChans[round] == nil {
				gc.nodeChans[round] = make([]chan *utils.Message, n)
				for i := 0; i < n; i++ {
					gc.nodeChans[round][i] = make(chan *utils.Message, 9999*n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, gc.nodeChans[round]...)
			mu.Unlock()
			if len(params) == 1 {
				chans[params[0]] <- msg
			} else {
				for i := 0; i < n; i++ {
					chans[i] <- msg
				}
			}
		}()
	}

	receive := func(id, round int) chan *utils.Message {
		mu.Lock()
		if gc.nodeChans[round] == nil {
			gc.nodeChans[round] = make([]chan *utils.Message, n)
			for i := 0; i < n; i++ {
				gc.nodeChans[round][i] = make(chan *utils.Message, 9999*n)
			}
		}
		ch := gc.nodeChans[round][id]
		mu.Unlock()
		return ch
	}


	// No valid signature for testing purposes
	h := pre.Hash()
	blockPointer := utils.NewBlockPointer(h[:], []byte{0})
	blockShare := utils.NewBlockShare(pre, blockPointer)

	// Set up individual graded consensus protocols
	for i := 0; i < n; i++ {
		vote := &Vote{
			Round:    0,
			BlockShare: blockShare,
			Commits:  nil,
		}
		gc.tickers[i] = make(chan int, n*n*n)
		gc.thresholdCrypto[i] = &thresholdCrypto{
			KeyShare: keyShares[i],
			KeyMeta:  keyMeta,
		}
		gc.gcs[i] = NewGradedConsensus(n, i, ts, round, gc.tickers[i], vote, gc.thresholdCrypto[i], leader, multicast, receive)
	}

	return gc
}

func TestGCEveryoneAgreesOnSameOutputInRoundOneWithGrade2(t *testing.T) {
	n := 4
	testGC := newTestGradedConsensusInstance(n, 1, 0)

	go tickr(testGC.tickers, 25*time.Millisecond, 10)
	for i := 0; i < testGC.n-testGC.ts; i++ {
		go testGC.gcs[i].run()
	}
	start := time.Now()

	for i := 0; i < testGC.n-testGC.ts; i++ {
		grade := testGC.gcs[i].GetValue()
		if grade.Grade != 2 {
			t.Errorf("Node %d got grade %d, expected %d", i, grade.Grade, 2)
		}
		if len(grade.Commits) < testGC.n-testGC.ts {
			t.Errorf("Set of commits is too small, got %d, expected %d", len(grade.Commits), 2)
		}
	}
	fmt.Println("Execution time:", time.Since(start))
}

func TestGCFailedRoundButStillTerminates(t *testing.T) {
	n := 4
	test := newTestGradedConsensusInstance(n, 1, 0)
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

// Note: this is not random at all
func leader(round, n int) int {
	return round % n
}