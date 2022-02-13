package blockagreement

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/upgrade/utils"
)

type testBlockAgreementInstance struct {
	n               int
	ts              int
	nodeChans       []chan *utils.Message
	outs            []chan *utils.BlockShare
	bas             []*BlockAgreement
	thresholdCrypto []*thresholdCrypto
	leaderChan      chan *leaderRequest
	delta           time.Duration
	kappa           int
	tickers         []chan int
}

func newTestBlockAgreementInstanceWithSamePreBlock(n, ts, kappa int, delta time.Duration) *testBlockAgreementInstance {
	ba := &testBlockAgreementInstance{
		n:               n,
		ts:              ts,
		nodeChans:       make([]chan *utils.Message, n),
		outs:            make([]chan *utils.BlockShare, n),
		bas:             make([]*BlockAgreement, n),
		thresholdCrypto: make([]*thresholdCrypto, n),
		leaderChan:      make(chan *leaderRequest),
		tickers:         make([]chan int, n),
		delta:           delta,
		kappa:           kappa,
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
	// TODO: change to real sig
	h := pre.Hash()
	blockPointer := utils.NewBlockPointer(h[:], []byte{0})
	blockShare := utils.NewBlockShare(pre, blockPointer)

	// Set up individual block agreement protocols
	for i := 0; i < n; i++ {
		ba.nodeChans[i] = make(chan *utils.Message, n*ba.kappa*n)
		ba.outs[i] = make(chan *utils.BlockShare, n*ba.kappa)
		ba.thresholdCrypto[i] = &thresholdCrypto{
			keyShare: keyShares[i],
			keyMeta:  keyMeta,
		}
		ba.tickers[i] = make(chan int, ba.kappa*ba.kappa*7)
		ba.bas[i] = NewBlockAgreement(n, i, ts, ba.kappa, ba.nodeChans, blockShare, ba.thresholdCrypto[i], ba.leaderChan, ba.outs[i], ba.delta, ba.tickers[i])
	}

	return ba
}

func TestBAEveryoneOutputsSameBlock(t *testing.T) {
	testBA := newTestBlockAgreementInstanceWithSamePreBlock(3, 1, 2, 20*time.Millisecond)

	helper := func() {
		var wg sync.WaitGroup
		for i := 0; i < testBA.n-testBA.ts; i++ {
			wg.Add(1)
			i := i
			go func() {
				defer wg.Done()
				testBA.bas[i].run()
			}()
		}
		go testLeader(testBA.leaderChan)
		go baTicker(testBA.tickers, testBA.delta, 7*testBA.kappa)
		wg.Wait()
	}

	start := time.Now()
	helper()
	fmt.Println("Execution time:", time.Since(start))

	for i := 0; i < testBA.n-testBA.ts; i++ {
		if len(testBA.outs[i]) != testBA.kappa {
			t.Errorf("Expected %d outputs, got %d from node %d", 3, len(testBA.outs[i]), i)
		}
	}
}

func baTicker(chans []chan int, interval time.Duration, maxTicks int) {
	ticker := time.NewTicker(interval)
	counter := 1

	for range ticker.C {
		log.Println("Tick:", counter)
		for _, c := range chans {
			c <- counter % 6
		}
		counter++

		if counter == maxTicks {
			log.Println("Ticker terminating")
			return
		}
	}
}
