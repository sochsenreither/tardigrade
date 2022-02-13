package blockagreement

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"fmt"

	//"io/ioutil"
	"log"
	//"os"
	"sync"
	"testing"
	"time"

	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/upgrade/utils"
)

// TODO:
// - invalid proposal from leader
// - round > 0

// func TestMain(m *testing.M) {
// 	log.SetOutput(ioutil.Discard)
// 	os.Exit(m.Run())
// }

type testProposeInstance struct {
	n               int
	ts              int
	proposer        int
	round           int
	nodeChans       []chan *utils.Message
	tickers         []chan int
	outs            []chan *utils.BlockShare
	ps              []*proposeProtocol
	kills           []chan struct{}
	thresholdCrypto []*thresholdCrypto
}

func newTestProposeInstance(n, ts, proposer, round int) *testProposeInstance {
	prop := &testProposeInstance{
		n:               n,
		ts:              ts,
		proposer:        proposer,
		round:           round,
		nodeChans:       make([]chan *utils.Message, n),
		tickers:         make([]chan int, n),
		outs:            make([]chan *utils.BlockShare, n),
		ps:              make([]*proposeProtocol, n),
		kills:           make([]chan struct{}, n),
		thresholdCrypto: make([]*thresholdCrypto, n),
	}

	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	if err != nil {
		panic(err)
	}

	// Fill pre-block with enough valid messages
	pre := utils.NewPreBlock(n)
	for i := 0; i < n; i++ {
		// Create a test Message with a corresponding signature by node i
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

	// Set up individual propose protocols
	for i := 0; i < n; i++ {
		vote := &vote{
			round:       0,
			blockShare:    blockShare,
			commits: nil,
		}
		prop.nodeChans[i] = make(chan *utils.Message, n*n)
		prop.tickers[i] = make(chan int, n*n)
		prop.outs[i] = make(chan *utils.BlockShare, n)
		prop.kills[i] = make(chan struct{}, n)
		prop.thresholdCrypto[i] = &thresholdCrypto{
			keyShare: keyShares[i],
			keyMeta:  keyMeta,
		}
		prop.ps[i] = NewProposeProtocol(n, i, ts, proposer, round, prop.nodeChans, prop.tickers[i], vote, prop.outs[i], prop.kills[i], prop.thresholdCrypto[i])
	}

	return prop
}

func TestPropEveryoneAgreesOnSameOutputInRoundOne(t *testing.T) {
	test := newTestProposeInstance(3, 1, 0, 0)

	for i := 0; i < test.n-test.ts; i++ {
		go test.ps[i].run()
	}

	start := time.Now()
	go tickr(test.tickers, 25*time.Millisecond, 4)

	for i := 0; i < test.n-test.ts; i++ {
		val := <-test.outs[i]
		if val == nil {
			t.Fatalf("Expected something")
		}
		if val.Block == nil {
			t.Fatalf("Received nil as output")
		}
		for _, m := range val.Block.Vec {
			if m == nil || m.Message == nil{
				t.Errorf("Block doesn't have messages")
			}
			if !bytes.Equal(m.Message, []byte("test")) {
				t.Errorf("Got %s, expected %s", m.Message, []byte("test"))
			}
		}
	}

	fmt.Println("Execution time:", time.Since(start))
}

func TestPropFailedRunButStillTerminates(t *testing.T) {
	test := newTestProposeInstance(10, 4, 0, 0)
	timeout := time.After(200 * time.Millisecond)
	done := make(chan struct{})

	helper := func() {
		var wg sync.WaitGroup
		// Start protocol for only 5 honest nodes
		for i := 0; i < test.n-test.ts-1; i++ {
			wg.Add(1)
			i := i
			go func() {
				defer wg.Done()
				test.ps[i].run()
			}()
		}
		start := time.Now()
		go tickr(test.tickers, 25*time.Millisecond, 4)
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

func tickr(chans []chan int, interval time.Duration, maxTicks int) {
	ticker := time.NewTicker(interval)
	counter := 1

	for range ticker.C {
		log.Println("Tick:", counter)
		for _, c := range chans {
			c <- counter
		}

		counter++
		if counter == maxTicks {
			log.Println("Ticker terminating")
			return
		}
	}
}
