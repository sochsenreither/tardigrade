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
	nodeChans       map[int][]chan *utils.Message
	bas             []*BlockAgreement
	thresholdCrypto []*thresholdCrypto
	delta           int
	kappa           int
}

func newTestBlockAgreementInstanceWithSamePreBlock(n, ts, kappa int, delta int) *testBlockAgreementInstance {
	ba := &testBlockAgreementInstance{
		n:               n,
		ts:              ts,
		nodeChans:       make(map[int][]chan *utils.Message),
		bas:             make([]*BlockAgreement, n),
		thresholdCrypto: make([]*thresholdCrypto, n),
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

	var mu sync.Mutex
	multicast := func(id, round int, msg *utils.Message, params ...int) {
		go func() {
			var chans []chan *utils.Message
			mu.Lock()
			if ba.nodeChans[round] == nil {
				ba.nodeChans[round] = make([]chan *utils.Message, n)
				for i := 0; i < n; i++ {
					ba.nodeChans[round][i] = make(chan *utils.Message, 9999*n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, ba.nodeChans[round]...)
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
		if ba.nodeChans[round] == nil {
			ba.nodeChans[round] = make([]chan *utils.Message, n)
			for i := 0; i < n; i++ {
				ba.nodeChans[round][i] = make(chan *utils.Message, 9999*n)
			}
		}
		ch := ba.nodeChans[round][id]
		mu.Unlock()
		return ch
	}

	// Set up individual block agreement protocols
	for i := 0; i < n; i++ {
		ba.bas[i] = NewBlockAgreement(n, i, ts, ba.kappa, blockShare, keyShares[i], keyMeta, leader, ba.delta, multicast, receive)
	}

	return ba
}

func newTestBlockAgreementInstanceWithDifferentPreBlocks(n, ts, kappa int, delta int, inputs [][]byte) *testBlockAgreementInstance {
	if len(inputs) != n {
		panic("wrong number of inputs")
	}
	blockShares := make([]*utils.BlockShare, n)
	ba := &testBlockAgreementInstance{
		n:               n,
		ts:              ts,
		nodeChans:       make(map[int][]chan *utils.Message),
		bas:             make([]*BlockAgreement, n),
		thresholdCrypto: make([]*thresholdCrypto, n),
		delta:           delta,
		kappa:           kappa,
	}

	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	if err != nil {
		panic(err)
	}

	// Setup valid input
	for i := 0; i < n; i++ {
		pre := utils.NewPreBlock(n)
		messageHash := sha256.Sum256(inputs[i])
		messageHashPadded, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, messageHash[:])
		sig, _ := keyShares[i].Sign(messageHashPadded, crypto.SHA256, keyMeta)

		preMes := &utils.PreBlockMessage{
			Message: inputs[i],
			Sig:     sig,
		}
		pre.AddMessage(i, preMes)
		// Fill pre-block with messages such that it becomes at least n-t-quality
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			// Create a test message with a corresponding signature by node i
			message := []byte("test")
			messageHash := sha256.Sum256(message)
			messageHashPadded, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, messageHash[:])
			sig, _ := keyShares[j].Sign(messageHashPadded, crypto.SHA256, keyMeta)

			preMes := &utils.PreBlockMessage{
				Message: message,
				Sig:     sig,
			}
			pre.AddMessage(j, preMes)
		}
		h := pre.Hash()
		blockPointer := utils.NewBlockPointer(h[:], []byte{0})
		blockShare := utils.NewBlockShare(pre, blockPointer)
		blockShares[i] = blockShare
	}

	var mu sync.Mutex
	multicast := func(id, round int, msg *utils.Message, params ...int) {
		go func() {
			var chans []chan *utils.Message
			mu.Lock()
			if ba.nodeChans[round] == nil {
				ba.nodeChans[round] = make([]chan *utils.Message, n)
				for i := 0; i < n; i++ {
					ba.nodeChans[round][i] = make(chan *utils.Message, 9999*n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, ba.nodeChans[round]...)
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
		if ba.nodeChans[round] == nil {
			ba.nodeChans[round] = make([]chan *utils.Message, n)
			for i := 0; i < n; i++ {
				ba.nodeChans[round][i] = make(chan *utils.Message, 9999*n)
			}
		}
		ch := ba.nodeChans[round][id]
		mu.Unlock()
		return ch
	}

	// Set up individual block agreement protocols
	for i := 0; i < n; i++ {
		ba.bas[i] = NewBlockAgreement(n, i, ts, ba.kappa, nil, keyShares[i], keyMeta, leader, ba.delta, multicast, receive)
		ba.bas[i].SetInput(blockShares[i])
	}

	return ba
}

func TestBAEveryoneOutputsSameBlock(t *testing.T) {
	n := 3
	testBA := newTestBlockAgreementInstanceWithSamePreBlock(n, 0, 2, 20)

	helper := func() {
		var wg sync.WaitGroup
		for i := 0; i < testBA.n-testBA.ts; i++ {
			wg.Add(1)
			i := i
			go func() {
				defer wg.Done()
				testBA.bas[i].Run()
			}()
		}
		wg.Wait()
	}

	start := time.Now()
	helper()
	fmt.Println("Execution time:", time.Since(start))

	var prevHash [32]byte

	for i := 0; i < testBA.n-testBA.ts; i++ {
		val := testBA.bas[i].GetValue()
		if i > 0 {
			if val.Hash() != prevHash {
				t.Errorf("Received differing values")
			}
		}
		prevHash = val.Hash()
	}
}

func TestBAEveryoneOutputsSameBlockWithDifferentInput(t *testing.T) {
	n := 3
	inputs := [][]byte{[]byte("0"), []byte("1"), []byte("2")}
	testBA := newTestBlockAgreementInstanceWithDifferentPreBlocks(n, 0, 2, 20, inputs)

	helper := func() {
		var wg sync.WaitGroup
		for i := 0; i < testBA.n-testBA.ts; i++ {
			wg.Add(1)
			i := i
			go func() {
				defer wg.Done()
				testBA.bas[i].Run()
			}()
		}
		wg.Wait()
	}

	start := time.Now()
	helper()
	fmt.Println("Execution time:", time.Since(start))

	var prevHash [32]byte

	for i := 0; i < testBA.n-testBA.ts; i++ {
		val := testBA.bas[i].GetValue()
		if i > 0 {
			if val.Hash() != prevHash {
				t.Errorf("Received differing values")
			}
		}
		prevHash = val.Hash()
	}
}

// func printBlock(pre *utils.PreBlock) {
// 	for i,m := range pre.Vec {
// 		fmt.Printf("Index: %d, Message: %s\n", i, m.Message)
// 	}
// }

func baTicker(chans []chan int, interval time.Duration, maxTicks int, killchan chan struct{}) {
	ticker := time.NewTicker(interval)
	counter := 1

	for {
		select {
		case <-ticker.C:
			log.Println("Tick:", counter)
			for _, c := range chans {
				c <- counter % 6
			}
			counter++

			if counter == maxTicks {
				log.Println("Ticker terminating")
				return
			}
		case <-killchan:
			log.Println("Ticker terminating")
			return
		}
	}
}
