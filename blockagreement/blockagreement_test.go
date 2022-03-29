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

type testBlockAgreementInstance struct {
	n               int
	ts              int
	nodeChans       map[int]chan *utils.HandlerMessage
	bas             []*BlockAgreement
	thresholdCrypto []*thresholdCrypto
	delta           int
	kappa           int
}

func newTestBlockAgreementInstanceWithSamePreBlock(n, ts, kappa int, delta int) *testBlockAgreementInstance {
	ba := &testBlockAgreementInstance{
		n:               n,
		ts:              ts,
		nodeChans:       make(map[int]chan *utils.HandlerMessage),
		bas:             make([]*BlockAgreement, n),
		thresholdCrypto: make([]*thresholdCrypto, n),
		delta:           delta,
		kappa:           kappa,
	}

	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	if err != nil {
		panic(err)
	}

	var handlers []*utils.LocalHandler
	for i := 0; i < n; i++ {
		ba.nodeChans[i] = make(chan *utils.HandlerMessage, 99999)
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

	h := pre.Hash()
	blockPointer := utils.NewBlockPointer(h[:], []byte{0})
	blockShare := utils.NewBlockShare(pre, blockPointer)

	// Set up individual block agreement protocols
	for i := 0; i < n; i++ {
		// Create new handler
		handlers = append(handlers, utils.NewLocalHandler(ba.nodeChans, nil, i, n, kappa))
		ba.bas[i] = NewBlockAgreement(0, n, i, ts, ba.kappa, blockShare, keyShares[i], keyMeta, leader, ba.delta, handlers[i].Funcs)
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
		nodeChans:       make(map[int]chan *utils.HandlerMessage),
		bas:             make([]*BlockAgreement, n),
		thresholdCrypto: make([]*thresholdCrypto, n),
		delta:           delta,
		kappa:           kappa,
	}

	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	if err != nil {
		panic(err)
	}

	var handlers []*utils.LocalHandler
	for i := 0; i < n; i++ {
		ba.nodeChans[i] = make(chan *utils.HandlerMessage, 99999)
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

	// Set up individual block agreement protocols
	for i := 0; i < n; i++ {
		// Create new handler
		handlers = append(handlers, utils.NewLocalHandler(ba.nodeChans, nil, i, n, kappa))
		ba.bas[i] = NewBlockAgreement(0, n, i, ts, ba.kappa, nil, keyShares[i], keyMeta, leader, ba.delta, handlers[i].Funcs)
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

func leader(round, n int) int {
	return round % n
}