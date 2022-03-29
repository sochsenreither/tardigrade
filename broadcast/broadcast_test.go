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
	"github.com/sochsenreither/upgrade/utils"
)

func setupKeys(n int) (tcrsa.KeyShareList, *tcrsa.KeyMeta) {
	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	if err != nil {
		panic(err)
	}
	return keyShares, keyMeta
}

func setupBlockShare(n, i int, mes []byte, keyShare *tcrsa.KeyShare, keyMeta *tcrsa.KeyMeta) *utils.BlockShare {
	preBlock := utils.NewPreBlock(n)
	preBlocKMessage, _ := utils.NewPreBlockMessage(mes, keyShare, keyMeta)
	preBlock.AddMessage(i, preBlocKMessage)
	preBlockHash := preBlock.Hash()
	// for now the signature isn't relevant, since this gets checked in the main protocol
	blockPointer := utils.NewBlockPointer(preBlockHash[:], []byte{0})
	blockShare := utils.NewBlockShare(preBlock, blockPointer)
	return blockShare
}

func TestBroadcastParallelMultipleSendersOneRound(t *testing.T) {
	// Scenario: Four honest nodes, one byzantine. Every node has a different initial input value.
	// Every node runs four instances of broadcast, one instance as sender. Every broadcast run in
	// one instance should output the same value. (The last instance doesn't output anything, since
	// the sender is byzantine. The test should still terminate and every other instance should be
	// correct)
	n := 4
	ta := 2
	kappa := 1
	var wg sync.WaitGroup
	nodeChans := make(map[int]chan *utils.HandlerMessage)
	var handlers []*utils.LocalHandler
	for i := 0; i < n; i++ {
		nodeChans[i] = make(chan *utils.HandlerMessage, 9999)
	}

	inputs := [4][]byte{[]byte("zero"), []byte("one"), []byte("two"), []byte("three")}
	broadcasts := make(map[int][]*ReliableBroadcast)
	keyShares, keyMeta := setupKeys(n + 1)
	committee := make(map[int]bool)
	committee[0] = true
	committee[1] = true
	var blockShares []*utils.BlockShare
	for i := 0; i < n; i++ {
		blockShares = append(blockShares, setupBlockShare(n, i, inputs[i], keyShares[i], keyMeta))
	}



	for i := 0; i < n-ta; i++ {
		// Dealer signs node id
		hash := sha256.Sum256([]byte(strconv.Itoa(i)))
		paddedHash, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
		sig, _ := keyShares[len(keyShares)-1].Sign(paddedHash, crypto.SHA256, keyMeta)
		signature := &Signature{
			Proof: sig,
			KeyMeta:  keyMeta,
		}

		// Create new handler
		handlers = append(handlers, utils.NewLocalHandler(nodeChans, nil, i, n, kappa))

		for j := 0; j < n; j++ {
			config := &ReliableBroadcastConfig{
				N:        n,
				NodeId:   i,
				T:        ta,
				Kappa:    1,
				Epsilon:  0,
				SenderId: j,
				Instance: j,
			}
			broadcasts[i] = append(broadcasts[i], NewReliableBroadcast(config, committee, signature, handlers[i].Funcs))
			if i == j {
				broadcasts[i][j].SetValue(blockShares[j])
			}
		}
	}
	start := time.Now()
	wg.Add((n - ta) * (n - ta))
	for i := 0; i < n-ta; i++ {
		i := i
		for j := 0; j < n; j++ {
			j := j
			go func() {
				defer wg.Done()
				broadcasts[i][j].Run()
			}()
		}
	}
	wg.Wait()
	fmt.Println("Execution time:", time.Since(start))

	for i := 0; i < n-ta; i++ {
		for j := 0; j < n-ta; j++ {
			val := broadcasts[i][j].GetValue()
			if !bytes.Equal(val.Block.Vec[j].Message, inputs[broadcasts[i][j].senderId]) {
				t.Errorf("Expected %q, got %q", inputs[broadcasts[i][j].senderId], val.Block.Vec[j].Message)
			}
		}
	}
}
