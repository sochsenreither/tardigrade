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

func TestBroadcastOneInstanceWithByzantineNode(t *testing.T) {
	n := 4
	ta := 1
	var wg sync.WaitGroup

	committee := make(map[int]bool)
	nodeChans := make(map[int]chan *utils.Message) // maps node -> message channel
	broadcasts := make([]*ReliableBroadcast, n)
	keyShares, keyMeta := setupKeys(n + 1)

	committee[0] = true
	committee[1] = true

	multicast := func(id, instance, round int, msg *utils.Message) {
		go func() {
			switch msg.Payload.(type) {
			case *SMessage:
				for k, node := range nodeChans {
					if committee[k] {
						node <- msg
					}
				}
			default:
				for _, node := range nodeChans {
					node <- msg
				}
			}
		}()
	}
	receive := func(id, instance, round int) *utils.Message {
		val := <-nodeChans[id]
		return val
	}

	for i := 0; i < n-ta; i++ {
		// Dealer signs node id
		hash := sha256.Sum256([]byte(strconv.Itoa(i)))
		paddedHash, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
		sig, _ := keyShares[len(keyShares)-1].Sign(paddedHash, crypto.SHA256, keyMeta)
		signature := &Signature{
			SigShare:     sig,
			KeyMeta: keyMeta,
		}
		config := &ReliableBroadcastConfig{
			N:        n,
			NodeId:   i,
			T:        ta,
			Kappa:    1,
			Epsilon:  0,
			SenderId: 0,
			Round:    0,
		}
		nodeChans[i] = make(chan *utils.Message, 999)
		broadcasts[i] = NewReliableBroadcast(config, committee, signature, multicast, receive)
	}
	// create message with signature of node 0.
	mes := []byte("foo")
	blockShare := setupBlockShare(n, 0, mes, keyShares[0], keyMeta)
	broadcasts[0].SetValue(blockShare)

	start := time.Now()
	wg.Add(n - ta)
	for i := 0; i < n-ta; i++ {
		i := i
		go func() {
			defer wg.Done()
			broadcasts[i].Run()
		}()
	}
	wg.Wait()
	fmt.Println("Execution time:", time.Since(start))

	for i := 0; i < n-ta; i++ {
		val := broadcasts[i].GetValue()
		if !bytes.Equal(val.Block.Vec[0].Message, mes) {
			t.Errorf("Expected %s, got %s from node %d", string(mes), string(val.Block.Vec[0].Message), i)
		}
	}
}

func TestBroadcastParallelMultipleSendersOneRound(t *testing.T) {
	// Scenario: Four honest nodes, one byzantine. Every node has a different initial input value.
	// Every node runs four instances of broadcast, one instance as sender. Every broadcast run in
	// one instance should output the same value. (The last instance doesn't output anything, since
	// the sender is byzantine. The test should still terminate and every other instance should be
	// correct)
	n := 4
	ta := 1
	var wg sync.WaitGroup
	var mu sync.Mutex
	inputs := [4][]byte{[]byte("zero"), []byte("one"), []byte("two"), []byte("three")}
	nodeChans := make(map[int]map[int][]chan *utils.Message) // maps round -> instance -> chans
	broadcasts := make(map[int][]*ReliableBroadcast)
	keyShares, keyMeta := setupKeys(n + 1)
	committee := make(map[int]bool)
	committee[0] = true
	committee[1] = true
	var blockShares []*utils.BlockShare
	for i := 0; i < n; i++ {
		blockShares = append(blockShares, setupBlockShare(n, i, inputs[i], keyShares[i], keyMeta))
	}


	multicast := func(id, instance, round int, msg *utils.Message) {
		go func() {
			var chans []chan *utils.Message
			// If channels for round or instance don't exist create them first
			mu.Lock()
			if nodeChans[round] == nil {
				nodeChans[round] = make(map[int][]chan *utils.Message)
			}
			if len(nodeChans[round][instance]) != n {
				nodeChans[round][instance] = make([]chan *utils.Message, n)
				for i := 0; i < n; i++ {
					nodeChans[round][instance][i] = make(chan *utils.Message, 999*n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, nodeChans[round][instance]...)
			mu.Unlock()

			switch msg.Payload.(type) {
			case *SMessage:
				for i, ch := range chans {
					if committee[i] {
						ch <- msg
					}
				}
			default:
				for _, ch := range chans {
					ch <- msg
				}
			}
		}()
	}
	receive := func(id, instance, round int) *utils.Message {
		// If channels for round or instance don't exist create them first
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make(map[int][]chan *utils.Message)
		}
		if len(nodeChans[round][instance]) != n {
			nodeChans[round][instance] = make([]chan *utils.Message, n)
			for k := 0; k < n; k++ {
				nodeChans[round][instance][k] = make(chan *utils.Message, 999*n)
			}
		}
		// Set receive channel to separate variable in order to prevent data/lock races
		ch := nodeChans[round][instance][id]
		mu.Unlock()
		val := <-ch
		return val
	}

	for i := 0; i < n-ta; i++ {
		// Dealer signs node id
		hash := sha256.Sum256([]byte(strconv.Itoa(i)))
		paddedHash, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
		sig, _ := keyShares[len(keyShares)-1].Sign(paddedHash, crypto.SHA256, keyMeta)
		signature := &Signature{
			SigShare:     sig,
			KeyMeta: keyMeta,
		}
		for j := 0; j < n; j++ {
			config := &ReliableBroadcastConfig{
				N:        n,
				NodeId:   i,
				T:        ta,
				Kappa:    1,
				Epsilon:  0,
				SenderId: j,
				Round:    0,
			}
			broadcasts[i] = append(broadcasts[i], NewReliableBroadcast(config, committee, signature, multicast, receive))
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
