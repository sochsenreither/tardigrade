package commonsubset

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
	aba "github.com/sochsenreither/upgrade/binaryagreement"
	rbc "github.com/sochsenreither/upgrade/broadcast"
)

func TestACSSameValue(t *testing.T) {
	n := 4
	ta := 0
	var wg sync.WaitGroup
	var mu sync.Mutex

	keyShares, keyMeta, coin := setupKeys(n)
	committee := make(map[int]bool)
	committee[0] = true
	committee[1] = true
	committee[2] = true

	// Setup pre-block with four messages "zero" and a corresponding block-share.
	preBlock := utils.NewPreBlock(n)
	for i := 0; i < n; i++ {
		mes, _ := utils.NewPreBlockMessage([]byte("zero"), keyShares[i], keyMeta)
		preBlock.AddMessage(i, mes)
	}
	preBlockHash := preBlock.Hash()
	// for now the signature isn't relevant, since this gets checked in the main protocol
	blockPointer := utils.NewBlockPointer(preBlockHash[:], []byte{0})
	blockShare := utils.NewBlockShare(preBlock, blockPointer)

	abas := setupAba(n, ta, keyShares, keyMeta, coin, &mu)
	rbcs := setupRbc(n, ta, keyShares, keyMeta, coin, &mu, []*utils.BlockShare{blockShare,blockShare,blockShare,blockShare}, committee)

	outs := make(map[int]chan []*utils.BlockShare)
	nodeChans := make(map[int][]chan *utils.Message) // round -> chans
	acs := make(map[int]*CommonSubset)

	multicast := func(id, round int, msg *utils.Message) {
		go func() {
			var chans []chan *utils.Message
			mu.Lock()
			if nodeChans[round] == nil {
				nodeChans[round] = make([]chan *utils.Message, n)
				for i := 0; i < n; i++ {
					nodeChans[round][i] = make(chan *utils.Message, 9999*n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, nodeChans[round]...)
			mu.Unlock()
			for i := 0; i < n; i++ {
				chans[i] <- msg
			}
		}()
	}

	receive := func(id, round int) *utils.Message {
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make([]chan *utils.Message, n)
			for i := 0; i < n; i++ {
				nodeChans[round][i] = make(chan *utils.Message, 9999*n)
			}
		}
		ch := nodeChans[round][id]
		mu.Unlock()
		val := <-ch
		return val
	}

	for i := 0; i < n; i++ {
		tc := &ThresholdCrypto{
			Sk: keyShares[i],
			KeyMeta:  keyMeta,
			SigShare: rbcs[i][0].Sig.SigShare,
		}
		cfg := &ACSConfig{
			N:       n,
			NodeId:  i,
			T:       ta,
			Kappa:   1,
			Epsilon: 0,
			Round:   0,
		}
		outs[i] = make(chan []*utils.BlockShare, 100)
		acs[i] = NewACS(cfg, committee, blockShare, outs[i], rbcs[i], abas[i], tc, multicast, receive)
	}

	start := time.Now()
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			acs[i].Run()
		}()
	}
	wg.Wait()
	fmt.Println("Execution time:", time.Since(start))
	var returnHash [32]byte

	for i := 0; i < n; i++ {
		got := acs[i].getValue()
		if len(got) != 1 {
			t.Errorf("Expected only one return value, got %d", len(got))
		}
		for _, v := range got[0].Block.Vec {
			if !bytes.Equal(v.Message, []byte("zero")) {
				t.Errorf("pre-block contains an unwanted value")
			}
		}
		if i == 0 {
			returnHash = got[0].Hash()
		}
		if got[0].Hash() != returnHash {
			t.Errorf("Got different block-shares")
		}
	}
}

func TestACSDifferentValues(t *testing.T) {
	n := 4
	ta := 0
	var wg sync.WaitGroup
	var mu sync.Mutex

	keyShares, keyMeta, coin := setupKeys(n)
	committee := make(map[int]bool)
	committee[0] = true
	committee[1] = true
	committee[2] = true
	inputs := [4][]byte{[]byte("zero"), []byte("one"), []byte("two"), []byte("three")}
	var blockShares []*utils.BlockShare
	for i := 0; i < n; i++ {
		blockShares = append(blockShares, setupBlockShare(n, i, inputs[i], keyShares[i], keyMeta))
	}

	abas := setupAba(n, ta, keyShares, keyMeta, coin, &mu)
	rbcs := setupRbc(n, ta, keyShares, keyMeta, coin, &mu, blockShares, committee)

	outs := make(map[int]chan []*utils.BlockShare)
	nodeChans := make(map[int][]chan *utils.Message) // round -> chans
	acs := make(map[int]*CommonSubset)

	multicast := func(id, round int, msg *utils.Message) {
		go func() {
			var chans []chan *utils.Message
			mu.Lock()
			if nodeChans[round] == nil {
				nodeChans[round] = make([]chan *utils.Message, n)
				for i := 0; i < n; i++ {
					nodeChans[round][i] = make(chan *utils.Message, 9999*n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, nodeChans[round]...)
			mu.Unlock()
			for i := 0; i < n; i++ {
				chans[i] <- msg
			}
		}()
	}

	receive := func(id, round int) *utils.Message {
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make([]chan *utils.Message, n)
			for i := 0; i < n; i++ {
				nodeChans[round][i] = make(chan *utils.Message, 9999*n)
			}
		}
		ch := nodeChans[round][id]
		mu.Unlock()
		val := <-ch
		return val
	}

	for i := 0; i < n; i++ {
		tc := &ThresholdCrypto{
			Sk: keyShares[i],
			KeyMeta: keyMeta,
			SigShare: rbcs[i][0].Sig.SigShare,
		}
		cfg := &ACSConfig{
				N:        n,
				NodeId:   i,
				T:        ta,
				Kappa:    1,
				Epsilon:  0,
				Round:    0,
			}
		outs[i] = make(chan []*utils.BlockShare, 100)
		acs[i] = NewACS(cfg, committee, blockShares[i], outs[i], rbcs[i], abas[i], tc, multicast, receive)
	}

	start := time.Now()
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			acs[i].Run()
		}()
	}
	wg.Wait()
	fmt.Println("Execution time:", time.Since(start))

	for i := 0; i < n; i++ {
		got := acs[i].getValue()
		if len(got) != len(blockShares) {
			t.Errorf("Got output that doesn't match input")
		}
		for i := 0; i < len(got); i++ {
			if !bytes.Equal(got[i].Block.Vec[i].Message, inputs[i]) {
				t.Errorf("Got output that doesn't match input")
			}
		}
	}
}

func setupAba(n, ta int, keyShares tcrsa.KeyShareList, keyMeta *tcrsa.KeyMeta, coin *aba.CommonCoin, mu *sync.Mutex) map[int][]*aba.BinaryAgreement {
	abas := make(map[int][]*aba.BinaryAgreement)
	nodeChans := make(map[int]map[int][]chan *aba.AbaMessage) // round -> instance -> chans
	outs := make(map[int][]chan int)

	multicast := func(id, instance, round int, msg *aba.AbaMessage) {
		go func() {
			var chans []chan *aba.AbaMessage
			mu.Lock()
			if nodeChans[round] == nil {
				nodeChans[round] = make(map[int][]chan *aba.AbaMessage)
			}
			if len(nodeChans[round][instance]) != n {
				nodeChans[round][instance] = make([]chan *aba.AbaMessage, n)
				for i := 0; i < n; i++ {
					nodeChans[round][instance][i] = make(chan *aba.AbaMessage, 99*n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, nodeChans[round][instance]...)
			mu.Unlock()
			for i := 0; i < len(chans); i++ {
				chans[i] <- msg
			}
		}()
	}
	receive := func(id, instance, round int) *aba.AbaMessage {
		// If channels for round or instance don't exist create them first
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make(map[int][]chan *aba.AbaMessage)
		}
		if len(nodeChans[round][instance]) != n {
			nodeChans[round][instance] = make([]chan *aba.AbaMessage, n)
			for k := 0; k < n; k++ {
				nodeChans[round][instance][k] = make(chan *aba.AbaMessage, 99*n)
			}
		}
		// Set receive channel to separate variable in order to prevent data/lock races
		ch := nodeChans[round][instance][id]
		mu.Unlock()
		val := <-ch
		return val
	}

	for i := 0; i < n; i++ {
		i := i
		thresholdCrypto := &aba.ThresholdCrypto{
			KeyShare: keyShares[i],
			KeyMeta:  keyMeta,
		}
		outs[i] = make([]chan int, n)
		for j := 0; j < n; j++ {
			outs[i][j] = make(chan int, 100)
			abas[i] = append(abas[i], aba.NewBinaryAgreement(n, i, ta, 0, j, coin, thresholdCrypto, multicast, receive, outs[i][j]))
		}
	}

	return abas
}

func setupRbc(n, ta int, keyShares tcrsa.KeyShareList, keyMeta *tcrsa.KeyMeta, coin *aba.CommonCoin, mu *sync.Mutex, inputs []*utils.BlockShare, committee map[int]bool) map[int][]*rbc.ReliableBroadcast {
	nodeChans := make(map[int]map[int][]chan *utils.Message) // maps round -> instance -> chans
	broadcasts := make(map[int][]*rbc.ReliableBroadcast)
	outs := make(map[int][]chan *utils.BlockShare)

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
			case *rbc.SMessage:
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
		signature := &rbc.Signature{
			SigShare: sig,
			KeyMeta:  keyMeta,
		}
		outs[i] = make([]chan *utils.BlockShare, n)
		for j := 0; j < n; j++ {
			config := &rbc.ReliableBroadcastConfig{
				N:        n,
				NodeId:   i,
				T:        ta,
				Kappa:    1,
				Epsilon:  0,
				SenderId: j,
				Round:    0,
			}
			outs[i][j] = make(chan *utils.BlockShare, 100)
			broadcasts[i] = append(broadcasts[i], rbc.NewReliableBroadcast(config, committee, outs[i][j], signature, multicast, receive))
			if i == j {
				broadcasts[i][j].SetValue(inputs[j])
			}
		}
	}

	return broadcasts
}

func setupKeys(n int) (tcrsa.KeyShareList, *tcrsa.KeyMeta, *aba.CommonCoin) {
	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	if err != nil {
		panic(err)
	}
	requestChannel := make(chan *aba.CoinRequest, 99999)
	commonCoin := aba.NewCommonCoin(n, keyMeta, requestChannel)
	go commonCoin.Run()

	return keyShares, keyMeta, commonCoin
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
