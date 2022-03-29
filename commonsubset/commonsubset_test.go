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
	aba "github.com/sochsenreither/upgrade/binaryagreement"
	rbc "github.com/sochsenreither/upgrade/broadcast"
	"github.com/sochsenreither/upgrade/utils"
)

func TestACSSameValue(t *testing.T) {
	n := 3
	ta := 0
	kappa := 1
	var wg sync.WaitGroup

	committee := make(map[int]bool)
	committee[0] = true
	committee[1] = true
	keyShares, keyMeta, coin, keySharesC, keyMetaC := setupKeys(n, committee)
	input := []byte("zero")
	var blockShares []*utils.BlockShare
	for i := 0; i < n-ta; i++ {
		blockShares = append(blockShares, setupBlockShare(n, i, input, keyShares[0], keyMeta))
	}

	nodeChans := make(map[int]chan *utils.HandlerMessage)
	var handlers []*utils.LocalHandler
	for i := 0; i < n; i++ {
		nodeChans[i] = make(chan *utils.HandlerMessage, 99)
	}
	for i := 0; i < n; i++ {
		handlers = append(handlers, utils.NewLocalHandler(nodeChans, coin.RequestChan, i, n, kappa))
	}

	abas := setupAba(n, ta, keyShares, keyMeta, coin, handlers)
	rbcs := setupRbc(n, ta, keyShares, keyMeta, coin, blockShares, committee, handlers)

	acs := make(map[int]*CommonSubset)

	for i := 0; i < n-ta; i++ {
		tc := &ThresholdCrypto{
			Sk:       keyShares[i],
			KeyMeta:  keyMeta,
			Proof: rbcs[i][0].Sig.Proof,
			KeyMetaC: keyMetaC,
		}
		if committee[i] {
			tc.SkC = keySharesC[i]
		}
		cfg := &ACSConfig{
			N:       n,
			NodeId:  i,
			T:       ta,
			Kappa:   1,
			Epsilon: 0,
			UROUND:  0,
		}
		acs[i] = NewACS(cfg, committee, blockShares[i], rbcs[i], abas[i], tc, handlers[i].Funcs)
	}

	start := time.Now()
	wg.Add(n - ta)
	for i := 0; i < n-ta; i++ {
		i := i
		go func() {
			defer wg.Done()
			acs[i].Run()
		}()
	}
	wg.Wait()
	fmt.Println("Execution time:", time.Since(start))

	for i := 0; i < n-ta; i++ {
		got := acs[i].GetValue()
		if len(got) != 1 {
			t.Errorf("Got output that doesn't match input. Expected %d, got %d", len(blockShares), len(got))
		}
	}
}

func TestACSDifferentValues(t *testing.T) {
	n := 3
	ta := 0
	kappa := 1
	var wg sync.WaitGroup

	committee := make(map[int]bool)
	committee[0] = true
	committee[1] = true
	keyShares, keyMeta, coin, keySharesC, keyMetaC := setupKeys(n, committee)
	inputs := [7][]byte{[]byte("zero"), []byte("one"), []byte("two"), []byte("three"), []byte("four"), []byte("five"), []byte("six")}
	var blockShares []*utils.BlockShare
	for i := 0; i < n; i++ {
		blockShares = append(blockShares, setupBlockShare(n, i, inputs[i], keyShares[i], keyMeta))
	}

	nodeChans := make(map[int]chan *utils.HandlerMessage)
	var handlers []*utils.LocalHandler
	for i := 0; i < n; i++ {
		nodeChans[i] = make(chan *utils.HandlerMessage, 99999)
	}
	for i := 0; i < n; i++ {
		handlers = append(handlers, utils.NewLocalHandler(nodeChans, coin.RequestChan, i, n, kappa))
	}

	abas := setupAba(n, ta, keyShares, keyMeta, coin, handlers)
	rbcs := setupRbc(n, ta, keyShares, keyMeta, coin, blockShares, committee, handlers)

	acs := make(map[int]*CommonSubset)

	for i := 0; i < n; i++ {
		tc := &ThresholdCrypto{
			Sk:       keyShares[i],
			KeyMeta:  keyMeta,
			Proof: rbcs[i][0].Sig.Proof,
			KeyMetaC: keyMetaC,
		}
		if committee[i] {
			tc.SkC = keySharesC[i]
		}
		cfg := &ACSConfig{
			N:       n,
			NodeId:  i,
			T:       ta,
			Kappa:   1,
			Epsilon: 0,
			UROUND:  0,
		}
		acs[i] = NewACS(cfg, committee, blockShares[i], rbcs[i], abas[i], tc, handlers[i].Funcs)
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
		got := acs[i].GetValue()
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

func setupAba(n, ta int, keyShares tcrsa.KeyShareList, keyMeta *tcrsa.KeyMeta, coin *aba.CommonCoin, handlers []*utils.LocalHandler) map[int][]*aba.BinaryAgreement {
	abas := make(map[int][]*aba.BinaryAgreement)

	for i := 0; i < n; i++ {
		i := i
		thresholdCrypto := &aba.ThresholdCrypto{
			KeyShare: keyShares[i],
			KeyMeta:  keyMeta,
		}
		for j := 0; j < n; j++ {
			abas[i] = append(abas[i], aba.NewBinaryAgreement(0, n, i, ta, 0, j, thresholdCrypto, handlers[i].Funcs))
		}
	}

	return abas
}

func setupRbc(n, ta int, keyShares tcrsa.KeyShareList, keyMeta *tcrsa.KeyMeta, coin *aba.CommonCoin, inputs []*utils.BlockShare, committee map[int]bool, handlers []*utils.LocalHandler) map[int][]*rbc.ReliableBroadcast {
	broadcasts := make(map[int][]*rbc.ReliableBroadcast)

	for i := 0; i < n-ta; i++ {
		// Dealer signs node id
		hash := sha256.Sum256([]byte(strconv.Itoa(i)))
		paddedHash, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
		sig, _ := keyShares[len(keyShares)-1].Sign(paddedHash, crypto.SHA256, keyMeta)
		signature := &rbc.Signature{
			Proof: sig,
			KeyMeta:  keyMeta,
		}
		for j := 0; j < n; j++ {
			config := &rbc.ReliableBroadcastConfig{
				N:        n,
				NodeId:   i,
				T:        ta,
				Kappa:    1,
				Epsilon:  0,
				SenderId: j,
				Instance: j,
				UROUND:   0,
			}
			broadcasts[i] = append(broadcasts[i], rbc.NewReliableBroadcast(config, committee, signature, handlers[i].Funcs))
			if i == j {
				broadcasts[i][j].SetValue(inputs[j])
			}
		}
	}

	return broadcasts
}

func setupKeys(n int, committee map[int]bool) (tcrsa.KeyShareList, *tcrsa.KeyMeta, *aba.CommonCoin, tcrsa.KeyShareList, *tcrsa.KeyMeta) {
	k := len(committee)
	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	if err != nil {
		panic(err)
	}
	keySharesC, keyMetaC, err := tcrsa.NewKey(512, uint16(k/2+1), uint16(k), nil)
	if err != nil {
		panic(err)
	}
	requestChannel := make(chan *utils.CoinRequest, 99999)
	commonCoin := aba.NewLocalCommonCoin(n, keyMeta, requestChannel)
	go commonCoin.Run()

	return keyShares, keyMeta, commonCoin, keySharesC, keyMetaC
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
