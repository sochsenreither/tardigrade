package simulation

import (
	"crypto"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/niclabs/tcpaillier"
	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/upgrade/utils"

	aba "github.com/sochsenreither/upgrade/binaryagreement"
	abc "github.com/sochsenreither/upgrade/upgrade"
)

type keys struct {
	KeyShares         tcrsa.KeyShareList
	KeyMeta           *tcrsa.KeyMeta
	KeySharesCommitte tcrsa.KeyShareList
	KeyMetaCommittee  *tcrsa.KeyMeta
	Pk                *tcpaillier.PubKey
	DecryptionShares  []*tcpaillier.KeyShare
}

func Run() {
	local(7, 0, 65, 600, 2, 8)
}

func local(n, t, delta, lambda, kappa, txSize int) {
	bufTicker := time.NewTicker(time.Duration(lambda) * time.Millisecond) // Ticker for filling buf

	// run ABCs
	abcs := setupSimulation(n, t, delta, lambda, kappa, txSize)
	fmt.Printf("Setup done, starting simulation...\n\n")
	for i := 0; i < n; i++ {
		i := i
		abcs[i].FillBuffer(randomTransactions(n, txSize, 20))
		go func() {
			abcs[i].Run(-1)
		}()
	}

	// fill bufs at certain interval
	statsTicker := time.NewTicker(5 * time.Second) // Ticker for stats
	ticks := 1
	txs := make(map[[32]byte]int) // Maps h(tx) -> count
	for {
		select {
		case <-statsTicker.C:
			blocks := abcs[0].GetBlocks()
			totalTxs := 0
			for _, block := range blocks {
				totalTxs += block.TxsCount
			}
			uniqueTransactions(blocks, txs, txSize)
			fmt.Printf("------------ %d seconds ------------\n", ticks*5)
			fmt.Printf("Total transactions: %d. Unique transactions: %d. txs/s: %d. Unique txs/s: %d\n", totalTxs, len(txs), totalTxs/(ticks*5), len(txs)/(ticks*5))
			ticks++
		case <-bufTicker.C:
			for i := range abcs {
				abcs[i].FillBuffer(randomTransactions(n, txSize, 10))
			}
		}
	}

	// show stats at certain interval. txs/s, unique txs/s. Throughput
	// Measure throuput: measure time for each tx when putting into buf.
	// Measure again after round finished? Or maybe every node measures throughput itself
	// map[h(tx)] -> end-start
}

func setupSimulation(n, t, delta, lambda, kappa, txSize int) []*abc.ABC {
	// Setup keys
	start := time.Now()
	keys := setupKeys(n, kappa)

	// Setup proofs on nodeId (Dealer is node 0)
	proofs := make([]*tcrsa.SigShare, n)
	for i := 0; i < n; i++ {
		hash := sha256.Sum256([]byte(strconv.Itoa(i)))
		paddedHash, _ := tcrsa.PrepareDocumentHash(keys.KeyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
		sig, err := keys.KeyShares[0].Sign(paddedHash, crypto.SHA256, keys.KeyMeta)
		if err != nil {
			panic(err)
		}
		proofs[i] = sig
	}
	fmt.Println("Key setup took", time.Since(start))

	// Setup committee
	// TODO: random num of byzantine nodes. committee corruption?
	committee := make(map[int]bool)
	for i := 0; i < kappa; i++ {
		committee[i] = true
	}

	// Create common coin
	req := make(chan *utils.CoinRequest, 9999)
	coin := aba.NewCommonCoin(n, keys.KeyMeta, req)
	go coin.Run()

	// Setup message handler
	nodeChans := make(map[int]chan *utils.HandlerMessage)
	handlers := make([]*utils.Handler, n)
	for i := 0; i < n; i++ {
		nodeChans[i] = make(chan *utils.HandlerMessage, 9999)
		handlers[i] = utils.NewHandler(nodeChans, coin.RequestChan, i, n, kappa)
	}

	// Setup leader func
	leaderFunc := func(r, n int) int {
		return r % n
	}

	// Setup ABCS
	abcs := make([]*abc.ABC, n)
	for i := 0; i < n; i++ {
		cfg := abc.NewABCConfig(n, i, t, t, kappa, delta, lambda, 0, txSize, committee, leaderFunc, handlers[i])
		if committee[i] {
			abcs[i] = abc.NewABC(cfg, abc.NewTcs(keys.KeyShares[i], keys.KeyMeta, keys.KeyMetaCommittee, keys.Pk, proofs[i], keys.KeySharesCommitte[i], keys.DecryptionShares[i]))
		} else {
			abcs[i] = abc.NewABC(cfg, abc.NewTcs(keys.KeyShares[i], keys.KeyMeta, keys.KeyMetaCommittee, keys.Pk, proofs[i], nil, nil))
		}
	}
	return abcs
}

func setupKeys(n, kappa int) *keys {
	// If a file containing keys exists use that file
	filename := fmt.Sprintf("keys/keys-%d", n)
	if fileExists(filename) {
		f, err := os.Open(filename)
		if err != nil {
			panic(err)
		}
		keys := new(keys)
		dec := gob.NewDecoder(f)
		dec.Decode(keys)
		f.Close()
		return keys
	}
	// Setup signature scheme
	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	if err != nil {
		panic(err)
	}

	keySharesCommittee, keyMetaCommittee, err := tcrsa.NewKey(512, uint16(kappa/2+1), uint16(kappa), nil)
	if err != nil {
		panic(err)
	}

	// Setup encryption scheme
	decryptionShares, pk, err := tcpaillier.NewKey(1024, 1, uint8(kappa), uint8(kappa/2+1))
	if err != nil {
		panic(err)
	}

	keys := &keys{
		KeyShares:         keyShares,
		KeyMeta:           keyMeta,
		KeySharesCommitte: keySharesCommittee,
		KeyMetaCommittee:  keyMetaCommittee,
		Pk:                pk,
		DecryptionShares:  decryptionShares,
	}

	// Setup proofs on nodeId (Dealer is node 0)
	proofs := make([]*tcrsa.SigShare, n)
	for i := 0; i < n; i++ {
		hash := sha256.Sum256([]byte(strconv.Itoa(i)))
		paddedHash, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
		sig, err := keyShares[0].Sign(paddedHash, crypto.SHA256, keyMeta)
		if err != nil {
			panic(err)
		}
		proofs[i] = sig
	}

	// Write keys to file
	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	enc := gob.NewEncoder(f)
	enc.Encode(keys)
	f.Close()

	return keys
}

func randomTransactions(n, txSize, scale int) [][]byte {
	bufsize := n * scale
	buf := make([][]byte, bufsize)
	for i := 0; i < bufsize; i++ {
		token := make([]byte, txSize)
		rand.Read(token)
		//fmt.Printf("Generated tx: %x\n", token)
		buf[i] = token
	}
	return buf
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func uniqueTransactions(blocks map[int]*utils.Block, txs map[[32]byte]int, txSize int) {
	for _, block := range blocks {
		for _, transactions := range block.Txs {
			//fmt.Printf("TX: %x\n", transactions)
			var tx [][]byte
			for i := 0; i < len(transactions); i += txSize {
				end := i + txSize

				if end > len(transactions) {
					end = len(transactions)
				}
				tx = append(tx, transactions[i:end])
			}
			for _, t := range tx {
				h := sha256.Sum256(t)
				txs[h]++
				if txs[h] > 1 {
					//fmt.Printf("Multiple tx: %x - %d\n", t, txs[h])
				}
			}
		}
	}
}
