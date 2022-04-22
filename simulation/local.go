package simulation

import (
	"fmt"
	"time"

	"github.com/sochsenreither/upgrade/utils"

	aba "github.com/sochsenreither/upgrade/binaryagreement"
	abc "github.com/sochsenreither/upgrade/upgrade"
)

func RunLocal() {
	local(6, 0, 20, 150, 2, 8)
}

func local(n, t, delta, lambda, kappa, txSize int) {
	bufTicker := time.NewTicker(time.Duration(lambda) * time.Millisecond) // Ticker for filling buf

	// run ABCs
	maxRounds := 1
	abcs := setupLocalSimulation(n, t, delta, lambda, kappa, txSize)
	rcfgs := make(map[int]*utils.RoundConfig)
	hCfg := &utils.RoundConfig{
		Ta:      0,
		Ts:      0,
		Crashed: map[int]bool{},
	}

	for i := 0; i < maxRounds; i++ {
		rcfgs[i] = hCfg
	}

	fmt.Printf("Setup done, starting simulation...\n\n")
	for i := 0; i < n; i++ {
		i := i
		abcs[i].FillBuffer(randomTransactions(n, txSize, 20))
		go func() {
			abcs[i].Run(maxRounds, rcfgs)
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
			fmt.Printf(" -------------------- %d seconds ---------------------\n", ticks*5)
			fmt.Printf("| Total transactions: %d, txs/s: %d\n", totalTxs, totalTxs/(ticks*5))
			fmt.Printf("| Unique transactions: %d, Unique txs/s: %d\n", len(txs), len(txs)/(ticks*5))
			fmt.Printf(" ----------------------------------------------------\n")
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

func setupLocalSimulation(n, t, delta, lambda, kappa, txSize int) []*abc.ABC {
	// Setup keys
	start := time.Now()
	keys := setupKeys(n, kappa)
	fmt.Println("Key setup took", time.Since(start))

	// Setup committee
	// TODO: random num of byzantine nodes. committee corruption?
	committee := make(map[int]bool)
	for i := 0; i < kappa; i++ {
		committee[i] = true
	}

	// Create common coin
	req := make(chan *utils.CoinRequest, 9999)
	coin := aba.NewLocalCommonCoin(n, keys.KeyMeta, req)
	go coin.Run()

	// Setup message handler
	nodeChans := make(map[int]chan *utils.HandlerMessage)
	handlers := make([]*utils.LocalHandler, n)
	for i := 0; i < n; i++ {
		nodeChans[i] = make(chan *utils.HandlerMessage, 9999)
		handlers[i] = utils.NewLocalHandler(nodeChans, coin.RequestChan, i, n, kappa)
	}

	// Setup leader func
	leaderFunc := func(r, n int) int {
		return r % n
	}

	// Setup abcs
	abcs := make([]*abc.ABC, n)
	for i := 0; i < n; i++ {
		cfg := abc.NewABCConfig(n, i, t, t, kappa, delta, lambda, 0, txSize, committee, leaderFunc, handlers[i].Funcs)
		if committee[i] {
			abcs[i] = abc.NewABC(cfg, abc.NewTcs(keys.KeyShares[i], keys.KeyMeta, keys.KeyMetaCommittee, keys.Pk, keys.Proofs[i], keys.KeySharesCommitte[i], keys.DecryptionShares[i]))
		} else {
			abcs[i] = abc.NewABC(cfg, abc.NewTcs(keys.KeyShares[i], keys.KeyMeta, keys.KeyMetaCommittee, keys.Pk, keys.Proofs[i], nil, nil))
		}
	}
	return abcs
}
