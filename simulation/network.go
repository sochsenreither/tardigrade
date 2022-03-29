package simulation

import (
	"fmt"
	"strconv"
	"time"

	aba "github.com/sochsenreither/upgrade/binaryagreement"
	abc "github.com/sochsenreither/upgrade/upgrade"
	"github.com/sochsenreither/upgrade/utils"
)

// TODO: t parameter is useless in setup. t gets dictated by roundCfg now

func RunNetwork() {
	networkSimulation(7, 0, 200, 1450, 2, 8)
}

func networkSimulation(n, t, delta, lambda, kappa, txSize int) {
	bufTicker := time.NewTicker(time.Duration(lambda) * time.Millisecond) // Ticker for filling buf
	done := make(chan struct{}, n)
	term := make(chan struct{})
	rounds := 2

	rcfgs := make(map[int]*abc.RoundConfig)
	hCfg := &abc.RoundConfig{
		Ta: 0,
		Ts: 0,
		Crashed: map[int]bool{},
	}
	cCfg := &abc.RoundConfig{
		Ta: 3,
		Ts: 3,
		Crashed: map[int]bool{
			4: true,
			5: true,
			6: true,
		},
	}

	for i := 0; i < 1; i++ {
		rcfgs[i] = cCfg
	}

	for i := 1; i < 2; i++ {
		rcfgs[i] = hCfg
	}

	// for i := 15; i < 25; i++ {
	// 	rcfgs[i] = hCfg
	// }
	// run ABCs
	abcs, _, _, coin, _ := setupNetworkSimulation(n, t, delta, lambda, kappa, txSize)
	go coin.Run()
	fmt.Printf("Setup done, starting simulation...\n\n")
	for i := 0; i < n; i++ {
		i := i
		abcs[i].FillBuffer(randomTransactions(n, txSize, 4))
		go func() {
			abcs[i].Run(rounds, rcfgs)
			done <- struct{}{}
		}()
	}
	start := time.Now()

	go func() {
		count := 0
		for range done {
			count++
			if count == n {
				term <- struct{}{}
			}
		}
	}()

	// fill bufs at certain interval
	statsTicker := time.NewTicker(3 * time.Second) // Ticker for stats
	ticks := 1
	txs := make(map[[32]byte]int) // Maps h(tx) -> count
	for {
		select {
		case <-term:
			runtime := time.Since(start)
			blocks := abcs[0].GetBlocks()
			totalTxs := 0
			for _, block := range blocks {
				totalTxs += block.TxsCount
			}
			uniqueTransactions(blocks, txs, txSize)
			txps := float64(totalTxs) / float64(runtime.Seconds())
			uTxps := float64(len(txs)) / float64(runtime.Seconds())
			fmt.Printf("Simulation ran for %s\n", runtime)
			fmt.Printf("Total transactions: %d, txs/s: %.2f\n", totalTxs, txps)
			fmt.Printf("Unique transactions: %d, Unique txs/s: %.2f\n", len(txs), uTxps)
			return
		case <-statsTicker.C:
			if rounds != -1 {
				break
			}
			blocks := abcs[0].GetBlocks()
			totalTxs := 0
			for _, block := range blocks {
				totalTxs += block.TxsCount
			}
			uniqueTransactions(blocks, txs, txSize)
			fmt.Printf(" -------------------- %d seconds ---------------------\n", ticks*5)
			fmt.Printf("| Total transactions: %d, txs/s: %d. Latency: %s\n", totalTxs, totalTxs/(ticks*3), abcs[0].LatencyTotal/time.Duration(abcs[0].FinishedRounds))
			fmt.Printf("| Unique transactions: %d, Unique txs/s: %d\n", len(txs), len(txs)/(ticks*3))
			fmt.Printf(" ----------------------------------------------------\n")
			ticks++
		case <-bufTicker.C:
			for i := range abcs {
				abcs[i].FillBuffer(randomTransactions(n, txSize, 3))
			}
		}
	}

}

func setupNetworkSimulation(n, t, delta, lambda, kappa, txSize int) ([]*abc.ABC, *Keys, map[int]string, *aba.CommonCoin, map[int]bool) {
	// Setup keys
	start := time.Now()
	keys := setupKeys(n, kappa)
	fmt.Println("Key setup took", time.Since(start))

	// Setup committee
	committee := make(map[int]bool)
	for i := 0; i < kappa; i++ {
		committee[i] = true
	}

	// Setup ip addresses
	// Create tcp message handlers
	ips := make(map[int]string)
	for i := 0; i < n; i++ {
		ips[i] = "127.0.0.1:123" + strconv.Itoa(i)
	}

	// Create common coin
	ips[-1] = "127.0.0.1:4321"
	coin := aba.NewNetworkCommonCoin(n, keys.KeyMeta, ips)

	// Setup handlers
	handlers := make([]*utils.NetworkHandler, n)
	for i := 0; i < n; i++ {
		handlers[i] = utils.NewNetworkHandler(ips, i, n, kappa)
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
	return abcs, keys, ips, coin, committee
}
