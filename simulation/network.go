package simulation

import (
	"fmt"
	"strconv"
	"time"

	aba "github.com/sochsenreither/upgrade/binaryagreement"
	abc "github.com/sochsenreither/upgrade/upgrade"
	"github.com/sochsenreither/upgrade/utils"
)


func RunNetwork() {
	networkSimulation(3, 0, 100, 2500, 2, 8)
}

func networkSimulation(n, t, delta, lambda, kappa, txSize int) {
	bufTicker := time.NewTicker(time.Duration(lambda) * time.Millisecond) // Ticker for filling buf

	// run ABCs
	abcs, _, _, coin, _ := setupNetworkSimulation(n, t, delta, lambda, kappa, txSize)
	go coin.Run()
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
