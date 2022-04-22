package simulation

import (
	"fmt"
	"log"
	"time"

	"github.com/sochsenreither/upgrade/utils"
)

func RunNode(id, n, t, delta, lambda, kappa, txSize int, startTime time.Time, cfg *utils.SimulationConfig) {
	fmt.Printf("Starttime: %s\n", startTime)
	// If id == -1 run coin
	if id == -1 {
		// keys := setupKeys(n, kappa)
		// ips := GetIPs(n)
		// coin := aba.NewNetworkCommonCoin(n, keys.KeyMeta, ips)
		// coin.Run()
		runCoin(n, kappa)
		return
	}

	node, handler := SetupNode(id, n, t, delta, lambda, kappa, txSize, cfg.RoundCfgs)
	fmt.Printf("Setup done for node %d. Synchronizing...\n", id)
	node.FillBuffer(randomTransactions(n, txSize, 5))
	term := make(chan struct{})


	<-time.After(time.Until(startTime))
	fmt.Printf("Starting\n")
	go func() {
		node.Run(cfg.Rounds, cfg.RoundCfgs)
		term <- struct{}{}
	}()
	start := time.Now()

	bufTicker := time.NewTicker(time.Duration(lambda) * time.Millisecond) // Ticker for filling buf
	statsTicker := time.NewTicker(5 * time.Second)                        // Ticker for stats
	ticks := 1
	txs := make(map[[32]byte]int) // Maps h(tx) -> count
	for {
		select {
		case <-term:
			runtime := time.Since(start)
			blocks := node.GetBlocks()
			totalTxs := 0
			for _, block := range blocks {
				totalTxs += block.TxsCount
			}
			uniqueTransactions(blocks, txs, txSize)
			txps := float64(totalTxs) / float64(runtime.Seconds())
			uTxps := float64(len(txs)) / float64(runtime.Seconds())
			log.Printf("Simulation ran for %s\n", runtime)
			log.Printf("Total transactions: %d, txs/s: %.2f\n", totalTxs, txps)
			log.Printf("Unique transactions: %d, Unique txs/s: %.2f\n", len(txs), uTxps)
			totalBytes := handler.BytesSent()
			log.Printf("Bytes sent: %d\n", totalBytes)
			return
		case <-statsTicker.C:
			blocks := node.GetBlocks()
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
			node.FillBuffer(randomTransactions(n, txSize, 2))
		}
	}
}
