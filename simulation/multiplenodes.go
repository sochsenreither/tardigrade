package simulation

import (
	"fmt"
	"log"
	"time"

	abc "github.com/sochsenreither/tardigrade/tardigrade"
	"github.com/sochsenreither/tardigrade/utils"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

func RunNodes(startId, endId, n, t, delta, lambda, kappa, txSize int, startTime time.Time, cfg *utils.SimulationConfig) {
	if startId == endId && startId == -1 {
		runCoin(n, kappa)
		return
	}
	done := make(chan struct{}, n*2)
	term := make(chan struct{})

	var nodes []*abc.ABC
	var handlers []*utils.NetworkHandler

	for i := startId; i < endId; i++ {
		node, handler := SetupNode(i, n, t, delta, lambda, kappa, txSize, cfg.RoundCfgs)
		nodes = append(nodes, node)
		handlers = append(handlers, handler)
	}

	runningNodes := len(nodes)

	for _, node := range nodes {
		node.FillBuffer(randomTransactions(n, txSize, 5))
	}

	for _, node := range nodes {
		go func(node *abc.ABC) {
			node.Run(cfg.Rounds, cfg.RoundCfgs, startTime)
			done <- struct{}{}
		}(node)
	}
	go func() {
		count := 0
		for range done {
			count++
			if count == runningNodes {
				term <- struct{}{}
			}
		}
	}()

	<-time.After(time.Until(startTime))
	bufTicker := time.NewTicker(time.Duration(lambda) * time.Millisecond) // Ticker for filling buf
	statsTicker := time.NewTicker(5 * time.Second)                        // Ticker for stats
	//ticks := 1
	txs := make(map[[32]byte]int) // Maps h(tx) -> count
	start := time.Now()
	for {
		select {
		case <-term:
			runtime := time.Since(start)
			blocks := nodes[0].GetBlocks()
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
			totalBytes := 0
			for _, h := range handlers {
				totalBytes += h.BytesSent()
			}
			p := message.NewPrinter(language.English)
			p.Printf("Bytes sent: %d\n", totalBytes)
			for i := startId; i < endId; i++ {
				if totalTxs == 0 {
					continue
				}
				p.Printf("Bytes sent by node %d: %d. B/tx: %d\n", i, handlers[i].BytesSent(), handlers[i].BytesSent()/totalTxs)
				log.Printf("Bytes sent by Node %d: %d", i, handlers[i].BytesSent())
			}
			return
		case <-statsTicker.C:
			// blocks := nodes[0].GetBlocks()
			// totalTxs := 0
			// for _, block := range blocks {
			// 	totalTxs += block.TxsCount
			// }
			// uniqueTransactions(blocks, txs, txSize)
			// fmt.Printf(" -------------------- %d seconds ---------------------\n", ticks*5)
			// fmt.Printf("| Total transactions: %d, txs/s: %d\n", totalTxs, totalTxs/(ticks*5))
			// fmt.Printf("| Unique transactions: %d, Unique txs/s: %d\n", len(txs), len(txs)/(ticks*5))
			// fmt.Printf(" ----------------------------------------------------\n")
			// ticks++
		case <-bufTicker.C:
			for _, node := range nodes {
				node.FillBuffer(randomTransactions(n, txSize, 2))
			}
		}
	}
}
