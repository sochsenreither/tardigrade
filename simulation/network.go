package simulation

import (
	"fmt"
	"time"

	"github.com/sochsenreither/upgrade/utils"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

func RunNetwork(cfg *utils.SimulationConfig) {
	networkSimulation(4, 80, 500, 4, 8, cfg)
}

func networkSimulation(n, delta, lambda, kappa, txSize int, cfg *utils.SimulationConfig) {
	bufTicker := time.NewTicker(time.Duration(lambda) * time.Millisecond) // Ticker for filling buf
	done := make(chan struct{}, n)
	term := make(chan struct{})
	rounds := 12

	rcfgs := make(map[int]*utils.RoundConfig)
	// hCfg := &abc.RoundConfig{
	// 	Ta: 0,
	// 	Ts: 0,
	// 	Crashed: map[int]bool{},
	// }
	cCfg := &utils.RoundConfig{
		Ta: 1,
		Ts: 1,
		Crashed: map[int]bool{
			3: true,
			//4: true,
		},
	}

	for i := 0; i < 12; i++ {
		rcfgs[i] = cCfg
	}

	// for i := 10; i < 12; i++ {
	// 	rcfgs[i] = cCfg
	// }

	// run ABCs
	abcs, _, _, coin, _, handlers := setupNetworkSimulation(n, delta, lambda, kappa, txSize, cfg.RoundCfgs)
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
			totalBytes := 0
			for _, h := range handlers {
				totalBytes += h.BytesSent()
			}
			p := message.NewPrinter(language.English)
			p.Printf("Bytes sent: %d\n", totalBytes)
			for i := 0; i < n; i++ {
				p.Printf("Bytes sent by node %d: %d. B/tx: %d\n", i, handlers[i].BytesSent(), handlers[i].BytesSent()/totalTxs)
			}
			return
		case <-statsTicker.C:
			// if rounds != -1 {
			// 	break
			// }
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
