package simulation

import (
	"fmt"
	"time"

	abc "github.com/sochsenreither/upgrade/upgrade"
	"github.com/sochsenreither/upgrade/utils"
)

func RunNodes(startId, endId, n, t, delta, lambda, kappa, txSize int, cfg *utils.SimulationConfig) {
	if startId == endId && startId == -1 {
		runCoin(n, kappa)
		return
	}

	var nodes []*abc.ABC
	var handlers []*utils.NetworkHandler

	for i := startId; i < endId; i++ {
		node, handler := SetupNode(i, n, t, delta, lambda, kappa, txSize, cfg.RoundCfgs)
		nodes = append(nodes, node)
		handlers = append(handlers, handler)
	}

	for _, node := range nodes {
		node.FillBuffer(randomTransactions(n, txSize, 5))
	}

	// Testsetup
	maxRounds := 30
	rcfgs := make(map[int]*utils.RoundConfig)
	hCfg := &utils.RoundConfig{
		Ta: 0,
		Ts: 0,
		Crashed: map[int]bool{},
	}
	for i := 0; i < maxRounds; i++ {
		rcfgs[i] = hCfg
	}

	for _, node := range nodes {
		fmt.Println("Starting node", node.Cfg.NodeId)
		go node.Run(maxRounds, rcfgs)
	}

	bufTicker := time.NewTicker(time.Duration(lambda) * time.Millisecond) // Ticker for filling buf
	statsTicker := time.NewTicker(5 * time.Second)                        // Ticker for stats
	ticks := 1
	txs := make(map[[32]byte]int) // Maps h(tx) -> count
	for {
		select {
		case <-statsTicker.C:
			blocks := nodes[0].GetBlocks()
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
			for _, node := range nodes {
				node.FillBuffer(randomTransactions(n, txSize, 2))
			}
		}
	}
}