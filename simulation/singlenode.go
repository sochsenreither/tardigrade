package simulation

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"

	aba "github.com/sochsenreither/upgrade/binaryagreement"
	abc "github.com/sochsenreither/upgrade/upgrade"
	"github.com/sochsenreither/upgrade/utils"
)

func SetupNode(id, n, t, delta, lambda, kappa, txSize int) *abc.ABC {
	// Read keys from file
	keys := setupKeys(n, kappa)

	// Read ips from file
	ips := GetIPs(n)

	// Read committee members from file
	committee := GetCommittee(kappa)

	// Create handler
	handler := utils.NewNetworkHandler(ips, id, n, kappa)

	// Create leader function
	leaderFunc := func(r, n int) int {
		return r % n
	}

	// Create abc
	cfg := abc.NewABCConfig(n, id, t, t, kappa, delta, lambda, 0, txSize, committee, leaderFunc, handler.Funcs)
	if committee[id] {
		tcs := abc.NewTcs(keys.KeyShares[id], keys.KeyMeta, keys.KeyMetaCommittee, keys.Pk, keys.Proofs[id], keys.KeySharesCommitte[id], keys.DecryptionShares[id])
		return abc.NewABC(cfg, tcs)
	} else {
		tcs := abc.NewTcs(keys.KeyShares[id], keys.KeyMeta, keys.KeyMetaCommittee, keys.Pk, keys.Proofs[id], nil, nil)
		return abc.NewABC(cfg, tcs)
	}
}

func RunNode(id, n, t, delta, lambda, kappa, txSize int) {
	// If id == -1 run coin
	if id == -1 {
		keys := setupKeys(n, kappa)
		ips := GetIPs(n)
		coin := aba.NewNetworkCommonCoin(n, keys.KeyMeta, ips)
		coin.Run()
		return
	}

	node := SetupNode(id, n, t, delta, lambda, kappa, txSize)
	fmt.Printf("Setup done for node %d. Starting...\n", id)
	node.FillBuffer(randomTransactions(n, txSize, 20))
	go node.Run(-1)

	bufTicker := time.NewTicker(time.Duration(lambda) * time.Millisecond) // Ticker for filling buf
	statsTicker := time.NewTicker(5 * time.Second)                        // Ticker for stats
	ticks := 1
	txs := make(map[[32]byte]int) // Maps h(tx) -> count
	for {
		select {
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
			node.FillBuffer(randomTransactions(n, txSize, 10))
		}
	}
}

func GetIPs(n int) map[int]string {
	// Read from file. If file doesn't exists create a new one
	filename := fmt.Sprintf("simulation/addresses-%d.json", n)
	if fileExists(filename) {
		content, err := ioutil.ReadFile(filename)
		if err != nil {
			panic(err)
		}
		addr := make(map[string]string)
		err = json.Unmarshal(content, &addr)
		if err != nil {
			panic(err)
		}
		ips := make(map[int]string)
		for i, ip := range addr {
			index, err := strconv.Atoi(i)
			if err != nil {
				panic(err)
			}
			ips[index] = ip
		}
		return ips
	}
	ips := make(map[int]string)
	for i := 0; i < n; i++ {
		ips[i] = "127.0.0.1:123" + strconv.Itoa(i)
	}
	ips[-1] = "127.0.0.1:4321"

	addr, err := json.Marshal(ips)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(filename, addr, 0644)
	if err != nil {
		panic(err)
	}
	return ips
}

func GetCommittee(kappa int) map[int]bool {
	filename := fmt.Sprintf("simulation/committee-%d", kappa)
	if fileExists(filename) {
		content, err := ioutil.ReadFile(filename)
		if err != nil {
			panic(err)
		}
		addr := make(map[string]bool)
		err = json.Unmarshal(content, &addr)
		if err != nil {
			panic(err)
		}
		committee := make(map[int]bool)
		for i, b := range addr {
			index, err := strconv.Atoi(i)
			if err != nil {
				panic(err)
			}
			committee[index] = b
		}
		return committee
	}
	committee := make(map[int]bool)
	for i := 0; i < kappa; i++ {
		committee[i] = true
	}

	addr, err := json.Marshal(committee)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(filename, addr, 0644)
	if err != nil {
		panic(err)
	}
	return committee
}
