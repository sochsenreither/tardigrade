package binaryagreement

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestABASameValue(t *testing.T) {
	n := 8
	ta := 2
	var wg sync.WaitGroup
	var mu sync.Mutex

	keyShares, keyMeta, coin := setup(n)

	abas := make(map[int][]*BinaryAgreement)
	nodeChans := make(map[int]map[int][]chan *abaMessage) // round -> instance -> chans
	outs := make(map[int][]chan int)

	multicast := func(instance, round int, msg *abaMessage) {
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make(map[int][]chan *abaMessage)
		}
		if len(nodeChans[round][instance]) != n {
			nodeChans[round][instance] = make([]chan *abaMessage, n)
			for i := 0; i < n; i++ {
				nodeChans[round][instance][i] = make(chan *abaMessage, 99*n)
			}
		}
		mu.Unlock()
		for _, node := range nodeChans[round][instance] {
			node <- msg
		}
	}

	for i := 0; i < n; i++ {
		i := i
		receive := func(instance, round int) chan *abaMessage {
			// If channels for round or instance don't exist create them first
			mu.Lock()
			if nodeChans[round] == nil {
				nodeChans[round] = make(map[int][]chan *abaMessage)
			}
			if len(nodeChans[round][instance]) != n {
				nodeChans[round][instance] = make([]chan *abaMessage, n)
				for k := 0; k < n; k++ {
					nodeChans[round][instance][k] = make(chan *abaMessage, 99*n)
				}
			}
			mu.Unlock()
			return nodeChans[round][instance][i]
		}
		thresholdCrypto := &thresholdCrypto{
			keyShare: keyShares[i],
			keyMeta: keyMeta,
		}
		outs[i] = make([]chan int, n)
		for j := 0; j < n; j++ {
			outs[i][j] = make(chan int, 100)
			abas[i] = append(abas[i], NewBinaryAgreement(n, i, ta, 0, j, coin, thresholdCrypto, multicast, receive, outs[i][j]))
		}
	}
	start := time.Now()
	wg.Add((n-ta)*(n-ta))
	for i := 0; i < n-ta; i++ {
		i := i
		for j := 0; j < n-ta; j++ {
			j := j
			go func() {
				defer wg.Done()
				abas[i][j].run()
			}()
		}
	}
	wg.Wait()
	fmt.Println("Execution time:", time.Since(start))

	// Test if every instance agreed on one value
	for i := 0; i < n-ta; i++ {
		var vals []int
		for j := 0; j < n-ta; j++ {
			val := <- outs[j][i]
			vals = append(vals, val)
		}
		for _, val := range vals {
			if val != vals[0] {
				t.Errorf("Expected %q, got %q", vals[0], val)
			}
		}
	}
}

func TestABADifferentValues(t *testing.T) {
	n := 8
	ta := 2
	var wg sync.WaitGroup
	var mu sync.Mutex

	keyShares, keyMeta, coin := setup(n)

	abas := make(map[int][]*BinaryAgreement)
	nodeChans := make(map[int]map[int][]chan *abaMessage) // round -> instance -> chans
	outs := make(map[int][]chan int)

	multicast := func(instance, round int, msg *abaMessage) {
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make(map[int][]chan *abaMessage)
		}
		if len(nodeChans[round][instance]) != n {
			nodeChans[round][instance] = make([]chan *abaMessage, n)
			for i := 0; i < n; i++ {
				nodeChans[round][instance][i] = make(chan *abaMessage, 99*n)
			}
		}
		mu.Unlock()
		for _, node := range nodeChans[round][instance] {
			node <- msg
		}
	}

	for i := 0; i < n; i++ {
		i := i
		receive := func(instance, round int) chan *abaMessage {
			// If channels for round or instance don't exist create them first
			mu.Lock()
			if nodeChans[round] == nil {
				nodeChans[round] = make(map[int][]chan *abaMessage)
			}
			if len(nodeChans[round][instance]) != n {
				nodeChans[round][instance] = make([]chan *abaMessage, n)
				for k := 0; k < n; k++ {
					nodeChans[round][instance][k] = make(chan *abaMessage, 99*n)
				}
			}
			mu.Unlock()
			return nodeChans[round][instance][i]
		}
		thresholdCrypto := &thresholdCrypto{
			keyShare: keyShares[i],
			keyMeta: keyMeta,
		}
		outs[i] = make([]chan int, n)
		for j := 0; j < n; j++ {
			outs[i][j] = make(chan int, 100)
			abas[i] = append(abas[i], NewBinaryAgreement(n, i, ta, i%2, j, coin, thresholdCrypto, multicast, receive, outs[i][j]))
		}
	}
	start := time.Now()
	wg.Add((n-ta)*(n-ta))
	for i := 0; i < n-ta; i++ {
		i := i
		for j := 0; j < n-ta; j++ {
			j := j
			go func() {
				defer wg.Done()
				abas[i][j].run()
			}()
		}
	}
	wg.Wait()
	fmt.Println("Execution time:", time.Since(start))

	// Test if every instance agreed on one value
	for i := 0; i < n-ta; i++ {
		var vals []int
		for j := 0; j < n-ta; j++ {
			val := <- outs[j][i]
			vals = append(vals, val)
		}
		for j, val := range vals {
			if val != vals[0] {
				t.Errorf("Expected %d, got %d from node %d in instance %d, %d", vals[0], val, i, j, vals)
			}
		}
	}
}