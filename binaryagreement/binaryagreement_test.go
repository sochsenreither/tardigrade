package binaryagreement

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sochsenreither/upgrade/utils"
)

func TestABADifferentValues(t *testing.T) {
	n := 4
	ta := 0
	kappa := 1
	var wg sync.WaitGroup

	keyShares, keyMeta, coin := setup(n)

	abas := make(map[int][]*BinaryAgreement)
	nodeChans := make(map[int]chan *utils.HandlerMessage)
	var handlers []*utils.LocalHandler
	for i := 0; i < n; i++ {
		nodeChans[i] = make(chan *utils.HandlerMessage, 99999)
	}


	for i := 0; i < n; i++ {
		i := i
		thresholdCrypto := &ThresholdCrypto{
			KeyShare: keyShares[i],
			KeyMeta:  keyMeta,
		}

		// Create new handler
		handlers = append(handlers, utils.NewLocalHandler(nodeChans, coin.RequestChan, i, n, kappa))

		for j := 0; j < n; j++ {
			abas[i] = append(abas[i], NewBinaryAgreement(0, n, i, ta, i%2, j, thresholdCrypto, handlers[i].Funcs))
		}
	}
	start := time.Now()
	wg.Add((n - ta) * (n - ta))
	for i := 0; i < n-ta; i++ {
		i := i
		for j := 0; j < n-ta; j++ {
			j := j
			go func() {
				defer wg.Done()
				abas[i][j].Run()
			}()
		}
	}
	wg.Wait()
	fmt.Println("Execution time:", time.Since(start))

	// Test if every instance agreed on one value
	for i := 0; i < n-ta; i++ {
		var vals []int
		for j := 0; j < n-ta; j++ {
			val := abas[j][i].GetValue()
			vals = append(vals, val)
		}
		for j, val := range vals {
			if val != vals[0] {
				t.Errorf("Expected %d, got %d from node %d in instance %d, %d", vals[0], val, i, j, vals)
			}
		}
	}
}
