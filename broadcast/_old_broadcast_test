package broadcast

import (
	"bytes"
	"fmt"

	// "io/ioutil"
	// "log"
	// "os"
	"sync"
	"testing"
	"time"
)

// func TestMain(m *testing.M) {
// 	log.SetOutput(ioutil.Discard)
// 	os.Exit(m.Run())
// }

func TestBBParallelMultipleSendersOneRound(t *testing.T) {
	n := 3
	var wg sync.WaitGroup
	var mu sync.Mutex
	killChans := make([]chan struct{}, n)
	inputs := [3][]byte{[]byte("zero"), []byte("one"), []byte("two")}
	outs := make(map[int][]chan []byte)
	nodeChans := make(map[int]map[int][]chan *broadcastMessage) // maps round -> instance -> chans
	broadcasts := make(map[int][]*broadcast)

	multicast := func(instance, round int, msg *broadcastMessage) {
		// If channels for round or instance don't exist create them first
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make(map[int][]chan *broadcastMessage)
		}
		if len(nodeChans[round][instance]) != n {
			nodeChans[round][instance] = make([]chan *broadcastMessage, n)
			for i := 0; i < n; i++ {
				nodeChans[round][instance][i] = make(chan *broadcastMessage, 99*n)
			}
		}
		mu.Unlock()
		for _, node := range nodeChans[round][instance] {
			node <- msg
		}
	}

	for i := 0; i < n; i++ {
		i := i
		receive := func(instance, round int) chan *broadcastMessage {
			// If channels for round or instance don't exist create them first
			mu.Lock()
			if nodeChans[round] == nil {
				nodeChans[round] = make(map[int][]chan *broadcastMessage)
			}
			if len(nodeChans[round][instance]) != n {
				nodeChans[round][instance] = make([]chan *broadcastMessage, n)
				for k := 0; k < n; k++ {
					nodeChans[round][instance][k] = make(chan *broadcastMessage, 99*n)
				}
			}
			mu.Unlock()
			return nodeChans[round][instance][i]
		}
		killChans[i] = make(chan struct{}, 99)
		outs[i] = make([]chan []byte, n)
		for j := 0; j < n; j++ {
			outs[i][j] = make(chan []byte, 100)
			broadcasts[i] = append(broadcasts[i], NewBroadcast(n, i, 0, 0, j, killChans[i], outs[i][j], multicast, receive))
			if i == j {
				broadcasts[i][j].setValue(inputs[j])
			}
		}
	}
	start := time.Now()
	wg.Add(n*n)
	for i := 0; i < n; i++ {
		i := i
		for j := 0; j < n; j++ {
			j := j
			go func() {
				defer wg.Done()
				broadcasts[i][j].run()
			}()
		}
	}

	wg.Wait()

	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			val := <- broadcasts[i][j].out
			if !bytes.Equal(val, inputs[broadcasts[i][j].senderId]) {
				t.Errorf("Expected %q, got %q", inputs[broadcasts[i][j].senderId], val)
			}
		}
	}


	fmt.Println("Execution time:", time.Since(start))
}
