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

type testBBInstance struct {
	n int
	ts int
	nodeChans []chan *broadcastMessage
	outs []chan []byte
	broadcasts []*broadcast
	killChans []chan struct{}
}

func NewTestBBInstance(n, ts, sender int) *testBBInstance {
	testBBInstance := &testBBInstance{
		n: n,
		ts: ts,
		nodeChans: make([]chan *broadcastMessage, n),
		outs: make([]chan []byte, n),
		broadcasts: make([]*broadcast, n),
		killChans: make([]chan struct{}, n),
	}

	for i := 0; i < n; i++ {
		testBBInstance.nodeChans[i] = make(chan *broadcastMessage, 100*n)
		testBBInstance.outs[i] = make(chan []byte, n)
		testBBInstance.killChans[i] = make(chan struct{}, n)
		testBBInstance.broadcasts[i] = NewBroadcast(n, i, ts, sender, testBBInstance.nodeChans, testBBInstance.killChans[i], testBBInstance.outs[i])
	}

	return testBBInstance
}

func TestBBEveryoneAgreesOnInput(t *testing.T) {
	testBB := NewTestBBInstance(10, 2, 0)
	var wg sync.WaitGroup

	inp := []byte("foo")
	testBB.broadcasts[0].setValue(inp)

	start := time.Now()
	for i := 0; i < testBB.n-testBB.ts; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			testBB.broadcasts[i].run()
		}()
	}
	wg.Wait()
	fmt.Println("Execution time:", time.Since(start))

	for i := 0; i < testBB.n-testBB.ts; i++ {
		val := <- testBB.outs[i]
		if !bytes.Equal(inp, val) {
			t.Errorf("Node %d returned %q, expected %q", i, val, inp)
		}
	}
}