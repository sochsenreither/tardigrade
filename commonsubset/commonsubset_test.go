package commonsubset

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/niclabs/tcrsa"
	aba "github.com/sochsenreither/upgrade/binaryagreement"
	rbc "github.com/sochsenreither/upgrade/broadcast"
)

func TestACSSameValue(t *testing.T) {
	n := 4
	ta := 0
	var wg sync.WaitGroup
	var mu sync.Mutex

	keyShares, keyMeta, coin := setupKeys(n)
	committee := make(map[int]bool)
	committee[0] = true
	committee[1] = true
	committee[2] = true
	inputs := [4][]byte{[]byte("zero"), []byte("zero"), []byte("zero"), []byte("zero")}

	abas := setupAba(n, ta, keyShares, keyMeta, coin, &mu)
	rbcs := setupRbc(n, ta, keyShares, keyMeta, coin, &mu, inputs[:], committee)

	outs := make(map[int]chan [][]byte)
	nodeChans := make(map[int][]chan *message) // round -> chans
	acs := make(map[int]*CommonSubset)

	multicast := func(id, round int, msg *message) {
		go func() {
			var chans []chan *message
			mu.Lock()
			if nodeChans[round] == nil {
				nodeChans[round] = make([]chan *message, n)
				for i := 0; i < n; i++ {
					nodeChans[round][i] = make(chan *message, 9999*n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, nodeChans[round]...)
			mu.Unlock()
			for i := 0; i < n; i++ {
				chans[i] <- msg
			}
		}()
	}

	receive := func(id, round int) *message {
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make([]chan *message, n)
			for i := 0; i < n; i++ {
				nodeChans[round][i] = make(chan *message, 9999*n)
			}
		}
		ch := nodeChans[round][id]
		mu.Unlock()
		val := <-ch
		return val
	}

	for i := 0; i < n; i++ {
		tc := &ThresholdCrypto{
			KeyShare: keyShares[i],
			KeyMeta: keyMeta,
			SigShare: rbcs[i][0].Sig.SigShare,
		}
		cfg := &ACSConfig{
				N:        n,
				NodeId:   i,
				T:        ta,
				Kappa:    1,
				Epsilon:  0,
				Round:    0,
			}
		outs[i] = make(chan [][]byte, 100)
		acs[i] = NewACS(cfg, committee, inputs[i], outs[i], rbcs[i], abas[i], tc, multicast, receive)
	}

	start := time.Now()
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			acs[i].Run()
		}()
	}
	wg.Wait()
	fmt.Println("Execution time:", time.Since(start))
}

func setupAba(n, ta int, keyShares tcrsa.KeyShareList, keyMeta *tcrsa.KeyMeta, coin *aba.CommonCoin, mu *sync.Mutex) map[int][]*aba.BinaryAgreement {
	abas := make(map[int][]*aba.BinaryAgreement)
	nodeChans := make(map[int]map[int][]chan *aba.AbaMessage) // round -> instance -> chans
	outs := make(map[int][]chan int)

	multicast := func(id, instance, round int, msg *aba.AbaMessage) {
		go func() {
			var chans []chan *aba.AbaMessage
			mu.Lock()
			if nodeChans[round] == nil {
				nodeChans[round] = make(map[int][]chan *aba.AbaMessage)
			}
			if len(nodeChans[round][instance]) != n {
				nodeChans[round][instance] = make([]chan *aba.AbaMessage, n)
				for i := 0; i < n; i++ {
					nodeChans[round][instance][i] = make(chan *aba.AbaMessage, 99*n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, nodeChans[round][instance]...)
			mu.Unlock()
			for i := 0; i < len(chans); i++ {
				chans[i] <- msg
			}
		}()
	}
	receive := func(id, instance, round int) *aba.AbaMessage {
		// If channels for round or instance don't exist create them first
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make(map[int][]chan *aba.AbaMessage)
		}
		if len(nodeChans[round][instance]) != n {
			nodeChans[round][instance] = make([]chan *aba.AbaMessage, n)
			for k := 0; k < n; k++ {
				nodeChans[round][instance][k] = make(chan *aba.AbaMessage, 99*n)
			}
		}
		// Set receive channel to separate variable in order to prevent data/lock races
		ch := nodeChans[round][instance][id]
		mu.Unlock()
		val := <-ch
		return val
	}

	for i := 0; i < n; i++ {
		i := i
		thresholdCrypto := &aba.ThresholdCrypto{
			KeyShare: keyShares[i],
			KeyMeta:  keyMeta,
		}
		outs[i] = make([]chan int, n)
		for j := 0; j < n; j++ {
			outs[i][j] = make(chan int, 100)
			abas[i] = append(abas[i], aba.NewBinaryAgreement(n, i, ta, 0, j, coin, thresholdCrypto, multicast, receive, outs[i][j]))
		}
	}

	return abas
}

func setupRbc(n, ta int, keyShares tcrsa.KeyShareList, keyMeta *tcrsa.KeyMeta, coin *aba.CommonCoin, mu *sync.Mutex, inputs [][]byte, committee map[int]bool) map[int][]*rbc.ReliableBroadcast {
	nodeChans := make(map[int]map[int][]chan *rbc.Message) // maps round -> instance -> chans
	broadcasts := make(map[int][]*rbc.ReliableBroadcast)
	outs := make(map[int][]chan []byte)

	multicast := func(id, instance, round int, msg *rbc.Message) {
		go func() {
			var chans []chan *rbc.Message
			// If channels for round or instance don't exist create them first
			mu.Lock()
			if nodeChans[round] == nil {
				nodeChans[round] = make(map[int][]chan *rbc.Message)
			}
			if len(nodeChans[round][instance]) != n {
				nodeChans[round][instance] = make([]chan *rbc.Message, n)
				for i := 0; i < n; i++ {
					nodeChans[round][instance][i] = make(chan *rbc.Message, 999*n)
				}
			}
			// Set channels to send to to different variable in order to prevent data/lock races
			chans = append(chans, nodeChans[round][instance]...)
			mu.Unlock()

			switch msg.Payload.(type) {
			case *rbc.SMessage:
				for i, ch := range chans {
					if committee[i] {
						ch <- msg
					}
				}
			default:
				for _, ch := range chans {
					ch <- msg
				}
			}
		}()
	}
	receive := func(id, instance, round int) *rbc.Message {
		// If channels for round or instance don't exist create them first
		mu.Lock()
		if nodeChans[round] == nil {
			nodeChans[round] = make(map[int][]chan *rbc.Message)
		}
		if len(nodeChans[round][instance]) != n {
			nodeChans[round][instance] = make([]chan *rbc.Message, n)
			for k := 0; k < n; k++ {
				nodeChans[round][instance][k] = make(chan *rbc.Message, 999*n)
			}
		}
		// Set receive channel to separate variable in order to prevent data/lock races
		ch := nodeChans[round][instance][id]
		mu.Unlock()
		val := <-ch
		return val
	}

	for i := 0; i < n-ta; i++ {
		// Dealer signs node id
		hash := sha256.Sum256([]byte(strconv.Itoa(i)))
		paddedHash, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
		sig, _ := keyShares[len(keyShares)-1].Sign(paddedHash, crypto.SHA256, keyMeta)
		signature := &rbc.Signature{
			SigShare:     sig,
			KeyMeta: keyMeta,
		}
		outs[i] = make([]chan []byte, n)
		for j := 0; j < n; j++ {
			config := &rbc.ReliableBroadcastConfig{
				N:        n,
				NodeId:   i,
				T:        ta,
				Kappa:    1,
				Epsilon:  0,
				SenderId: j,
				Round:    0,
			}
			outs[i][j] = make(chan []byte, 100)
			broadcasts[i] = append(broadcasts[i], rbc.NewReliableBroadcast(config, committee, outs[i][j], signature, multicast, receive))
			if i == j {
				broadcasts[i][j].SetValue(inputs[j])
			}
		}
	}

	return broadcasts
}

func setupKeys(n int) (tcrsa.KeyShareList, *tcrsa.KeyMeta, *aba.CommonCoin) {
	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	if err != nil {
		panic(err)
	}
	requestChannel := make(chan *aba.CoinRequest, 99999)
	commonCoin := aba.NewCommonCoin(n, keyMeta, requestChannel)
	go commonCoin.Run()

	return keyShares, keyMeta, commonCoin
}
