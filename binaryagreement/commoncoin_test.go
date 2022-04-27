package binaryagreement

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/gob"
	"net"

	//"io/ioutil"
	"log"
	//"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/tardigrade/utils"
)

var wg sync.WaitGroup

// func TestMain(m *testing.M) {
// 	log.SetOutput(ioutil.Discard)
// 	os.Exit(m.Run())
// }

func TestCoinMultipleRounds(t *testing.T) {
	n := 64
	keyShares, keyMeta, coin := setup(n)

	for i := 0; i < 7; i++ {
		go repeatRunner(t, i, n, keyShares, keyMeta, coin.RequestChan, 1)
	}
	wg.Wait()
}

func TestCoinRedundantCalls(t *testing.T) {
	n := 2
	keyShares, keyMeta, coin := setup(n)

	go repeatRunner(t, 0, n, keyShares, keyMeta, coin.RequestChan, 3)

	wg.Wait()
}

func TestCoinIsBlocking(t *testing.T) {
	n := 2
	done := make(chan struct{})

	keyShares, keyMeta, coin := setup(n)
	timeout := time.After(200 * time.Millisecond)

	// Call the coin with only 3 nodes. This should block and there should be no output
	go func() {
		repeatRunner(t, 0, 1, keyShares, keyMeta, coin.RequestChan, 1)
		done <- struct{}{}
	}()

	select {
	case <-done:
		t.Errorf("Coin should block")
	case <-timeout:
	}
}

func TestNetworkCoin(t *testing.T) {
	n := 3
	ips := map[int]string{
		-1: "127.0.0.1:1234",
		0:  "127.0.0.1:1243",
		1:  "127.0.0.1:1432",
		2:  "127.0.0.1:4321",
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	vals := make(map[int]map[int]byte)
	rounds := 8
	wg.Add(n * rounds)

	keyShares, keyMeta, _ := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	coin := NewNetworkCommonCoin(n, keyMeta, ips)
	sigShares := make(map[int]map[int]*tcrsa.SigShare) // round -> node

	go coin.Run()
	for round := 0; round < rounds; round++ {
		time.Sleep(250*time.Millisecond)
		if vals[round] == nil {
			vals[round] = make(map[int]byte)
		}
		if sigShares[round] == nil {
			sigShares[round] = make(map[int]*tcrsa.SigShare)
		}
		// Call coin
		h := sha256.Sum256([]byte(strconv.Itoa(round)))
		hash, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, h[:])
		for node := 0; node < n; node++ {
			sigShares[round][node], _ = keyShares[node].Sign(hash, crypto.SHA256, keyMeta)

			coinRequest := &utils.CoinRequest{
				Sender:      node,
				UROUND:      0,
				Round:       round,
				Sig:         sigShares[round][node],
				AnswerLocal: nil,
				Instance:    0,
			}

			//log.Printf("Node %d sending request to coin", node)
			send(coinRequest, ips[-1])

			// Wait for answer
			go func(round, node int) {
				val := receive(ips[node], node)
				//log.Printf("Node %d round %d received: %d", node, round, val)
				mu.Lock()
				defer mu.Unlock()
				vals[round][node] = val
				wg.Done()
			}(round, node)
		}
	}

	wg.Wait()

	// Everyone needs to get the same answer per round.
	for i, r := range vals {
		tmp := make(map[byte]bool)
		for _, n := range r {
			tmp[n] = true
		}
		if len(tmp) != 1 {
			t.Errorf("Got different values in round %d", i)
		}
	}

}

func send(req *utils.CoinRequest, ip string) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(req)
	if err != nil {
		log.Fatalf("Unanble to encode request")
	}
	c, err := net.Dial("tcp", ip)
	for err != nil {
		time.Sleep(2000 * time.Millisecond)
		c, err = net.Dial("tcp", ip)
	}
	c.Write(buf.Bytes())
}

func receive(ip string, id int) byte {
	l, err := net.Listen("tcp", ip)
	for err != nil {
		l, err = net.Listen("tcp", ip)
		//log.Fatalf("Unable to create listener. %s", err)
	}
	defer l.Close()
	c, err := l.Accept()
	if err != nil {
		log.Fatalf("Unable tp create connection")
	}
	data := make([]byte, 1000)
	c.Read(data)
	buf := bytes.NewBuffer(data)
	msg := new(utils.HandlerMessage)
	dec := gob.NewDecoder(buf)
	err = dec.Decode(msg)
	if err != nil {
		log.Printf("Node %d got error while decoding. %s", id, err)
	}
	//log.Printf("Node %d received data. val: %d", id, msg.Payload.Sender)
	return byte(msg.Payload.Sender)
}

func setup(n int) (tcrsa.KeyShareList, *tcrsa.KeyMeta, *CommonCoin) {
	keyShares, keyMeta, _ := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	requestChannel := make(chan *utils.CoinRequest, 99999)
	commonCoin := NewLocalCommonCoin(n, keyMeta, requestChannel)
	go commonCoin.Run()

	return keyShares, keyMeta, commonCoin
}

func repeatRunner(t testing.TB, round, n int, keyShares tcrsa.KeyShareList, keyMeta *tcrsa.KeyMeta, requestChan chan *utils.CoinRequest, r int) {
	t.Helper()
	wg.Add(1)
	defer wg.Done()
	answerChans := make([]chan byte, n)

	// PKI setup
	sigShares := make([]*tcrsa.SigShare, n)
	h := sha256.Sum256([]byte(strconv.Itoa(round)))
	hash, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, h[:])
	for i := 0; i < n; i++ {
		sigShares[i], _ = keyShares[i].Sign(hash, crypto.SHA256, keyMeta)
		answerChans[i] = make(chan byte, 1234)
		coinRequest := &utils.CoinRequest{
			Sender:      i,
			Round:       round,
			Sig:         sigShares[i],
			AnswerLocal: answerChans[i],
			Instance:    0,
		}
		for i := 0; i < r; i++ {
			requestChan <- coinRequest
		}
	}

	res := <-answerChans[0]

	for i := 1; i < n; i++ {
		tmp := <-answerChans[i]
		if tmp != res {
			t.Errorf("Differing coin values in round %d", round)
		}
	}
}
