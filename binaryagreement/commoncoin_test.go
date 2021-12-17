package binaryagreement

import (
	"crypto"
	"crypto/sha256"

	"io/ioutil"
	"log"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/niclabs/tcrsa"
)

var wg sync.WaitGroup

func TestMain(m *testing.M) {
	log.SetOutput(ioutil.Discard)
	os.Exit(m.Run())
}

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

func setup(n int) (tcrsa.KeyShareList, *tcrsa.KeyMeta, *CommonCoin) {
	keyShares, keyMeta, _ := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	requestChannel := make(chan *coinRequest, 99999)
	commonCoin := NewCommonCoin(n, keyMeta, requestChannel)
	go commonCoin.run()

	return keyShares, keyMeta, commonCoin
}

func repeatRunner(t testing.TB, round, n int, keyShares tcrsa.KeyShareList, keyMeta *tcrsa.KeyMeta, requestChan chan *coinRequest, r int) {
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
		coinRequest := &coinRequest{
			sender: i,
			round:  round,
			sig:    sigShares[i],
			answer: answerChans[i],
			instance: 0,
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
