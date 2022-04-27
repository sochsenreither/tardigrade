package simulation

import (
	"crypto"
	"crypto/sha256"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/niclabs/tcpaillier"
	"github.com/niclabs/tcrsa"
	aba "github.com/sochsenreither/tardigrade/binaryagreement"
	abc "github.com/sochsenreither/tardigrade/tardigrade"
	"github.com/sochsenreither/tardigrade/utils"
)


type Keys struct {
	KeyShares         tcrsa.KeyShareList
	KeyMeta           *tcrsa.KeyMeta
	KeySharesCommitte tcrsa.KeyShareList
	KeyMetaCommittee  *tcrsa.KeyMeta
	Pk                *tcpaillier.PubKey
	DecryptionShares  []*tcpaillier.KeyShare
	Proofs            []*tcrsa.SigShare
}

func GetIPs(n int) map[int]string {
	// Read from file. If file doesn't exists create a new one
	filename := fmt.Sprintf("simulation/addresses/addresses-%d.json", n)
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

func SetupNode(id, n, t, delta, lambda, kappa, txSize int, rcfgs utils.RoundConfigs) (*abc.ABC, *utils.NetworkHandler) {
	// Read keys from file
	keys := setupKeys(n, kappa)

	// Read ips from file
	ips := GetIPs(n)

	// Read committee members from file
	committee := GetCommittee(kappa)

	// Create handler
	handler := utils.NewNetworkHandler(ips, id, n, kappa, rcfgs)

	// Create leader function
	leaderFunc := func(r, n int) int {
		return r % n
	}

	// Create abc
	cfg := abc.NewABCConfig(n, id, t, t, kappa, delta, lambda, 0, txSize, committee, leaderFunc, handler.Funcs)
	if committee[id] {
		tcs := abc.NewTcs(keys.KeyShares[id], keys.KeyMeta, keys.KeyMetaCommittee, keys.Pk, keys.Proofs[id], keys.KeySharesCommitte[id], keys.DecryptionShares[id])
		return abc.NewABC(cfg, tcs), handler
	} else {
		tcs := abc.NewTcs(keys.KeyShares[id], keys.KeyMeta, keys.KeyMetaCommittee, keys.Pk, keys.Proofs[id], nil, nil)
		return abc.NewABC(cfg, tcs), handler
	}
}

func runCoin(n, kappa int) {
	keys := setupKeys(n, kappa)
	ips := GetIPs(n)
	coin := aba.NewNetworkCommonCoin(n, keys.KeyMeta, ips)
	coin.Run()
}

func setupNetworkSimulation(n, delta, lambda, kappa, txSize int, rcfgs utils.RoundConfigs) ([]*abc.ABC, *Keys, map[int]string, *aba.CommonCoin, map[int]bool, []*utils.NetworkHandler) {
	// Setup keys
	start := time.Now()
	keys := setupKeys(n, kappa)
	fmt.Println("Key setup took", time.Since(start))

	// Setup committee
	committee := make(map[int]bool)
	for i := 0; i < kappa; i++ {
		committee[i] = true
	}

	// Setup ip addresses
	// Create tcp message handlers
	ips := make(map[int]string)
	for i := 0; i < n; i++ {
		ips[i] = "127.0.0.1:123" + strconv.Itoa(i)
	}

	// Create common coin
	ips[-1] = "127.0.0.1:4321"
	coin := aba.NewNetworkCommonCoin(n, keys.KeyMeta, ips)

	// Setup handlers
	handlers := make([]*utils.NetworkHandler, n)
	for i := 0; i < n; i++ {
		handlers[i] = utils.NewNetworkHandler(ips, i, n, kappa, rcfgs)
	}

	// Setup leader func
	leaderFunc := func(r, n int) int {
		return r % n
	}

	// Setup abcs
	abcs := make([]*abc.ABC, n)
	for i := 0; i < n; i++ {
		cfg := abc.NewABCConfig(n, i, 0, 0, kappa, delta, lambda, 0, txSize, committee, leaderFunc, handlers[i].Funcs)
		if committee[i] {
			abcs[i] = abc.NewABC(cfg, abc.NewTcs(keys.KeyShares[i], keys.KeyMeta, keys.KeyMetaCommittee, keys.Pk, keys.Proofs[i], keys.KeySharesCommitte[i], keys.DecryptionShares[i]))
		} else {
			abcs[i] = abc.NewABC(cfg, abc.NewTcs(keys.KeyShares[i], keys.KeyMeta, keys.KeyMetaCommittee, keys.Pk, keys.Proofs[i], nil, nil))
		}
	}
	return abcs, keys, ips, coin, committee, handlers
}

func KeySetup(n, kappa int) {
	setupKeys(n, kappa)
}

func setupKeys(n, kappa int) *Keys {
	// If a file containing keys exists use that file
	filename := fmt.Sprintf("simulation/keys/keys-%d-%d", n, kappa)
	if fileExists(filename) {
		f, err := os.Open(filename)
		if err != nil {
			panic(err)
		}
		keys := new(Keys)
		dec := gob.NewDecoder(f)
		dec.Decode(keys)
		f.Close()
		return keys
	}
	// Setup signature scheme
	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(n/2+1), uint16(n), nil)
	if err != nil {
		panic(err)
	}

	keySharesCommittee, keyMetaCommittee, err := tcrsa.NewKey(512, uint16(kappa/2+1), uint16(kappa), nil)
	if err != nil {
		panic(err)
	}

	keySize := 128

	// Setup encryption scheme
	decryptionShares, pk, err := tcpaillier.NewKey(keySize, 1, uint8(kappa), uint8(kappa/2+1))
	if err != nil {
		panic(err)
	}

	// Setup proofs on nodeId (Dealer is node 0)
	proofs := make([]*tcrsa.SigShare, n)
	for i := 0; i < n; i++ {
		hash := sha256.Sum256([]byte(strconv.Itoa(i)))
		paddedHash, _ := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, hash[:])
		sig, err := keyShares[0].Sign(paddedHash, crypto.SHA256, keyMeta)
		if err != nil {
			panic(err)
		}
		proofs[i] = sig
	}

	keys := &Keys{
		KeyShares:         keyShares,
		KeyMeta:           keyMeta,
		KeySharesCommitte: keySharesCommittee,
		KeyMetaCommittee:  keyMetaCommittee,
		Pk:                pk,
		DecryptionShares:  decryptionShares,
		Proofs:            proofs,
	}

	// Write keys to file
	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	enc := gob.NewEncoder(f)
	enc.Encode(keys)
	f.Close()

	return keys
}

func randomTransactions(n, txSize, scale int) [][]byte {
	bufsize := n * scale
	buf := make([][]byte, bufsize)
	for i := 0; i < bufsize; i++ {
		token := make([]byte, txSize)
		rand.Read(token)
		// fmt.Printf("Generated tx: %x\n", token)
		buf[i] = token
	}
	return buf
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func uniqueTransactions(blocks map[int]*utils.Block, txs map[[32]byte]int, txSize int) {
	for _, block := range blocks {
		for _, transactions := range block.Txs {
			//fmt.Printf("TX: %x\n", transactions)
			var tx [][]byte
			for i := 0; i < len(transactions); i += txSize {
				end := i + txSize

				if end > len(transactions) {
					end = len(transactions)
				}
				tx = append(tx, transactions[i:end])
			}
			for _, t := range tx {
				h := sha256.Sum256(t)
				txs[h]++
				if txs[h] > 1 {
					//fmt.Printf("Multiple tx: %x - %d\n", t, txs[h])
				}
			}
		}
	}
}
