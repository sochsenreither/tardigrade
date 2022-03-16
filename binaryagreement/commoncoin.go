package binaryagreement

import (
	"crypto"
	"crypto/sha256"

	"log"
	"strconv"

	"github.com/niclabs/tcrsa"
	"github.com/sochsenreither/upgrade/utils"
)

type CommonCoin struct {
	N           int               // Number of nodes
	KeyMeta     *tcrsa.KeyMeta    // PKI
	RequestChan chan *utils.CoinRequest // Channel to receive requests
}

func NewCommonCoin(n int, keyMeta *tcrsa.KeyMeta, requestChannel chan *utils.CoinRequest) *CommonCoin {
	coin := &CommonCoin{
		N:           n,
		KeyMeta:     keyMeta,
		RequestChan: requestChannel,
	}
	return coin
}

func (cc *CommonCoin) Run() {
	// Maps from UROUND -> round -> instance -> nodeId
	received := make(map[int]map[int]map[int]map[int]*utils.CoinRequest)
	alreadySent := make(map[int]map[int]map[int]bool)
	coinVals := make(map[int]map[int]byte)

	for request := range cc.RequestChan {
		sender := request.Sender
		UROUND := request.UROUND
		round := request.Round
		instance := request.Instance

		if received[UROUND] == nil {
			received[UROUND] = make(map[int]map[int]map[int]*utils.CoinRequest)
		}
		if alreadySent[UROUND] == nil {
			alreadySent[UROUND] = make(map[int]map[int]bool)
		}
		if coinVals[UROUND] == nil {
			coinVals[UROUND] = make(map[int]byte)
		}
		// Create a new map the first time a request from a new round comes in
		if received[UROUND][round] == nil {
			received[UROUND][round] = make(map[int]map[int]*utils.CoinRequest)
		}
		if alreadySent[UROUND][round] == nil {
			alreadySent[UROUND][round] = make(map[int]bool)
		}

		if received[UROUND][round][instance] == nil {
			received[UROUND][round][instance] = make(map[int]*utils.CoinRequest)
		}
		received[UROUND][round][instance][sender] = request

		// Hash the round number
		h := sha256.Sum256([]byte(strconv.Itoa(round)))
		hash, err := tcrsa.PrepareDocumentHash(cc.KeyMeta.PublicKey.Size(), crypto.SHA256, h[:])
		if err != nil {
			log.Println("Common coin failed to create hash for round", round, err)
		}

		// Verify if the received signature share is valid
		if err := request.Sig.Verify(hash, cc.KeyMeta); err != nil {
			log.Print("Common coin couldn't verify signature share from node", sender)
			continue
		}

		// If enough signature shares were received for a given round combine them to a certificate
		if len(received[UROUND][round][instance]) >= cc.N/2+1 {
			if alreadySent[UROUND][round][instance] {
				// If the coin was already created and multicasted and if some node asks for the value at a later time, send the value only to this node
				answer(request.Answer, coinVals[UROUND][round])
			} else {
				// Combine all received signature shares to a certificate
				// log.Println("Creating certificate in round", round)
				var sigShares tcrsa.SigShareList
				for _, req := range received[UROUND][round][instance] {
					sigShares = append(sigShares, req.Sig)
				}
				certificate, err := sigShares.Join(hash, cc.KeyMeta)
				if err != nil {
					log.Println("Common coin failed to create a certificate for round", round)
					continue
				}

				// Compute the hash of the certificate, take the least significant bit and use that as coin.
				certHash := sha256.Sum256(certificate)
				lsb := certHash[len(certHash)-1] & 0x01

				for _, req := range received[UROUND][round][instance] {
					answer(req.Answer, lsb)
				}
				alreadySent[UROUND][round][instance] = true
				coinVals[UROUND][round] = lsb
			}
		}
	}
}

func answer(receiver chan byte, val byte) {
	receiver <- val
}