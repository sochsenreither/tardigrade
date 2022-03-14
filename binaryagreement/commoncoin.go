package binaryagreement

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"

	"log"
	"strconv"

	"github.com/niclabs/tcrsa"
)

type CommonCoin struct {
	n           int               // Number of nodes
	keyMeta     *tcrsa.KeyMeta    // PKI
	RequestChan chan *CoinRequest // Channel to receive requests
}

type CoinRequest struct {
	sender   int
	UROUND   int
	round    int
	sig      *tcrsa.SigShare
	answer   chan byte
	instance int
}

func NewCommonCoin(n int, keyMeta *tcrsa.KeyMeta, requestChannel chan *CoinRequest) *CommonCoin {
	coin := &CommonCoin{
		n:           n,
		keyMeta:     keyMeta,
		RequestChan: requestChannel,
	}
	return coin
}

func (cc *CommonCoin) Run() {
	// Maps from UROUND -> round -> instance -> nodeId
	received := make(map[int]map[int]map[int]map[int]*CoinRequest)
	alreadySent := make(map[int]map[int]map[int]bool)
	coinVals := make(map[int]map[int]byte)

	for request := range cc.RequestChan {
		sender := request.sender
		UROUND := request.UROUND
		round := request.round
		instance := request.instance

		if received[UROUND] == nil {
			received[UROUND] = make(map[int]map[int]map[int]*CoinRequest)
		}
		if alreadySent[UROUND] == nil {
			alreadySent[UROUND] = make(map[int]map[int]bool)
		}
		if coinVals[UROUND] == nil {
			coinVals[UROUND] = make(map[int]byte)
		}
		// Create a new map the first time a request from a new round comes in
		if received[UROUND][round] == nil {
			received[UROUND][round] = make(map[int]map[int]*CoinRequest)
		}
		if alreadySent[UROUND][round] == nil {
			alreadySent[UROUND][round] = make(map[int]bool)
		}

		if received[UROUND][round][instance] == nil {
			received[UROUND][round][instance] = make(map[int]*CoinRequest)
		}
		received[UROUND][round][instance][sender] = request

		// Hash the round number
		h := sha256.Sum256([]byte(strconv.Itoa(round)))
		hash, err := tcrsa.PrepareDocumentHash(cc.keyMeta.PublicKey.Size(), crypto.SHA256, h[:])
		if err != nil {
			log.Println("Common coin failed to create hash for round", round, err)
		}

		// Verify if the received signature share is valid
		if err := request.sig.Verify(hash, cc.keyMeta); err != nil {
			log.Print("Common coin couldn't verify signature share from node", sender)
			continue
		}

		// If enough signature shares were received for a given round combine them to a certificate
		if len(received[UROUND][round][instance]) >= cc.n/2+1 {
			if alreadySent[UROUND][round][instance] {
				// If the coin was already created and multicasted and if some node asks for the value at a later time, send the value only to this node
				request.answer <- coinVals[UROUND][round]
			} else {
				// Combine all received signature shares to a certificate
				// log.Println("Creating certificate in round", round)
				var sigShares tcrsa.SigShareList
				for _, req := range received[UROUND][round][instance] {
					sigShares = append(sigShares, req.sig)
				}
				certificate, err := sigShares.Join(hash, cc.keyMeta)
				if err != nil {
					log.Println("Common coin failed to create a certificate for round", round)
					continue
				}
				// TODO: not really necessary to check right after creating?
				err = rsa.VerifyPKCS1v15(cc.keyMeta.PublicKey, crypto.SHA256, h[:], certificate)
				if err != nil {
					log.Println("Common coin failed to verfiy created certificate for round", round)
				}

				// Compute the hash of the certificate, take the least significant bit and use that as coin.
				certHash := sha256.Sum256(certificate)
				lsb := certHash[len(certHash)-1] & 0x01

				for _, req := range received[UROUND][round][instance] {
					req.answer <- lsb
				}
				alreadySent[UROUND][round][instance] = true
				coinVals[UROUND][round] = lsb
			}
		}
	}
}
