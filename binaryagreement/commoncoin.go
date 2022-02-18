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
	// Maps from round -> instance -> nodeId
	received := make(map[int]map[int]map[int]*CoinRequest)
	alreadySent := make(map[int]map[int]bool)
	coinVals := make(map[int]byte)

	for request := range cc.RequestChan {
		sender := request.sender
		round := request.round
		instance := request.instance

		// Create a new map the first time a request from a new round comes in
		if received[round] == nil {
			received[round] = make(map[int]map[int]*CoinRequest)
		}
		if alreadySent[round] == nil {
			alreadySent[round] = make(map[int]bool)
		}

		if received[round][instance] == nil {
			received[round][instance] = make(map[int]*CoinRequest)
		}
		received[round][instance][sender] = request

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
		if len(received[round][instance]) >= cc.n/2+1 {
			if alreadySent[round][instance] {
				// If the coin was already created and multicasted and if some node asks for the value at a later time, send the value only to this node
				request.answer <- coinVals[round]
			} else {
				// Combine all received signature shares to a certificate
				// log.Println("Creating certificate in round", round)
				var sigShares tcrsa.SigShareList
				for _, req := range received[round][instance] {
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

				for _, req := range received[round][instance] {
					req.answer <- lsb
				}
				alreadySent[round][instance] = true
				coinVals[round] = lsb
			}
		}
	}
}
