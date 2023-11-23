package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"
)

const RPC_URL = "http://127.0.0.1:8545"

var ZERO_ADDRESS = common.HexToAddress("0x0000000000000000000000000000000000000000")

var globalEthClient *ethclient.Client

var globalTxNonce uint64 = 0
var globalTxNonceMutex = sync.Mutex{}

var globalTxGasPrice *big.Int
var globalTxGasPriceMutex = sync.Mutex{}

var mixPayloadNonce = 200
var mutex = sync.Mutex{}

func main() {
	// 传入私钥 解析私钥 传入tick，workload,amount
	privateKeyString := flag.String("key", "error", "Set your environment")
	workloadString := flag.String("workload", "error", "Set your environment")
	tickString := flag.String("tick", "error", "Set your environment")
	amountString := flag.String("amount", "error", "Set your environment")
	flag.Parse()
	if privateKeyString == nil || *privateKeyString == "error" || workloadString == nil || *workloadString == "error" || tickString == nil || *tickString == "error" || amountString == nil || *amountString == "error" {
		log.Fatalln("Error: invalid params")
		return
	}

	privateKeyStringTemp := strings.Replace(*privateKeyString, "0x", "", -1)
	privateKeyString = &privateKeyStringTemp

	log.Println("Private key: ", *privateKeyString)
	log.Println("Workload: ", *workloadString)
	log.Println("Tick: ", *tickString)
	log.Println("Amount: ", *amountString)

	// parse private key
	privateKey, err := crypto.HexToECDSA(*privateKeyString)
	if err != nil {
		log.Fatalf("Error converting private key: %s", err)
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	log.Println("Address: ", address.Hex())

	eClint, err := ethclient.Dial(RPC_URL)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	globalEthClient = eClint
	accountNonce, err := globalEthClient.PendingNonceAt(context.Background(), address)
	if err != nil {
		log.Fatalln("Error getting account nonce: ", err)
	}
	globalTxNonce = accountNonce
	gasPrice, err := globalEthClient.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalln("Error getting gas price: ", err)
	}
	globalTxGasPrice = gasPrice
	log.Println("Account nonce: ", globalTxNonce, " Gas price: ", globalTxGasPrice)

	// 开启10个goroutine
	for i := 0; i < 10; i++ {
		go func(privateKey *ecdsa.PrivateKey) {
			for {
				gasLimit := uint64(25000)
				payloadNonce := genPayloadNonce()
				payload := fmt.Sprintf(`data:application/json,{"p":"ierc-20","op":"mint","tick":"%s","amt":"%s","nonce":"%s"}`, *tickString, *amountString, payloadNonce)

				globalTxNonceMutex.Lock()
				txNonce := globalTxNonce
				globalTxNonceMutex.Unlock()

				globalTxGasPriceMutex.Lock()
				txGasPrice := globalTxGasPrice
				globalTxGasPriceMutex.Unlock()

				tx := types.NewTx(&types.LegacyTx{
					Nonce:    txNonce,
					To:       &ZERO_ADDRESS,
					Value:    big.NewInt(0),
					Gas:      gasLimit,
					GasPrice: txGasPrice,
					Data:     []byte(payload),
				})

				signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, privateKey)
				if err != nil {
					log.Fatalln("Error signing tx: ", err)
				}
				txHash := signedTx.Hash()
				txHashString := txHash.Hex()
				if strings.HasPrefix(txHashString, *workloadString) {
					log.Println("Find workload tx hash: ", txHashString)
					log.Println("Find workload tx nonce: ", txNonce)
					log.Println("Find workload tx gas price: ", txGasPrice)
					log.Println("Find workload tx payload: ", payload)
					log.Println("Find workload tx payload nonce: ", payloadNonce)
					log.Println("Find workload tx payload tick: ", *tickString)
					log.Println("Find workload tx payload amount: ", *amountString)
					log.Println("Find workload tx address: ", address.Hex())
					rawTxBytes, err := signedTx.MarshalBinary()
					if err != nil {
						log.Fatalf("failed to encode transaction: %v", err)
					}
					rawTxHex := hex.EncodeToString(rawTxBytes)
					log.Println("Find workload tx raw: ", rawTxHex)

					globalTxNonceMutex.Lock()
					if signedTx.Nonce() != globalTxNonce {
						log.Println("Skip changed nonce: ", signedTx.Nonce(), globalTxNonce)
						globalTxNonceMutex.Unlock()
						continue
					}
					err = globalEthClient.SendTransaction(context.Background(), signedTx)
					if err != nil {
						log.Fatalln("Error sending tx: ", err)
					}
					time.Sleep(5 * time.Second)
					globalTxNonceMutex.Unlock()

					log.Println("Sent out tx: ", txHashString, " nonce: ", txNonce, " gas price: ", txGasPrice, " payload: ", payload, " payload nonce: ", payloadNonce, " payload tick: ", *tickString, " payload amount: ", *amountString, " payload address: ", address.Hex(), " raw: ", rawTxHex)
					globalTxNonceMutex.Lock()
					globalTxNonce++
					globalTxNonceMutex.Unlock()

					globalTxGasPriceMutex.Lock()
					globalTxGasPrice, err = globalEthClient.SuggestGasPrice(context.Background())
					if err != nil {
						log.Fatalln("Error getting gas price: ", err)
					}
					globalTxGasPriceMutex.Unlock()
				}
			}
		}(privateKey)
	}
	select {}
}

func genPayloadNonce() string {
	currentTimestamp := time.Now().UnixNano() / 1e6
	mutex.Lock()
	mixPayloadNonce++
	defer mutex.Unlock()
	currentTimestampString := fmt.Sprintf("%d", currentTimestamp)
	nonceString := fmt.Sprintf("%d", mixPayloadNonce)
	nonce := currentTimestampString + nonceString
	return nonce
}
