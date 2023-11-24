package main

import (
	"context"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"log"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"time"
)

const EachAccountMaxMintNumber = 10 // 每个账户最多mint10笔同一种资产，这里不做链上历史索引。

var ZeroAddress = common.HexToAddress("0x0000000000000000000000000000000000000000")
var globalEthClient *ethclient.Client
var globalTxNonce uint64 = 0
var globalTxGasPrice *big.Int
var globalCurrentAccountPrivateKey *ecdsa.PrivateKey
var globalCurrentAccountIndex uint

var eachAccountMintedNumber = make(map[string]int)

var mixPayloadNonce = 200

var accountMutex = sync.Mutex{}
var payloadInnerMutex = sync.Mutex{}

var mnemonic string

func main() {
	// tick:币种，workload:挖矿难度,amount:mint数量
	mnemonicString := flag.String("m", "error", "Set your environment")
	// 从哪个账户开始自动化Mint，如果从X开始，当X对应的账户Mint达到10笔后，自动滚动到X+1账户
	starAccountIndex := flag.Uint("start-account-index", 0, "Set your environment")
	workloadString := flag.String("workload", "error", "Set your environment")
	tickString := flag.String("tick", "error", "Set your environment")
	amountString := flag.String("amount", "error", "Set your environment")
	rpcString := flag.String("rpc", "error", "Set your environment")
	flag.Parse()
	if workloadString == nil || *workloadString == "error" || tickString == nil || *tickString == "error" || amountString == nil || *amountString == "error" || mnemonicString == nil || *mnemonicString == "error" || starAccountIndex == nil || *starAccountIndex < 0 || rpcString == nil || *rpcString == "error" {
		log.Fatalln("Error: invalid params")
		return
	}
	log.Println("Workload: ", *workloadString)
	log.Println("Tick: ", *tickString)
	log.Println("Amount: ", *amountString)
	log.Println("Start account index: ", *starAccountIndex)
	log.Println("RPC-URL: ", *rpcString)

	mnemonic = *mnemonicString

	globalCurrentAccountIndex = *starAccountIndex
	eachAccountMintedNumber = make(map[string]int)
	// 生成mint操作账户
	startAccountPriKey := getPrivateKey(*starAccountIndex)
	globalCurrentAccountPrivateKey = startAccountPriKey
	startAccountAddress := crypto.PubkeyToAddress(startAccountPriKey.PublicKey)
	log.Println("Start with mint account address: ", startAccountAddress.Hex())

	eClint, err := ethclient.Dial(*rpcString)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	globalEthClient = eClint
	startAccountNonce, err := globalEthClient.PendingNonceAt(context.Background(), startAccountAddress)
	if err != nil {
		log.Fatalln("Error getting account nonce: ", err)
	}
	globalTxNonce = startAccountNonce
	gasPrice, err := globalEthClient.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalln("Error getting gas price: ", err)
	}
	globalTxGasPrice = gasPrice
	log.Println("Start mint account nonce: ", globalTxNonce, " Gas price: ", globalTxGasPrice)

	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			for {
				gasLimit := uint64(25000)
				payloadNonce := genPayloadNonce()
				payload := fmt.Sprintf(`data:application/json,{"p":"ierc-20","op":"mint","tick":"%s","amt":"%s","nonce":"%s"}`, *tickString, *amountString, payloadNonce)

				accountMutex.Lock()
				txNonce := globalTxNonce
				privateKey := globalCurrentAccountPrivateKey
				txGasPrice := globalTxGasPrice
				accountMutex.Unlock()

				tx := types.NewTx(&types.LegacyTx{
					Nonce:    txNonce,
					To:       &ZeroAddress,
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
				addressString := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
				if strings.HasPrefix(txHashString, *workloadString) {
					// just for debug
					// use https://www.ethereumdecoder.com/ to decode raw tx
					//rawTxBytes, err := signedTx.MarshalBinary()
					//if err != nil {
					//	log.Fatalf("failed to encode transaction: %v", err)
					//}
					//rawTxHex := hex.EncodeToString(rawTxBytes)
					//log.Println("Find workload tx raw: 0x", rawTxHex)
					{
						accountMutex.Lock()
						// 如果该账户nonce已经变化，说明该账户已经被其他程序使用，跳过该交易
						if signedTx.Nonce() != globalTxNonce {
							log.Println("Skip changed nonce: ", signedTx.Nonce(), "=>", globalTxNonce)
							accountMutex.Unlock()
							continue
						}
						// 检查该账户是否已经mint了10笔
						accountMintedNumber := eachAccountMintedNumber[addressString]
						if accountMintedNumber >= EachAccountMaxMintNumber {
							// switch to next account
							globalCurrentAccountIndex++
							globalCurrentAccountPrivateKey = getPrivateKey(globalCurrentAccountIndex)
							globalTxNonce, err = globalEthClient.PendingNonceAt(context.Background(), crypto.PubkeyToAddress(globalCurrentAccountPrivateKey.PublicKey))
							if err != nil {
								log.Fatalln("Error getting account nonce: ", err)
							}
							log.Println("Switch to next mint account: ", crypto.PubkeyToAddress(globalCurrentAccountPrivateKey.PublicKey).Hex(), " index: ", globalCurrentAccountIndex)
							accountMutex.Unlock()
							// 跳过该交易
							continue
						}
						log.Println("Find workload matched tx ==> user address: ", addressString)
						log.Println("Find workload matched tx ==> hash: ", txHashString)
						log.Println("Find workload matched tx ==> nonce: ", txNonce)
						log.Println("Find workload matched tx ==> workload: ", *workloadString)
						log.Println("Find workload matched tx ==> gas limit: ", gasLimit)
						log.Println("Find workload matched tx ==> gas price: ", txGasPrice)
						log.Println("Find workload matched tx ==> payload: ", payload)
						log.Println("Find workload matched tx ==> payload nonce: ", payloadNonce)
						log.Println("Find workload matched tx ==> payload tick: ", *tickString)
						log.Println("Find workload matched tx ==> payload amount: ", *amountString)
						// 发送交易
						err = globalEthClient.SendTransaction(context.Background(), signedTx)
						if err != nil {
							log.Fatalln("Error sending tx: ", err)
						}
						// 必须等待交易确认，该协议要求，同一个区块中+同一个账户+同一个资产的mint交易，只会有一笔生效。
						ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
						for {
							_, isPending, err := globalEthClient.TransactionByHash(context.Background(), txHash)
							if err != nil {
								log.Fatalln("Error getting transaction: ", err)
							}
							if !isPending {
								// 交易已经确认
								log.Println("Sent workload matched tx ==> ", txHashString, "and is confirmed.")
								break
							}
							select {
							case <-ctx.Done():
								cancel()
								// 考虑RBF
								log.Fatalln("Shut down because tx ", txHashString, " is not confirmed in 3 minutes, doing something else.")
							default:
								// 5秒钟轮询一次
								time.Sleep(5 * time.Second)
							}
						}
						globalTxNonce++
						eachAccountMintedNumber[addressString] = accountMintedNumber + 1

						globalTxGasPrice, err = globalEthClient.SuggestGasPrice(context.Background())
						if err != nil {
							log.Fatalln("Error getting gas price: ", err)
						}
						accountMutex.Unlock()
					}
					// 重置payload inner nonce
					payloadInnerMutex.Lock()
					mixPayloadNonce = 200
					payloadInnerMutex.Unlock()
				}
			}
		}()
	}
	select {}
}

func genPayloadNonce() string {
	currentTimestamp := time.Now().UnixNano() / 1e6
	payloadInnerMutex.Lock()
	mixPayloadNonce++
	defer payloadInnerMutex.Unlock()
	currentTimestampString := fmt.Sprintf("%d", currentTimestamp)
	nonceString := fmt.Sprintf("%d", mixPayloadNonce)
	nonce := currentTimestampString + nonceString
	return nonce
}

func getPrivateKey(accountIndex uint) *ecdsa.PrivateKey {
	seed := bip39.NewSeed(mnemonic, "") // 可以提供密码短语
	masterKey, _ := bip32.NewMasterKey(seed)
	// 44'
	purposeKey, _ := masterKey.NewChildKey(0x8000002C)
	// 60'
	coinTypeKey, _ := purposeKey.NewChildKey(0x8000003C)
	// 0'
	accountKey, _ := coinTypeKey.NewChildKey(0x80000000)
	// 0
	changeKey, _ := accountKey.NewChildKey(0)
	// addressIndex
	addressKey, _ := changeKey.NewChildKey(uint32(accountIndex))
	privateKey, _ := crypto.ToECDSA(addressKey.Key)
	return privateKey
}
