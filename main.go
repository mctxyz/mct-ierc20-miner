package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/shopspring/decimal"
	"github.com/urfave/cli"
	"log"
	"math/big"
	"os"
	"runtime"
	"strings"
	"time"
)

var (
	app *cli.App = cli.NewApp()
)

func init() {
	app.Name = "IERC20 Miner"
	app.Author = "MCT"
	app.Version = "1.0.0"
	app.Commands = []cli.Command{
		{
			Name:  "mine",
			Usage: "mine",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "rpc",
					Value: "https://mainnet.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161",
					Usage: "rpc url",
				},
				&cli.StringFlag{
					Name:  "ticker",
					Value: "",
					Usage: "IERC Ticker",
				},
				&cli.StringFlag{
					Name:  "diff",
					Value: "",
					Usage: "difficulty",
				},
				&cli.StringFlag{
					Name:  "pk",
					Value: "",
					Usage: "PrivateKey",
				},
				&cli.Int64Flag{
					Name:  "amount",
					Value: 1000,
					Usage: "Amount",
				},
				&cli.Float64Flag{
					Name:  "maxFee",
					Value: 0,
					Usage: "MaxFeePerGas",
				},
				&cli.Float64Flag{
					Name:  "priorityFee",
					Value: 0,
					Usage: "MaxPriorityFeePerGas",
				},
				&cli.Int64Flag{
					Name:  "n",
					Value: 1,
					Usage: "Number of executions",
				},
			},
			Action: mine,
		},
	}

}
func main() {

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

}
func mine(ctx *cli.Context) error {
	if ctx.String("rpc") == "" {
		fmt.Fprintln(os.Stderr, "Please enter rpc url!")
		return nil

	}
	if ctx.String("ticker") == "" {
		fmt.Fprintln(os.Stderr, "Please enter ticker!")
		return nil
	}
	if ctx.String("diff") == "" {
		fmt.Fprintln(os.Stderr, "Please enter difficulty!")
		return nil
	}
	if ctx.String("pk") == "" {
		fmt.Fprintln(os.Stderr, "Please enter privateKey!")
		return nil
	}
	config := &MineCfg{
		RPC:         ctx.String("rpc"),
		Ticker:      ctx.String("ticker"),
		DIfficulty:  ctx.String("diff"),
		PrivateKey:  ctx.String("pk"),
		Amount:      ctx.Int64("amount"),
		MaxFee:      ctx.Float64("maxFee"),
		PriorityFee: ctx.Float64("priorityFee"),
	}
	for i := 0; i < int(ctx.Float64("n")); i++ {
		fmt.Println(fmt.Sprintf("====================================================== %d ======================================================", i+1))
		if err := startMine(config); err != nil {
			log.Println("mine error", err)
		}
		//time.Sleep(5 * time.Second)
	}
	return nil

}

type MineCfg struct {
	RPC         string
	Ticker      string
	DIfficulty  string
	PrivateKey  string
	Amount      int64
	MaxFee      float64
	PriorityFee float64
}

func startMine(cfg *MineCfg) error {

	client, err := ethclient.Dial(cfg.RPC)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Rpc connect error "+err.Error())
		return nil
	}
	defer client.Close()
	gas, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		panic(err)
	}
	ticker := cfg.Ticker
	privateKey := strings.ReplaceAll(cfg.PrivateKey, "0x", "")
	pk, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		panic(err)
		//log.Fatal(err)
	}
	publicKey := pk.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("error casting public key to ECDSA")
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	log.Println("Wallet: ", fromAddress.Hex())
	log.Println("Ticker: ", ticker)
	log.Println("Difficulty: ", cfg.DIfficulty)
	log.Println("Amount: ", cfg.Amount)
	maxFee := cfg.MaxFee
	maxFeePerGas := (&big.Int{}).Mul((&big.Int{}).Div(gas, big.NewInt(100)), big.NewInt(150))
	maxPriorityFeePerGas := (&big.Int{}).Div((&big.Int{}).Mul(gas, big.NewInt(15)), big.NewInt(100))
	if maxFee != 0 {
		maxFeePerGas = ToWei(maxFee, 9)
	}
	priorityFee := cfg.PriorityFee
	if priorityFee != 0 {
		maxPriorityFeePerGas = ToWei(priorityFee, 9)
	}
	nonce, err := client.NonceAt(context.Background(), fromAddress, nil)
	log.Println("MaxFee: ", ToDecimal(maxFeePerGas, 9).String(), "Gwei", ", Priority Fee: ", ToDecimal(maxPriorityFeePerGas, 9).String(), "Gwei")
	nullAddress := common.HexToAddress("0x0000000000000000000000000000000000000000")
	var total int64 = 0

	threadCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inscribeTx := make(chan *types.Transaction, 1)
	generateReport := make(chan int, runtime.NumCPU())
	for i := 0; i < runtime.NumCPU(); i++ {
		go func(i int) {
			id := 0
			generated := 0
			for {
				select {
				case <-threadCtx.Done():
					log.Println("stop")
					return
				default:
					now := time.Now().UnixNano()
					callData := fmt.Sprintf(`data:application/json,{"p":"ierc-20","op":"mint","tick":"%s","amt":"%d","nonce":"%d%d%d"}`, ticker, cfg.Amount, now, i, id)
					data := common.Hex2Bytes(stringToHex(callData))
					tx := types.NewTx(&types.DynamicFeeTx{
						ChainID:   big.NewInt(1),
						Nonce:     nonce,
						GasFeeCap: maxFeePerGas,
						GasTipCap: maxPriorityFeePerGas,
						To:        &nullAddress,
						Value:     big.NewInt(0),
						Data:      data,
						Gas:       25000,
					})
					tx, _ = types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(1)), pk)
					hash := tx.Hash().String()
					if strings.Contains(hash, cfg.DIfficulty) {
						log.Println("Found CallData", callData)
						inscribeTx <- tx
					}
					id++
					generated++
					if generated >= 1000 {
						generateReport <- generated
						generated = 0
					}
				}

			}
		}(i)
	}
	intervalTicker := time.Tick(5 * time.Second)
	for {
		select {
		case <-intervalTicker:
			fmt.Printf("%d/s \n", total/5)
			total = 0
		case generated := <-generateReport:
			total += int64(generated)
		case inscribeTx := <-inscribeTx:
			log.Println("Inscribe tx", inscribeTx.Hash().String())
			if err := client.SendTransaction(context.Background(), inscribeTx); err != nil {

				return fmt.Errorf("SendTransaction error: %w", err)
			}
			return nil
		}

	}
	return nil
}
func stringToHex(input string) string {
	// Convert the string to a byte slice
	bytes := []byte(input)

	// Use the hex package to encode the byte slice to a hexadecimal string
	hexString := hex.EncodeToString(bytes)

	return hexString
}
func ToDecimal(ivalue interface{}, decimals int) decimal.Decimal {
	value := new(big.Int)
	switch v := ivalue.(type) {
	case string:
		value.SetString(v, 10)
	case *big.Int:
		value = v
	}

	mul := decimal.NewFromFloat(float64(10)).Pow(decimal.NewFromFloat(float64(decimals)))
	num, _ := decimal.NewFromString(value.String())
	result := num.Div(mul)

	return result
}

func ToWei(iamount interface{}, decimals int) *big.Int {
	amount := decimal.NewFromFloat(0)
	switch v := iamount.(type) {
	case string:
		amount, _ = decimal.NewFromString(v)
	case float64:
		amount = decimal.NewFromFloat(v)
	case int64:
		amount = decimal.NewFromFloat(float64(v))
	case decimal.Decimal:
		amount = v
	case *decimal.Decimal:
		amount = *v

	}

	mul := decimal.NewFromFloat(float64(10)).Pow(decimal.NewFromFloat(float64(decimals)))
	result := amount.Mul(mul)
	wei := new(big.Int)
	wei.SetString(result.String(), 10)

	return wei
}
