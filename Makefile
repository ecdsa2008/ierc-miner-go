.PHONY: dev prod test

run-test:
	go run cmd/mint/main.go -m="test test test test test test test test test test test junk" -workload=0x00 -tick=cro -amount=1000 -rpc="http://127.0.0.1:8545" -start-account-index=2