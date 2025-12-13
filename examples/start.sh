#!/bin/bash

export CHAIN_NETWORK="localhost"
export CHAIN_ID="1337"
export CHAIN_RPC="http://127.0.0.1:8545"
export TOKEN_CONTRACT="0xC35898F0f03C0894107869844d7467Af417aD868"
export FACILITATOR_URL="http://localhost:8080"

export PAYER_PRIVATE_KEY=""
export PAYEE_WALLET_ADDRESS="0x"

go run examples/payer.go examples/common.go examples/account.go
