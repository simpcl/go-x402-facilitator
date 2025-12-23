#!/bin/bash

export CHAIN_NETWORK="localhost"
export CHAIN_ID="1337"
export CHAIN_RPC="http://127.0.0.1:8545"
export TOKEN_CONTRACT="0xBA32c2Ee180e743cCe34CbbC86cb79278C116CEb"
export TOKEN_NAME="MyToken"
export TOKEN_VERSION="1"
export FACILITATOR_URL="http://localhost:8080"

export PAYER_PRIVATE_KEY=""

export PAYEE_WALLET_ADDRESS="0x"
go run examples/pay.go examples/common.go
