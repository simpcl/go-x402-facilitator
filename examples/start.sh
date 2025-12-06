#!/bin/bash

export PAYER_PRIVATE_KEY=""
export PAYEE_WALLET_ADDRESS="0x"

go run examples/payer.go examples/common.go examples/account.go
