#! /bin/bash

# JWT_SECRET=$(openssl rand -base64 32)
# echo "Generated JWT Secret: $JWT_SECRET"
set -a
source .env
set +a

echo "Starting X402 Facilitator"
go run cmd/main.go -config config.yaml