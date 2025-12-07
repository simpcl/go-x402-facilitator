#! /bin/bash

# JWT_SECRET=$(openssl rand -base64 32)
# echo "Generated JWT Secret: $JWT_SECRET"

# # 2. 设置环境变量
# export X402_AUTH_JWT_SECRET="$JWT_SECRET"
# export X402_FACILITATOR_PRIVATE_KEY="43ebbdeddabbc90732ffc9fbb3a8ac8f9b5c41585da86a5cf2603d84b9f75281"
# #export X402_FACILITATOR_PRIVATE_KEY="f2c4e8be64a85540d642c86111f948c1ea2033c47734c70bd5e4698fec0f674f"

# # 3. 可选：设置 API keys
# export X402_AUTH_API_KEYS="key1,key2,key3"

source .env

echo "Starting X402 Facilitator"
go run cmd/main.go -config config.yaml