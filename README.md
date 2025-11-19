# go-x402-facilitator

A Go implementation of x402 payment facilitators, providing gasless ERC20 token transfers and payment processing functionality.

## Features

- **Multiple Facilitators**: Alpha (0.5%), Beta (1.0%), Gamma (2.0%) fee structures
- **EIP-2612 Support**: Gasless permit-based payments
- **Generic ERC20 Transfers**: Support for any ERC20 token contract
- **Gas Limit Control**: Customizable gas limits for transactions
- **Real-time Statistics**: Live monitoring and settlement tracking
- **BNB Testnet Ready**: Configured for BNB Chain testnet

## API Endpoints

### Facilitator Services

#### POST `/api/facilitators/alpha`
- **Fee**: 0.5%
- **Description**: Alpha facilitator payment processing
- **Request Body**:
```json
{
  "owner": "0x...",
  "value": "1000000",
  "deadline": "1234567890",
  "v": 27,
  "r": "0x...",
  "s": "0x..."
}
```

#### POST `/api/facilitators/beta`
- **Fee**: 1.0%
- **Description**: Beta facilitator payment processing

#### POST `/api/facilitators/gamma`
- **Fee**: 2.0%
- **Description**: Gamma facilitator payment processing

### Generic ERC20 Transfer

#### POST `/api/transfer`
- **Description**: Transfer any ERC20 tokens with custom gas limits
- **Request Body**:
```json
{
  "privateKey": "your_private_key",
  "tokenAddress": "0x...",
  "destination": "0x...",
  "amount": "1.5",
  "gasLimit": 100000
}
```

### Merchant Endpoints

#### GET `/api/secret`
- **Description**: Protected resource that returns 402 Payment Required with facilitator list
- **Headers**: `x-paid-proof: facilitator_name` to access protected content

#### GET `/api/stats`
- **Description**: Real-time statistics and settlement history
- **Response**: Facilitator status, transaction volumes, uptime metrics

#### GET `/api/health`
- **Description**: Health check endpoint

## Installation & Setup

1. **Clone and install dependencies**:
```bash
git clone <repository>
cd go-x402-facilitator
go mod tidy
```

2. **Environment Configuration**:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Required Environment Variables**:
```bash
# Blockchain Configuration
BLOCKCHAIN_RPC=http://127.0.0.1:8545
BLOCKCHAIN_ID=1337

# Token Configuration
GENERIC_ERC20_TOKEN_CONTRACT_ADDRESS=0x6C90aa4A4196E01dba6Ff8269493FDa7b66b95C5

# Facilitator Private Keys (TESTNET ONLY)
FACILITATOR_ALPHA_PRIVATE_KEY=your_alpha_private_key
FACILITATOR_BETA_PRIVATE_KEY=your_beta_private_key
FACILITATOR_GAMMA_PRIVATE_KEY=your_gamma_private_key

# Merchant Configuration
MERCHANT_WALLET_ADDRESS=0x183052a3526d2ebd0f8dd7a90bed2943e0126795

# Server Configuration
PORT=8080
HOST=localhost
```

4. **Run the server**:
```bash
go run main.go
```

## Usage Examples

### Direct ERC20 Transfer

```bash
curl -X POST http://localhost:8080/api/transfer \
  -H "Content-Type: application/json" \
  -d '{
    "privateKey": "your_private_key",
    "tokenAddress": "0xcfFA309a5Fb3ac7419eBC8Ba4a6063Ff2a7585F5",
    "destination": "0x183052a3526d2ebd0f8dd7a90bed2943e0126795",
    "amount": "10.5",
    "gasLimit": 100000
  }'
```

### Access Protected Resource

```bash
# First call returns 402 with facilitator list
curl http://localhost:8080/api/secret

# Response:
{
  "price": "1 tokens",
  "asset": "0xcfFA309a5Fb3ac7419eBC8Ba4a6063Ff2a7585F5",
  "facilitators": [
    {
      "name": "Alpha",
      "fee": "0.5%",
      "endpoint": "/api/facilitators/alpha",
      "address": "0x...",
      "live": true
    }
  ]
}
```

### View Statistics

```bash
curl http://localhost:8080/api/stats
```

## Project Structure

```
go-x402-facilitator/
├── config/           # Configuration management
├── models/           # Data models and types
├── blockchain/       # Ethereum/BNB Chain interactions
├── services/         # Business logic services
├── handlers/         # HTTP request handlers
├── state/            # In-memory state management
├── cmd/server/       # Server entry point
├── main.go          # Main application
├── .env.example     # Environment template
└── README.md        # This file
```

## Architecture

The project follows the original Facora architecture:

- **Facilitator Layer**: Multiple facilitators competing on fees and uptime
- **State Management**: In-memory tracking of settlements and statistics
- **Blockchain Integration**: Direct interaction with ERC20 tokens and EIP-2612 permits
- **API Layer**: RESTful endpoints matching the original specification

## Security Notes

- **TESTNET ONLY**: This implementation is configured for BNB Testnet only
- **Private Keys**: Never expose private keys in production environments
- **Gas Management**: Facilitators pay gas for users (sponsorship model)
- **Rate Limiting**: Consider implementing rate limiting for production use

## Development

### Build for Production
```bash
go build -o x402-facilitator main.go
./x402-facilitator
```

### Testing
```bash
go test ./...
```

### Dependencies
- `github.com/ethereum/go-ethereum` - Ethereum blockchain interaction
- `github.com/gin-gonic/gin` - HTTP web framework
- `github.com/shopspring/decimal` - Precise decimal arithmetic


## Acknowledgments

Based on the original Facora project architecture for x402 payments on BNB Chain.
