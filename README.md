# Go X402 Facilitator

X402 payment facilitator service written in Go, supporting exact@EVM payment scheme verification and settlement.

## Features

- ✅ **Complete Protocol Implementation** - Full X402 exact@EVM scheme support
- ✅ **Production-Ready** - Structured logging, error handling, graceful shutdown
- ✅ **EVM Network Support** - Supports any EVM-compatible network (configurable via RPC endpoint)
- ✅ **HTTP API** - RESTful endpoints for verify, settle, and supported networks
- ✅ **Monitoring** - Structured logging with request tracking
- ✅ **Easy Configuration** - Environment variable based configuration
- ✅ **Secure** - Request validation, CORS support
- ✅ **Scalable** - Concurrent processing with graceful shutdown

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   HTTP API      │    │   Facilitator   │    │   EVM Clients   │
│   (Gin)         │───▶│   Service       │───▶│   (go-ethereum) │
│                 │    │                 │    │                 │
│ /verify         │    │ - Verify logic  │    │ - RPC calls     │
│ /settle         │    │ - Settle logic  │    │ - Transaction   │
│ /supported      │    │ - Network info  │    │   execution     │
│ /health         │    │ - EIP-712 sig   │    │ - Balance check │
│ /ready          │    │   verification  │    │ - Nonce check   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites

- Go 1.21 or later
- Ethereum private key for transaction signing
- Access to an Ethereum RPC endpoint (local node or public RPC)

### Running

1. **Install dependencies:**
   ```bash
   go mod download
   ```

2. **Configure:**
   ```bash
   cp env.example .env
   # Edit .env file with your configuration
   # Required: FACILITATOR_PRIVATE_KEY
   # Required: FACILITATOR_CHAIN_RPC
   # Required: FACILITATOR_CHAIN_ID
   # Required: FACILITATOR_TOKEN_ADDRESS
   ```

3. **Run:**
   ```bash
   # Using .env file (automatically loaded)
   go run cmd/main.go
   
   # Or specify custom config file
   go run cmd/main.go -config .env
   
   # Or use start script
   ./start.sh
   ```

## API Documentation

### Endpoints

#### Verify Payment
```http
POST /facilitator/verify
Content-Type: application/json

{
  "paymentPayload": {
    "x402Version": 1,
    "scheme": "exact",
    "network": "localhost",
    "payload": {
      "signature": "0x...",
      "authorization": {
        "from": "0x...",
        "to": "0x...",
        "value": "10000",
        "validAfter": "1740672089",
        "validBefore": "1740672154",
        "nonce": "0x..."
      }
    }
  },
  "paymentRequirements": {
    "scheme": "exact",
    "network": "localhost",
    "maxAmountRequired": "10000",
    "resource": "https://api.example.com/premium-data",
    "description": "Access to premium market data",
    "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  }
}
```

**Note:** The `network` field must match the `FACILITATOR_NETWORK` configuration value.

**Response:**
```json
{
  "isValid": true,
  "invalidReason": "",
  "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66"
}
```

#### Settle Payment
```http
POST /facilitator/settle
Content-Type: application/json

# Same request body as /verify endpoint
```

**Response:**
```json
{
  "success": true,
  "errorReason": "",
  "transaction": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  "network": "localhost",
  "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66"
}
```

#### Get Supported Networks
```http
GET /facilitator/supported
```

**Response:**
```json
{
  "x402Version": 1,
  "kinds": [
    {
      "x402Version": 1,
      "scheme": "exact",
      "network": "localhost"
    }
  ]
}
```

### Health Checks

- **Health Check:** `GET /health` - Basic health status
- **Readiness Check:** `GET /ready` - Detailed readiness status (checks if facilitator is initialized)

## Configuration

The service is configured via environment variables. You can use a `.env` file (see `env.example`) or set environment variables directly.

### Key Configuration Options

#### Server Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_HOST` | Server host address | `0.0.0.0` |
| `SERVER_PORT` | Server port | `8080` |
| `SERVER_READ_TIMEOUT` | Read timeout duration | `30s` |
| `SERVER_WRITE_TIMEOUT` | Write timeout duration | `30s` |
| `SERVER_IDLE_TIMEOUT` | Idle timeout duration | `120s` |
| `SERVER_LOG_LEVEL` | Log level (trace, debug, info, warn, error, fatal, panic) | `info` |
| `SERVER_LOG_FORMAT` | Log format (json, console) | `json` |

#### Facilitator Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `FACILITATOR_NETWORK` | Network identifier (e.g., localhost, base-sepolia) | `localhost` | Yes |
| `FACILITATOR_CHAIN_RPC` | Ethereum RPC endpoint URL | `http://127.0.0.1:8545` | Yes |
| `FACILITATOR_CHAIN_ID` | Chain ID for the network | `1337` | Yes |
| `FACILITATOR_TOKEN_ADDRESS` | ERC20 token contract address | - | Yes |
| `FACILITATOR_TOKEN_NAME` | Token name (for EIP-712) | `MyToken` | No |
| `FACILITATOR_TOKEN_VERSION` | Token version (for EIP-712) | `1` | No |
| `FACILITATOR_TOKEN_DECIMALS` | Token decimals | `6` | No |
| `FACILITATOR_PRIVATE_KEY` | Private key for transaction signing (hex format, no 0x prefix) | - | **Yes** |
| `FACILITATOR_GAS_LIMIT` | Gas limit for transactions | `100000` | No |
| `FACILITATOR_GAS_PRICE` | Gas price (leave empty for auto) | - | No |
| `FACILITATOR_SUPPORTED_SCHEME` | Supported payment scheme | `exact` | No |

### Example .env File

```bash
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
SERVER_READ_TIMEOUT=30s
SERVER_WRITE_TIMEOUT=30s
SERVER_IDLE_TIMEOUT=120s
SERVER_LOG_LEVEL=info
SERVER_LOG_FORMAT=json

# Facilitator Configuration
FACILITATOR_NETWORK=localhost
FACILITATOR_CHAIN_RPC=http://127.0.0.1:8545
FACILITATOR_CHAIN_ID=1337
FACILITATOR_TOKEN_ADDRESS=0xYourTokenAddress
FACILITATOR_TOKEN_NAME=MyToken
FACILITATOR_TOKEN_VERSION=1
FACILITATOR_TOKEN_DECIMALS=6
FACILITATOR_PRIVATE_KEY=your-private-key-hex-without-0x-prefix
FACILITATOR_GAS_LIMIT=100000
FACILITATOR_SUPPORTED_SCHEME=exact
```

## Monitoring

### Logging

The service uses structured JSON logging (or console format) with the following features:

- **Structured Logging** - JSON format by default for easy parsing
- **Request ID Tracking** - Each request gets a unique ID (via `X-Request-ID` header)
- **Log Levels** - Configurable log levels (trace, debug, info, warn, error, fatal, panic)
- **Context Fields** - Automatic service name and version in all logs

Log fields include:
- `service` - Service name ("x402-facilitator")
- `version` - Service version (1.0.0)
- `request_id` - Unique request identifier
- `method` - HTTP method
- `path` - Request path
- `status` - HTTP status code
- `duration_ms` - Request duration in milliseconds

## Security

### Best Practices

1. **Use HTTPS** in production - Always use TLS/SSL for production deployments
2. **Secure private keys** - Never commit private keys to version control
   - Use environment variables or secure secret management
   - The `.env` file should be in `.gitignore`
3. **Network security** - Restrict RPC endpoint access
   - Use private RPC endpoints when possible
   - Consider rate limiting on RPC calls
4. **Monitor logs** - Regularly review logs for suspicious activity
5. **Input validation** - All requests are validated before processing
6. **CORS configuration** - Currently allows all origins; restrict in production if needed

## Development

### Building

```bash
# Build binary
go build -o x402-facilitator ./cmd/main.go

# Or using the standard Go build command
go build -o bin/x402-facilitator ./cmd
```

### Running Examples

See the `examples/` directory for example usage:

```bash
cd examples
# Set up environment variables (see examples/common.go)
go run pay.go
```

## License

This project is licensed under the Apache License - see the [LICENSE](LICENSE) file for details.

## Roadmap

- [ ] Support for additional payment schemes (deferred, subscription)
- [ ] Database integration for payment history
- [ ] Webhook support for payment notifications
- [ ] Advanced rate limiting and throttling
- [ ] Prometheus metrics endpoint
- [ ] API key authentication middleware
- [ ] Multi-network support (single facilitator instance)
- [ ] SDK for popular languages
