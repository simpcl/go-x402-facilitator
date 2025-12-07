# Go X402 Facilitator

X402 payment facilitator service written in Go, supporting exact@EVM payment scheme verification and settlement.

## Features

- ✅ **Complete Protocol Implementation** - Full X402 exact@EVM scheme support
- ✅ **Production-Ready** - Authentication, logging, metrics, error handling
- ✅ **Multi-Network Support** - Ethereum, Base, Avalanche, Polygon testnets and mainnets
- ✅ **HTTP API** - RESTful endpoints for verify, settle, supported, and discovery
- ✅ **Monitoring** - Prometheus metrics and structured logging
- ✅ **Containerized** - Docker and Docker Compose support
- ✅ **Secure** - API key authentication, request validation
- ✅ **Scalable** - Concurrent processing with graceful shutdown

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   HTTP API      │    │   Facilitator   │    │   EVM Clients   │
│   (Gin)         │───▶│   Service       │───▶│   (go-ethereum) │
│                 │    │                 │    │                 │
│ /verify         │    │ - Verify logic  │    │ - RPC calls     │
│ /settle         │    │ - Settle logic  │    │ - Transaction   │
│ /supported      │    │ - Discovery     │    │   execution     │
│ /discovery      │    │ - Multi-network │    │ - Balance check │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites

- Go 1.21 or later
- Docker and Docker Compose (optional)
- Ethereum private key for transaction signing

### Running

1. **Install dependencies:**
   ```bash
   go mod download
   ```

2. **Configure:**
   ```bash
   cp config.yaml config.local.yaml
   # Edit config.local.yaml as needed
   export X402_FACILITATOR_PRIVATE_KEY=your-private-key-here
   ```

3. **Run:**
   ```bash
   go run cmd/main.go -config config.local.yaml
   ```

## API Documentation

### Endpoints

#### Verify Payment
```http
POST /facilitator/verify
Content-Type: application/json
Authorization: Bearer <api-key>

{
  "paymentPayload": {
    "x402Version": 1,
    "scheme": "exact",
    "network": "base-sepolia",
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
    "network": "base-sepolia",
    "maxAmountRequired": "10000",
    "resource": "https://api.example.com/premium-data",
    "description": "Access to premium market data",
    "mimeType": "application/json",
    "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    "maxTimeoutSeconds": 60,
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  }
}
```

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
Authorization: Bearer <api-key>

# Same request body as /verify
```

**Response:**
```json
{
  "success": true,
  "errorReason": "",
  "transaction": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  "network": "base-sepolia",
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
      "network": "base-sepolia"
    },
    {
      "x402Version": 1,
      "scheme": "exact",
      "network": "base"
    }
  ]
}
```

#### Discover Resources
```http
GET /discovery/resources?type=http&limit=10&offset=0
```

**Response:**
```json
{
  "x402Version": 1,
  "items": [
    {
      "resource": "https://api.example.com/premium-data",
      "type": "http",
      "x402Version": 1,
      "accepts": [...],
      "lastUpdated": 1703123456
    }
  ]
}
```

### Health Checks

- **Health Check:** `GET /health` - Basic health status
- **Readiness Check:** `GET /ready` - Detailed readiness status
- **Metrics:** `GET /metrics` - Prometheus metrics (port 9090)

## Configuration

The service can be configured via:

1. **Configuration file** (`config.yaml`)
2. **Environment variables** (prefixed with `X402_`)

### Key Configuration Options

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: 30s
  write_timeout: 30s

facilitator:
  private_key: ""  # Set via X402_FACILITATOR_PRIVATE_KEY
  gas_limit: 100000

auth:
  enabled: true
  require_auth: false
  api_keys: []  # Set via X402_AUTH_API_KEYS

monitoring:
  metrics_enabled: true
  metrics_port: 9090
  log_level: "info"
  log_format: "json"
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `X402_FACILITATOR_PRIVATE_KEY` | Private key for transaction signing | - |
| `X402_AUTH_API_KEYS` | Comma-separated API keys | - |
| `X402_AUTH_JWT_SECRET` | JWT secret for authentication | - |
| `X402_SERVER_PORT` | Server port | 8080 |
| `X402_MONITORING_LOG_LEVEL` | Log level (trace, debug, info, warn, error) | info |
| `X402_MONITORING_LOG_FORMAT` | Log format (json, console) | json |

## Monitoring

### Metrics

The service exposes Prometheus metrics on port 9090:

- `http_requests_total` - Total HTTP requests by method, path, status
- `http_request_duration_seconds` - HTTP request duration
- `http_active_connections` - Number of active connections

### Logging

Structured JSON logging with the following fields:

- `service` - Service name ("x402-facilitator")
- `version` - Service version
- `request_id` - Unique request identifier
- `method` - HTTP method
- `path` - Request path
- `status` - HTTP status code
- `duration_ms` - Request duration in milliseconds

### Grafana Dashboard

When using Docker Compose, Grafana is available at `http://localhost:3000`:

- Username: `admin`
- Password: Set via `GRAFANA_PASSWORD` environment variable

## Security

### Authentication

The service supports API key authentication:

1. Set `auth.require_auth: true` in configuration
2. Configure API keys via `X402_AUTH_API_KEYS` environment variable
3. Include `Authorization: Bearer <api-key>` header in requests

### Best Practices

1. **Use HTTPS** in production
2. **Secure private keys** - use environment variables, not config files
3. **Enable authentication** for production deployments
4. **Monitor logs** for suspicious activity
5. **Rate limiting** - consider adding rate limiting middleware
6. **Network security** - restrict RPC endpoint access

## Development

### Building

```bash
# Build binary
go build -o x402-facilitator ./cmd
```

## License

This project is licensed under the Apache License - see the [LICENSE](LICENSE) file for details.

## Roadmap

- [ ] Support for additional payment schemes (deferred, subscription)
- [ ] Database integration for payment history
- [ ] Webhook support for payment notifications
- [ ] Advanced rate limiting and throttling
- [ ] Multi-region deployment support
- [ ] GraphQL API alternative
- [ ] SDK for popular languages
