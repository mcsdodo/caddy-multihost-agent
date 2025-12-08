# Test Infrastructure

Test environment for caddy-multihost-agent on remote hosts.

## Test Hosts

| Host | IP | Role |
|------|-----|------|
| host1 | 192.168.0.96 | Server (caddy-docker-proxy) |
| host2 | 192.168.0.98 | Agent |
| host3 | 192.168.0.99 | Agent |

## Quick Start

```bash
# Build and deploy all hosts
./deploy-hosts.sh --build

# Run integration tests
python test_all.py --integration

# Cleanup
./cleanup-hosts.sh
```

## Files

| File | Description |
|------|-------------|
| `Dockerfile.Caddy` | Caddy image with docker-proxy, cloudflare DNS, and Layer4 |
| `docker-compose-prod-server.yml` | Server compose (host1) |
| `docker-compose-prod-agent2.yml` | Agent compose (host2) |
| `docker-compose-prod-agent3.yml` | Agent compose (host3) |
| `deploy-hosts.sh` | Deploy to test hosts |
| `cleanup-hosts.sh` | Remove containers from hosts |
| `test_all.py` | Automated test suite |
| `.env.example` | Environment variables template |

## Environment Variables

Copy `.env.example` and set:
- `CF_API_TOKEN` - Cloudflare API token for DNS challenge
- `EMAIL` - ACME email for Let's Encrypt

## Layer4 Support

The test Caddy image includes Layer4 (TCP/UDP) module. Use labels:

```yaml
labels:
  caddy.layer4: ":1883"
  caddy.layer4.route.proxy: "localhost:11883"
```

## Test Commands

```bash
# Unit tests (no hosts needed)
python test_all.py --unit

# Integration tests
python test_all.py --integration

# Server mode tests
python test_all.py --server-mode

# All tests
python test_all.py
```
