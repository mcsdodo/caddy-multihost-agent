# Remote Access

**Test Hosts** (SSH passwordless with keys):
- host1: `ssh root@192.168.0.96` - Server mode (caddy-docker-proxy)
- host2: `ssh root@192.168.0.98` - Agent mode
- host3: `ssh root@192.168.0.99` - Agent mode

**Production Hosts** (SSH passwordless with keys):
- prod-host1: `ssh root@192.168.0.112` - Server mode
- prod-host2: `ssh root@192.168.0.235` - Agent mode
- prod-host3: `ssh root@192.168.0.212` - Agent mode

IMPORTANT: Developed on Windows, must work on Linux.

---

# Caddy Multi-Host Agent System

> Multi-host Docker reverse proxying using caddy-docker-proxy + custom agents.

## Architecture

```
host1 (.96) - SERVER
├─ Caddy (caddy-docker-proxy)
│  ├─ Port 80/443 (routes)
│  └─ Port 2020 (admin API proxy)
├─ caddy-agent-server (uses 'agent' prefix)
│  └─ Tests server mode functionality
└─ Local containers (via docker labels)
        ▲
        │ HTTP POST :2020/load
    ┌───┴───┐
host2 (.98) host3 (.99)
Agent       Agent
Containers  Containers
```

**Key Points**:
- Server uses `caddy-docker-proxy` for `caddy.*` labeled containers
- `caddy-agent-server` tests server mode with `agent.*` labeled containers
- Admin API exposed via reverse proxy on port 2020 (not 2019 directly)
- Remote agents push routes to :2020 which proxies to internal :2019

## Components

### Server (host1)
- `caddy-docker-proxy` - Watches `caddy.*` labels, manages Caddy config
- `caddy-agent-server` - Watches `agent.*` labels (server mode testing)
- Global config via labels on Caddy container itself
- Admin API proxy: `:2020` → `localhost:2019`

### Dual-Agent Setup on Host1

Host1 runs both systems to test server mode:

| Component | Label Prefix | Purpose |
|-----------|--------------|---------|
| caddy-docker-proxy | `caddy.*` | Production routing |
| caddy-agent-server | `agent.*` | Server mode testing |

Test domains use `*.server.lan` pattern (e.g., `test.server.lan`).

### Remote Agents (host2, host3)
- `caddy-agent-watch.py` - Watches Docker events, pushes routes to server
- Connects to `http://192.168.0.96:2020` (not 2019!)

### Route Recovery Mechanism

Agents automatically recover routes after Caddy restarts using two mechanisms:

| Mechanism | Interval | Purpose |
|-----------|----------|---------|
| Health check | 5s | Fast detection of missing routes |
| Periodic resync | 300s | Fallback for network issues |

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `HEALTH_CHECK_INTERVAL` | `5` | Seconds between health checks. `0` to disable. |
| `RESYNC_INTERVAL` | `300` | Seconds between periodic resyncs. `0` to disable. |

**How it works:**
1. Health check runs every 5s, compares route count in Caddy vs expected from Docker
2. If routes missing, triggers resync within ~15s (10s startup delay + 5s check)
3. Exponential backoff (5s → 10s → 20s → 30s max) when Caddy API unreachable
4. Periodic resync runs every 5 minutes as fallback

**Test recovery:**
```bash
# Restart Caddy and observe recovery
ssh root@192.168.0.96 "docker restart caddy-server"
sleep 20
curl -sk --resolve test-remote.lan:443:192.168.0.96 https://test-remote.lan
```

## Docker Compose Files

- `docker-compose-prod-server.yml` - Caddy with caddy-docker-proxy + global config
- `docker-compose-prod-agent2.yml` - Agent + test services (host2)
- `docker-compose-prod-agent3.yml` - Agent + test services (host3)

## Deployment

### Using Scripts (Recommended)

```bash
# Build and deploy all hosts
./deploy-hosts.sh --build

# Deploy single host
./deploy-hosts.sh host1 --build

# Deploy without starting containers
./deploy-hosts.sh --build --no-start

# Cleanup all hosts
./cleanup-hosts.sh

# Cleanup with volume pruning
./cleanup-hosts.sh --volumes
```

### Manual Deployment

```bash
# Build images
docker build -f Dockerfile.Caddy -t caddy-docker-proxy:latest .
docker save caddy-docker-proxy:latest | gzip > caddy-docker-proxy.tar.gz
docker build -t caddy-agent:latest .
docker save caddy-agent:latest | gzip > caddy-agent.tar.gz

# Deploy host1 (server)
scp caddy-docker-proxy.tar.gz docker-compose-prod-server.yml root@192.168.0.96:/root/caddy-multihost/
ssh root@192.168.0.96 "cd /root/caddy-multihost && gunzip -c caddy-docker-proxy.tar.gz | docker load && docker compose -f docker-compose-prod-server.yml up -d"

# Deploy host2/host3 (agents)
scp caddy-agent.tar.gz docker-compose-prod-agent2.yml root@192.168.0.98:/root/caddy-multihost/
ssh root@192.168.0.98 "cd /root/caddy-multihost && gunzip -c caddy-agent.tar.gz | docker load && docker compose -f docker-compose-prod-agent2.yml up -d"
```

## Testing Guide

### Server Configuration (via Caddy labels)

Global config is set via labels on the Caddy container:
- `caddy_0.email` - ACME email
- `caddy_0.auto_https` - prefer_wildcard
- `caddy_1: (wildcard)` - Cloudflare DNS snippet
- `caddy_11: (internal)` - Internal CA snippet for .lan
- `caddy_12: "*.lan"` - Wildcard .lan with internal certs

### Test Routes

Run tests from a Linux host (use `--resolve` for proper SNI):

```bash
# HTTPS routes with internal certificates (.lan)
curl -sk --resolve test-remote.lan:443:192.168.0.96 https://test-remote.lan
curl -sk --resolve host2-app1.lan:443:192.168.0.96 https://host2-app1.lan
curl -sk --resolve test-host3.lan:443:192.168.0.96 https://test-host3.lan

# HTTPS routes with Cloudflare wildcard (*.lacny.me)
curl -sk --resolve test-phase2.lacny.me:443:192.168.0.96 https://test-phase2.lacny.me

# HTTP-only routes (use http:// prefix in labels)
curl -s --resolve httponly.test.lan:80:192.168.0.96 http://httponly.test.lan

# Server mode test routes (uses 'agent' prefix)
curl -sk --resolve test.server.lan:443:192.168.0.96 https://test.server.lan
```

### Verify Routes

```bash
# Check routes via Admin API proxy
curl -s http://192.168.0.96:2020/config/apps/http/servers | python -m json.tool | head -50

# Check agent logs
ssh root@192.168.0.98 "docker logs caddy-agent-remote --tail 10"
ssh root@192.168.0.99 "docker logs caddy-agent-remote3 --tail 10"
```

### Restart After Changes

```bash
# Server - recreate to pick up label changes
ssh root@192.168.0.96 "cd /root/caddy-multihost && docker compose -f docker-compose-prod-server.yml up -d --force-recreate"

# Agents - recreate to pick up env changes
ssh root@192.168.0.98 "cd /root/caddy-multihost && docker compose -f docker-compose-prod-agent2.yml up -d --force-recreate"
ssh root@192.168.0.99 "cd /root/caddy-multihost && docker compose -f docker-compose-prod-agent3.yml up -d --force-recreate"
```

## TLS Certificates

| Domain Pattern | Method | Configuration |
|----------------|--------|---------------|
| `*.lacny.me` | Cloudflare DNS | `caddy.import: wildcard` |
| `*.lan` | Internal CA | `caddy.import: internal` (or auto) |
| `http://domain` | No TLS | Routes to srv2 (HTTP-only) |

## File Structure

```
_caddy-testing/
├── caddy-agent-watch.py          # Remote agent script
├── Dockerfile                     # Agent image
├── Dockerfile.Caddy              # Caddy + docker-proxy + cloudflare
├── docker-compose-prod-server.yml # Server (caddy-docker-proxy)
├── docker-compose-prod-agent2.yml # Agent host2
├── docker-compose-prod-agent3.yml # Agent host3
├── deploy-hosts.sh               # Deploy to test hosts
├── cleanup-hosts.sh              # Cleanup test hosts
├── test_all.py                   # Comprehensive test suite
└── CLAUDE.md                      # This file
```

## Automated Testing

```bash
# Run all tests
python test_all.py

# Run unit tests only (no remote hosts needed)
python test_all.py --unit

# Run integration tests only (requires deployed hosts)
python test_all.py --integration

# Run server mode tests only (requires host1 with caddy-agent-server)
python test_all.py --server-mode
```

## Debugging

**Check Admin API:**
```bash
curl -s http://192.168.0.96:2020/config/ | head -c 500
```

**Check server logs:**
```bash
ssh root@192.168.0.96 "docker logs caddy-server --tail 20"
```

**Check agent connectivity:**
```bash
ssh root@192.168.0.98 "curl -s http://192.168.0.96:2020/config/ | head -c 100"
```

## Key Differences from Previous Setup

1. **No caddy-config.json** - Config via Docker labels only
2. **Admin API on :2020** - Not :2019 (internal only)
3. **caddy-docker-proxy** - Handles local containers automatically
4. **Agents use :2020** - `CADDY_URL=http://192.168.0.96:2020`
