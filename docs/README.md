# Caddy Agent - Multi-Host Docker Reverse Proxy

A Python-based agent system for managing Caddy reverse proxy across multiple Docker hosts without requiring container orchestration (Kubernetes, Docker Swarm, etc.).

## Overview

**Caddy Agent** automatically discovers containers across multiple hosts and configures reverse proxy routes in Caddy via its Admin API. Perfect for environments where you want Caddy's simplicity and Let's Encrypt integration without the complexity of full orchestration.

### Key Features

- ✅ **Multi-Host Support** - Manage Caddy routes across multiple physical hosts
- ✅ **Automatic Discovery** - Watch Docker events and auto-configure routes from container labels
- ✅ **Zero Downtime** - Update Caddy config via Admin API without restart
- ✅ **Agent Coordination** - Multiple agents safely update routes with conflict prevention
- ✅ **Dynamic Updates** - Add/remove/restart containers, routes update automatically
- ✅ **Simple Configuration** - Docker labels define routes, no external config files needed
- ✅ **Production Ready** - Tested across 3 hosts with comprehensive test suite

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        host1 (Server)                           │
│  ┌──────────────┐      ┌─────────────────────────────────┐     │
│  │ Caddy Server │◄─────┤ Agent (Server Mode)             │     │
│  │ (80/443/2019)│      │ - Watches local Docker          │     │
│  └──────────────┘      │ - Serves Admin API              │     │
│         ▲              │ - Merges routes from all agents │     │
│         │              └─────────────────────────────────┘     │
│         │                                                       │
└─────────┼───────────────────────────────────────────────────────┘
          │ HTTP POST :2019/load
    ┌─────┴────────────────────────────────┐
    │                                      │
┌───┴─────────────────┐    ┌──────────────┴────┐
│  host2 (Agent)      │    │  host3 (Agent)    │
│ ┌─────────────────┐ │    │ ┌────────────────┐│
│ │ Agent (Remote)  │ │    │ │ Agent (Remote) ││
│ │ - Watches local │ │    │ │ - Watches local││
│ │   Docker        │ │    │ │   Docker       ││
│ └─────────────────┘ │    │ └────────────────┘│
└─────────────────────┘    └───────────────────┘
```

## How It Works

1. **Agent Discovery** - Each agent watches its local Docker daemon for events
2. **Label Reading** - Extracts route information from container labels (e.g., `caddy=example.com`)
3. **Route Generation** - Creates Caddy reverse proxy configuration from labels
4. **Merge Strategy** - Uses AGENT_ID prefixing to prevent route conflicts
5. **API Update** - POSTs merged config to Caddy Admin API (port 2019)
6. **Zero Downtime** - Caddy reloads config without dropping connections

## Quick Start

### Prerequisites

- Docker (any recent version)
- 3+ hosts (or can run all on localhost for testing)
- Network connectivity between hosts on port 2019 (Caddy Admin API)

### 1. Build the Agent Image

```bash
cd caddy-agent
docker build -t caddy-agent:latest .
docker save caddy-agent:latest | gzip > caddy-agent.tar.gz
```

### 2. Deploy on Host1 (Server)

```bash
scp caddy-agent.tar.gz docker-compose-prod-server.yml Caddyfile root@host1:/root/caddy/
ssh root@host1 << 'EOF'
  cd /root/caddy
  gunzip -c caddy-agent.tar.gz | docker load
  docker compose -f docker-compose-prod-server.yml up -d
EOF
```

### 3. Deploy on Host2 (Agent)

```bash
scp caddy-agent.tar.gz docker-compose-prod-agent2.yml root@host2:/root/caddy/
ssh root@host2 << 'EOF'
  cd /root/caddy
  gunzip -c caddy-agent.tar.gz | docker load
  docker compose -f docker-compose-prod-agent2.yml up -d
EOF
```

### 4. Deploy Your First Container

```bash
# On host2, create a container with caddy labels
docker run -d \
  --name myapp \
  --network host \
  --label caddy=myapp.example.com \
  --label caddy.reverse_proxy=192.168.1.10:3000 \
  myapp:latest
```

### 5. Verify Routing

```bash
# From any host
curl -H "Host: myapp.example.com" http://192.168.1.10

# Or with DNS pointing to host1
curl https://myapp.example.com
```

## Configuration

### Agent Modes

| Mode | Use Case | Config |
|------|----------|--------|
| `standalone` | Single host, local Caddy | `AGENT_MODE=standalone` |
| `server` | Multi-host server node | `AGENT_MODE=server` |
| `agent` | Remote agent node | `AGENT_MODE=agent` |

### Environment Variables

```bash
# All modes
AGENT_MODE=server|agent|standalone    # Operation mode (default: standalone)
AGENT_ID=myhost-1                     # Unique identifier (default: hostname)
DOCKER_LABEL_PREFIX=caddy             # Label prefix to watch (default: caddy)

# Server mode
CADDY_API_URL=http://localhost:2019   # Local Caddy Admin API

# Agent mode
CADDY_SERVER_URL=http://host1:2019    # Remote Caddy Admin API
HOST_IP=192.168.1.11                  # This host's IP (auto-detected if not set)

# Optional
CADDY_API_TOKEN=secret123             # API token (if Caddy requires auth)
AGENT_FILTER_LABEL=team=backend       # Filter containers by label
```

### Docker Labels

Container labels define routes. Format:

```dockerfile
LABEL caddy=example.com                              # Domain
LABEL caddy.reverse_proxy=192.168.1.10:3000         # Upstream target
```

Advanced labels:

```dockerfile
# Use {{upstreams PORT}} to auto-detect published port
LABEL caddy.reverse_proxy={{upstreams 3000}}

# Or explicit host:port
LABEL caddy.reverse_proxy=localhost:8080
```

## Examples

### Single Host (Standalone Mode)

```yaml
# docker-compose.yml
version: '3'
services:
  caddy:
    image: caddy:2
    network_mode: host
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config

  agent:
    image: caddy-agent:latest
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - AGENT_MODE=standalone
      - AGENT_ID=localhost

  myapp:
    image: myapp:latest
    network_mode: host
    labels:
      caddy: myapp.localhost
      caddy.reverse_proxy: localhost:3000

volumes:
  caddy_data:
  caddy_config:
```

### Multi-Host Setup

**Host1 (Server):**
```yaml
services:
  caddy:
    image: caddy:2
    network_mode: host
    ports:
      - "80:80"
      - "443:443"
      - "2019:2019"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config

  agent:
    image: caddy-agent:latest
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - AGENT_MODE=server
      - AGENT_ID=host1-server
      - CADDY_API_URL=http://localhost:2019
```

**Host2/Host3 (Agents):**
```yaml
services:
  agent:
    image: caddy-agent:latest
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - AGENT_MODE=agent
      - AGENT_ID=host2-remote
      - CADDY_SERVER_URL=http://192.168.1.10:2019
      - HOST_IP=192.168.1.11
```

## Route Merging Strategy

Multiple agents can safely update routes without conflicts through AGENT_ID prefixing:

- **Route ID Format**: `{AGENT_ID}_{container_name}`
- **Example**: `host1-server_api`, `host2-remote_web`, `host3-remote_db`
- **Merge Logic**: Each agent keeps routes from other agents and updates its own

This prevents agents from overwriting each other's routes while allowing dynamic updates.

## Troubleshooting

### Routes Not Appearing

```bash
# Check agent logs
docker logs caddy-agent-server

# Verify Caddy API is accessible
curl http://localhost:2019/config/

# Check container labels
docker inspect mycontainer | jq '.Config.Labels'

# Verify agent mode and server URL
docker inspect caddy-agent-server | grep -A5 AGENT_MODE
```

### Caddy Config Won't Load

```bash
# Check Caddy logs
docker logs caddy-server

# Validate JSON config
curl http://localhost:2019/config/ | python3 -m json.tool

# Check for admin API errors
curl -v http://localhost:2019/config/ 2>&1 | grep -E "HTTP|Error"
```

### Routes Disappearing After Server Restart

Caddy doesn't persist config by default. Agents will resync when the server restarts, but this takes time.

**Solution**: Use persistent config storage or implement agent heartbeat/watchdog.

### Port Binding Issues

```bash
# Allow unprivileged port binding (if needed)
sysctl -w net.ipv4.ip_unprivileged_port_start=80

# Verify ports are available
netstat -tulpn | grep -E ':80|:443|:2019'
```

## API Reference

### Caddy Admin API Endpoints

Caddy Agent uses these endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/config/` | GET | Fetch current config |
| `/load` | POST | Load new config |
| `/config/apps/http/servers/reverse_proxy/routes` | GET | List all routes |

Example:

```bash
# Get current routes
curl http://localhost:2019/config/apps/http/servers/reverse_proxy/routes | jq

# Count routes
curl http://localhost:2019/config/apps/http/servers/reverse_proxy/routes | \
  jq 'length'

# Filter routes by agent
curl http://localhost:2019/config/apps/http/servers/reverse_proxy/routes | \
  jq '.[] | select(.["@id"] | startswith("host2"))'
```

## Performance

Tested with:
- **3 hosts** (host1: server, host2-3: agents)
- **Multiple containers**: Handled 5+ concurrent container additions
- **Rapid updates**: 3+ container restarts per second without issues
- **Concurrent agents**: 3 agents pushing routes simultaneously without conflicts

## Limitations

1. **Configuration Persistence**: Caddy loses routes on restart (doesn't persist by default)
2. **Stale Route Cleanup**: Dead agents' routes remain until agent restarts or manual cleanup
3. **No Automatic Failover**: If server goes down, agents can't update routes
4. **Published Ports Required**: Agent mode requires containers to publish ports to host
5. **No Service Discovery**: Containers must explicitly set labels (no auto-discovery)

## Development

### Building from Source

```bash
# Install dependencies
pip install docker requests

# Run locally
export AGENT_MODE=standalone
python caddy-agent-watch.py

# Build Docker image
docker build -t caddy-agent:latest .
```

### Testing

Full test suite included in [05-TESTING-PLAN.md](05-TESTING-PLAN.md):

```bash
# Run all tests
bash test-all.sh

# Or manually run test categories:
# 1. Deployment tests
# 2. Routing tests
# 3. Dynamic updates
# 4. Multi-agent coordination
# 5. Failure scenarios
# 6. Performance tests
# 7. Edge cases
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## Support & Issues

- **GitHub Issues**: Report bugs and request features
- **Documentation**: See [docs/](docs/) directory
- **Test Results**: See [06-TEST-RUN-*.md](06-TEST-RUN-2025-11-16.md) for latest test run

## Roadmap

- [ ] Persistent configuration storage
- [ ] Agent heartbeat/TTL mechanism for stale route cleanup
- [ ] Prometheus metrics export
- [ ] Support for multiple Caddy instances
- [ ] Automatic failover/backup server support
- [ ] Web UI for route management
- [ ] Kubernetes operator

## FAQ

**Q: Can I use this without Docker?**
A: No, the agent watches Docker daemon events. For non-Docker use cases, consider using Caddy's native config.

**Q: Does it work with Kubernetes?**
A: Not directly. Kubernetes users should use Caddy's Kubernetes plugin or Traefik.

**Q: How do I secure the Admin API?**
A: Implement IP whitelisting at firewall level or use API tokens (environment variable support included).

**Q: Can I mix this with manual Caddy config?**
A: Yes, but agent routes will be in a separate route block. Be careful with overlapping domains.

**Q: What happens if two containers have the same domain label?**
A: The agent will overwrite with the latest one. Use unique domains or filter containers by label.

---

**Version**: 1.0
**Status**: Production Ready
**Last Updated**: 2025-11-16
