# Caddy Multihost Agent

Extend [caddy-docker-proxy](https://github.com/lucaslorentz/caddy-docker-proxy) to support containers across multiple hosts.

## Why This Exists

[caddy-docker-proxy](https://github.com/lucaslorentz/caddy-docker-proxy) is excellent for automatic reverse proxy configuration via Docker labels on a single host. However, it doesn't support multi-host setups - you can't route traffic to containers running on other machines.

**caddy-multihost-agent** solves this by:
- Running agents on remote hosts that watch local Docker containers
- Pushing route configurations to a central Caddy server via the Admin API
- Using the same Docker label syntax as caddy-docker-proxy

This gives you caddy-docker-proxy's simplicity across your entire infrastructure.

## Quick Start

### Docker Image

```bash
docker pull mcsdodo/caddy-agent:latest
```

### Single Host Setup

For a single host, just use caddy-docker-proxy directly. This agent is only needed for multi-host setups.

### Multi-Host Setup

**Host 1 (Server)** - runs Caddy with caddy-docker-proxy:

```yaml
# docker-compose.yml on host1
services:
  caddy:
    image: lucaslorentz/caddy-docker-proxy:latest
    container_name: caddy-server
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - caddy_data:/data
    labels:
      # Expose Admin API for remote agents
      caddy_0: ":2020"
      caddy_0.reverse_proxy: "localhost:2019"

  # Optional: agent for testing server mode
  caddy-agent:
    image: mcsdodo/caddy-agent:latest
    container_name: caddy-agent-server
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - CADDY_URL=http://localhost:2019
      - AGENT_ID=host1-server
      - DOCKER_LABEL_PREFIX=agent  # Use different prefix to avoid conflict
      - SNIPPET_API_PORT=8567      # Serve snippets to remote agents

volumes:
  caddy_data:
```

**Host 2 (Remote Agent)** - watches containers and pushes routes to host1:

```yaml
# docker-compose.yml on host2
services:
  caddy-agent:
    image: mcsdodo/caddy-agent:latest
    container_name: caddy-agent-remote
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - CADDY_URL=http://192.168.1.10:2020   # Point to host1
      - AGENT_ID=host2-remote
      - DOCKER_LABEL_PREFIX=caddy
      - SNIPPET_SOURCES=http://192.168.1.10:8567  # Fetch snippets from host1

  # Example app - routes automatically configured
  myapp:
    image: nginx
    network_mode: host
    labels:
      caddy: myapp.example.com
      caddy.reverse_proxy: "{{upstreams 80}}"
```

**Test it:**

```bash
# From host1
curl -sk --resolve myapp.example.com:443:127.0.0.1 https://myapp.example.com
```

## Architecture

```
host1 (192.168.1.10) - SERVER
├── Caddy (caddy-docker-proxy)
│   ├── Port 80/443 (routes)
│   └── Port 2020 (Admin API proxy → 2019)
└── Local containers (via caddy.* labels)
        ▲
        │ HTTP POST /load
    ┌───┴───┐
host2       host3
Agent       Agent
└── Local   └── Local
    containers  containers
```

Each agent:
1. Watches its local Docker daemon for container events
2. Extracts route config from `caddy.*` labels
3. Pushes routes to the central Caddy server via Admin API
4. Uses unique `AGENT_ID` prefixes to prevent route conflicts

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CADDY_URL` | `http://localhost:2019` | Caddy Admin API URL |
| `AGENT_ID` | hostname | Unique identifier (prefixes route IDs) |
| `DOCKER_LABEL_PREFIX` | `caddy` | Label prefix to watch |
| `DOCKER_PROXY_URL` | empty | Docker API proxy URL (overrides `DOCKER_HOST`) |
| `HOST_IP` | auto-detected | IP for upstream addresses |
| `SNIPPET_API_PORT` | `0` (disabled) | Port to serve snippet API |
| `SNIPPET_SOURCES` | empty | Comma-separated URLs to fetch snippets |
| `SNIPPET_CACHE_TTL` | `300` | Snippet cache duration in seconds |
| `HEALTH_CHECK_INTERVAL` | `5` | Seconds between health checks |
| `RESYNC_INTERVAL` | `300` | Seconds between full resyncs |
| `CONFIG_PUSH_ENABLED` | `true` | Set to `false` for snippet-only mode |
| `LOG_LEVEL` | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### Docker Labels

Standard caddy-docker-proxy labels work:

```yaml
labels:
  # Basic reverse proxy
  caddy: example.com
  caddy.reverse_proxy: "{{upstreams 8080}}"

  # Multiple domains
  caddy: app1.example.com, app2.example.com
  caddy.reverse_proxy: "{{upstreams 8080}}"

  # HTTP-only (no TLS)
  caddy: http://internal.lan
  caddy.reverse_proxy: "{{upstreams 8080}}"

  # With snippet import
  caddy: secure.example.com
  caddy.import: internal
  caddy.reverse_proxy: "{{upstreams 8080}}"

  # Numbered labels for complex configs
  caddy_0: api.example.com
  caddy_0.reverse_proxy: "{{upstreams 8080}}"
  caddy_0.reverse_proxy.header_up: "X-Real-IP {remote_host}"

  # Port-based server (creates separate listener)
  caddy: ":3000"
  caddy.reverse_proxy: "{{upstreams 8080}}"
```

### Layer4 (TCP/UDP) Routing

Route raw TCP/UDP traffic (not HTTP) through Caddy. Requires Caddy built with [caddy-l4](https://github.com/mholt/caddy-l4) module.

```yaml
labels:
  # Simple TCP proxy (e.g., MQTT broker)
  caddy.layer4: ":1883"
  caddy.layer4.route.proxy: "{{upstreams 11883}}"

  # With SNI matching (TLS passthrough)
  caddy.layer4: ":443"
  caddy.layer4.@sni: "tls sni *.example.com"
  caddy.layer4.route.proxy: "192.168.1.50:443"

  # Multiple L4 routes (numbered)
  caddy.layer4_0: ":1883"
  caddy.layer4_0.route.proxy: "{{upstreams 1883}}"
  caddy.layer4_1: ":8883"
  caddy.layer4_1.route.proxy: "{{upstreams 8883}}"
```

**Note:** If Caddy doesn't have the Layer4 module, the agent logs a warning and skips L4 routes (HTTP routes still work).

### Snippet Sharing

Define snippets on host1, use them on all hosts:

**Host1 (serves snippets):**
```yaml
labels:
  caddy_1: (internal)
  caddy_1.tls: internal

  caddy_2: (https)
  caddy_2.reverse_proxy.transport: http
  caddy_2.reverse_proxy.transport.tls: ""
  caddy_2.reverse_proxy.transport.tls_insecure_skip_verify: ""
```

**Remote agents fetch automatically** when `SNIPPET_SOURCES` is configured.

**Snippet compatibility with reverse_proxy:**

| Snippet | Safe to import? | Reason |
|---------|-----------------|--------|
| `internal` | Yes | Only sets TLS cert type |
| `https` | Yes | Forces TLS to backend (for self-signed certs) |
| `wildcard` | No | Contains `handle.abort` - terminates request |

**Note:** Wildcard domains (e.g., `*.example.com`) should import `wildcard` to set up TLS certs. Individual services should NOT import `wildcard` - just declare their domain and the cert is used automatically.

**Snippet-only mode:** To run an agent that only serves snippets without pushing any routes to Caddy, set `CONFIG_PUSH_ENABLED=false`:

```yaml
caddy-agent:
  environment:
    - SNIPPET_API_PORT=8567
    - CONFIG_PUSH_ENABLED=false  # Disable route pushing, only serve snippets
```

## Route Recovery

When Caddy restarts, routes are lost. Agents automatically recover:

1. **Health check** (every 5s) - detects missing routes quickly
2. **Periodic resync** (every 5 min) - fallback for network issues
3. **Exponential backoff** - reduces load when Caddy is unreachable

## Troubleshooting

### Routes not appearing

```bash
# Check agent logs
docker logs caddy-agent-remote

# Check Caddy API is accessible from agent host
curl http://192.168.1.10:2020/config/

# Check container labels
docker inspect myapp | jq '.[0].Config.Labels'
```

### Routes disappear after restart

Routes are pushed to Caddy's in-memory config. After Caddy restarts, agents resync within ~15 seconds (10s startup delay + 5s health check).

### Connection refused to Admin API

Make sure port 2020 is exposed and accessible:

```bash
# Test from agent host
curl http://192.168.1.10:2020/config/
```

### Duplicate AGENT_ID conflicts

Each agent must have a unique `AGENT_ID`. Routes are prefixed with this ID to prevent conflicts:

```
host1-server_myapp
host2-remote_webapp
```

## Complete Example

Three-host setup with Cloudflare DNS:

**Host1 (Server):**
```yaml
services:
  caddy:
    # Option A: Use caddy-docker-proxy (recommended for single-host)
    image: lucaslorentz/caddy-docker-proxy:latest
    # Option B: Use regular Caddy + caddy-agent (full control)
    # image: caddy:latest  # Requires caddy-agent with CONFIG_PUSH_ENABLED=true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - caddy_data:/data
    labels:
      # Global config
      caddy_0.email: admin@example.com
      caddy_0.auto_https: prefer_wildcard

      # Cloudflare DNS for wildcard certs
      caddy_1: (wildcard)
      caddy_1.tls.dns: "cloudflare {env.CF_API_TOKEN}"
      caddy_1.handle.abort: ""

      caddy_10: "*.example.com"
      caddy_10.import: wildcard

      # Admin API proxy for agents
      caddy_20: ":2020"
      caddy_20.reverse_proxy: "localhost:2019"

  caddy-agent:
    image: mcsdodo/caddy-agent:latest
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - CADDY_URL=http://localhost:2019
      - AGENT_ID=host1-server
      - SNIPPET_API_PORT=8567
      - CONFIG_PUSH_ENABLED=false  # Snippet-only mode

volumes:
  caddy_data:
```

**Host2/Host3 (Agents):**
```yaml
services:
  caddy-agent:
    image: mcsdodo/caddy-agent:latest
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - CADDY_URL=http://192.168.1.10:2020
      - AGENT_ID=host2-remote  # Change for each host
      - SNIPPET_SOURCES=http://192.168.1.10:8567

  myapp:
    image: myapp:latest
    network_mode: host
    labels:
      caddy: myapp.example.com
      caddy.reverse_proxy: "{{upstreams 8080}}"
```

## FAQ

**Q: Can I use this without caddy-docker-proxy?**
A: Yes, but you'll need a Caddyfile that enables the Admin API and defines your base config.

**Q: What happens if two containers have the same domain?**
A: The agent overwrites with the latest one. Use unique domains.

**Q: Does it work with Docker Swarm or Kubernetes?**
A: Not directly. For orchestrated environments, use native ingress controllers.

**Q: How do I secure the Admin API?**
A: Use firewall rules to restrict access to port 2020 to agent IPs only.

## License

MIT
