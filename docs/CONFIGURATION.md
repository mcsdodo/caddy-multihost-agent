# Configuration Reference

Complete reference for all configuration options and Docker labels.

## Server Architecture

The caddy-docker-proxy manages Caddy configuration via Docker labels. The server structure:

| Server | Port | Purpose |
|--------|------|---------|
| srv0 | :2020 | Admin API proxy (optional) |
| srv1 | :443, :8080 | Main HTTPS server (with internal CA for .lan domains) |
| srv2 | :80 | HTTP-only server |

Routes are automatically placed:
- Regular domains → srv1 (HTTPS)
- `http://` prefix domains → srv2 (HTTP-only)

## Environment Variables

All configuration is done via environment variables. Set them in your docker-compose.yml or .env file.

### Caddy Connection

#### `CADDY_URL` (optional)

URL of the Caddy Admin API to push configurations to.

**Default**: `http://localhost:2019`
**Example**:
```yaml
environment:
  # Local Caddy (same host)
  - CADDY_URL=http://localhost:2019

  # Remote Caddy (central server)
  - CADDY_URL=http://192.168.0.96:2019
```

### Remote Mode Configuration

#### `HOST_IP` (optional)

IP address to use for upstream addresses. When set (or auto-detected), the agent operates in "remote mode" - upstreams are configured as `HOST_IP:port` instead of container names.

**Default**: None (local mode) or auto-detected with `network_mode: host`
**Auto-detection**: When running with `network_mode: host` and `HOST_IP` is not set, the agent automatically detects the host's IP address.

**Example**:
```yaml
environment:
  # Explicit (required for bridge network)
  - HOST_IP=192.168.0.98

  # Or omit for auto-detection (with network_mode: host)
  # HOST_IP will be auto-detected
```

**Mode Detection Logic**:
| HOST_IP | network_mode | Behavior |
|---------|--------------|----------|
| Set | Any | Use explicit HOST_IP for upstreams |
| Not set | host | Auto-detect IP, use for upstreams |
| Not set | bridge | Local mode, use container names |

**Logging**: The agent logs which mode it's using at startup:
```
INFO  Using HOST_IP: 192.168.0.98 (explicit)
INFO  Using HOST_IP: 192.168.0.98 (auto-detected, network_mode: host)
INFO  Using local addressing (no HOST_IP, container network)
```

### Identity

#### `AGENT_ID` (optional)

Unique identifier for this agent. Used to prefix route IDs and prevent conflicts.

**Default**: Hostname of the container
**Format**: String, no spaces (use hyphens for readability)
**Example**:
```yaml
environment:
  - AGENT_ID=host1-prod-server
  - AGENT_ID=host2-us-west
  - AGENT_ID=kubernetes-node-1
```

**Important**: Must be unique across all agents. Use meaningful names for debugging.

### Docker Integration

#### `DOCKER_LABEL_PREFIX` (optional)

Prefix for Docker labels that define routes.

**Default**: `caddy`
**Example**:
```yaml
environment:
  - DOCKER_LABEL_PREFIX=caddy
```

This means the agent will look for labels like:
- `caddy=example.com` (domain)
- `caddy.reverse_proxy=localhost:3000` (upstream)

If you set `DOCKER_LABEL_PREFIX=proxy`, use:
- `proxy=example.com`
- `proxy.reverse_proxy=localhost:3000`

#### `AGENT_FILTER_LABEL` (optional)

Only watch containers with a specific label. Useful for multi-tenant environments.

**Default**: None (watch all containers)
**Format**: `key=value` (exact match) or `key` (any value)
**Example**:
```yaml
environment:
  # Only watch containers labeled team=backend
  - AGENT_FILTER_LABEL=team=backend

  # Or only watch containers with "managed=true" label
  - AGENT_FILTER_LABEL=managed=true
```

This allows multiple caddy-agent instances on the same host managing different sets of containers.

### Authentication

#### `CADDY_API_TOKEN` (optional)

API token for Caddy Admin API authentication.

**Default**: None (no authentication)
**Format**: Bearer token string
**Example**:
```yaml
environment:
  - CADDY_API_TOKEN=my-secret-token-123
```

Only needed if your Caddy Admin API requires authentication (set in Caddyfile).

### Advanced Options

#### `DOCKER_SOCK` (optional)

Path to Docker daemon socket.

**Default**: `/var/run/docker.sock`
**Example**:
```yaml
environment:
  - DOCKER_SOCK=/var/run/docker.sock  # Default
  - DOCKER_SOCK=unix:///run/docker.sock  # Absolute path
```

### Snippet Sharing API

Share snippet definitions between hosts via HTTP API. Enables remote agents to fetch snippets defined on the central Caddy server host.

#### `SNIPPET_API_PORT` (optional)

Port to serve the snippet API on. Set to enable snippet sharing.

**Default**: `0` (disabled)
**Example**:
```yaml
environment:
  # Enable snippet API on port 8567
  - SNIPPET_API_PORT=8567
```

When enabled with `network_mode: host`, the port is automatically exposed.

#### `SNIPPET_SOURCES` (optional)

Comma-separated URLs to fetch snippets from.

**Default**: Empty (no remote snippets)
**Example**:
```yaml
environment:
  # Fetch snippets from central server
  - SNIPPET_SOURCES=http://192.168.0.96:8567

  # Multiple sources (fallback)
  - SNIPPET_SOURCES=http://192.168.0.96:8567,http://192.168.0.97:8567
```

#### `SNIPPET_CACHE_TTL` (optional)

How long to cache fetched snippets (in seconds).

**Default**: `300` (5 minutes)
**Example**:
```yaml
environment:
  - SNIPPET_CACHE_TTL=300  # 5 minutes
  - SNIPPET_CACHE_TTL=60   # 1 minute (more frequent updates)
```

#### Snippet Compatibility

**Important:** Not all snippets are safe to import with `reverse_proxy`:

| Snippet | Safe to import? | Reason |
|---------|-----------------|--------|
| `internal` | ✅ Yes | Only sets TLS cert type |
| `wildcard` | ❌ No | Has `handle.abort` - terminates request |
| `https` | ⚠️ Depends | Forces TLS to backend (needs HTTPS backend) |

**Pattern:** Wildcard domains (`*.lacny.me`) import `wildcard` to configure TLS. Individual services should NOT import `wildcard` - just declare their domain and the wildcard cert is used automatically.

#### Example Setup

**Host1 (serves snippets):**
```yaml
caddy-agent:
  network_mode: host
  environment:
    - SNIPPET_API_PORT=8567
```

**Host2 (fetches snippets):**
```yaml
caddy-agent:
  environment:
    - SNIPPET_SOURCES=http://192.168.0.96:8567
```

**Test snippet API:**
```bash
curl -s http://192.168.0.96:8567/snippets | python -m json.tool
```

## Docker Labels

Container labels define routes and reverse proxy targets. Format:

```dockerfile
LABEL {PREFIX}=domain.com
LABEL {PREFIX}.reverse_proxy=upstream:port
```

### Basic Labels

#### `caddy={domain}` (required)

The domain(s) to route to this container.

**Format**: Single domain or comma-separated domains
**Example**:
```dockerfile
LABEL caddy=example.com
LABEL caddy=api.example.com
LABEL caddy=api.example.com,example.com
```

#### `caddy.reverse_proxy={upstream}` (required)

Where to send traffic for this domain.

**Format**: `hostname:port` or `{{upstreams PORT}}`
**Example**:
```dockerfile
# Explicit upstream
LABEL caddy.reverse_proxy=192.168.1.10:3000
LABEL caddy.reverse_proxy=localhost:8080
LABEL caddy.reverse_proxy=db-service:5432

# Auto-detect published port
LABEL caddy.reverse_proxy={{upstreams 3000}}
LABEL caddy.reverse_proxy={{upstreams 8080}}
```

### Port Binding Options

#### Option 1: Explicit IP:Port (Most Reliable)

```dockerfile
LABEL caddy.reverse_proxy=192.168.1.11:3000
```

Use when:
- You know the host IP
- Container listens on a fixed port
- Using host networking mode

#### Option 2: Localhost:Port (Single Host Only)

```dockerfile
LABEL caddy.reverse_proxy=localhost:3000
```

Use when:
- Caddy and container on same host
- Container listens on fixed port

#### Option 3: Auto-detect with {{upstreams PORT}}

```dockerfile
LABEL caddy.reverse_proxy={{upstreams 3000}}
```

Use when:
- Container publishes port 3000
- Agent is in remote mode (HOST_IP configured)
- Need automatic port detection

### HTTP-only Routes

Use `http://` prefix to route traffic to the HTTP-only server (srv2 on port 80):

```dockerfile
# HTTP-only route (no TLS, served on port 80)
LABEL caddy=http://internal-api.lan
LABEL caddy.reverse_proxy={{upstreams 3000}}
```

This is useful for:
- Internal services that don't need TLS
- IoT devices that don't support HTTPS
- Legacy applications requiring HTTP

### Route Ordering

The agent automatically orders routes so specific domains match before wildcards:
- Specific routes (`app.example.com`) are processed first
- Wildcard routes (`*.example.com`) are processed last

This ensures that `app.example.com` routes to your app, not the wildcard catch-all.

### Advanced Labels

#### Custom Caddy Matcher (Optional)

```dockerfile
# Route only specific paths
LABEL caddy.uri_path=/api/v1/*

# Route specific HTTP methods
LABEL caddy.http_method=POST

# Multiple matchers
LABEL caddy.matcher=path /api/* && method POST
```

#### Health Check Labels

```dockerfile
# Mark as health-checkable (future feature)
LABEL caddy.health_path=/health
LABEL caddy.health_interval=30s
```

#### Metadata Labels

```dockerfile
# Add custom metadata (informational only)
LABEL caddy.team=backend
LABEL caddy.environment=production
LABEL caddy.version=1.2.3
```

## Configuration Examples

### Single Host (Local Mode)

```yaml
version: '3'
services:
  agent:
    image: mcsdodo/caddy-agent:latest
    environment:
      CADDY_URL: http://localhost:2019
      AGENT_ID: localhost
      DOCKER_LABEL_PREFIX: caddy
      # No HOST_IP = local mode (uses container names)
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro

  app:
    image: myapp:latest
    labels:
      caddy: myapp.local
      caddy.reverse_proxy: "{{upstreams 3000}}"
```

### Multi-Host Setup

**Host 1 (Server - Local Mode):**
```yaml
version: '3'
services:
  agent:
    image: mcsdodo/caddy-agent:latest
    environment:
      CADDY_URL: http://localhost:2019
      AGENT_ID: prod-server
      DOCKER_LABEL_PREFIX: caddy
      # No HOST_IP = local mode
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

**Host 2 (Remote Agent - Auto-detect with network_mode: host):**
```yaml
version: '3'
services:
  agent:
    image: mcsdodo/caddy-agent:latest
    network_mode: host
    environment:
      CADDY_URL: http://192.168.1.10:2019
      AGENT_ID: prod-host2
      DOCKER_LABEL_PREFIX: caddy
      # HOST_IP auto-detected with network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

**Host 3 (Remote Agent - Explicit HOST_IP with bridge network):**
```yaml
version: '3'
services:
  agent:
    image: mcsdodo/caddy-agent:latest
    environment:
      CADDY_URL: http://192.168.1.10:2019
      AGENT_ID: prod-host3
      HOST_IP: 192.168.1.12
      DOCKER_LABEL_PREFIX: caddy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

### Multi-Tenant with Label Filtering

**Agent for Team A:**
```yaml
agent-team-a:
  image: mcsdodo/caddy-agent:latest
  environment:
    CADDY_URL: http://192.168.1.10:2019
    AGENT_ID: team-a-agent
    HOST_IP: 192.168.1.11
    DOCKER_LABEL_PREFIX: caddy
    AGENT_FILTER_LABEL: team=a
```

**Agent for Team B:**
```yaml
agent-team-b:
  image: mcsdodo/caddy-agent:latest
  environment:
    CADDY_URL: http://192.168.1.10:2019
    AGENT_ID: team-b-agent
    HOST_IP: 192.168.1.11
    DOCKER_LABEL_PREFIX: caddy
    AGENT_FILTER_LABEL: team=b
```

**Container Deployment:**
```bash
# Team A app
docker run -d \
  --label team=a \
  --label caddy=team-a.example.com \
  --label caddy.reverse_proxy=localhost:3000 \
  team-a-app:latest

# Team B app
docker run -d \
  --label team=b \
  --label caddy=team-b.example.com \
  --label caddy.reverse_proxy=localhost:3000 \
  team-b-app:latest
```

### With Authentication Token

```yaml
agent:
  image: mcsdodo/caddy-agent:latest
  environment:
    CADDY_URL: http://192.168.1.10:2019
    AGENT_ID: prod-host2
    HOST_IP: 192.168.1.11
    CADDY_API_TOKEN: ${CADDY_API_TOKEN}  # From .env file
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock:ro
```

`.env` file:
```
CADDY_API_TOKEN=my-secret-api-token-12345
```

### Custom Label Prefix

```yaml
agent:
  image: mcsdodo/caddy-agent:latest
  environment:
    CADDY_URL: http://localhost:2019
    AGENT_ID: localhost
    DOCKER_LABEL_PREFIX: proxy  # Changed from 'caddy'
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock:ro

app:
  image: myapp:latest
  labels:
    proxy: example.com  # Using 'proxy' instead of 'caddy'
    proxy.reverse_proxy: "{{upstreams 3000}}"
```

## Route Generation

The agent generates Caddy routes from labels using this algorithm:

1. **Get domain** from `{PREFIX}=` label
2. **Get upstream** from `{PREFIX}.reverse_proxy=` label
3. **Generate route ID**: `{AGENT_ID}_{container_name}`
4. **Create Caddy route**:
   ```json
   {
     "@id": "host1-server_myapp",
     "match": [{
       "host": ["example.com"]
     }],
     "handle": [{
       "handler": "reverse_proxy",
       "upstreams": [{
         "dial": "localhost:3000"
       }]
     }]
   }
   ```

## Environment Variable Precedence

1. Docker compose `.environment` section
2. `.env` file (if using `env_file`)
3. `--env` flags in docker run
4. Defaults listed above

## Validation

The agent validates configuration on startup:

```
🚀 Caddy Docker Agent Starting
   Agent ID: host1-server
   Caddy URL: http://localhost:2019
   Docker Label Prefix: caddy
   Mode: LOCAL (upstreams use container names)
```

Or for remote mode:
```
🚀 Caddy Docker Agent Starting
   Agent ID: host2-remote
   Caddy URL: http://192.168.0.96:2019
   Using HOST_IP: 192.168.0.98 (auto-detected, network_mode: host)
   Mode: REMOTE (upstreams use 192.168.0.98)
```

## Common Configuration Mistakes

### ❌ Mistake 1: Wrong CADDY_URL for Remote Agents

```yaml
# Wrong - agent can't reach server
CADDY_URL: http://localhost:2019  # Points to itself!

# Correct - point to central server
CADDY_URL: http://192.168.1.10:2019  # Points to server host
```

### ❌ Mistake 2: Missing HOST_IP with Bridge Network

```yaml
# If using bridge network (not network_mode: host), you need explicit HOST_IP
HOST_IP: not_set  # Bad - auto-detection won't work

# Explicitly set when using bridge network
HOST_IP: 192.168.1.11  # Good
```

### ❌ Mistake 3: Duplicate AGENT_ID

```yaml
# Two agents with same ID cause conflicts!
agent1:
  AGENT_ID: prod-agent  # OK

agent2:
  AGENT_ID: prod-agent  # ❌ Conflict!

# Correct
agent2:
  AGENT_ID: prod-agent-2  # ✅ Unique
```

### ❌ Mistake 4: Container Not Publishing Port

```dockerfile
# Container must expose/publish the port
# ❌ Wrong - container internal port only
EXPOSE 3000

# ✅ Correct - depends on container setup
CMD ["node", "app.js", "--port", "3000"]
```

## Debugging Configuration

### Check Environment Variables

```bash
docker inspect caddy-agent-server | jq '.[].Config.Env'
```

### Check Detected Host IP

```bash
docker logs caddy-agent-server | grep "HOST_IP"
```

### Verify Label Detection

```bash
docker logs caddy-agent-server | grep "Routes added"
```

### Check Generated Routes

```bash
# HTTPS routes (srv1)
curl -s http://localhost:2019/config/apps/http/servers/srv1/routes | python3 -m json.tool

# HTTP-only routes (srv2)
curl -s http://localhost:2019/config/apps/http/servers/srv2/routes | python3 -m json.tool

# Local agent config copy
docker exec caddy-agent-server cat /app/caddy-output.json | python3 -m json.tool
```

## Performance Tuning

### Debounce Interval

Currently hardcoded to 2 seconds. To change:

Edit `caddy-agent-watch.py`:
```python
time.sleep(2)  # Change this value
```

Smaller = faster updates, higher CPU usage
Larger = fewer updates, delayed routing

### Max Containers

No hard limit, but tested up to 50+ containers on a single host.

---

**Version**: 1.1
**Last Updated**: 2025-11-28
