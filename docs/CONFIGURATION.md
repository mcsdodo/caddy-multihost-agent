# Configuration Reference

Complete reference for all configuration options and Docker labels.

## Environment Variables

All configuration is done via environment variables. Set them in your docker-compose.yml or .env file.

### Mode Selection

#### `AGENT_MODE` (required)

Determines how the agent operates.

| Value | Use Case | Details |
|-------|----------|---------|
| `standalone` | Single-host setup | Agent and Caddy on same host, agent manages local Docker only |
| `server` | Multi-host server | Central server where Caddy runs, accepts route updates from agents |
| `agent` | Multi-host remote | Remote agent, pushes routes to central server |

**Default**: `standalone`
**Example**:
```yaml
environment:
  - AGENT_MODE=server
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

### Server Mode Configuration

These options apply only when `AGENT_MODE=server`.

#### `CADDY_API_URL` (required for server mode)

URL of the local Caddy Admin API.

**Default**: `http://caddy:2019`
**Example**:
```yaml
environment:
  - CADDY_API_URL=http://localhost:2019
  - CADDY_API_URL=http://127.0.0.1:2019
```

Should point to the Caddy Admin API endpoint.

### Agent Mode Configuration

These options apply only when `AGENT_MODE=agent`.

#### `CADDY_SERVER_URL` (required for agent mode)

URL of the remote Caddy Admin API (on server host).

**Default**: None
**Format**: `http://hostname:port`
**Example**:
```yaml
environment:
  - CADDY_SERVER_URL=http://192.168.1.10:2019
  - CADDY_SERVER_URL=http://caddy-server.internal:2019
  - CADDY_SERVER_URL=http://caddy.example.com:2019
```

#### `HOST_IP` (optional for agent mode)

The IP address of this host, used when constructing upstream targets.

**Default**: Auto-detected by connecting to 8.8.8.8 (Google DNS)
**Format**: IPv4 address
**Example**:
```yaml
environment:
  - HOST_IP=192.168.1.11
  - HOST_IP=10.0.0.5
```

Required if:
- Auto-detection fails (no default route)
- The host has multiple IPs and you need a specific one
- The host isn't connected to the internet for auto-detection

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
- Agent is in `agent` mode (remote host)
- Need automatic port detection

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

### Single Host (Standalone)

```yaml
version: '3'
services:
  agent:
    image: caddy-agent:latest
    environment:
      AGENT_MODE: standalone
      AGENT_ID: localhost
      CADDY_API_URL: http://localhost:2019
      DOCKER_LABEL_PREFIX: caddy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro

  app:
    image: myapp:latest
    labels:
      caddy: myapp.local
      caddy.reverse_proxy: localhost:3000
```

### Multi-Host Server

**Host 1 (Server):**
```yaml
version: '3'
services:
  agent:
    image: caddy-agent:latest
    environment:
      AGENT_MODE: server
      AGENT_ID: prod-server
      CADDY_API_URL: http://localhost:2019
      DOCKER_LABEL_PREFIX: caddy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

**Host 2 (Agent):**
```yaml
version: '3'
services:
  agent:
    image: caddy-agent:latest
    environment:
      AGENT_MODE: agent
      AGENT_ID: prod-host2
      CADDY_SERVER_URL: http://192.168.1.10:2019
      HOST_IP: 192.168.1.11
      DOCKER_LABEL_PREFIX: caddy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

### Multi-Tenant with Label Filtering

**Agent for Team A:**
```yaml
agent-team-a:
  image: caddy-agent:latest
  environment:
    AGENT_MODE: agent
    AGENT_ID: team-a-agent
    CADDY_SERVER_URL: http://192.168.1.10:2019
    HOST_IP: 192.168.1.11
    DOCKER_LABEL_PREFIX: caddy
    AGENT_FILTER_LABEL: team=a
```

**Agent for Team B:**
```yaml
agent-team-b:
  image: caddy-agent:latest
  environment:
    AGENT_MODE: agent
    AGENT_ID: team-b-agent
    CADDY_SERVER_URL: http://192.168.1.10:2019
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
  image: caddy-agent:latest
  environment:
    AGENT_MODE: agent
    AGENT_ID: prod-host2
    CADDY_SERVER_URL: http://192.168.1.10:2019
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
  image: caddy-agent:latest
  environment:
    AGENT_MODE: server
    AGENT_ID: localhost
    CADDY_API_URL: http://localhost:2019
    DOCKER_LABEL_PREFIX: proxy  # Changed from 'caddy'
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock:ro

app:
  image: myapp:latest
  labels:
    proxy: example.com  # Using 'proxy' instead of 'caddy'
    proxy.reverse_proxy: localhost:3000
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
✅ Agent ID: host1-server
✅ Mode: server
✅ Caddy API: http://localhost:2019
✅ Label Prefix: caddy
```

Configuration errors will be logged as:
```
❌ Error: AGENT_MODE must be one of: standalone, server, agent
```

## Common Configuration Mistakes

### ❌ Mistake 1: Wrong CADDY_SERVER_URL

```yaml
# Wrong - agent can't reach server
CADDY_SERVER_URL: http://localhost:2019  # Points to itself!

# Correct
CADDY_SERVER_URL: http://192.168.1.10:2019  # Points to server host
```

### ❌ Mistake 2: Missing HOST_IP in Agent Mode

```yaml
# If auto-detection doesn't work
HOST_IP: not_set  # Bad

# Explicitly set
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
docker logs caddy-agent-server | grep "Host IP"
```

### Verify Label Detection

```bash
docker logs caddy-agent-server | grep "Route:"
```

### Check Generated Routes

```bash
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

**Version**: 1.0
**Last Updated**: 2025-11-16
