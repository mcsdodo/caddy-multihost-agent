# Deployment Guide

Complete step-by-step guide for deploying Caddy Agent in production environments.

## Prerequisites

### Host Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+)
- **Docker**: 20.10+ with Docker Compose
- **Python**: 3.8+ (if running outside container)
- **Network**: All hosts must be able to reach each other
- **Ports**:
  - `80/tcp` - HTTP (Caddy)
  - `443/tcp` - HTTPS (Caddy)
  - `2019/tcp` - Caddy Admin API (must be open between hosts)

### Network Configuration

```bash
# Verify connectivity between hosts
ssh root@host2 "ping -c 1 192.168.1.10"  # host1
ssh root@host3 "ping -c 1 192.168.1.10"  # host1
ssh root@host3 "ping -c 1 192.168.1.11"  # host2
```

Allow port 2019 through firewall:

```bash
# UFW (Ubuntu)
ufw allow 2019/tcp comment "Caddy Admin API"

# firewall-cmd (RHEL)
firewall-cmd --permanent --add-port=2019/tcp
firewall-cmd --reload

# iptables
iptables -A INPUT -p tcp --dport 2019 -j ACCEPT
```

### Unprivileged Port Binding (if not using sudo)

```bash
# On all hosts - allow non-root to bind port 80
sysctl -w net.ipv4.ip_unprivileged_port_start=80

# Make permanent
echo "net.ipv4.ip_unprivileged_port_start=80" >> /etc/sysctl.conf
sysctl -p
```

## Step 1: Build Docker Image

On a build machine (can be your laptop or CI/CD system):

```bash
# Clone or download the caddy-agent repository
git clone https://github.com/yourusername/caddy-agent.git
cd caddy-agent

# Build the image
docker build -t caddy-agent:1.0 .

# Save as tarball for distribution
docker save caddy-agent:1.0 | gzip > caddy-agent-1.0.tar.gz

# Verify image size
ls -lh caddy-agent-1.0.tar.gz  # ~156MB compressed
```

## Step 2: Deploy to Host1 (Server)

### Prepare Host1

```bash
ssh root@host1 << 'EOF'
mkdir -p /opt/caddy
cd /opt/caddy

# Create minimal Caddyfile
cat > Caddyfile << 'CADDY'
{
  admin 0.0.0.0:2019
}

http://localhost {
  respond "Caddy is running"
}
CADDY

# Create necessary directories
mkdir -p data config
chown -R nobody:nogroup data config

EOF
```

### Transfer and Load Image

```bash
scp caddy-agent-1.0.tar.gz root@host1:/tmp/

ssh root@host1 << 'EOF'
cd /opt/caddy
gunzip -c /tmp/caddy-agent-1.0.tar.gz | docker load
rm /tmp/caddy-agent-1.0.tar.gz
EOF
```

### Create docker-compose.yml for Host1

```bash
scp docker-compose-prod-server.yml root@host1:/opt/caddy/docker-compose.yml

# Or create inline:
ssh root@host1 << 'EOF'
cd /opt/caddy

cat > docker-compose.yml << 'COMPOSE'
version: '3.8'

services:
  caddy:
    image: caddy:2
    container_name: caddy-server
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./data:/data
      - ./config:/config
    environment:
      - CADDY_ADMIN=0.0.0.0:2019

  agent:
    image: caddy-agent:1.0
    container_name: caddy-agent-server
    restart: unless-stopped
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - AGENT_MODE=server
      - AGENT_ID=host1-prod-server
      - CADDY_API_URL=http://localhost:2019
      - DOCKER_LABEL_PREFIX=caddy
    depends_on:
      - caddy
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
COMPOSE

EOF
```

### Start Services on Host1

```bash
ssh root@host1 << 'EOF'
cd /opt/caddy

# Start services
docker compose up -d

# Verify
sleep 5
docker compose ps
docker logs caddy-agent-server --tail 5

# Verify Admin API
curl http://localhost:2019/config/ | head -c 200
EOF
```

## Step 3: Deploy to Host2 (Agent)

### Prepare Host2

```bash
ssh root@host2 << 'EOF'
mkdir -p /opt/caddy
cd /opt/caddy
EOF
```

### Transfer and Load Image

```bash
scp caddy-agent-1.0.tar.gz root@host2:/tmp/

ssh root@host2 << 'EOF'
cd /opt/caddy
gunzip -c /tmp/caddy-agent-1.0.tar.gz | docker load
rm /tmp/caddy-agent-1.0.tar.gz
EOF
```

### Create docker-compose.yml for Host2

Replace `192.168.1.10` with host1 IP and `192.168.1.11` with host2 IP:

```bash
ssh root@host2 << 'EOF'
cd /opt/caddy

cat > docker-compose.yml << 'COMPOSE'
version: '3.8'

services:
  agent:
    image: caddy-agent:1.0
    container_name: caddy-agent
    restart: unless-stopped
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - AGENT_MODE=agent
      - AGENT_ID=host2-prod-agent
      - CADDY_SERVER_URL=http://192.168.1.10:2019
      - HOST_IP=192.168.1.11
      - DOCKER_LABEL_PREFIX=caddy
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
COMPOSE

EOF
```

### Start Agent on Host2

```bash
ssh root@host2 << 'EOF'
cd /opt/caddy

docker compose up -d
sleep 3
docker logs caddy-agent --tail 10
EOF
```

### Verify Host2 Agent Connected

```bash
# Check logs
ssh root@host2 "docker logs caddy-agent | grep -E 'Syncing|updated successfully'"

# Should see: "✅ Caddy config updated successfully [Agent: host2-prod-agent]"
```

## Step 4: Deploy to Host3 (Agent)

Repeat Step 3 but for host3:

```bash
# On your local machine
scp caddy-agent-1.0.tar.gz root@host3:/tmp/

ssh root@host3 << 'EOF'
mkdir -p /opt/caddy
cd /opt/caddy
gunzip -c /tmp/caddy-agent-1.0.tar.gz | docker load

cat > docker-compose.yml << 'COMPOSE'
version: '3.8'

services:
  agent:
    image: caddy-agent:1.0
    container_name: caddy-agent
    restart: unless-stopped
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - AGENT_MODE=agent
      - AGENT_ID=host3-prod-agent
      - CADDY_SERVER_URL=http://192.168.1.10:2019
      - HOST_IP=192.168.1.12
      - DOCKER_LABEL_PREFIX=caddy
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
COMPOSE

docker compose up -d
sleep 3
docker logs caddy-agent | grep -E 'Syncing|updated successfully'
EOF
```

## Step 5: Deploy Your First Container

### Test Container on Host1

```bash
ssh root@host1 << 'EOF'
docker run -d \
  --name testapp-host1 \
  --network host \
  --label caddy=testapp-host1.local \
  --label caddy.reverse_proxy=localhost:8081 \
  hashicorp/http-echo:latest \
  -listen=:8081 \
  -text="Hello from host1"

# Wait for agent to discover
sleep 3
EOF
```

### Test Container on Host2

```bash
ssh root@host2 << 'EOF'
docker run -d \
  --name testapp-host2 \
  --network host \
  --label caddy=testapp-host2.local \
  --label caddy.reverse_proxy=192.168.1.11:8082 \
  hashicorp/http-echo:latest \
  -listen=:8082 \
  -text="Hello from host2"

sleep 3
EOF
```

### Verify Routes

```bash
# Check routes in Caddy
curl http://192.168.1.10:2019/config/apps/http/servers/reverse_proxy/routes | \
  jq '.[] | {id: .["@id"], domain: .match[0].host[0]}'

# Test routing
ssh root@host1 << 'EOF'
curl -H "Host: testapp-host1.local" http://localhost
curl -H "Host: testapp-host2.local" http://localhost
EOF
```

Expected output:
```
Hello from host1
Hello from host2
```

## Step 6: Enable HTTPS with Let's Encrypt

Update Caddyfile on host1:

```bash
ssh root@host1 << 'EOF'
cat > Caddyfile << 'CADDY'
{
  admin 0.0.0.0:2019
}

# Email for Let's Encrypt notifications
*.local {
  tls internal
}

*.example.com {
  tls your-email@example.com
}
CADDY

# Reload Caddy
curl -X POST http://localhost:2019/reload
EOF
```

## Monitoring & Health Checks

### Container Health

```bash
# All hosts
watch -n 5 'docker ps | grep -E caddy | grep -v "name"'

# Specific
docker stats caddy-agent-server
docker stats caddy-agent
```

### Agent Connectivity

```bash
# Check if agents are syncing
ssh root@host1 "docker logs caddy-agent-server 2>&1 | grep -c 'updated successfully'"

# Should be > 0 (agent has synced at least once)
```

### Caddy Admin API

```bash
# Health check
curl -s http://localhost:2019/config/ > /dev/null && echo "OK" || echo "DOWN"

# Route count
curl -s http://localhost:2019/config/apps/http/servers/reverse_proxy/routes | \
  jq 'length'

# Uptime (check from logs)
docker logs caddy-server | grep "serving"
```

## Updating

### Update Agent Image

```bash
# On build machine
docker build -t caddy-agent:1.1 .
docker save caddy-agent:1.1 | gzip > caddy-agent-1.1.tar.gz

# On each host
ssh root@host2 << 'EOF'
cd /opt/caddy
gunzip -c /tmp/caddy-agent-1.1.tar.gz | docker load

# Update compose file to use new image
sed -i 's/caddy-agent:1.0/caddy-agent:1.1/' docker-compose.yml

# Restart agent
docker compose up -d --no-deps --build agent

# Verify
docker logs caddy-agent --tail 5
EOF
```

### Update Caddy

```bash
ssh root@host1 << 'EOF'
cd /opt/caddy

# Update to new Caddy version in compose file
sed -i 's/caddy:2/caddy:2.7/' docker-compose.yml

# Restart (routes will be restored by agents)
docker compose down caddy
docker compose up -d caddy

# Agents will automatically resync
sleep 10
curl http://localhost:2019/config/apps/http/servers/reverse_proxy/routes | jq 'length'
EOF
```

## Backup & Recovery

### Backup Configuration

```bash
# Backup all configs
ssh root@host1 << 'EOF'
tar czf /opt/caddy/backup-$(date +%Y%m%d).tar.gz \
  /opt/caddy/Caddyfile \
  /opt/caddy/data \
  /opt/caddy/config

# List backups
ls -lh /opt/caddy/backup-*.tar.gz
EOF
```

### Recovery

```bash
# If Caddy is corrupted
ssh root@host1 << 'EOF'
cd /opt/caddy

# Remove containers
docker compose down

# Restore backup
tar xzf backup-20251116.tar.gz -C /

# Restart
docker compose up -d

# Agents will resync routes
sleep 10
EOF
```

## Troubleshooting Deployment

### Agent fails to connect to Caddy

```bash
# Check network connectivity
ssh root@host2 "curl -v http://192.168.1.10:2019/"

# Check firewall
ssh root@host1 "netstat -tulpn | grep 2019"

# Check routing
ssh root@host2 "ip route | grep 192.168"
```

### Routes not appearing

```bash
# Check agent logs
docker logs caddy-agent-server

# Manually push config
docker exec caddy-agent-server python3 -c \
  "import json; c=json.load(open('/app/caddy-output.json')); print(len(c['apps']['http']['servers']['reverse_proxy']['routes'])) routes"

# Check container labels
docker inspect testapp-host1 | jq '.Config.Labels'
```

### Admin API unreachable

```bash
# Verify Caddy is running
docker ps | grep caddy-server

# Check logs
docker logs caddy-server | tail -20

# Restart if needed
docker restart caddy-server

# Wait for startup
sleep 5
curl http://localhost:2019/config/
```

## Scaling to More Hosts

Simply repeat Step 3 for each new host:

1. Build and transfer image
2. Create `/opt/caddy/docker-compose.yml` with unique `AGENT_ID` and `HOST_IP`
3. Start with `docker compose up -d`
4. Verify with `docker logs caddy-agent`

The system scales linearly - 10 hosts = 10 agents, all coordinating safely.

## Security Considerations

1. **Admin API** - Port 2019 should be restricted to trusted hosts
2. **Network** - Use VPN or private network for inter-host communication
3. **Container Labels** - Sanitize container names/labels if untrusted
4. **API Tokens** - Set `CADDY_API_TOKEN` if Caddy Admin API requires authentication
5. **SSH Keys** - Use key-based SSH authentication, not passwords

## Next Steps

1. Review [CONFIGURATION.md](CONFIGURATION.md) for advanced options
2. Set up monitoring with Prometheus metrics
3. Configure automated backups
4. Review [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues

---

**Version**: 1.0
**Last Updated**: 2025-11-16
