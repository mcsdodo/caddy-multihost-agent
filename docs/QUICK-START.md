# Quick Start Guide

Get Caddy Agent running in 5 minutes.

## Prerequisites

- Linux host(s) with Docker installed
- SSH access to hosts
- ~500MB free disk space

## Single Host (Easiest)

### 1. Build

```bash
git clone <repo>
cd caddy-agent
docker build -t caddy-agent:latest .
```

### 2. Deploy

```bash
docker compose up -d
```

### 3. Add Routes

```bash
docker run -d \
  --name myapp \
  --network host \
  --label caddy=example.com \
  --label caddy.reverse_proxy=localhost:3000 \
  myapp:latest
```

### 4. Test

```bash
curl -H "Host: example.com" http://localhost
```

Done! 🎉

---

## Three Hosts (Production)

### 1. Build

```bash
docker build -t caddy-agent:1.0 .
docker save caddy-agent:1.0 | gzip > caddy-agent-1.0.tar.gz
```

### 2. Deploy Host1 (Server)

```bash
scp caddy-agent-1.0.tar.gz docker-compose-prod-server.yml root@host1:/tmp/

ssh root@host1 << 'EOF'
mkdir -p /opt/caddy && cd /opt/caddy
gunzip -c /tmp/caddy-agent-1.0.tar.gz | docker load
cp /tmp/docker-compose-prod-server.yml .
docker compose up -d
EOF
```

### 3. Deploy Host2 (Agent)

```bash
scp caddy-agent-1.0.tar.gz docker-compose-prod-agent2.yml root@host2:/tmp/

ssh root@host2 << 'EOF'
mkdir -p /opt/caddy && cd /opt/caddy
gunzip -c /tmp/caddy-agent-1.0.tar.gz | docker load
cp /tmp/docker-compose-prod-agent2.yml docker-compose.yml
# Edit docker-compose.yml: change CADDY_SERVER_URL and HOST_IP to your IPs
docker compose up -d
EOF
```

### 4. Deploy Host3 (Agent)

Same as Host2, but use `docker-compose-prod-agent3.yml`

### 5. Verify

```bash
ssh root@host1 "curl http://localhost:2019/config/apps/http/servers/reverse_proxy/routes | jq 'length'"
# Should show: 0 (no routes yet)
```

### 6. Add Routes

```bash
# On host2
docker run -d --name app2 --network host \
  --label caddy=app2.example.com \
  --label caddy.reverse_proxy=192.168.1.11:3000 \
  myapp:latest

# On host3
docker run -d --name app3 --network host \
  --label caddy=app3.example.com \
  --label caddy.reverse_proxy=192.168.1.12:3000 \
  myapp:latest

# Wait 5 seconds for agent sync
sleep 5

# Verify routes
ssh root@host1 "curl http://localhost:2019/config/apps/http/servers/reverse_proxy/routes | jq 'length'"
# Should show: 2 (routes from host2 and host3)
```

### 7. Test from Host1

```bash
ssh root@host1 << 'EOF'
curl -H "Host: app2.example.com" http://localhost
curl -H "Host: app3.example.com" http://localhost
EOF
```

---

## Common Commands

### View Routes

```bash
curl http://localhost:2019/config/apps/http/servers/reverse_proxy/routes | jq '.[] | {id: .["@id"], domain: .match[0].host[0]}'
```

### View Logs

```bash
# Agent logs
docker logs caddy-agent-server -f

# Caddy logs
docker logs caddy-server -f

# Combined
docker compose logs -f
```

### Add Container

```bash
docker run -d --name myapp --network host \
  --label caddy=myapp.example.com \
  --label caddy.reverse_proxy=localhost:8080 \
  myimage:tag
```

### Remove Container

```bash
docker rm -f myapp
# Route will disappear within 5 seconds
```

### Check Health

```bash
# Agent running?
docker ps | grep caddy-agent

# Caddy running?
docker ps | grep caddy-server

# API accessible?
curl http://localhost:2019/config/ > /dev/null && echo "OK" || echo "FAIL"

# Routes present?
curl http://localhost:2019/config/apps/http/servers/reverse_proxy/routes | jq 'length'
```

### Restart Services

```bash
# Just agent
docker restart caddy-agent-server

# Just caddy
docker restart caddy-server

# Both
docker compose restart
```

---

## Docker Compose Files

All necessary files are in the repo:

- `docker-compose-prod-server.yml` - Server (host1)
- `docker-compose-prod-agent2.yml` - Agent (host2)
- `docker-compose-prod-agent3.yml` - Agent (host3)

Just copy and configure with your IPs.

---

## Documentation

- **README.md** - Full documentation
- **DEPLOYMENT.md** - Detailed deployment guide
- **CONFIGURATION.md** - All config options
- **TROUBLESHOOTING.md** - Common issues & fixes
- **TESTING.md** - Test suite

---

## Next Steps

1. Add more hosts by copying and modifying the agent compose file
2. Configure your apps with caddy labels
3. Set up DNS pointing to host1
4. Enable HTTPS by updating Caddyfile
5. Monitor with `docker stats` or Prometheus

---

**Need Help?** Check TROUBLESHOOTING.md or create a GitHub issue.

