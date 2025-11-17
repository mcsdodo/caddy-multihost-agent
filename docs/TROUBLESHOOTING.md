# Troubleshooting Guide

Common issues and their solutions.

## Agent Issues

### Agent Not Starting

**Symptom**: `docker: Error response from daemon: ... OCI runtime error`

**Solutions**:

1. Check Docker daemon is running:
   ```bash
   docker ps
   ```

2. Check available disk space:
   ```bash
   df -h | grep /
   # Need at least 1GB free
   ```

3. Check for port conflicts:
   ```bash
   netstat -tulpn | grep -E '2019|80|443'
   ```

4. View full error logs:
   ```bash
   docker logs caddy-agent-server --tail 100
   ```

### "Connection refused" Errors

**Symptom**:
```
ERROR ❌ Error pushing to Caddy: HTTPConnectionPool(...): Max retries exceeded ... Connection refused
```

**Root Cause**: Agent can't reach Caddy Admin API

**Solutions**:

1. Verify Caddy is running on server:
   ```bash
   # On server host
   docker ps | grep caddy-server
   ```

2. Check Caddy Admin API is listening:
   ```bash
   # On server host
   netstat -tulpn | grep 2019
   # Should show: tcp  0  0 0.0.0.0:2019  0.0.0.0:*  LISTEN
   ```

3. Verify connectivity from agent host:
   ```bash
   # On agent host
   curl -v http://192.168.1.10:2019/config/
   # Should return 200 OK
   ```

4. Check firewall allows port 2019:
   ```bash
   # On server host
   ufw allow 2019/tcp  # Ubuntu
   firewall-cmd --permanent --add-port=2019/tcp && firewall-cmd --reload  # RHEL
   ```

5. Check DNS resolution:
   ```bash
   # If using hostnames
   nslookup caddy-server.example.com
   ping caddy-server.example.com
   ```

### "No docker.sock found" Error

**Symptom**:
```
ERROR ❌ Cannot connect to Docker daemon at unix:///var/run/docker.sock
```

**Solutions**:

1. Verify docker.sock exists:
   ```bash
   ls -la /var/run/docker.sock
   # Should show: srw-rw---- root docker
   ```

2. Check volume mount in compose file:
   ```yaml
   volumes:
     - /var/run/docker.sock:/var/run/docker.sock:ro
   ```

3. Check Docker daemon is running:
   ```bash
   ps aux | grep dockerd
   service docker status
   ```

4. Check user permissions:
   ```bash
   # Agent container may be running as non-root
   docker exec caddy-agent-server id
   # Might need to add user to docker group
   usermod -aG docker agent-user
   ```

### Agent Syncing But Routes Not Appearing

**Symptom**: `✅ Caddy config updated successfully` but routes don't show in Caddy

**Root Cause**: Configuration validation error (silent failure)

**Solutions**:

1. Check what config the agent saved:
   ```bash
   docker exec caddy-agent-server cat /app/caddy-output.json | \
     python3 -m json.tool | head -50
   ```

2. Manually validate the config:
   ```bash
   docker exec caddy-agent-server python3 << 'EOF'
   import json
   with open('/app/caddy-output.json', 'r') as f:
       config = json.load(f)
       routes = config['apps']['http']['servers']['reverse_proxy']['routes']
       print(f"Routes in config: {len(routes)}")
       for r in routes:
           print(f"  - {r.get('@id')}")
   EOF
   ```

3. Check Caddy logs for errors:
   ```bash
   docker logs caddy-server | grep -i error | tail -10
   ```

4. Try manual config push:
   ```bash
   docker exec caddy-agent-server \
     curl -X POST -H 'Content-Type: application/json' \
     -d @/app/caddy-output.json \
     http://localhost:2019/load
   ```

## Routing Issues

### Routes Not Being Discovered

**Symptom**: Container is running but route doesn't appear in Caddy

**Solutions**:

1. Verify container has correct labels:
   ```bash
   docker inspect mycontainer | jq '.Config.Labels'
   # Should show: {
   #   "caddy": "example.com",
   #   "caddy.reverse_proxy": "localhost:3000"
   # }
   ```

2. Check label prefix matches agent config:
   ```bash
   docker inspect caddy-agent-server | grep DOCKER_LABEL_PREFIX
   # Or check docker-compose.yml
   ```

3. Verify agent is watching this container:
   ```bash
   docker logs caddy-agent-server 2>&1 | grep -A2 mycontainer
   ```

4. Check if container passes filter label (if configured):
   ```bash
   docker logs caddy-agent-server | grep -i "filter"
   docker inspect mycontainer | jq '.Config.Labels | keys'
   ```

5. Wait for agent sync cycle:
   ```bash
   # Agent syncs every ~2 seconds
   sleep 5
   curl http://localhost:2019/config/apps/http/servers/reverse_proxy/routes | \
     jq '.[] | select(.["@id"] | contains("mycontainer"))'
   ```

### Routes Not Responding (404/502)

**Symptom**: Route exists in Caddy but returns 404 or 502

**Solutions**:

1. Verify upstream container is running and listening:
   ```bash
   docker ps | grep mycontainer  # Should show running

   # Test the upstream directly
   docker exec mycontainer curl localhost:3000
   # Or from host if container is in host network
   curl localhost:3000
   ```

2. Check upstream address in route:
   ```bash
   curl http://localhost:2019/config/apps/http/servers/reverse_proxy/routes | \
     jq '.[] | select(.["@id"] | contains("mycontainer")) | .handle[0].upstreams'
   ```

3. Verify the IP:port is correct:
   ```bash
   # If route shows 192.168.1.11:3000
   ssh root@host2 "curl -v http://192.168.1.11:3000"
   # Should reach the container
   ```

4. Check container logs:
   ```bash
   docker logs mycontainer | tail -20
   # Look for startup errors or crashes
   ```

5. Test with direct curl:
   ```bash
   # Test HTTP to the upstream
   curl -v http://192.168.1.11:3000

   # Test through Caddy
   curl -v -H "Host: example.com" http://localhost
   ```

### Stale Routes Remaining

**Symptom**: Deleted container's route still appears in Caddy

**Symptom**: `rm -f oldcontainer` but route still routes to 502

**Root Cause**: Agent doesn't clean up routes when containers are deleted (known limitation)

**Solutions**:

1. Manual cleanup - remove route via Admin API:
   ```bash
   # Get the route ID
   ROUTE_ID="host1-server_oldcontainer"

   # Delete it
   curl -X DELETE \
     "http://localhost:2019/config/apps/http/servers/reverse_proxy/routes?id=$ROUTE_ID"
   ```

2. Restart the agent:
   ```bash
   docker restart caddy-agent-server
   # Agent will re-sync all containers and remove stale routes
   ```

3. Prevent by adding docker.sock event watching:
   - (Future feature planned)

## Caddy Issues

### Caddy Not Starting

**Symptom**: Caddy container exits immediately

**Solutions**:

1. Check logs:
   ```bash
   docker logs caddy-server --tail 50
   ```

2. Verify Caddyfile syntax:
   ```bash
   # Test locally
   caddy validate --config ./Caddyfile
   ```

3. Check port binding:
   ```bash
   # Port 80/443 might be in use
   lsof -i :80
   lsof -i :443
   ```

4. Allow non-privileged port binding:
   ```bash
   sysctl -w net.ipv4.ip_unprivileged_port_start=80
   ```

### Admin API Not Responding

**Symptom**: `curl http://localhost:2019/config/` times out or refused

**Solutions**:

1. Verify Caddy is running:
   ```bash
   docker ps | grep caddy-server
   ```

2. Check Admin API is enabled in Caddyfile:
   ```caddy
   {
     admin 0.0.0.0:2019  # or localhost:2019
   }
   ```

3. Check firewall allows 2019:
   ```bash
   netstat -tulpn | grep 2019
   ```

4. Restart Caddy:
   ```bash
   docker restart caddy-server
   sleep 5
   curl http://localhost:2019/config/ | head -c 100
   ```

### Routes Lost After Restart

**Symptom**: After `docker restart caddy-server`, all routes are gone

**Root Cause**: Caddy doesn't persist config by default

**Solutions**:

1. Agents will automatically resync:
   ```bash
   # Wait ~30 seconds
   sleep 30
   curl http://localhost:2019/config/apps/http/servers/reverse_proxy/routes | \
     jq 'length'
   # Should show number of routes again
   ```

2. Force agent resync:
   ```bash
   docker restart caddy-agent-server
   docker restart caddy-agent-remote
   docker restart caddy-agent-remote3
   # Wait for sync messages in logs
   ```

3. Backup config before restart:
   ```bash
   # Save current config
   curl http://localhost:2019/config/ > caddy-backup.json

   # After restart, manually restore if needed
   curl -X POST -H 'Content-Type: application/json' \
     -d @caddy-backup.json \
     http://localhost:2019/load
   ```

## Multi-Agent Issues

### Agent Conflicts (Routes Overwriting)

**Symptom**: Routes from one agent disappear when another agent syncs

**Root Cause**: Agents not using AGENT_ID prefixing (old bug - now fixed)

**Solutions**:

1. Verify agent versions are up-to-date:
   ```bash
   docker exec caddy-agent-server python3 --version
   docker exec caddy-agent-remote python3 --version
   ```

2. Check AGENT_ID is set and unique:
   ```bash
   docker inspect caddy-agent-server | grep AGENT_ID
   docker inspect caddy-agent-remote | grep AGENT_ID
   # Should show unique IDs like host1-server, host2-remote
   ```

3. View actual route IDs:
   ```bash
   curl http://localhost:2019/config/apps/http/servers/reverse_proxy/routes | \
     jq '.[] | .["@id"]'
   # Should show:
   # "host1-server_..."
   # "host2-remote_..."
   # "host3-remote_..."
   ```

### Agent Connectivity Issues

**Symptom**: Some agents sync, others show connection errors

**Solutions**:

1. Test connectivity from each agent host:
   ```bash
   # From host2
   curl -v http://192.168.1.10:2019/config/ | head

   # From host3
   curl -v http://192.168.1.10:2019/config/ | head
   ```

2. Check firewall rules on server:
   ```bash
   # On server host
   iptables -L -n | grep 2019
   ```

3. Verify network routing:
   ```bash
   traceroute 192.168.1.10  # From agent host
   ```

4. Check network isolation:
   ```bash
   # If using VPN, verify it's connected
   ifconfig | grep -A3 vpn0
   ```

## Performance Issues

### High CPU Usage

**Symptom**: Agent container using >50% CPU

**Solutions**:

1. Check for sync loops (agent syncing every second):
   ```bash
   docker logs caddy-agent-server | grep "Syncing config" | tail -5
   # Should be ~once per 2-5 seconds, not every second
   ```

2. Check for Docker event spam:
   ```bash
   docker logs caddy-agent-server | wc -l
   # If growing very fast, too many Docker events
   ```

3. Reduce logging:
   ```bash
   # In docker-compose.yml
   logging:
     driver: json-file
     options:
       max-size: "10m"
       max-file: "3"
   ```

### Memory Usage Growing

**Symptom**: Agent container memory increasing over time

**Solutions**:

1. Check for memory leaks:
   ```bash
   docker stats caddy-agent-server --no-stream
   # Check memory usage every minute
   for i in {1..5}; do docker stats caddy-agent-server --no-stream; sleep 60; done
   ```

2. Restart agent:
   ```bash
   docker restart caddy-agent-server
   ```

3. Monitor with limits:
   ```yaml
   services:
     agent:
       image: caddy-agent:latest
       deploy:
         resources:
           limits:
             memory: 512M
   ```

## Debugging

### Enable Verbose Logging

Edit `caddy-agent-watch.py` to add logging:

```python
# Change this line
logging.basicConfig(level=logging.INFO, ...)

# To this
logging.basicConfig(level=logging.DEBUG, ...)
```

Rebuild and redeploy.

### Collect Diagnostic Info

```bash
#!/bin/bash
echo "=== Host Info ==="
uname -a
docker version | head

echo "=== Container Status ==="
docker ps | grep -E caddy

echo "=== Agent Logs (last 50 lines) ==="
docker logs caddy-agent-server --tail 50

echo "=== Caddy Logs (last 20 lines) ==="
docker logs caddy-server --tail 20

echo "=== Routes in Caddy ==="
curl -s http://localhost:2019/config/apps/http/servers/reverse_proxy/routes | \
  jq '.[] | {id: .["@id"], domain: .match[0].host[0], upstream: .handle[0].upstreams[0].dial}'

echo "=== Agent Generated Config ==="
docker exec caddy-agent-server wc -l /app/caddy-output.json
```

Save as `diagnose.sh` and run when reporting issues.

## Getting Help

If you're stuck:

1. Run diagnostic script and save output
2. Check logs for error messages
3. Review [CONFIGURATION.md](CONFIGURATION.md) for config issues
4. Review [DEPLOYMENT.md](DEPLOYMENT.md) for setup issues
5. Report issue with:
   - `docker version`
   - `docker ps` output
   - Agent and Caddy logs
   - Routes output from Admin API
   - Configuration environment variables
   - Network topology diagram

---

**Version**: 1.0
**Last Updated**: 2025-11-16
