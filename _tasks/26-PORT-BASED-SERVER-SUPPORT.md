# Task 26: Port-Based Server Support

**Status: COMPLETED** (2025-12-03)

## Problem

The caddy-agent currently only supports domain-based routes. Port-based routes like:

```yaml
caddy_20: ":2020"
caddy_20.reverse_proxy: "localhost:2019"
```

Are not supported. In Caddy, this creates a separate server listening on port 2020, not a route matching `:2020` as a hostname.

## Current Behavior

The agent treats `:2020` as a hostname, creating:
```json
{
  "match": [{"host": [":2020"]}],
  "handle": [{"handler": "reverse_proxy", ...}]
}
```

This is incorrect - Caddy won't match requests on port 2020.

## Required Behavior

Port-based routes (starting with `:`) should create a new server:
```json
{
  "apps": {
    "http": {
      "servers": {
        "srv_2020": {
          "listen": [":2020"],
          "routes": [...]
        }
      }
    }
  }
}
```

## Implementation Plan

1. **Detection**: In `parse_container_labels()`, detect if domain starts with `:`
2. **Flagging**: Add `_port_server` field to route to indicate port-based server
3. **Server Creation**: In `push_to_caddy()`, create separate servers for port-based routes
4. **Route ID**: Use format `{AGENT_ID}_{container}_port{port}` for uniqueness

## Test Plan

1. Add test container with port-based route to compose file
2. Add unit test for port detection
3. Add integration test to verify server creation and connectivity

## Files to Modify

- `caddy-agent-watch.py` - Core implementation
- `docker-compose-prod-agent2.yml` - Add test container
- `test_all.py` - Add tests

## Implementation Summary

### Changes Made

1. **`caddy-agent-watch.py`**:
   - `parse_container_labels()`: Added detection for port-based routes (domains starting with `:`)
   - Added `_port_server` flag to routes for port-based servers
   - `push_to_caddy()`: Added logic to create/update separate servers for port-based routes
   - Server naming: `srv_port_{port}` (e.g., `srv_port_3000`)

2. **`docker-compose-prod-agent2.yml`**:
   - Added `test-port-server` container with `caddy: ":3000"` label

3. **`test_all.py`**:
   - Added unit tests: `test_port_based_route`, `test_port_based_numbered`
   - Added integration tests: `test_port_based_server_connectivity`, `test_port_based_server_config`

### Test Results

```
All tests pass (38/38):
- Unit Tests: 10/10 (including 2 new port-based tests)
- Integration Tests: 18/18 (including 2 new port-based tests)
- Server Mode Tests: 3/3
- Snippet API Tests: 5/5
- Config Tests: 2/2
```

### Verification

```bash
# Server created in Caddy config
curl -s http://192.168.0.96:2020/config/apps/http/servers | grep srv_port_3000
# "srv_port_3000": { "listen": [":3000"], ...}

# Connectivity works
curl http://192.168.0.96:3000
# SUCCESS - Port-based server on :3000 (host2)
```
