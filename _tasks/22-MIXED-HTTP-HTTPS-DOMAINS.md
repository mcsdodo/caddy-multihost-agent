# Mixed HTTP/HTTPS Domains Support

**Date:** 2025-11-28
**Status:** ✅ COMPLETE

## Problem

Labels with multiple domains where some need HTTP-only and some need HTTPS weren't working:

```yaml
caddy_116: http://frigate-gpu.lan, frigate-gpu.lacny.me
```

**Previous behavior:**
- Entire label checked for `http://` prefix
- Both domains treated as HTTP-only (went to srv2)
- HTTPS domain `frigate-gpu.lacny.me` unreachable on srv1

**Needed behavior:**
- Each domain checked individually for `http://` prefix
- `frigate-gpu.lan` → srv2 (HTTP-only)
- `frigate-gpu.lacny.me` → srv1 (HTTPS)

## Implementation

### File: `caddy-agent-watch.py`

### Fix 1: Parse each domain individually (line ~284)

```python
# Parse multiple domains (comma-separated) and check each for http:// prefix
raw_domains = [d.strip() for d in domain.split(',')]
http_only_domains = []
https_domains = []
for d in raw_domains:
    if d.startswith('http://'):
        http_only_domains.append(d[7:])  # Strip http:// prefix
    else:
        https_domains.append(d)
```

### Fix 2: Create separate routes for mixed domains (line ~332)

```python
# Create separate routes for HTTP-only and HTTPS domains
if http_only_domains:
    route_id = base_route_id if not https_domains else f"{base_route_id}_http"
    route = {
        "@id": route_id,
        "handle": copy.deepcopy(handle),
        "match": [{"host": http_only_domains}],
        "_http_only": True
    }
    routes.append(route)

if https_domains:
    route_id = base_route_id if not http_only_domains else f"{base_route_id}_https"
    route = {
        "@id": route_id,
        "handle": copy.deepcopy(handle),
        "match": [{"host": https_domains}],
        "_http_only": False
    }
    routes.append(route)
```

### Fix 3: Handle spaces in upstreams template (line ~531)

```python
# Handle both {{upstreams PORT}} and {{ upstreams PORT }} (with optional spaces)
upstreams_match = re.match(r"\{\{\s*upstreams\s+(\d+)\s*}}", proxy_target.strip())
```

## Test Results

**Agent logs show correct separation:**
```
Processing route 116: domain=http://frigate-gpu.lan, frigate-gpu.lacny.me
Route: http_only_domains=['frigate-gpu.lan'], https_domains=['frigate-gpu.lacny.me'], upstream='192.168.0.115:5012'
HTTP-only routes: ['big-ai_surveillance-frigate-testing_116_http', 'big-ai_alloy']
HTTPS routes: ['big-ai_surveillance-frigate-testing_116_https', 'big-ai_webserver']
Server selection: HTTPS=srv1, HTTP-only=srv2
```

**End-to-end tests:**
- `http://frigate-gpu.lan` → 200 ✅
- `https://frigate-gpu.lacny.me` → 200 ✅

**Image pushed:** `mcsdodo/caddy-agent:latest`
