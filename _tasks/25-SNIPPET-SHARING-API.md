# Snippet Sharing API

**Date:** 2025-11-28
**Status:** IMPLEMENTED

## Problem

Remote agents cannot access snippets defined on other hosts. Snippets like `(wildcard)` and `(https)` are defined via Docker labels on the Caddy server host, but agents on remote hosts can't see them.

Current workaround: Use explicit labels instead of imports, or duplicate snippet definitions on each host.

## Solution

Add an HTTP API to the host1 agent that serves snippet definitions. Remote agents fetch snippets on-demand when building routes.

### Design Decisions

- **Centralized management** - Snippets defined only on host1 (Caddy server), single source of truth
- **No authentication** - Rely on network isolation (internal network only)
- **On-demand fetching** - Fetch when building routes, not on a schedule
- **5 minute cache** - Snippets rarely change, minimize network traffic

### Architecture

```
host1 (Caddy server)                    host2/host3 (remote agents)
┌──────────────────────┐                ┌─────────────────────────┐
│ caddy-agent          │                │ caddy-agent             │
│ ┌──────────────────┐ │                │                         │
│ │ Snippet API      │◄├────────────────┤ fetch_snippets()        │
│ │ :8567/snippets   │ │   on-demand    │ (when building routes)  │
│ └──────────────────┘ │                │                         │
│         ▲            │                │ ┌─────────────────────┐ │
│         │ discovers  │                │ │ Cache (5 min TTL)   │ │
│ ┌───────┴──────────┐ │                │ └─────────────────────┘ │
│ │ Docker socket    │ │                └─────────────────────────┘
│ │ (snippet labels) │ │
│ └──────────────────┘ │
└──────────────────────┘
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SNIPPET_API_PORT` | `0` | Port to serve snippets API. `0` = disabled. |
| `SNIPPET_SOURCES` | `` | Comma-separated URLs to fetch snippets from |
| `SNIPPET_CACHE_TTL` | `300` | Cache duration in seconds (5 min default) |

### API Endpoint

**GET /snippets**

Returns all discovered snippets as JSON:

```json
{
  "wildcard": {
    "tls.dns": "cloudflare ${CF_API_TOKEN}",
    "tls.resolvers": "1.1.1.1 1.0.0.1",
    "handle.abort": ""
  },
  "internal": {
    "tls": "internal"
  },
  "https": {
    "transport": "http",
    "transport.tls": "",
    "transport.tls_insecure_skip_verify": ""
  }
}
```

### Snippet Compatibility

**Important:** Not all snippets are safe to import with `reverse_proxy`:

| Snippet | Safe to import? | Reason |
|---------|-----------------|--------|
| `internal` | ✅ Yes | Only sets TLS cert type |
| `wildcard` | ❌ No | Has `handle.abort` - terminates request before proxy |
| `https` | ⚠️ Depends | Has `transport.tls` - requires HTTPS backend |

**Pattern from production:** Snippets like `wildcard` are imported by wildcard domain declarations (`*.lacny.me`) to configure TLS. Individual services should NOT import these snippets - they just declare their domain and Caddy uses the already-configured wildcard cert.

### Implementation

#### 1. Snippet Server (host1 agent)

```python
SNIPPET_API_PORT = int(os.getenv("SNIPPET_API_PORT", "0"))

def start_snippet_api():
    """Start HTTP server to serve snippets (if enabled)"""
    if SNIPPET_API_PORT <= 0:
        return

    from http.server import HTTPServer, BaseHTTPRequestHandler
    import json

    class SnippetHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/snippets":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(snippets).encode())
            else:
                self.send_error(404)

        def log_message(self, format, *args):
            logger.debug(f"Snippet API: {args[0]}")

    server = HTTPServer(("0.0.0.0", SNIPPET_API_PORT), SnippetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info(f"Snippet API listening on :{SNIPPET_API_PORT}")
```

#### 2. Snippet Client (remote agents)

```python
SNIPPET_SOURCES = os.getenv("SNIPPET_SOURCES", "")
SNIPPET_CACHE_TTL = int(os.getenv("SNIPPET_CACHE_TTL", "300"))

_snippet_cache = {}
_snippet_cache_time = 0

def fetch_remote_snippets():
    """Fetch snippets from remote sources (with caching)"""
    global _snippet_cache, _snippet_cache_time

    if not SNIPPET_SOURCES:
        return {}

    # Return cached if still valid
    if time.time() - _snippet_cache_time < SNIPPET_CACHE_TTL:
        return _snippet_cache

    for source in SNIPPET_SOURCES.split(","):
        source = source.strip()
        try:
            response = requests.get(f"{source}/snippets", timeout=5)
            if response.ok:
                _snippet_cache = response.json()
                _snippet_cache_time = time.time()
                logger.info(f"Fetched {len(_snippet_cache)} snippets from {source}")
                return _snippet_cache
        except Exception as e:
            logger.warning(f"Failed to fetch snippets from {source}: {e}")

    # Return stale cache on failure
    if _snippet_cache:
        logger.warning("Using stale snippet cache")
    return _snippet_cache
```

#### 3. Integration

In `get_caddy_routes()`, merge remote snippets before processing imports:

```python
def get_caddy_routes():
    # Discover local snippets from Docker labels
    snippets = discover_snippets_from_labels()

    # Merge remote snippets (fetched on-demand, cached)
    snippets.update(fetch_remote_snippets())

    # ... rest of route building uses merged snippets
```

### Usage

**Host1 (serves snippets):**
```yaml
caddy-agent:
  network_mode: host  # Port automatically exposed, no mapping needed
  environment:
    - SNIPPET_API_PORT=8567
```

**Host2/Host3 (fetches snippets):**
```yaml
caddy-agent:
  environment:
    - SNIPPET_SOURCES=http://192.168.0.96:8567
```

Now remote agents can fetch and use snippets defined on host1. Use `caddy.import: internal` for safe snippet imports with `reverse_proxy`.

### Error Handling

- **Source unreachable**: Log warning, use stale cache if available, continue with route push
- **Invalid response**: Log warning, skip source, try next source if configured
- **Caddy rejects config**: Normal Caddy error handling applies (snippet references unresolved)

### Security

- **Network isolation** - Only expose API on internal network
- **No sensitive data** - Snippets contain placeholders like `${CF_API_TOKEN}` which Caddy resolves, not the agent

### Files to Modify

1. **`caddy-agent-watch.py`**
   - Add `start_snippet_api()` function
   - Add `fetch_remote_snippets()` function
   - Merge remote snippets in `get_caddy_routes()`

2. **`CLAUDE.md`**
   - Document new environment variables

3. **`docker-compose-prod-server.yml`**
   - Add `SNIPPET_API_PORT=8567` and expose port `8567:8567`

4. **`docker-compose-prod-agent2.yml` / `agent3.yml`**
   - Add `SNIPPET_SOURCES=http://192.168.0.96:8567`

### Testing

**Manual Testing:**
1. Deploy agent on host1 with `SNIPPET_API_PORT=8567`
2. Deploy agent on host2 with `SNIPPET_SOURCES=http://192.168.0.96:8567`
3. Define snippets via labels on host1
4. Use `caddy.import: snippet_name` on host2
5. Verify snippets are resolved correctly
6. Test cache: make request, verify no re-fetch within 5 minutes
7. Test failure: stop host1 API, verify host2 uses stale cache

**Automated Testing (test_all.py):**

Add new test class `SnippetAPITests`:

```python
class SnippetAPITests:
    """Tests for Snippet Sharing API"""

    @staticmethod
    def test_snippet_api_accessible():
        """Test: Snippet API is accessible on host1"""
        result = subprocess.run(
            ["curl", "-s", "--max-time", "5", f"http://{CADDY_SERVER}:8567/snippets"],
            capture_output=True, text=True, timeout=7
        )
        assert result.returncode == 0, "Snippet API not accessible"
        data = json.loads(result.stdout)
        assert isinstance(data, dict), "Expected JSON object"
        print("[PASS] test_snippet_api_accessible")

    @staticmethod
    def test_snippet_api_returns_snippets():
        """Test: Snippet API returns expected snippets"""
        result = subprocess.run(
            ["curl", "-s", "--max-time", "5", f"http://{CADDY_SERVER}:8567/snippets"],
            capture_output=True, text=True, timeout=7
        )
        data = json.loads(result.stdout)
        assert "wildcard" in data, "Missing 'wildcard' snippet"
        assert "internal" in data, "Missing 'internal' snippet"
        print("[PASS] test_snippet_api_returns_snippets")

    @staticmethod
    def test_remote_snippet_import():
        """Test: Remote agent can use snippet fetched from host1"""
        # Route on host2 using caddy.import: wildcard (fetched from host1)
        result = IntegrationTests.run_curl("remote-snippet-test.lan", port=443, https=True)
        assert result and "remote-snippet" in result.lower(), f"Expected remote-snippet response, got: {result}"
        print("[PASS] test_remote_snippet_import")
```

**Files to Update:**

5. **`test_all.py`**
   - Add `SnippetAPITests` class
   - Add `--snippet-api` flag
   - Include in default test run

6. **`docker-compose-prod-agent2.yml`**
   - Add test container with `caddy.import: internal` (fetched remotely)
   - Domain: `remote-snippet-test.lan`
   - Note: Uses `internal` not `wildcard` (wildcard has handle.abort)
