# Route Recovery on Caddy Restart

**Date:** 2025-11-28
**Status:** IMPLEMENTED - Deployed and tested

## Problem

When Caddy restarts, all routes pushed by remote agents are lost because:
1. Caddy doesn't persist routes by default (in-memory only)
2. Agents only push routes on Docker events (container start/stop)
3. Agents don't know when Caddy restarts

**Impact:** After Caddy restart, remote host routes are unavailable until agents are manually restarted.

## Current Behavior

```
Agent startup → sync_config() → push routes
Docker event  → sync_config() → push routes
Caddy restart → (agents unaware) → routes lost
```

---

## Approach 1: Periodic Resync

**Periodic resync every 60 seconds** (configurable)

```
Agent startup     → sync_config() → push routes
Docker event      → sync_config() → push routes
Every 60 seconds  → sync_config() → push routes (if needed)
```

### Implementation

Add a timer thread to `caddy-agent-watch.py`:

```python
RESYNC_INTERVAL = int(os.getenv("RESYNC_INTERVAL", "60"))  # seconds, 0 to disable

def periodic_resync():
    """Periodically resync routes to handle Caddy restarts"""
    while True:
        time.sleep(RESYNC_INTERVAL)
        logger.info("⏰ Periodic resync triggered")
        sync_config()

# In main(), after initial sync:
if RESYNC_INTERVAL > 0:
    resync_thread = threading.Thread(target=periodic_resync, daemon=True)
    resync_thread.start()
    logger.info(f"⏰ Periodic resync enabled: every {RESYNC_INTERVAL}s")
```

### Smart Checking (Optimization)

To avoid unnecessary API calls, check if routes exist before pushing:

```python
def routes_need_sync():
    """Check if our routes are missing from Caddy"""
    try:
        response = requests.get(f"{CADDY_URL}/config/apps/http/servers/srv1/routes")
        routes = response.json()
        our_routes = [r for r in routes if r.get("@id", "").startswith(f"{AGENT_ID}_")]
        # Compare with expected routes from local Docker containers
        expected_count = len(get_caddy_routes()[0])  # HTTPS routes
        return len(our_routes) != expected_count
    except:
        return True  # If can't check, assume resync needed
```

## Environment Variable

| Variable | Default | Description |
|----------|---------|-------------|
| `RESYNC_INTERVAL` | `60` | Seconds between resyncs. Set to `0` to disable. |

## Benefits

1. **Handles Caddy restarts** - Routes restored within 60s
2. **Handles network blips** - Eventual consistency
3. **Handles config resets** - Self-healing
4. **Low overhead** - One GET + conditional POST per minute

## Testing

1. Deploy agents with `RESYNC_INTERVAL=60`
2. Restart Caddy: `docker restart caddy-server`
3. Wait 60 seconds
4. Verify routes are restored: `curl http://host1:2020/config/apps/http/servers/srv1/routes`

## Files to Modify

1. `caddy-agent-watch.py` - Add periodic resync thread
2. `docker-compose-prod-agent*.yml` - Add `RESYNC_INTERVAL` env var (optional)
3. `CLAUDE.md` - Document new environment variable
4. `docs/CONFIGURATION.md` - Document `RESYNC_INTERVAL`

---

## Approach 2: Caddy Health Check

**Detect Caddy restart by tracking config hash or uptime, resync immediately**

```
Agent startup     → get config hash → sync_config()
Every 5 seconds   → check config hash → if changed, sync_config()
Caddy restart     → hash changes → immediate resync
```

### Implementation

```python
HEALTH_CHECK_INTERVAL = int(os.getenv("HEALTH_CHECK_INTERVAL", "5"))  # seconds, 0 to disable

last_config_hash = None

def get_caddy_config_hash():
    """Get hash of current Caddy config to detect restarts"""
    try:
        response = requests.get(f"{CADDY_URL}/config/", timeout=2)
        if response.ok:
            import hashlib
            return hashlib.md5(response.text.encode()).hexdigest()
    except:
        pass
    return None

def health_check_loop():
    """Monitor Caddy for restarts and resync when detected"""
    global last_config_hash
    last_config_hash = get_caddy_config_hash()

    while True:
        time.sleep(HEALTH_CHECK_INTERVAL)
        current_hash = get_caddy_config_hash()

        if current_hash is None:
            logger.warning("⚠️ Caddy API unreachable")
            continue

        if current_hash != last_config_hash:
            logger.info("🔄 Caddy config changed, resyncing...")
            sync_config()
            last_config_hash = get_caddy_config_hash()  # Update after our sync

# In main(), after initial sync:
if HEALTH_CHECK_INTERVAL > 0:
    health_thread = threading.Thread(target=health_check_loop, daemon=True)
    health_thread.start()
    logger.info(f"🏥 Health check enabled: every {HEALTH_CHECK_INTERVAL}s")
```

### Environment Variable

| Variable | Default | Description |
|----------|---------|-------------|
| `HEALTH_CHECK_INTERVAL` | `5` | Seconds between health checks. Set to `0` to disable. |

### Benefits

1. **Fast recovery** - Detects restart within 5 seconds
2. **Low overhead** - Small GET request, no POST unless needed
3. **Precise detection** - Only resyncs when config actually changes

### Limitations

1. **Doesn't handle network issues** - If API is down, can't detect restart
2. **Hash changes on any config change** - May trigger unnecessary resyncs
3. **Slightly more complex** - Needs state tracking

---

## Implementation: Combined Approach

**Both mechanisms run together for maximum resilience:**

- **Health check** (every 5s) - Fast detection of Caddy restarts
- **Periodic resync** (every 5min) - Fallback for network issues, edge cases

### Full Implementation

```python
import threading
import time
# NOTE: Assumes existing imports: os, requests, logger, get_caddy_routes, sync_config, CADDY_URL, AGENT_ID

# Environment variables
# NOTE: RESYNC_INTERVAL default changed from 60s (Approach 1) to 300s here
#       because health check handles fast recovery; periodic is fallback only
HEALTH_CHECK_INTERVAL = int(os.getenv("HEALTH_CHECK_INTERVAL", "5"))    # seconds, 0 to disable
RESYNC_INTERVAL = int(os.getenv("RESYNC_INTERVAL", "300"))              # seconds, 0 to disable

# Shared state
last_sync_time = 0
sync_lock = threading.Lock()

def get_our_route_count():
    """Get count of our routes currently in Caddy"""
    try:
        # Check both srv1 (HTTPS) and srv2 (HTTP-only)
        count = 0
        for server in ["srv1", "srv2"]:
            response = requests.get(f"{CADDY_URL}/config/apps/http/servers/{server}/routes", timeout=2)
            if response.ok:
                routes = response.json() or []
                count += len([r for r in routes if r.get("@id", "").startswith(f"{AGENT_ID}_")])
        return count
    except:
        return -1  # Error state

def get_expected_route_count():
    """Get count of routes we should have (from local Docker containers)"""
    https_routes, http_routes, _, _ = get_caddy_routes()
    return len(https_routes) + len(http_routes)

def routes_need_sync():
    """Check if our routes are missing or incomplete"""
    current = get_our_route_count()
    if current == -1:
        return None  # Can't determine, API error
    expected = get_expected_route_count()
    return current < expected

def safe_sync():
    """Thread-safe sync with deduplication"""
    global last_sync_time
    with sync_lock:
        # Debounce: don't sync more than once per 5 seconds
        now = time.time()
        if now - last_sync_time < 5:
            logger.debug("Sync skipped (debounce)")
            return False
        last_sync_time = now
        sync_config()  # IMPORTANT: Must be inside lock to prevent concurrent syncs
    return True

def health_check_loop():
    """Fast detection: check if our routes are present every few seconds"""
    time.sleep(10)  # Startup delay: let initial sync settle before checking
    consecutive_failures = 0

    while True:
        # Exponential backoff on repeated failures (max 30s)
        interval = min(HEALTH_CHECK_INTERVAL * (2 ** consecutive_failures), 30)
        time.sleep(interval)

        need_sync = routes_need_sync()
        if need_sync is None:
            consecutive_failures += 1
            logger.warning("🏥 Health check: Caddy API unreachable")
            continue

        consecutive_failures = 0  # Reset on success
        if need_sync:
            logger.info("🏥 Routes missing, resyncing...")
            safe_sync()

def periodic_resync_loop():
    """Fallback: force resync periodically regardless of state"""
    while True:
        time.sleep(RESYNC_INTERVAL)

        need_sync = routes_need_sync()
        if need_sync is None:
            logger.info("⏰ Periodic check: API unreachable, forcing sync...")
            safe_sync()
        elif need_sync:
            logger.info("⏰ Periodic check: routes missing, resyncing...")
            safe_sync()
        else:
            logger.debug("⏰ Periodic check: routes OK")

def start_recovery_threads():
    """Start both recovery mechanisms"""
    if HEALTH_CHECK_INTERVAL > 0:
        health_thread = threading.Thread(target=health_check_loop, daemon=True, name="health-check")
        health_thread.start()
        logger.info(f"🏥 Health check enabled: every {HEALTH_CHECK_INTERVAL}s")

    if RESYNC_INTERVAL > 0:
        resync_thread = threading.Thread(target=periodic_resync_loop, daemon=True, name="periodic-resync")
        resync_thread.start()
        logger.info(f"⏰ Periodic resync enabled: every {RESYNC_INTERVAL}s")

# In main(), after initial sync:
start_recovery_threads()
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HEALTH_CHECK_INTERVAL` | `5` | Seconds between health checks. `0` to disable. |
| `RESYNC_INTERVAL` | `300` | Seconds between periodic resyncs. `0` to disable. |

### Behavior Matrix

| Scenario | Health Check | Periodic Resync | Recovery Time |
|----------|--------------|-----------------|---------------|
| Caddy restart | ✅ Detects missing routes | ✅ Fallback | ~15 seconds* |
| Network blip | ❌ API unreachable (backoff) | ✅ Retries later | ~5 minutes |
| Config corruption | ✅ Detects missing routes | ✅ Fallback | ~15 seconds* |
| Agent restart | N/A (initial sync) | N/A | Immediate |

*10s startup delay + 5s health check interval

### Key Features

1. **Debouncing** - `sync_lock` prevents multiple concurrent syncs
2. **Smart checking** - `routes_need_sync()` avoids unnecessary pushes
3. **Graceful degradation** - Each mechanism works independently
4. **Configurable** - Both intervals can be tuned or disabled
5. **Exponential backoff** - Reduces load when Caddy is unreachable
6. **Startup delay** - Prevents false positives after agent start

---

## Testing

```bash
# 1. Deploy with recovery enabled (default)
docker compose up -d

# 2. Verify threads started
docker logs caddy-agent-remote | grep -E "Health check|Periodic resync"

# 3. Restart Caddy and observe recovery
docker restart caddy-server
sleep 10
curl http://host1:2020/config/apps/http/servers/srv1/routes | jq '.[].["@id"]'

# 4. Test periodic fallback (simulate network issue)
# Block agent -> caddy traffic briefly, then restore
# Routes should recover within RESYNC_INTERVAL
```

## Files to Modify

1. **`caddy-agent-watch.py`**
   - Add `get_our_route_count()` - count agent's routes in Caddy
   - Add `get_expected_route_count()` - count routes from local Docker
   - Add `routes_need_sync()` - compare current vs expected
   - Add `safe_sync()` with debouncing (sync inside lock!)
   - Add `health_check_loop()` with startup delay + exponential backoff
   - Add `periodic_resync_loop()`
   - Add `start_recovery_threads()`
   - Call `start_recovery_threads()` in main

2. **`docker-compose-prod-agent*.yml`**
   - Add env vars for visibility (even if using defaults):
     ```yaml
     environment:
       - HEALTH_CHECK_INTERVAL=5
       - RESYNC_INTERVAL=300
     ```

3. **`docs/CONFIGURATION.md`**
   - Document `HEALTH_CHECK_INTERVAL`
   - Document `RESYNC_INTERVAL`

4. **`CLAUDE.md`**
   - Add recovery mechanism to architecture section

---

## Review Notes (2025-11-28)

Changes made based on code review:

1. **Fixed race condition in `safe_sync()`** - Moved `sync_config()` inside the lock to prevent concurrent syncs
2. **Added startup delay** - 10s delay in `health_check_loop()` prevents false positives after agent start
3. **Added exponential backoff** - Reduces API load when Caddy is unreachable (5s → 10s → 20s → 30s max)
4. **Fixed log level** - API unreachable now logs at WARNING, not DEBUG
5. **Fixed behavior matrix** - Changed "hash" references to "missing routes" (combined approach uses route count, not hash)
6. **Fixed function name** - Documentation now correctly references `routes_need_sync()`
7. **Documented default change** - Added note explaining why `RESYNC_INTERVAL` changed from 60s to 300s
8. **Added import note** - Clarified that code assumes existing imports
9. **Updated Files to Modify** - Added docker-compose env vars and fixed function names
