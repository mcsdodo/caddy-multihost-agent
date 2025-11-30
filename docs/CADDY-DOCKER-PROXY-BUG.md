# caddy-docker-proxy Snippet Merging Bug

## Summary

`caddy-docker-proxy` does not properly merge `reverse_proxy` subdirectives from imported snippets with the route's own `reverse_proxy` directive. Instead, it creates **two separate** `reverse_proxy` handlers, causing "no upstreams available" errors.

## The Problem

When using a snippet that defines `reverse_proxy.transport.*` directives:

```yaml
# Snippet definition
caddy_2: (https)
caddy_2.reverse_proxy.transport: http
caddy_2.reverse_proxy.transport.tls: ""
caddy_2.reverse_proxy.transport.tls_insecure_skip_verify: ""

# Route using the snippet
caddy_115: proxmox.lacny.me
caddy_115.import: https
caddy_115.reverse_proxy: 192.168.0.111:8006
```

### Expected Behavior

A single `reverse_proxy` handler with both `transport` and `upstreams`:

```json
{
  "handler": "reverse_proxy",
  "transport": {
    "protocol": "http",
    "tls": { "insecure_skip_verify": true }
  },
  "upstreams": [{ "dial": "192.168.0.111:8006" }]
}
```

### Actual Behavior (Bug)

Two separate `reverse_proxy` handlers:

```json
{
  "handle": [
    {
      "handler": "reverse_proxy",
      "transport": { "protocol": "http", "tls": { "insecure_skip_verify": true } }
      // NO upstreams!
    },
    {
      "handler": "reverse_proxy",
      "upstreams": [{ "dial": "192.168.0.111:8006" }]
      // NO transport!
    }
  ]
}
```

The first handler has no upstreams, causing: `"no upstreams available"` error.

## Root Cause

`caddy-docker-proxy` converts Docker labels to Caddyfile format, then to JSON. When a snippet defines `reverse_proxy.transport.*` and the route defines `reverse_proxy`, they are not recognized as the same directive and are processed separately.

## Workaround for caddy-docker-proxy

Don't use snippets for transport config. Define everything inline:

```yaml
caddy_115: proxmox.lacny.me
caddy_115.reverse_proxy: 192.168.0.111:8006
caddy_115.reverse_proxy.transport: http
caddy_115.reverse_proxy.transport.tls: ""
caddy_115.reverse_proxy.transport.tls_insecure_skip_verify: ""
```

## caddy-agent Solution

`caddy-agent` handles this correctly by:
1. Using JSON API directly (not Caddyfile conversion)
2. Recognizing `reverse_proxy.transport.*` keys in snippets
3. Properly merging them with route's `reverse_proxy` config

The fix in `parse_transport_config()` handles both formats:
- Legacy: `transport`, `transport.tls`, `transport.tls_insecure_skip_verify`
- New: `reverse_proxy.transport`, `reverse_proxy.transport.tls`, etc.

## Comparison

| Feature | caddy-docker-proxy | caddy-agent |
|---------|-------------------|-------------|
| Config method | Caddyfile → JSON | Direct JSON API |
| Snippet merging | ❌ Creates duplicate handlers | ✅ Properly merges |
| `reverse_proxy.transport.*` | ❌ Not merged | ✅ Merged correctly |
| Workaround | Inline config only | Use snippets normally |

## Affected Versions

- `caddy-docker-proxy`: All versions (as of 2024)
- `caddy-agent`: Fixed in commit `f33ecd2`

## References

- caddy-docker-proxy: https://github.com/lucaslorentz/caddy-docker-proxy
- Caddy JSON API: https://caddyserver.com/docs/json/
