# Layer4 Support Task

## Original Request

Verify if caddy-agent can push Layer4 routes to Caddy server.

Reference Caddyfile:
```
{
    admin :2019 {
        origins 192.168.0.20, 0.0.0.0, localhost
    }
    layer4 {
        mqtt.lan:8883 {
            route {
                proxy {
                    upstream 192.168.0.204:8883
                }
            }
        }
        mqtt.lan:1883 {
            route {
                proxy {
                    upstream 192.168.0.204:1883
                }
            }
        }
        :443 {
            @lacny tls sni *.lacny.me
            route @lacny {
                proxy {
                    upstream 192.168.0.21:443
                }
            }
        }
    }
}
```

## Status: COMPLETED

Layer4 support has been implemented and tested successfully.

---

# Implementation Summary

## JSON Structure

Layer4 config lives in `apps.layer4.servers`:

```json
{
  "apps": {
    "layer4": {
      "servers": {
        "server_name": {
          "listen": [":1883"],
          "routes": [{
            "handle": [{
              "handler": "proxy",
              "upstreams": [{"dial": ["host:port"]}]
            }]
          }]
        }
      }
    }
  }
}
```

**Key difference from HTTP**: The `dial` field is an **array**, not a string.

## Label Format

```yaml
# Simple Layer4 TCP proxy
caddy.layer4: ":1883"
caddy.layer4.route.proxy: "{{upstreams 11883}}"

# With SNI matching
caddy.layer4: ":443"
caddy.layer4.@sni: "tls sni *.lacny.me"
caddy.layer4.route.proxy: "192.168.0.21:443"

# Multiple L4 routes (numbered)
caddy.layer4_0: ":1883"
caddy.layer4_0.route.proxy: "host:1883"
caddy.layer4_1: ":8883"
caddy.layer4_1.route.proxy: "host:8883"
```

## Changes Made

**New functions in `caddy-agent-watch.py`**:
- `parse_layer4_labels()` - Parses `caddy.layer4*` labels
- `check_layer4_support()` - Detects if Caddy has Layer4 module

**Modified functions**:
- `get_caddy_routes()` - Returns Layer4 routes as 4th element
- `push_to_caddy()` - Handles Layer4 routes
- `get_our_route_count()` / `get_expected_route_count()` - Count L4 servers

**Bug fixes**:
- Null config handling from fresh Caddy instances
- Layer4 detection uses read-only GET (avoids race condition where PUT could wipe existing L4 config)

## Test Results

**Remote hosts test**:
- host1 (192.168.0.96): Caddy with Layer4 module
- host2 (192.168.0.98): Agent + MQTT broker

```
Client null sending CONNECT
Client null received CONNACK (0)
Client null sending PUBLISH (d0, q0, r0, m1, 'test', ... (18 bytes))
Client null sending DISCONNECT
```

**Connection flow**: MQTT client → host1:1883 (Caddy L4) → host2:11883 (MQTT broker)

## Files Modified

- `caddy-agent-watch.py`: Layer4 parsing, detection, push support
- `tests/Dockerfile.Caddy`: Added `--with github.com/mholt/caddy-l4`
- `tests/docker-compose-prod-agent2.yml`: Added MQTT test service
- `tests/mosquitto.conf`: MQTT broker config
- `tests/test_all.py`: Added Layer4 unit and integration tests

## Building Caddy with Layer4

```dockerfile
FROM caddy:2-builder AS builder
RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/lucaslorentz/caddy-docker-proxy/v2 \
    --with github.com/mholt/caddy-l4

FROM caddy:2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
CMD ["caddy", "docker-proxy"]
```
