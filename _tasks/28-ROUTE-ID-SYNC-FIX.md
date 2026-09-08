# A missing route never comes back if a stale route keeps the count right

**Date:** 2026-09-08
**Status:** IMPLEMENTED - tested on host1/host2/host3, not yet released

## Problem

One domain went dark and stayed dark. The container was healthy, the agent
resolved its route every 5 seconds, and the route was absent from Caddy. The
agent sent no `POST /load` for 15 minutes.

`routes_need_sync()` compared route **counts**:

```python
current = get_our_route_count()      # routes in Caddy with our AGENT_ID prefix
expected = get_expected_route_count()  # routes our containers ask for
need_sync = current < expected
```

The agent owned 40 routes in Caddy and generated 40 routes from Docker, so
`40 < 40` was False. The two sets were not the same 40:

```
generated, not live : infra_kniha-jazd     <- lost during a container redeploy
live, not generated : infra_portainer_http <- container removed months earlier
```

The orphan hid the missing route. Both recovery paths (health check and
periodic resync) call `routes_need_sync()`, so neither ever fired.

## Why the orphan could not be pruned

`push_to_caddy()` merged the HTTP-only server only when it had HTTP-only routes
to add:

```python
if http_only_routes and http_server:
```

The agent generates no `http://`-prefixed route any more, so the `:80` server
was never merged and `merge_routes()` never removed the orphan from it.
`get_our_route_count()` counts every server, so the orphan kept inflating the
count.

## Changes

1. **`get_our_route_ids()` / `get_expected_route_ids()`** replace the two count
   functions. Both return `None` when they cannot read their source. The old
   `get_expected_route_count()` returned `0` on an exception, which reads as
   "we expect no routes" and can only ever suppress a sync.

2. **`routes_need_sync()` compares ID sets.** Only a *missing* route asks for a
   sync. A stale route does not: a port-based or Layer4 server whose container
   is gone is never merged, so treating an orphan as a reason to push would
   repeat that push every 5 seconds forever.

3. **`push_to_caddy()` merges each server exactly once, and prunes.** A server
   is merged even when we generate no route for it, so orphans go. Merging by
   server also fixes a second bug: when HTTPS and HTTP-only resolved to the
   same server, the second merge pruned everything the first one had just
   added. Pruning is skipped when no route was generated at all, because an
   empty result can also mean the Docker enumeration failed.

## Tests

`python tests/test_all.py --sync` - 9 unit tests, no hosts needed. Each one was
watched failing against the old code first.

Integration: 23/23 on host1/host2/host3.

## The A/B that proves it

`outage_repro.py` deletes one route of host2's from Caddy and injects an orphan
with host2's prefix, so the count stays the same and the sets differ.

| Agent build | victim route restored | ghost route pruned |
|---|---|---|
| pre-fix | No | No |
| patched | Yes | Yes |

Same rig, same experiment, only the binary differs.

## Not fixed here

The test agents fill their 7G disks with unrotated Docker json logs - one file
had grown to 4.8 GB and stopped the LXC from starting at all. The test compose
files need a `logging` block with `max-size` and `max-file`.
