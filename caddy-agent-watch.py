import docker
import requests
import os
import json
import threading
import logging
import signal
import sys
import time
import socket
import copy

# Configuration - Simplified model
CADDY_URL = os.getenv("CADDY_URL", "http://localhost:2019")
HOST_IP = os.getenv("HOST_IP", None)  # If set, enables remote mode. Auto-detects with network_mode: host
AGENT_ID = os.getenv("AGENT_ID", socket.gethostname())
CADDY_API_TOKEN = os.getenv("CADDY_API_TOKEN", "")
DOCKER_LABEL_PREFIX = os.getenv("DOCKER_LABEL_PREFIX", "caddy")
AGENT_FILTER_LABEL = os.getenv("AGENT_FILTER_LABEL", None)

# Recovery mechanism configuration
HEALTH_CHECK_INTERVAL = int(os.getenv("HEALTH_CHECK_INTERVAL", "5"))    # seconds, 0 to disable
RESYNC_INTERVAL = int(os.getenv("RESYNC_INTERVAL", "300"))              # seconds, 0 to disable

# Logging configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()  # DEBUG, INFO, WARNING, ERROR

# Snippet sharing API configuration
SNIPPET_API_PORT = int(os.getenv("SNIPPET_API_PORT", "0"))  # 0 = disabled
SNIPPET_SOURCES = os.getenv("SNIPPET_SOURCES", "")  # Comma-separated URLs
SNIPPET_CACHE_TTL = int(os.getenv("SNIPPET_CACHE_TTL", "300"))  # 5 minutes

# Cached effective host IP (computed once at startup)
_effective_host_ip = None

# Snippet API cache
_snippet_cache = {}
_snippet_cache_time = 0

client = docker.DockerClient(base_url='unix://var/run/docker.sock')

# Configure logging with LOG_LEVEL env var
log_level = getattr(logging, LOG_LEVEL, logging.INFO)
logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

def detect_host_ip():
    """Auto-detect host IP address"""
    try:
        # Try to get IP by connecting to a remote host (doesn't actually connect)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logger.warning(f"Failed to auto-detect host IP: {e}. Using 127.0.0.1")
        return "127.0.0.1"

def is_host_network_mode():
    """Check if the agent container itself is running in host network mode.
    We detect this by checking if we can see the host's network interfaces.
    """
    try:
        # In host network mode, we can detect the host IP
        # In bridge mode, detect_host_ip returns the container's gateway
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        # If IP starts with 172.17 or 172.18, we're likely in bridge mode
        # This is a heuristic - not 100% reliable but good enough
        return not ip.startswith("172.")
    except Exception:
        return False

def get_effective_host_ip():
    """Get the effective HOST_IP for upstream resolution.

    Returns:
        str: IP address to use for upstreams (remote mode)
        None: Use container names/localhost (local mode)

    Logic:
        1. If HOST_IP is explicitly set, use it
        2. If running in network_mode: host, auto-detect
        3. Otherwise, return None (local mode)
    """
    global _effective_host_ip

    # Return cached value if already computed
    if _effective_host_ip is not None:
        return _effective_host_ip if _effective_host_ip != "" else None

    if HOST_IP:
        logger.info(f"Using HOST_IP: {HOST_IP} (explicit)")
        _effective_host_ip = HOST_IP
        return HOST_IP

    if is_host_network_mode():
        detected = detect_host_ip()
        logger.info(f"Using HOST_IP: {detected} (auto-detected, network_mode: host)")
        _effective_host_ip = detected
        return detected

    logger.info("Using local addressing (no HOST_IP, container network)")
    _effective_host_ip = ""  # Empty string means "computed, result is None"
    return None

def get_published_port(container, internal_port):
    """Get the published (host) port for a given container internal port"""
    try:
        ports = container.attrs.get('NetworkSettings', {}).get('Ports', {})
        port_key = f"{internal_port}/tcp"
        if port_key in ports and ports[port_key]:
            published = ports[port_key][0].get('HostPort')
            if published:
                return published

        # Fallback: check all ports for a match
        for key, bindings in ports.items():
            if bindings and key.startswith(str(internal_port)):
                return bindings[0].get('HostPort')

        logger.warning(f"No published port found for container {container.name} internal port {internal_port}")
        return None
    except Exception as e:
        logger.error(f"Error getting published port for {container.name}: {e}")
        return None

def get_caddy_routes():
    """Get routes from Docker containers based on labels"""
    routes = []
    global_settings = {}
    snippets = {}
    host_ip = get_effective_host_ip()

    # First pass: collect snippets and global settings
    containers = []
    for container in client.containers.list():
        labels = container.attrs['Config']['Labels']
        if not labels:
            continue

        # Optional: filter containers by agent filter label
        if AGENT_FILTER_LABEL:
            filter_key, filter_value = AGENT_FILTER_LABEL.split("=", 1) if "=" in AGENT_FILTER_LABEL else (AGENT_FILTER_LABEL, None)
            container_filter_value = labels.get(filter_key)
            if not container_filter_value:
                continue
            if filter_value and container_filter_value != filter_value:
                continue
            logger.debug(f"Container {container.name} matches filter {AGENT_FILTER_LABEL}")

        containers.append(container)

        # Extract global settings and snippets
        container_globals, container_snippets = parse_globals_and_snippets(labels)
        global_settings.update(container_globals)
        snippets.update(container_snippets)

    # Log discovered snippets
    if snippets:
        logger.info(f"Discovered {len(snippets)} snippet(s): {list(snippets.keys())}")
    if global_settings:
        logger.info(f"Global settings: {list(global_settings.keys())}")

    # Second pass: build routes with imports applied and collect TLS DNS policies
    tls_dns_policies = []
    for container in containers:
        labels = container.attrs['Config']['Labels']
        container_routes, container_tls_policies = parse_container_labels(container, labels, host_ip, snippets)
        routes.extend(container_routes)
        tls_dns_policies.extend(container_tls_policies)

    return routes, global_settings, tls_dns_policies

def parse_globals_and_snippets(labels):
    """Extract global settings and snippet definitions from labels.
    Global settings: caddy_N.email, caddy_N.auto_https (without domain)
    Snippets: caddy_N: (snippet_name)
    """
    import re

    global_settings = {}
    snippets = {}
    route_configs = {}

    # First, collect all label configurations
    for label_key, label_value in labels.items():
        if not label_key.startswith(DOCKER_LABEL_PREFIX):
            continue

        match = re.match(f"^{re.escape(DOCKER_LABEL_PREFIX)}(?:_(\\d+))?(?:\\.(.+))?$", label_key)
        if not match:
            continue

        route_num = match.group(1) or "0"
        directive = match.group(2) or ""

        if route_num not in route_configs:
            route_configs[route_num] = {}

        if not directive:
            route_configs[route_num]['domain'] = label_value
        else:
            route_configs[route_num][directive] = label_value

    # Now identify snippets and global settings
    for route_num, config in route_configs.items():
        domain = config.get('domain', '')

        # Check if this is a snippet definition: (snippet_name)
        if domain.startswith('(') and domain.endswith(')'):
            snippet_name = domain[1:-1]
            # Remove 'domain' from config
            snippet_config = {k: v for k, v in config.items() if k != 'domain'}
            snippets[snippet_name] = snippet_config
            logger.info(f"Snippet defined: '{snippet_name}' with {len(snippet_config)} directive(s)")
            continue

        # Check if this is a global setting (no domain, only directives)
        if not domain and config:
            # This is a global setting
            for directive, value in config.items():
                global_settings[directive] = value
                logger.info(f"Global setting: {directive} = {value}")

    return global_settings, snippets

def parse_globals_and_snippets_from_all_containers():
    """Collect global settings and snippets from all Docker containers"""
    global_settings = {}
    snippets = {}

    for container in client.containers.list():
        labels = container.attrs['Config']['Labels']
        if not labels:
            continue

        # Optional: filter containers by agent filter label
        if AGENT_FILTER_LABEL:
            filter_key, filter_value = AGENT_FILTER_LABEL.split("=", 1) if "=" in AGENT_FILTER_LABEL else (AGENT_FILTER_LABEL, None)
            container_filter_value = labels.get(filter_key)
            if not container_filter_value:
                continue
            if filter_value and container_filter_value != filter_value:
                continue

        container_globals, container_snippets = parse_globals_and_snippets(labels)
        global_settings.update(container_globals)
        snippets.update(container_snippets)

    return global_settings, snippets

def parse_container_labels(container, labels, host_ip, snippets=None):
    """Parse container labels to extract route configurations.
    Supports both simple labels (caddy) and numbered labels (caddy_0, caddy_1).
    Phase 2: Applies snippet imports.
    """
    import re

    if snippets is None:
        snippets = {}

    route_configs = {}

    # Find all numbered and non-numbered caddy labels
    for label_key, label_value in labels.items():
        if not label_key.startswith(DOCKER_LABEL_PREFIX):
            continue

        # Match: caddy_N or caddy_N.directive or caddy or caddy.directive
        match = re.match(f"^{re.escape(DOCKER_LABEL_PREFIX)}(?:_(\\d+))?(?:\\.(.+))?$", label_key)
        if not match:
            continue

        route_num = match.group(1) or "0"  # Default to "0" for simple labels
        directive = match.group(2) or ""  # Empty string for base domain label

        if route_num not in route_configs:
            route_configs[route_num] = {}

        if not directive:
            # Base label: caddy or caddy_N
            # Keep raw value - http:// prefix handling done per-domain later
            route_configs[route_num]['domain'] = label_value
        else:
            # Directive label: caddy.reverse_proxy or caddy_N.reverse_proxy
            route_configs[route_num][directive] = label_value

    # Generate routes from parsed configurations
    routes = []
    tls_dns_policies = []  # Collect TLS DNS policies for automation
    for route_num, config in sorted(route_configs.items()):
        domain = config.get('domain')
        logger.info(f"Processing route {route_num}: domain={domain}, config_keys={list(config.keys())}")

        # Skip snippets and global settings (no domain or snippet pattern)
        if not domain or (domain.startswith('(') and domain.endswith(')')):
            logger.info(f"Skipping route {route_num} (no domain or snippet)")
            continue

        # Phase 2: Apply imports from snippets (supports multiple comma-separated snippets)
        if 'import' in config:
            import_value = config['import']
            snippet_names = [s.strip() for s in import_value.split(',')]
            merged_config = {}
            for snippet_name in snippet_names:
                if snippet_name in snippets:
                    logger.info(f"Applying snippet '{snippet_name}' to route {route_num}")
                    # Merge snippet config (later snippets override earlier)
                    merged_config = {**merged_config, **snippets[snippet_name]}
                else:
                    logger.warning(f"Snippet '{snippet_name}' not found for route {route_num}")
            # Route config overrides all snippets
            config = {**merged_config, **config}
            logger.info(f"Merged config keys after import: {list(config.keys())}")

        proxy_target = config.get('reverse_proxy')
        if not proxy_target:
            # Check if this is a wildcard/TLS-only route without reverse_proxy
            # For now, skip routes without reverse_proxy
            continue

        # Resolve {{upstreams PORT}} syntax
        proxy_target = resolve_upstreams(container, proxy_target, domain, host_ip)
        if not proxy_target:
            continue

        # Parse multiple domains (comma-separated) and check each for http:// prefix
        raw_domains = [d.strip() for d in domain.split(',')]
        http_only_domains = []
        https_domains = []
        for d in raw_domains:
            if d.startswith('http://'):
                http_only_domains.append(d[7:])  # Strip http:// prefix
            else:
                https_domains.append(d)

        logger.info(f"Route: http_only_domains={http_only_domains}, https_domains={https_domains}, upstream='{proxy_target}'")

        # Build route with agent metadata
        base_route_id = f"{AGENT_ID}_{container.name}"
        if route_num != "0":
            base_route_id += f"_{route_num}"

        # Build handle section with reverse_proxy
        handle = [{
            "handler": "reverse_proxy",
            "upstreams": [{"dial": proxy_target}]
        }]

        # Phase 2: Add TLS configuration if present
        tls_config = parse_tls_config(config)
        transport_config = parse_transport_config(config)
        header_config = parse_header_config(config)

        if transport_config:
            # Apply transport config to reverse_proxy handler
            handle[0].update(transport_config)

        # Phase 3: Apply header manipulation
        if header_config:
            handle[0].update(header_config)

        # Phase 2: Add handle directives (handle.abort, etc.)
        handle_directives = parse_handle_directives(config)
        if handle_directives:
            # Insert handle directives before reverse_proxy
            handle = handle_directives + handle

        # Create separate routes for HTTP-only and HTTPS domains
        # This allows mixed labels like: http://foo.lan, bar.lacny.me

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

            # Add TLS config if present (only for HTTPS domains)
            if tls_config:
                tls_policy = {
                    "subjects": https_domains,
                    "tls_config": tls_config
                }
                tls_dns_policies.append(tls_policy)
                logger.info(f"TLS DNS policy created for domains: {https_domains}")

    return routes, tls_dns_policies

def parse_tls_config(config):
    """Parse TLS configuration directives.
    Supports: tls.dns, tls.resolvers
    """
    tls_config = {}
    logger.info(f"parse_tls_config: checking config keys: {list(config.keys())}")

    for key, value in config.items():
        if key.startswith('tls.'):
            directive = key[4:]  # Remove 'tls.' prefix
            logger.info(f"Found TLS directive: {key} = {value}")

            if directive == 'dns':
                # Parse: "cloudflare ${CF_API_TOKEN}" or "cloudflare {env.CF_API_TOKEN}"
                parts = value.split()
                if len(parts) >= 2:
                    provider = parts[0]
                    # Extract token (handle both ${VAR} and {env.VAR} formats)
                    token = parts[1]
                    tls_config['dns_provider'] = provider
                    tls_config['dns_token'] = token
                    logger.info(f"TLS DNS challenge: provider={provider}")

            elif directive == 'resolvers':
                # Parse space-separated list of DNS resolvers
                tls_config['resolvers'] = value.split()
                logger.info(f"TLS resolvers: {tls_config['resolvers']}")

    return tls_config

def parse_transport_config(config):
    """Parse transport configuration directives.
    Supports: transport, transport.tls, transport.tls_insecure_skip_verify
    """
    transport_config = {}

    # Check if transport configuration exists
    has_transport = any(key.startswith('transport') for key in config.keys())
    if not has_transport:
        return transport_config

    for key, value in config.items():
        if key == 'transport':
            # transport: http
            transport_config['transport'] = {'protocol': value}

        elif key.startswith('transport.'):
            directive = key[10:]  # Remove 'transport.' prefix

            if 'transport' not in transport_config:
                transport_config['transport'] = {'protocol': 'http'}

            if directive == 'tls':
                # Enable TLS for backend
                transport_config['transport']['tls'] = {}

            elif directive == 'tls_insecure_skip_verify':
                # Skip TLS verification
                if 'tls' not in transport_config['transport']:
                    transport_config['transport']['tls'] = {}
                transport_config['transport']['tls']['insecure_skip_verify'] = True
                logger.info("Transport: TLS insecure skip verify enabled")

    return transport_config

def parse_header_config(config):
    """Parse header manipulation directives.
    Supports:
    - reverse_proxy.header_up: Modify request headers sent to backend
    - reverse_proxy.header_down: Modify response headers sent to client

    Formats:
    - -HeaderName: Remove header
    - +HeaderName "value": Add header with value
    - HeaderName "value": Set header to value (replaces existing)

    Returns Caddy JSON structure:
    {
        "headers": {
            "request": {
                "set": {"Header": ["value"]},
                "delete": ["Header"]
            },
            "response": {
                "set": {"Header": ["value"]},
                "delete": ["Header"]
            }
        }
    }
    """
    headers_config = {}

    for key, value in config.items():
        if key.startswith('reverse_proxy.header_up'):
            # Parse header_up directives (request headers)
            if 'headers' not in headers_config:
                headers_config['headers'] = {}
            if 'request' not in headers_config['headers']:
                headers_config['headers']['request'] = {}

            if value.startswith('-'):
                # Remove header: -X-Forwarded-For
                header_name = value[1:].strip()
                if 'delete' not in headers_config['headers']['request']:
                    headers_config['headers']['request']['delete'] = []
                headers_config['headers']['request']['delete'].append(header_name)
                logger.info(f"Header up: removing {header_name}")
            else:
                # Set/Add header: HeaderName "value" or +HeaderName "value"
                clean_value = value[1:].strip() if value.startswith('+') else value
                parts = clean_value.split(None, 1)
                if len(parts) == 2:
                    header_name = parts[0]
                    header_value = parts[1].strip('"')
                    if 'set' not in headers_config['headers']['request']:
                        headers_config['headers']['request']['set'] = {}
                    headers_config['headers']['request']['set'][header_name] = [header_value]
                    logger.info(f"Header up: setting {header_name} = {header_value}")

        elif key.startswith('reverse_proxy.header_down'):
            # Parse header_down directives (response headers)
            if 'headers' not in headers_config:
                headers_config['headers'] = {}
            if 'response' not in headers_config['headers']:
                headers_config['headers']['response'] = {}

            if value.startswith('-'):
                # Remove header: -Server
                header_name = value[1:].strip()
                if 'delete' not in headers_config['headers']['response']:
                    headers_config['headers']['response']['delete'] = []
                headers_config['headers']['response']['delete'].append(header_name)
                logger.info(f"Header down: removing {header_name}")
            else:
                # Set/Add header: Server "value" or +HeaderName "value"
                clean_value = value[1:].strip() if value.startswith('+') else value
                parts = clean_value.split(None, 1)
                if len(parts) == 2:
                    header_name = parts[0]
                    header_value = parts[1].strip('"')
                    if 'set' not in headers_config['headers']['response']:
                        headers_config['headers']['response']['set'] = {}
                    headers_config['headers']['response']['set'][header_name] = [header_value]
                    logger.info(f"Header down: setting {header_name} = {header_value}")

    return headers_config

def parse_handle_directives(config):
    """Parse handle directives.
    Supports: handle.abort
    """
    handle_directives = []

    for key, value in config.items():
        if key.startswith('handle.'):
            directive = key[7:]  # Remove 'handle.' prefix

            if directive == 'abort':
                # Abort handler (terminates request without forwarding)
                handle_directives.append({
                    "handler": "static_response",
                    "close": True
                })
                logger.info("Handle: abort directive added")

    return handle_directives

def resolve_upstreams(container, proxy_target, domain, host_ip):
    """Resolve {{upstreams PORT}} template to actual upstream address"""
    import re

    # Handle both {{upstreams PORT}} and {{ upstreams PORT }} (with optional spaces)
    upstreams_match = re.match(r"\{\{\s*upstreams\s+(\d+)\s*}}", proxy_target.strip())
    if not upstreams_match:
        return proxy_target  # Already resolved or static address

    port = upstreams_match.group(1)

    try:
        # Check if container is using host networking
        network_mode = container.attrs.get('HostConfig', {}).get('NetworkMode', '')
        is_host_network = network_mode == 'host'

        # Remote mode: use host IP + port (when host_ip is available)
        if host_ip:
            if is_host_network:
                # Host networking: use host IP + internal port directly
                resolved = f"{host_ip}:{port}"
                logger.info(f"[REMOTE] Resolved {{{{upstreams {port}}}}} for domain '{domain}' (host network): {resolved}")
                return resolved
            else:
                # Bridge networking: need published port
                published_port = get_published_port(container, port)
                if published_port:
                    resolved = f"{host_ip}:{published_port}"
                    logger.info(f"[REMOTE] Resolved {{{{upstreams {port}}}}} for domain '{domain}': {resolved}")
                    return resolved
                else:
                    logger.error(f"[REMOTE] Cannot resolve upstream for {container.name}: port {port} not published")
                    return None
        # Local mode: use container addressing
        else:
            if is_host_network:
                # Host networking: containers share host network, use localhost
                resolved = f"localhost:{port}"
                logger.info(f"[LOCAL] Resolved {{{{upstreams {port}}}}} for domain '{domain}' (host network): {resolved}")
                return resolved
            else:
                # Bridge networking: use container IP
                network_settings = container.attrs.get('NetworkSettings', {})
                networks = network_settings.get('Networks', {})
                if networks:
                    ip = list(networks.values())[0].get('IPAddress')
                    if ip:
                        resolved = f"{ip}:{port}"
                        logger.info(f"[LOCAL] Resolved {{{{upstreams {port}}}}} for domain '{domain}': {resolved}")
                        return resolved
            logger.error(f"Failed to resolve {{{{upstreams {port}}}}} for {container.name}")
            return None
    except Exception as e:
        logger.error(f"Failed to resolve {{{{upstreams {port}}}}} for {container.name}: {e}")
        return None

def push_to_caddy(routes, global_settings=None, tls_dns_policies=None):
    """Push routes to Caddy server based on mode.
    Phase 2: Apply global settings and TLS DNS policies if provided.
    """
    target_url = CADDY_URL

    if global_settings is None:
        global_settings = {}
    if tls_dns_policies is None:
        tls_dns_policies = []

    # Build headers
    headers = {"Content-Type": "application/json"}
    if CADDY_API_TOKEN:
        headers["Authorization"] = f"Bearer {CADDY_API_TOKEN}"

    # Load local config
    config = load_local_config()

    # Ensure admin section is always present and accessible
    if "admin" not in config:
        config["admin"] = {}
    config["admin"]["listen"] = "0.0.0.0:2019"

    # Ensure apps structure exists
    if "apps" not in config:
        config["apps"] = {}
    if "http" not in config["apps"]:
        config["apps"]["http"] = {}
    if "servers" not in config["apps"]["http"]:
        config["apps"]["http"]["servers"] = {}

    # Separate routes by protocol (HTTP-only vs HTTPS)
    http_only_routes = []
    https_routes = []
    for route in routes:
        is_http_only = route.pop('_http_only', False)  # Remove internal flag
        if is_http_only:
            http_only_routes.append(route)
        else:
            https_routes.append(route)

    if http_only_routes:
        logger.info(f"HTTP-only routes: {[r.get('@id') for r in http_only_routes]}")
    if https_routes:
        logger.info(f"HTTPS routes: {[r.get('@id') for r in https_routes]}")

    # Find servers
    servers = config["apps"]["http"]["servers"]
    https_server = None
    http_server = None

    if servers:
        for name, srv in servers.items():
            listeners = srv.get("listen", [])
            listeners_str = ' '.join(listeners)
            has_443 = ':443' in listeners_str
            has_80 = ':80' in listeners_str

            if has_443:
                https_server = name
            elif has_80 and not has_443:
                http_server = name

        # Fallback: if no dedicated servers, use first one for both
        if not https_server and not http_server and servers:
            https_server = list(servers.keys())[0]
            http_server = https_server
    else:
        # Create new server only if none exist
        servers["reverse_proxy"] = {
            "listen": [":80", ":443"],
            "routes": []
        }
        https_server = "reverse_proxy"
        http_server = "reverse_proxy"

    logger.info(f"Server selection: HTTPS={https_server}, HTTP-only={http_server}")

    # Phase 2: Apply global settings to HTTPS server config
    if global_settings and https_server:
        apply_global_settings(config, https_server, global_settings)

    # Phase 2: Apply TLS DNS policies
    logger.info(f"DEBUG: tls_dns_policies count: {len(tls_dns_policies) if tls_dns_policies else 0}")
    if tls_dns_policies:
        logger.info(f"DEBUG: Calling apply_tls_dns_policies with {len(tls_dns_policies)} policies")
        apply_tls_dns_policies(config, tls_dns_policies)

    # Merge HTTPS routes to HTTPS server
    if https_routes and https_server:
        if "routes" not in servers[https_server]:
            servers[https_server]["routes"] = []
        local_routes = servers[https_server].get("routes", [])
        merged_routes = merge_routes(local_routes, https_routes)
        config["apps"]["http"]["servers"][https_server]["routes"] = merged_routes

    # Merge HTTP-only routes to HTTP server
    if http_only_routes and http_server:
        if "routes" not in servers[http_server]:
            servers[http_server]["routes"] = []
        local_routes = servers[http_server].get("routes", [])
        merged_routes = merge_routes(local_routes, http_only_routes)
        config["apps"]["http"]["servers"][http_server]["routes"] = merged_routes
    # Save updated config
    save_local_config(config)

    try:
        host_ip = get_effective_host_ip()
        mode_desc = f"remote (HOST_IP={host_ip})" if host_ip else "local"
        logger.info(f"Pushing config to {target_url} [Mode: {mode_desc}]")
        logger.debug(f"Full config being pushed:\n{json.dumps(config, indent=2)}")
        response = requests.post(f"{target_url}/load", json=config, headers=headers)
        if response.status_code == 200:
            logger.info(f"✅ Caddy config updated successfully [Agent: {AGENT_ID}]")
        else:
            logger.error(f"❌ Caddy update failed: {response.status_code} - {response.text}")
            logger.debug(f"Failed config:\n{json.dumps(config, indent=2)}")
    except Exception as e:
        logger.error(f"❌ Error pushing to Caddy: {e}")

    # Add a short delay to avoid hammering the Caddy API
    time.sleep(2)

def apply_global_settings(config, server_name, global_settings):
    """Apply global settings to Caddy server configuration.
    Supports: email, auto_https
    """
    server_config = config["apps"]["http"]["servers"][server_name]

    for setting, value in global_settings.items():
        if setting == 'email':
            # Apply email to TLS automation
            if 'tls_connection_policies' not in server_config:
                server_config['automatic_https'] = {}
            # Email goes in apps.tls.automation.policies
            if 'tls' not in config['apps']:
                config['apps']['tls'] = {}
            if 'automation' not in config['apps']['tls']:
                config['apps']['tls']['automation'] = {}
            if 'policies' not in config['apps']['tls']['automation']:
                config['apps']['tls']['automation']['policies'] = []

            # Check if email policy exists, update or add
            email_policy_exists = False
            for policy in config['apps']['tls']['automation']['policies']:
                if 'issuers' in policy:
                    for issuer in policy['issuers']:
                        if 'module' in issuer and issuer['module'] == 'acme':
                            issuer['email'] = value
                            email_policy_exists = True
                            logger.info(f"Updated ACME email: {value}")
                            break

            if not email_policy_exists:
                # Add new policy with email
                config['apps']['tls']['automation']['policies'].append({
                    'issuers': [{
                        'module': 'acme',
                        'email': value
                    }]
                })
                logger.info(f"Added ACME email: {value}")

        elif setting == 'auto_https':
            # Apply auto_https setting
            if 'automatic_https' not in server_config:
                server_config['automatic_https'] = {}
            if value == 'prefer_wildcard':
                server_config['automatic_https']['prefer_wildcard'] = True
                logger.info("Automatic HTTPS: prefer_wildcard enabled")

def apply_tls_dns_policies(config, tls_dns_policies):
    """Apply TLS DNS challenge policies to Caddy TLS automation.
    Creates automation policies for DNS-01 challenge with Cloudflare provider.

    IMPORTANT: Policies with specific subjects must come BEFORE catch-all policies (no subjects).
    """
    # Ensure TLS app structure exists
    if 'tls' not in config['apps']:
        config['apps']['tls'] = {}
    if 'automation' not in config['apps']['tls']:
        config['apps']['tls']['automation'] = {}
    if 'policies' not in config['apps']['tls']['automation']:
        config['apps']['tls']['automation']['policies'] = []

    policies = config['apps']['tls']['automation']['policies']

    for policy_data in tls_dns_policies:
        subjects = policy_data['subjects']
        tls_config = policy_data['tls_config']

        # Build DNS challenge configuration
        if 'dns_provider' in tls_config and 'dns_token' in tls_config:
            provider = tls_config['dns_provider']
            token = tls_config['dns_token']

            # Create issuer with DNS challenge
            # Use the email from global_settings if available
            issuer = {
                "module": "acme",
                "challenges": {
                    "dns": {
                        "provider": {
                            "name": provider,
                            "api_token": token  # Can be {env.VAR} or ${VAR}
                        }
                    }
                }
            }

            # Add email to DNS issuer (use first non-empty email from default policy)
            for policy in config['apps']['tls']['automation']['policies']:
                if 'issuers' in policy and policy['issuers']:
                    for issuer_check in policy['issuers']:
                        if 'email' in issuer_check and issuer_check['email']:
                            issuer['email'] = issuer_check['email']
                            break
                    if 'email' in issuer:
                        break

            # Add resolvers if specified
            if 'resolvers' in tls_config:
                issuer['challenges']['dns']['resolvers'] = tls_config['resolvers']

            # Create or update policy for these subjects
            policy = {
                "subjects": subjects,
                "issuers": [issuer]
            }

            # Check if policy for these subjects already exists
            existing_policy = None
            for p in policies:
                if p.get('subjects') == subjects:
                    existing_policy = p
                    break

            if existing_policy:
                # Update existing policy
                existing_policy['issuers'] = [issuer]
                logger.info(f"Updated TLS DNS policy for subjects: {subjects}")
            else:
                # Add new policy
                policies.append(policy)
                logger.info(f"Added TLS DNS policy for subjects: {subjects} (provider: {provider})")

    # ALWAYS reorder policies: specific subjects first, catch-all (no subjects) last
    # This is critical for DNS challenge policies to work correctly
    logger.info(f"Before reordering: {len(policies)} total policies")
    specific_policies = [p for p in policies if 'subjects' in p and p['subjects']]
    catch_all_policies = [p for p in policies if 'subjects' not in p or not p['subjects']]
    logger.info(f"After sorting: {len(specific_policies)} specific, {len(catch_all_policies)} catch-all")

    if len(specific_policies) > 0 or len(catch_all_policies) > 0:
        config['apps']['tls']['automation']['policies'] = specific_policies + catch_all_policies
        logger.info(f"TLS policies ordered: {len(specific_policies)} specific first, {len(catch_all_policies)} catch-all last")

def load_local_config():
    """Load local config or fetch from Caddy server"""
    # Always try to fetch current config from Caddy first to preserve routes from all agents
    target_url = CADDY_URL
    try:
        headers = {}
        if CADDY_API_TOKEN:
            headers["Authorization"] = f"Bearer {CADDY_API_TOKEN}"

        response = requests.get(f"{target_url}/config/", headers=headers, timeout=5)
        if response.status_code == 200:
            config = response.json()
            logger.info("📥 Fetched existing config from Caddy")
            return config
    except Exception as e:
        logger.warning(f"Could not fetch existing config from Caddy: {e}")

    # Fallback: try to load cached config if fetch failed
    if os.path.exists("caddy-output.json"):
        try:
            with open("caddy-output.json", "r") as f:
                logger.info("📥 Using cached Caddy config (fetch failed)")
                return json.load(f)
        except Exception as e:
            logger.error(f"❌ Failed to load cached Caddy config: {e}")

    # Return a new config structure with admin preserved
    return {
        "admin": {
            "listen": "0.0.0.0:2019"
        },
        "apps": {
            "http": {
                "servers": {
                    "reverse_proxy": {
                        "listen": [":80", ":443"],
                        "routes": []
                    }
                }
            }
        }
    }

def save_local_config(config):
    try:
        with open("caddy-output.json", "w") as f:
            json.dump(config, f, indent=2)
        logger.info("💾 Local copy of Caddy config saved to caddy-output.json")
    except Exception as e:
        logger.error(f"❌ Failed to save local Caddy config: {e}")

def is_wildcard_route(route):
    """Check if route matches wildcard domains (e.g., *.lacny.me)"""
    match = route.get("match", [{}])
    if match:
        hosts = match[0].get("host", [])
        return any(h.startswith("*") for h in hosts)
    return False

def merge_routes(local_routes, new_routes):
    """Merge local and new routes, using route ID and agent ID for tracking"""

    def get_route_id(route):
        """Get route ID, falling back to domain if no ID present"""
        if "@id" in route:
            return route["@id"]
        # Fallback to domain for routes without ID
        return route["match"][0]["host"][0] if route.get("match") and route["match"][0].get("host") else None

    def get_agent_id_from_route(route):
        """Extract agent ID from route ID"""
        route_id = get_route_id(route)
        if route_id and "_" in route_id:
            return route_id.split("_")[0]
        return None

    # Build dicts for fast lookup
    local_dict = {get_route_id(r): r for r in local_routes if get_route_id(r)}
    new_dict = {get_route_id(r): r for r in new_routes if get_route_id(r)}

    # Track changes
    added = []
    removed = []

    # Start with local routes, but only keep routes from other agents
    merged = {}
    for route_id, route in local_dict.items():
        agent_id = get_agent_id_from_route(route)
        # Keep routes from other agents or routes without agent ID
        if agent_id != AGENT_ID:
            merged[route_id] = route

    # Add/update routes from this agent
    for route_id, route in new_dict.items():
        if route_id not in local_dict:
            added.append(route_id)
        merged[route_id] = route

    # Track removed routes (only from this agent)
    for route_id in list(local_dict.keys()):
        agent_id = get_agent_id_from_route(local_dict[route_id])
        if agent_id == AGENT_ID and route_id not in new_dict:
            removed.append(route_id)

    if added:
        logger.info(f"Routes added: {added}")
    if removed:
        logger.info(f"Routes removed: {removed}")

    # Sort routes: specific domains first, wildcards last
    # This ensures routes like 'agent-remote.lacny.me' come before '*.lacny.me'
    merged_list = list(merged.values())
    specific_routes = [r for r in merged_list if not is_wildcard_route(r)]
    wildcard_routes = [r for r in merged_list if is_wildcard_route(r)]

    return specific_routes + wildcard_routes

def sync_config():
    logger.info("🔄 Syncing config...")
    routes, global_settings, tls_dns_policies = get_caddy_routes()
    push_to_caddy(routes, global_settings, tls_dns_policies)

# =============================================================================
# Route Recovery Mechanism
# Handles Caddy restarts by periodically checking if routes are present
# =============================================================================

# Shared state for recovery threads
last_sync_time = 0
sync_lock = threading.Lock()

def get_our_route_count():
    """Get count of our routes currently in Caddy"""
    try:
        headers = {}
        if CADDY_API_TOKEN:
            headers["Authorization"] = f"Bearer {CADDY_API_TOKEN}"

        count = 0
        our_route_ids = []
        # Check all servers for our routes
        response = requests.get(f"{CADDY_URL}/config/apps/http/servers", headers=headers, timeout=5)
        if response.ok:
            servers = response.json() or {}
            for server_name, server_config in servers.items():
                routes = server_config.get("routes", [])
                for r in routes:
                    route_id = r.get("@id", "")
                    if route_id.startswith(f"{AGENT_ID}_"):
                        count += 1
                        our_route_ids.append(route_id)
            logger.debug(f"Found {count} routes in Caddy for agent {AGENT_ID}: {our_route_ids}")
        else:
            logger.debug(f"Failed to get routes from Caddy: {response.status_code}")
        return count
    except Exception as e:
        logger.debug(f"Error getting route count: {e}")
        return -1  # Error state

def get_expected_route_count():
    """Get count of routes we should have (from local Docker containers)"""
    try:
        routes, _, _ = get_caddy_routes()
        route_ids = [r.get("@id", "unknown") for r in routes]
        logger.debug(f"Expected {len(routes)} routes from Docker: {route_ids}")
        return len(routes)
    except Exception as e:
        logger.debug(f"Error getting expected route count: {e}")
        return 0

def routes_need_sync():
    """Check if our routes are missing or incomplete.
    Returns: True if sync needed, False if OK, None if can't determine (API error)
    """
    current = get_our_route_count()
    if current == -1:
        return None  # Can't determine, API error
    expected = get_expected_route_count()
    need_sync = current < expected
    logger.debug(f"Route check: current={current}, expected={expected}, need_sync={need_sync}")
    return need_sync

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
        sync_config()  # Must be inside lock to prevent concurrent syncs
    return True

def health_check_loop():
    """Fast detection: check if our routes are present every few seconds"""
    logger.debug("🏥 Health check thread starting, waiting 10s for initial sync to settle...")
    time.sleep(10)  # Startup delay: let initial sync settle before checking
    consecutive_failures = 0
    logger.debug("🏥 Health check thread active, beginning monitoring")

    while True:
        # Exponential backoff on repeated failures (max 30s)
        interval = min(HEALTH_CHECK_INTERVAL * (2 ** consecutive_failures), 30)
        if consecutive_failures > 0:
            logger.debug(f"🏥 Backoff active: sleeping {interval}s (failures={consecutive_failures})")
        time.sleep(interval)

        need_sync = routes_need_sync()
        if need_sync is None:
            consecutive_failures += 1
            logger.warning(f"🏥 Health check: Caddy API unreachable (failure #{consecutive_failures})")
            continue

        consecutive_failures = 0  # Reset on success
        if need_sync:
            logger.info("🏥 Routes missing, resyncing...")
            safe_sync()
        else:
            logger.debug("🏥 Health check: routes OK")

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

# =============================================================================

def start_snippet_api():
    """Start HTTP server to serve snippets (if enabled)"""
    if SNIPPET_API_PORT <= 0:
        return

    from http.server import HTTPServer, BaseHTTPRequestHandler

    class SnippetHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/snippets":
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    # Get current snippets from Docker labels
                    _, current_snippets = parse_globals_and_snippets_from_all_containers()
                    self.wfile.write(json.dumps(current_snippets).encode())
                except Exception as e:
                    logger.error(f"Error serving snippets: {e}")
                    self.send_error(500, f"Internal server error: {e}")
            else:
                self.send_error(404)

        def log_message(self, format, *args):
            logger.debug(f"Snippet API: {args[0]}")

    try:
        server = HTTPServer(("0.0.0.0", SNIPPET_API_PORT), SnippetHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        logger.info(f"Snippet API listening on :{SNIPPET_API_PORT}")
    except Exception as e:
        logger.error(f"Failed to start Snippet API server on port {SNIPPET_API_PORT}: {e}")
        logger.info("Continuing without Snippet API server...")

last_update = 0
debounce_seconds = 5  # Increased debounce to 5 seconds

def watch_docker_events():
    logger.info("👀 Watching Docker events...")
    for event in client.events(decode=True):
        if event.get("Type") == "container":
            action = event.get("Action")
            if action in ["start", "stop", "die", "destroy"]:
                global last_update
                now = time.time()
                if now - last_update > debounce_seconds:
                    threading.Thread(target=sync_config).start()
                    last_update = now

def shutdown_handler(signum, frame):
    logger.info("Shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)

if __name__ == "__main__":
    logger.info("="*60)
    logger.info("🚀 Caddy Docker Agent Starting")
    logger.info(f"   Agent ID: {AGENT_ID}")
    logger.info(f"   Caddy URL: {CADDY_URL}")
    logger.info(f"   Docker Label Prefix: {DOCKER_LABEL_PREFIX}")

    # Compute and log effective host IP
    effective_ip = get_effective_host_ip()
    if effective_ip:
        logger.info(f"   Mode: REMOTE (upstreams use {effective_ip})")
    else:
        logger.info(f"   Mode: LOCAL (upstreams use container names)")

    if CADDY_API_TOKEN:
        logger.info(f"   Authentication: Enabled (token configured)")
    else:
        logger.info(f"   Authentication: Disabled (no token)")

    if AGENT_FILTER_LABEL:
        logger.info(f"   Container Filter: {AGENT_FILTER_LABEL}")

    logger.info(f"   Health Check: {HEALTH_CHECK_INTERVAL}s (0=disabled)")
    logger.info(f"   Periodic Resync: {RESYNC_INTERVAL}s (0=disabled)")
    logger.info(f"   Log Level: {LOG_LEVEL}")
    logger.info(f"   Snippet API Port: {SNIPPET_API_PORT} (0=disabled)")
    if SNIPPET_SOURCES:
        logger.info(f"   Snippet Sources: {SNIPPET_SOURCES}")

    logger.info("="*60)

    sync_config()  # Initial sync
    start_recovery_threads()  # Start health check and periodic resync

    # Start snippet API server (if enabled)
    if SNIPPET_API_PORT > 0:
        start_snippet_api()

    watch_docker_events()
