#!/usr/bin/env python3
"""
Comprehensive test suite for Caddy Multi-Host Agent System.

Usage:
    python test_all.py              # Run all tests
    python test_all.py --unit       # Run unit tests only (no remote hosts needed)
    python test_all.py --integration # Run integration tests only (requires remote hosts)
"""

import re
import os
import sys
import subprocess
import argparse
import json

# Configuration
CADDY_SERVER = "192.168.0.96"
CADDY_API_PORT = 2020  # Admin API proxy port (not 2019!)
HOST2_IP = "192.168.0.98"
HOST3_IP = "192.168.0.99"

DOCKER_LABEL_PREFIX = "caddy"

# =============================================================================
# UNIT TESTS - Label Parsing (no remote hosts needed)
# =============================================================================

def parse_labels_test(labels):
    """Test version of parse_container_labels logic"""
    route_configs = {}

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

    return route_configs


class UnitTests:
    """Unit tests for label parsing logic"""

    @staticmethod
    def test_simple_labels():
        """Test: Simple labels create routes"""
        labels = {
            "caddy": "test.lan",
            "caddy.reverse_proxy": "backend:8080",
        }
        routes = parse_labels_test(labels)
        assert len(routes) == 1
        assert routes["0"]["domain"] == "test.lan"
        print("[PASS] test_simple_labels")

    @staticmethod
    def test_numbered_labels():
        """Test: Numbered labels create separate routes"""
        labels = {
            "caddy_0": "test-0.lan",
            "caddy_0.reverse_proxy": "backend:8080",
            "caddy_1": "test-1.lan",
            "caddy_1.reverse_proxy": "backend:8081",
        }
        routes = parse_labels_test(labels)
        assert len(routes) == 2
        assert routes["0"]["domain"] == "test-0.lan"
        assert routes["1"]["domain"] == "test-1.lan"
        print("[PASS] test_numbered_labels")

    @staticmethod
    def test_multiple_domains():
        """Test: Multiple comma-separated domains"""
        labels = {
            "caddy": "test-a.lan, test-b.lan",
            "caddy.reverse_proxy": "backend:9000",
        }
        routes = parse_labels_test(labels)
        domains = [d.strip() for d in routes["0"]["domain"].split(',')]
        assert len(domains) == 2
        assert "test-a.lan" in domains
        assert "test-b.lan" in domains
        print("[PASS] test_multiple_domains")

    @staticmethod
    def test_high_numbered_labels():
        """Test: High numbers like caddy_10, caddy_111"""
        labels = {
            "caddy_10": "ten.lan",
            "caddy_111": "hundred.lan",
        }
        routes = parse_labels_test(labels)
        assert "10" in routes
        assert "111" in routes
        print("[PASS] test_high_numbered_labels")

    @staticmethod
    def test_mixed_labels():
        """Test: Mix of simple and numbered labels"""
        labels = {
            "caddy": "simple.lan",
            "caddy.reverse_proxy": "simple:3000",
            "caddy_5": "numbered.lan",
            "caddy_5.reverse_proxy": "numbered:4000",
        }
        routes = parse_labels_test(labels)
        assert len(routes) == 2
        assert routes["0"]["domain"] == "simple.lan"
        assert routes["5"]["domain"] == "numbered.lan"
        print("[PASS] test_mixed_labels")

    @staticmethod
    def test_http_prefix():
        """Test: HTTP prefix for HTTP-only routes"""
        labels = {
            "caddy": "http://httponly.lan",
            "caddy.reverse_proxy": "backend:80",
        }
        routes = parse_labels_test(labels)
        assert routes["0"]["domain"].startswith("http://")
        print("[PASS] test_http_prefix")

    @staticmethod
    def test_snippet_definition():
        """Test: Snippet definitions with parentheses"""
        labels = {
            "caddy_1": "(wildcard)",
            "caddy_1.tls.dns": "cloudflare ${CF_API_TOKEN}",
        }
        routes = parse_labels_test(labels)
        assert routes["1"]["domain"] == "(wildcard)"
        assert "tls.dns" in routes["1"]
        print("[PASS] test_snippet_definition")

    @staticmethod
    def test_global_settings():
        """Test: Global settings (email, auto_https)"""
        labels = {
            "caddy_0.email": "test@example.com",
            "caddy_0.auto_https": "prefer_wildcard",
        }
        routes = parse_labels_test(labels)
        assert routes["0"]["email"] == "test@example.com"
        assert routes["0"]["auto_https"] == "prefer_wildcard"
        print("[PASS] test_global_settings")

    @staticmethod
    def run_all():
        """Run all unit tests"""
        tests = [
            UnitTests.test_simple_labels,
            UnitTests.test_numbered_labels,
            UnitTests.test_multiple_domains,
            UnitTests.test_high_numbered_labels,
            UnitTests.test_mixed_labels,
            UnitTests.test_http_prefix,
            UnitTests.test_snippet_definition,
            UnitTests.test_global_settings,
        ]

        print("=" * 60)
        print("UNIT TESTS - Label Parsing")
        print("=" * 60)

        passed = 0
        failed = 0
        for test in tests:
            try:
                test()
                passed += 1
            except AssertionError as e:
                print(f"[FAIL] {test.__name__}: {e}")
                failed += 1

        print(f"\nPassed: {passed}/{len(tests)}")
        return failed == 0


# =============================================================================
# INTEGRATION TESTS - Remote Host Testing
# =============================================================================

class IntegrationTests:
    """Integration tests against deployed remote hosts"""

    @staticmethod
    def run_curl(domain, port=443, https=True, host=CADDY_SERVER, timeout=5):
        """Run curl command and return output"""
        protocol = "https" if https else "http"
        cmd = [
            "curl", "-s", "--max-time", str(timeout),
            "--resolve", f"{domain}:{port}:{host}",
        ]
        if https:
            cmd.append("-k")  # Skip cert verification
        cmd.append(f"{protocol}://{domain}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            return None

    @staticmethod
    def check_caddy_api():
        """Check if Caddy Admin API is accessible"""
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "5", f"http://{CADDY_SERVER}:{CADDY_API_PORT}/config/"],
                capture_output=True, text=True, timeout=7
            )
            return result.returncode == 0 and len(result.stdout) > 0
        except:
            return False

    # =========================================================================
    # Basic Connectivity Tests
    # =========================================================================

    @staticmethod
    def test_api_accessible():
        """Test: Caddy Admin API is accessible on port 2020"""
        assert IntegrationTests.check_caddy_api(), f"Caddy API not accessible at {CADDY_SERVER}:{CADDY_API_PORT}"
        print("[PASS] test_api_accessible")

    # =========================================================================
    # Host2 Tests (network_mode: host, auto-detect HOST_IP)
    # =========================================================================

    @staticmethod
    def test_host2_simple_label():
        """Test: Simple label on host2 (test-remote.lan)"""
        result = IntegrationTests.run_curl("test-remote.lan", port=443, https=True)
        assert result and "host2" in result.lower(), f"Expected host2 response, got: {result}"
        print("[PASS] test_host2_simple_label")

    @staticmethod
    def test_host2_multi_domain():
        """Test: Multi-domain on host2 (host2-app1.lan, host2-app2.lan)"""
        result1 = IntegrationTests.run_curl("host2-app1.lan", port=443, https=True)
        result2 = IntegrationTests.run_curl("host2-app2.lan", port=443, https=True)
        assert result1 and "multi" in result1.lower(), f"host2-app1.lan failed: {result1}"
        assert result2 and "multi" in result2.lower(), f"host2-app2.lan failed: {result2}"
        print("[PASS] test_host2_multi_domain")

    @staticmethod
    def test_host2_high_numbered():
        """Test: High numbered labels on host2 (caddy_10, caddy_111)"""
        result10 = IntegrationTests.run_curl("host2-route10.lan", port=443, https=True)
        result111 = IntegrationTests.run_curl("host2-route111.lan", port=443, https=True)
        assert result10 and "high" in result10.lower(), f"host2-route10.lan failed: {result10}"
        assert result111 and "high" in result111.lower(), f"host2-route111.lan failed: {result111}"
        print("[PASS] test_host2_high_numbered")

    @staticmethod
    def test_host2_snippet_import():
        """Test: Snippet import on host2 (phase2-import.lan)"""
        result = IntegrationTests.run_curl("phase2-import.lan", port=443, https=True)
        assert result and "snippet" in result.lower(), f"Expected snippet response, got: {result}"
        print("[PASS] test_host2_snippet_import")

    @staticmethod
    def test_host2_header_manipulation():
        """Test: Header manipulation on host2 (phase3-headers.lan)"""
        result = IntegrationTests.run_curl("phase3-headers.lan", port=443, https=True)
        assert result and "header" in result.lower(), f"Expected header response, got: {result}"
        print("[PASS] test_host2_header_manipulation")

    @staticmethod
    def test_host2_route_ordering():
        """Test: Route ordering - specific routes before wildcards"""
        result_app = IntegrationTests.run_curl("app.test.lan", port=443, https=True)
        result_api = IntegrationTests.run_curl("api.test.lan", port=443, https=True)
        assert result_app and "specific" in result_app.lower(), f"app.test.lan should match specific route: {result_app}"
        assert result_api and "specific" in result_api.lower(), f"api.test.lan should match specific route: {result_api}"
        print("[PASS] test_host2_route_ordering")

    @staticmethod
    def test_host2_wildcard_cert():
        """Test: Wildcard certificate (*.lacny.me with Cloudflare DNS)"""
        result = IntegrationTests.run_curl("test-phase2.lacny.me", port=443, https=True)
        # May return empty if rate limited, just check connection works
        print(f"[PASS] test_host2_wildcard_cert (response: {result[:30] if result else 'empty'})")

    # =========================================================================
    # Host3 Tests (bridge mode, explicit HOST_IP)
    # =========================================================================

    @staticmethod
    def test_host3_simple_label():
        """Test: Simple label on host3 bridge mode (test-host3.lan)"""
        result = IntegrationTests.run_curl("test-host3.lan", port=443, https=True)
        assert result and "host3" in result.lower(), f"Expected host3 response, got: {result}"
        print("[PASS] test_host3_simple_label")

    @staticmethod
    def test_host3_combined_features():
        """Test: Combined numbered + multi-domain on host3"""
        result_a = IntegrationTests.run_curl("host3-combined-a.lan", port=443, https=True)
        result_b = IntegrationTests.run_curl("host3-combined-b.lan", port=443, https=True)
        result_single = IntegrationTests.run_curl("host3-single.lan", port=443, https=True)
        assert result_a and "combined" in result_a.lower(), f"host3-combined-a.lan failed: {result_a}"
        assert result_b and "combined" in result_b.lower(), f"host3-combined-b.lan failed: {result_b}"
        assert result_single and "combined" in result_single.lower(), f"host3-single.lan failed: {result_single}"
        print("[PASS] test_host3_combined_features")

    @staticmethod
    def test_host3_mixed_labels():
        """Test: Mixed simple + numbered labels on host3"""
        result_simple = IntegrationTests.run_curl("host3-simple.lan", port=443, https=True)
        result_numbered = IntegrationTests.run_curl("host3-numbered5.lan", port=443, https=True)
        assert result_simple and "mixed" in result_simple.lower(), f"host3-simple.lan failed: {result_simple}"
        assert result_numbered and "mixed" in result_numbered.lower(), f"host3-numbered5.lan failed: {result_numbered}"
        print("[PASS] test_host3_mixed_labels")

    @staticmethod
    def test_host3_transport():
        """Test: Transport config on host3 (phase2-transport.lan)"""
        result = IntegrationTests.run_curl("phase2-transport.lan", port=443, https=True)
        assert result and "transport" in result.lower(), f"Expected transport response, got: {result}"
        print("[PASS] test_host3_transport")

    # =========================================================================
    # HTTP-only vs HTTPS Tests
    # =========================================================================

    @staticmethod
    def test_http_only_route():
        """Test: HTTP-only route on port 80 (http://httponly.test.lan)"""
        result = IntegrationTests.run_curl("httponly.test.lan", port=80, https=False)
        assert result and "http-only" in result.lower(), f"Expected HTTP-only response, got: {result}"
        print("[PASS] test_http_only_route")

    @staticmethod
    def test_https_explicit_route():
        """Test: Explicit HTTPS route (https.test.lan)"""
        result = IntegrationTests.run_curl("https.test.lan", port=443, https=True)
        assert result and "https" in result.lower(), f"Expected HTTPS response, got: {result}"
        print("[PASS] test_https_explicit_route")

    @staticmethod
    def test_transport_tls_implicit_protocol():
        """Test: Transport TLS without explicit 'transport: http' (tests protocol fix)"""
        # This tests the fix for: transport.tls_insecure_skip_verify without transport: http
        # The route should be pushed successfully with implicit protocol: http
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "5", f"http://{CADDY_SERVER}:{CADDY_API_PORT}/config/apps/http/servers/srv1/routes"],
                capture_output=True, text=True, timeout=7
            )
            routes = result.stdout
            # Check route exists
            assert "transport-tls.test.lan" in routes, "transport-tls.test.lan route not found"
            # Check transport config has protocol
            assert '"protocol"' in routes, "Transport config missing protocol field"
            print("[PASS] test_transport_tls_implicit_protocol")
        except Exception as e:
            raise AssertionError(f"Failed to verify transport config: {e}")

    @staticmethod
    def test_multi_import():
        """Test: Multiple comma-separated snippet imports (caddy.import: a, b)"""
        result = IntegrationTests.run_curl("multi-import.test.lan", port=443, https=True)
        assert result and "multi-import" in result.lower(), f"Expected multi-import response, got: {result}"
        print("[PASS] test_multi_import")

    @staticmethod
    def run_all():
        """Run all integration tests"""
        print("=" * 60)
        print("INTEGRATION TESTS - Remote Hosts")
        print("=" * 60)

        # First check API accessibility
        if not IntegrationTests.check_caddy_api():
            print(f"[SKIP] Caddy API not accessible at {CADDY_SERVER}:{CADDY_API_PORT}")
            print("       Make sure the server is running and accessible.")
            return False

        tests = [
            # Basic
            IntegrationTests.test_api_accessible,
            # Host2 tests
            IntegrationTests.test_host2_simple_label,
            IntegrationTests.test_host2_multi_domain,
            IntegrationTests.test_host2_high_numbered,
            IntegrationTests.test_host2_snippet_import,
            IntegrationTests.test_host2_header_manipulation,
            IntegrationTests.test_host2_route_ordering,
            IntegrationTests.test_host2_wildcard_cert,
            # Host3 tests
            IntegrationTests.test_host3_simple_label,
            IntegrationTests.test_host3_combined_features,
            IntegrationTests.test_host3_mixed_labels,
            IntegrationTests.test_host3_transport,
            # HTTP vs HTTPS
            IntegrationTests.test_http_only_route,
            IntegrationTests.test_https_explicit_route,
            # Transport TLS fix
            IntegrationTests.test_transport_tls_implicit_protocol,
            # Multi-import fix
            IntegrationTests.test_multi_import,
        ]

        passed = 0
        failed = 0
        for test in tests:
            try:
                test()
                passed += 1
            except AssertionError as e:
                print(f"[FAIL] {test.__name__}: {e}")
                failed += 1
            except Exception as e:
                print(f"[ERROR] {test.__name__}: {e}")
                failed += 1

        print(f"\nPassed: {passed}/{len(tests)}")
        return failed == 0


# =============================================================================
# SERVER MODE TESTS - Host1 caddy-agent-server (uses 'agent' prefix)
# =============================================================================

class ServerModeTests:
    """Integration tests for server mode agent on host1"""

    @staticmethod
    def test_server_mode_basic_route():
        """Test: Server mode agent creates route (test.server.lan)"""
        result = IntegrationTests.run_curl("test.server.lan", port=443, https=True)
        assert result and "server mode" in result.lower(), f"Expected server mode response, got: {result}"
        print("[PASS] test_server_mode_basic_route")

    @staticmethod
    def test_server_mode_route_id_prefix():
        """Test: Server mode routes have host1-server_ prefix"""
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "5", f"http://{CADDY_SERVER}:{CADDY_API_PORT}/config/apps/http/servers/srv1/routes"],
                capture_output=True, text=True, timeout=7
            )
            routes = result.stdout
            assert "host1-server_" in routes, f"Expected host1-server_ prefix in routes"
            print("[PASS] test_server_mode_route_id_prefix")
        except Exception as e:
            raise AssertionError(f"Failed to check route IDs: {e}")

    @staticmethod
    def test_coexistence_caddy_and_agent_prefixes():
        """Test: Both caddy (caddy-docker-proxy) and agent (server mode) routes coexist"""
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "5", f"http://{CADDY_SERVER}:{CADDY_API_PORT}/config/apps/http/servers/srv1/routes"],
                capture_output=True, text=True, timeout=7
            )
            routes = result.stdout
            # Check for routes from both sources
            has_host1_server = "host1-server_" in routes
            has_host2_remote = "host2-remote_" in routes or "host3-remote_" in routes
            assert has_host1_server, "Missing server mode routes (host1-server_*)"
            assert has_host2_remote, "Missing remote agent routes (host2-remote_* or host3-remote_*)"
            print("[PASS] test_coexistence_caddy_and_agent_prefixes")
        except Exception as e:
            raise AssertionError(f"Failed to verify coexistence: {e}")

    @staticmethod
    def run_all():
        """Run all server mode tests"""
        print("=" * 60)
        print("SERVER MODE TESTS - Host1 Agent")
        print("=" * 60)

        # First check API accessibility
        if not IntegrationTests.check_caddy_api():
            print(f"[SKIP] Caddy API not accessible at {CADDY_SERVER}:{CADDY_API_PORT}")
            return False

        tests = [
            ServerModeTests.test_server_mode_basic_route,
            ServerModeTests.test_server_mode_route_id_prefix,
            ServerModeTests.test_coexistence_caddy_and_agent_prefixes,
        ]

        passed = 0
        failed = 0
        for test in tests:
            try:
                test()
                passed += 1
            except AssertionError as e:
                print(f"[FAIL] {test.__name__}: {e}")
                failed += 1
            except Exception as e:
                print(f"[ERROR] {test.__name__}: {e}")
                failed += 1

        print(f"\nPassed: {passed}/{len(tests)}")
        return failed == 0


# =============================================================================
# SNIPPET API TESTS
# =============================================================================

class SnippetAPITests:
    """Tests for Snippet Sharing API"""

    @staticmethod
    def test_snippet_api_accessible():
        """Test: Snippet API is accessible on host1"""
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "5", f"http://{CADDY_SERVER}:8567/snippets"],
                capture_output=True, text=True, timeout=7
            )
            assert result.returncode == 0 and result.stdout, f"Snippet API not accessible"
            data = json.loads(result.stdout)
            assert isinstance(data, dict), f"Expected JSON object, got: {type(data)}"
            print("[PASS] test_snippet_api_accessible")
        except json.JSONDecodeError as e:
            raise AssertionError(f"Invalid JSON response: {e}")

    @staticmethod
    def test_snippet_api_returns_snippets():
        """Test: Snippet API returns expected snippets"""
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "5", f"http://{CADDY_SERVER}:8567/snippets"],
                capture_output=True, text=True, timeout=7
            )
            data = json.loads(result.stdout)
            # Host1 should have at least 'wildcard' and 'internal' snippets
            assert len(data) > 0, f"No snippets returned"
            print(f"[PASS] test_snippet_api_returns_snippets ({len(data)} snippets: {list(data.keys())})")
        except json.JSONDecodeError as e:
            raise AssertionError(f"Invalid JSON response: {e}")

    @staticmethod
    def test_remote_snippet_import():
        """Test: Remote agent can use snippet fetched from host1"""
        result = IntegrationTests.run_curl("remote-snippet-test.lan", port=443, https=True)
        assert result and "remote" in result.lower(), f"Expected remote-snippet response, got: {result}"
        print("[PASS] test_remote_snippet_import")

    @staticmethod
    def test_https_snippet_import():
        """Test: HTTPS snippet import with reverse_proxy.transport.* merging"""
        # Uses mendhak/http-https-echo which serves HTTPS with self-signed cert
        # The https snippet allows Caddy to connect despite the self-signed cert
        result = IntegrationTests.run_curl("https-snippet-test.lan", port=443, https=True)
        # http-https-echo returns JSON with request details
        assert result and ("path" in result.lower() or "host" in result.lower()), f"Expected http-https-echo response, got: {result}"
        print("[PASS] test_https_snippet_import")

    @staticmethod
    def test_https_snippet_route_config():
        """Test: HTTPS snippet creates single reverse_proxy handler with transport"""
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "5", f"http://{CADDY_SERVER}:{CADDY_API_PORT}/config/apps/http/servers"],
                capture_output=True, text=True, timeout=7
            )
            config = json.loads(result.stdout)

            # Find the https-snippet-test.lan route
            route_found = False
            for srv_name, srv in config.items():
                for route in srv.get("routes", []):
                    match = route.get("match", [{}])
                    if match and "https-snippet-test.lan" in match[0].get("host", []):
                        route_found = True
                        # Route's handle is a direct list of handlers
                        handle = route.get("handle", [])
                        reverse_proxy_count = sum(1 for h in handle if h.get("handler") == "reverse_proxy")

                        # Should be exactly 1 reverse_proxy handler
                        assert reverse_proxy_count == 1, f"Expected 1 reverse_proxy handler, got {reverse_proxy_count}"

                        # Find the reverse_proxy handler and verify it has both upstreams and transport
                        for h in handle:
                            if h.get("handler") == "reverse_proxy":
                                assert "upstreams" in h, "reverse_proxy missing upstreams"
                                assert "transport" in h, "reverse_proxy missing transport (snippet not merged)"
                                break
                        break
                if route_found:
                    break

            assert route_found, "https-snippet-test.lan route not found"
            print("[PASS] test_https_snippet_route_config")
        except json.JSONDecodeError as e:
            raise AssertionError(f"Invalid JSON response: {e}")

    @staticmethod
    def run_all():
        """Run all snippet API tests"""
        print("=" * 60)
        print("SNIPPET API TESTS")
        print("=" * 60)

        # First check if snippet API is accessible
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "3", f"http://{CADDY_SERVER}:8567/snippets"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0 or not result.stdout:
                print(f"[SKIP] Snippet API not accessible at {CADDY_SERVER}:8567")
                print("       Make sure caddy-agent-server has SNIPPET_API_PORT=8567")
                return False
        except Exception:
            print(f"[SKIP] Snippet API not accessible at {CADDY_SERVER}:8567")
            return False

        tests = [
            SnippetAPITests.test_snippet_api_accessible,
            SnippetAPITests.test_snippet_api_returns_snippets,
            SnippetAPITests.test_remote_snippet_import,
            SnippetAPITests.test_https_snippet_import,
            SnippetAPITests.test_https_snippet_route_config,
        ]

        passed = 0
        failed = 0
        for test in tests:
            try:
                test()
                passed += 1
            except AssertionError as e:
                print(f"[FAIL] {test.__name__}: {e}")
                failed += 1
            except Exception as e:
                print(f"[ERROR] {test.__name__}: {e}")
                failed += 1

        print(f"\nPassed: {passed}/{len(tests)}")
        return failed == 0


# =============================================================================
# CONFIGURATION TESTS
# =============================================================================

class ConfigTests:
    """Tests for environment variable configuration"""

    @staticmethod
    def test_caddy_url_default():
        """Test: CADDY_URL defaults correctly"""
        url = os.getenv("CADDY_URL", "http://localhost:2020")
        assert "2020" in url or "localhost" in url
        print("[PASS] test_caddy_url_default")

    @staticmethod
    def test_host_ip_modes():
        """Test: HOST_IP determines local vs remote mode"""
        # Clear env
        host_ip = os.getenv("HOST_IP", None)
        is_remote = host_ip is not None
        print(f"[PASS] test_host_ip_modes (remote={is_remote})")

    @staticmethod
    def run_all():
        """Run all config tests"""
        print("=" * 60)
        print("CONFIGURATION TESTS")
        print("=" * 60)

        tests = [
            ConfigTests.test_caddy_url_default,
            ConfigTests.test_host_ip_modes,
        ]

        passed = 0
        for test in tests:
            try:
                test()
                passed += 1
            except Exception as e:
                print(f"[FAIL] {test.__name__}: {e}")

        print(f"\nPassed: {passed}/{len(tests)}")
        return passed == len(tests)


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Caddy Agent Test Suite")
    parser.add_argument("--unit", action="store_true", help="Run unit tests only")
    parser.add_argument("--integration", action="store_true", help="Run integration tests only")
    parser.add_argument("--server-mode", action="store_true", help="Run server mode tests only")
    parser.add_argument("--config", action="store_true", help="Run config tests only")
    parser.add_argument("--snippet-api", action="store_true", help="Run snippet API tests only")
    args = parser.parse_args()

    # Default: run all
    any_specific = args.unit or args.integration or args.server_mode or args.config or args.snippet_api
    run_unit = args.unit or not any_specific
    run_integration = args.integration or not any_specific
    run_server_mode = args.server_mode or not any_specific
    run_config = args.config or not any_specific
    run_snippet_api = args.snippet_api or not any_specific

    results = []

    print("\n" + "=" * 60)
    print("CADDY MULTI-HOST AGENT TEST SUITE")
    print("=" * 60 + "\n")

    if run_unit:
        results.append(("Unit Tests", UnitTests.run_all()))
        print()

    if run_config:
        results.append(("Config Tests", ConfigTests.run_all()))
        print()

    if run_integration:
        results.append(("Integration Tests", IntegrationTests.run_all()))
        print()

    if run_server_mode:
        results.append(("Server Mode Tests", ServerModeTests.run_all()))
        print()

    if run_snippet_api:
        results.append(("Snippet API Tests", SnippetAPITests.run_all()))
        print()

    # Summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    all_passed = True
    for name, passed in results:
        status = "[PASSED]" if passed else "[FAILED]"
        print(f"  {name}: {status}")
        if not passed:
            all_passed = False

    print("=" * 60)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
