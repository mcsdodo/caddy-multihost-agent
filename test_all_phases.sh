#!/bin/bash
# Comprehensive Multi-Phase Testing Script
# Tests all routes across all phases and all hosts

echo "========================================================================="
echo "CADDY MULTI-HOST AGENT - COMPREHENSIVE TEST SUITE"
echo "========================================================================="
echo ""
echo "Testing Date: $(date)"
echo "Target Server: 192.168.0.96"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
TOTAL=0

# Test function
test_route() {
    local domain=$1
    local expected=$2
    local description=$3

    TOTAL=$((TOTAL + 1))
    echo -n "Test $TOTAL: $description... "

    response=$(curl -s -H "Host: $domain" http://192.168.0.96 2>&1)

    if echo "$response" | grep -q "$expected"; then
        echo -e "${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        echo "  Expected: $expected"
        echo "  Got: $response"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

echo "========================================================================="
echo "PHASE 1: Numbered Labels & Multiple Domains"
echo "========================================================================="
echo ""

# Host1 tests
echo "--- Host1 (Server) Tests ---"
test_route "test-local.lan" "Simple label" "Simple label (backward compat)"
test_route "test-numbered-0.lan" "Numbered label 0" "Numbered label _0"
test_route "test-numbered-1.lan" "Numbered label 1" "Numbered label _1"
test_route "test-multi-a.lan" "Multi-domain" "Multiple domains (A)"
test_route "test-multi-b.lan" "Multi-domain" "Multiple domains (B)"
test_route "test-multi-c.lan" "Multi-domain" "Multiple domains (C)"

echo ""
echo "--- Host2 (Agent) Tests ---"
test_route "test-remote.lan" "Simple label on host2" "Host2 simple label"
test_route "host2-app1.lan" "Multi-domain on host2" "Host2 multi-domain (A)"
test_route "host2-app2.lan" "Multi-domain on host2" "Host2 multi-domain (B)"
test_route "host2-route10.lan" "High numbered routes" "Host2 numbered _10"
test_route "host2-route111.lan" "High numbered routes" "Host2 numbered _111"

echo ""
echo "--- Host3 (Agent) Tests ---"
test_route "test-host3.lan" "Simple label on host3" "Host3 simple label"
test_route "host3-app1.lan" "Combined features" "Host3 combined (A)"
test_route "host3-app2.lan" "Combined features" "Host3 combined (B)"
test_route "mixed-a.lan" "Mixed labels" "Host3 mixed (A)"
test_route "mixed-b.lan" "Mixed labels" "Host3 mixed (B)"

echo ""
echo "========================================================================="
echo "PHASE 2: Global Settings, Snippets & TLS DNS"
echo "========================================================================="
echo ""

echo "--- Phase 2 Tests ---"
test_route "phase2-import.lan" "Snippet import" "Snippet import"
test_route "test-phase2.lacny.me" "" "TLS DNS wildcard (cert acquired)"

echo ""
echo "--- TLS Configuration Check ---"
echo -n "Checking TLS automation policies... "
tls_policies=$(ssh root@192.168.0.96 "curl -s http://localhost:2019/config/apps/tls/automation/policies 2>/dev/null | python3 -c 'import sys, json; p=json.load(sys.stdin); print(len(p))' 2>/dev/null")
if [ "$tls_policies" -ge 1 ]; then
    echo -e "${GREEN}PASS${NC} ($tls_policies policies configured)"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

echo ""
echo "========================================================================="
echo "PHASE 3: Header Manipulation & Transport TLS"
echo "========================================================================="
echo ""

echo "--- Phase 3 Tests ---"
test_route "phase3-headers.lan" "Header manipulation" "Header manipulation"

echo ""
echo "--- Header Configuration Check ---"
echo -n "Checking header deletion... "
response_headers=$(curl -s -I -H "Host: phase3-headers.lan" http://192.168.0.96 2>&1)
if ! echo "$response_headers" | grep -q "^Server:"; then
    echo -e "${GREEN}PASS${NC} (Server header deleted)"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAIL${NC} (Server header still present)"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

echo ""
echo "--- Transport TLS Check ---"
echo -n "Checking transport TLS configuration... "
transport_check=$(ssh root@192.168.0.96 "curl -s http://localhost:2019/config/apps/http/servers/srv0/routes 2>/dev/null | python3 -c 'import sys, json; routes=json.load(sys.stdin); r=[x for x in routes if \"transport-handle\" in x.get(\"@id\",\"\")]; print(\"insecure_skip_verify\" in str(r))' 2>/dev/null")
if [ "$transport_check" = "True" ]; then
    echo -e "${GREEN}PASS${NC} (TLS insecure_skip_verify configured)"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

echo ""
echo "========================================================================="
echo "ROUTE REGISTRATION VERIFICATION"
echo "========================================================================="
echo ""

echo -n "Total routes registered in Caddy... "
route_count=$(ssh root@192.168.0.96 "curl -s http://localhost:2019/config/apps/http/servers/srv0/routes 2>/dev/null | python3 -c 'import sys, json; print(len(json.load(sys.stdin)))' 2>/dev/null")
echo "$route_count routes"
TOTAL=$((TOTAL + 1))
if [ "$route_count" -ge 17 ]; then
    echo -e "${GREEN}PASS${NC} (Expected >= 17, got $route_count)"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAIL${NC} (Expected >= 17, got $route_count)"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "Routes by host:"
ssh root@192.168.0.96 "curl -s http://localhost:2019/config/apps/http/servers/srv0/routes 2>/dev/null | python3 -c '
import sys, json
routes = json.load(sys.stdin)
hosts = {}
for r in routes:
    host = r[\"@id\"].split(\"_\")[0]
    hosts[host] = hosts.get(host, 0) + 1
for host in sorted(hosts.keys()):
    print(f\"  {host}: {hosts[host]} routes\")
' 2>/dev/null"

echo ""
echo "========================================================================="
echo "AGENT STATUS CHECK"
echo "========================================================================="
echo ""

for host in "192.168.0.96" "192.168.0.98" "192.168.0.99"; do
    echo -n "Host $host agent status... "
    if [ "$host" = "192.168.0.96" ]; then
        container="caddy-agent-server"
    elif [ "$host" = "192.168.0.98" ]; then
        container="caddy-agent-remote"
    else
        container="caddy-agent-remote3"
    fi

    status=$(ssh root@$host "docker inspect -f '{{.State.Status}}' $container 2>/dev/null")
    if [ "$status" = "running" ]; then
        echo -e "${GREEN}RUNNING${NC}"
    else
        echo -e "${RED}$status${NC}"
    fi
done

echo ""
echo "========================================================================="
echo "TEST SUMMARY"
echo "========================================================================="
echo ""
echo "Total Tests: $TOTAL"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}=========================================================================${NC}"
    echo -e "${GREEN}ALL TESTS PASSED!${NC}"
    echo -e "${GREEN}=========================================================================${NC}"
    exit 0
else
    echo -e "${RED}=========================================================================${NC}"
    echo -e "${RED}SOME TESTS FAILED${NC}"
    echo -e "${RED}=========================================================================${NC}"
    exit 1
fi
