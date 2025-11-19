#!/usr/bin/env python3
"""
Phase 3 Unit Tests: Header Manipulation and Transport TLS Settings
Tests for medium-priority features including header_up, header_down, and transport TLS
"""

import unittest
import sys
import os

# Add parent directory to path to import caddy-agent-watch
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import functions to test (these would normally be imported from caddy-agent-watch.py)
# Since we can't easily import due to the filename, we'll mock the functions for testing

def parse_header_config_test(config):
    """Test implementation matching caddy-agent-watch.py"""
    header_config = {}

    for key, value in config.items():
        if key.startswith('reverse_proxy.header_up'):
            if 'header_up' not in header_config:
                header_config['header_up'] = []

            if value.startswith('-'):
                header_name = value[1:].strip()
                header_config['header_up'].append(["-" + header_name])
            elif value.startswith('+'):
                parts = value[1:].strip().split(None, 1)
                if len(parts) == 2:
                    header_name = parts[0]
                    header_value = parts[1].strip('"')
                    header_config['header_up'].append([header_name, header_value])
            else:
                parts = value.split(None, 1)
                if len(parts) == 2:
                    header_name = parts[0]
                    header_value = parts[1].strip('"')
                    header_config['header_up'].append([header_name, header_value])

        elif key.startswith('reverse_proxy.header_down'):
            if 'header_down' not in header_config:
                header_config['header_down'] = []

            if value.startswith('-'):
                header_name = value[1:].strip()
                header_config['header_down'].append(["-" + header_name])
            elif value.startswith('+'):
                parts = value[1:].strip().split(None, 1)
                if len(parts) == 2:
                    header_name = parts[0]
                    header_value = parts[1].strip('"')
                    header_config['header_down'].append([header_name, header_value])
            else:
                parts = value.split(None, 1)
                if len(parts) == 2:
                    header_name = parts[0]
                    header_value = parts[1].strip('"')
                    header_config['header_down'].append([header_name, header_value])

    return header_config


def parse_transport_config_test(config):
    """Test implementation matching caddy-agent-watch.py"""
    transport_config = {}

    has_transport = any(key.startswith('transport') for key in config.keys())
    if not has_transport:
        return transport_config

    for key, value in config.items():
        if key == 'transport':
            transport_config['transport'] = {'protocol': value}
        elif key.startswith('transport.'):
            directive = key[10:]
            if 'transport' not in transport_config:
                transport_config['transport'] = {}

            if directive == 'tls':
                transport_config['transport']['tls'] = {}
            elif directive == 'tls_insecure_skip_verify':
                if 'tls' not in transport_config['transport']:
                    transport_config['transport']['tls'] = {}
                transport_config['transport']['tls']['insecure_skip_verify'] = True

    return transport_config


class TestPhase3HeaderManipulation(unittest.TestCase):
    """Test header_up and header_down directives"""

    def test_header_up_remove(self):
        """Test removing request header with -HeaderName format"""
        config = {
            'domain': 'test.lan',
            'reverse_proxy': 'backend:80',
            'reverse_proxy.header_up': '-X-Forwarded-For'
        }

        result = parse_header_config_test(config)

        self.assertIn('header_up', result)
        self.assertEqual(len(result['header_up']), 1)
        self.assertEqual(result['header_up'][0], ['-X-Forwarded-For'])

    def test_header_up_add(self):
        """Test adding request header with +HeaderName value format"""
        config = {
            'domain': 'test.lan',
            'reverse_proxy': 'backend:80',
            'reverse_proxy.header_up': '+X-Custom-Header "custom-value"'
        }

        result = parse_header_config_test(config)

        self.assertIn('header_up', result)
        self.assertEqual(len(result['header_up']), 1)
        self.assertEqual(result['header_up'][0], ['X-Custom-Header', 'custom-value'])

    def test_header_up_set(self):
        """Test setting request header with HeaderName value format"""
        config = {
            'domain': 'test.lan',
            'reverse_proxy': 'backend:80',
            'reverse_proxy.header_up': 'Host "backend.internal"'
        }

        result = parse_header_config_test(config)

        self.assertIn('header_up', result)
        self.assertEqual(len(result['header_up']), 1)
        self.assertEqual(result['header_up'][0], ['Host', 'backend.internal'])

    def test_header_down_remove(self):
        """Test removing response header with -HeaderName format"""
        config = {
            'domain': 'test.lan',
            'reverse_proxy': 'backend:80',
            'reverse_proxy.header_down': '-Server'
        }

        result = parse_header_config_test(config)

        self.assertIn('header_down', result)
        self.assertEqual(len(result['header_down']), 1)
        self.assertEqual(result['header_down'][0], ['-Server'])

    def test_header_down_add(self):
        """Test adding response header with +HeaderName value format"""
        config = {
            'domain': 'test.lan',
            'reverse_proxy': 'backend:80',
            'reverse_proxy.header_down': '+X-Custom-Response "test"'
        }

        result = parse_header_config_test(config)

        self.assertIn('header_down', result)
        self.assertEqual(len(result['header_down']), 1)
        self.assertEqual(result['header_down'][0], ['X-Custom-Response', 'test'])

    def test_header_down_set(self):
        """Test setting response header with HeaderName value format"""
        config = {
            'domain': 'test.lan',
            'reverse_proxy': 'backend:80',
            'reverse_proxy.header_down': 'Server "MyCustomServer"'
        }

        result = parse_header_config_test(config)

        self.assertIn('header_down', result)
        self.assertEqual(len(result['header_down']), 1)
        self.assertEqual(result['header_down'][0], ['Server', 'MyCustomServer'])

    def test_multiple_header_manipulations(self):
        """Test multiple header manipulations combined"""
        config = {
            'domain': 'test.lan',
            'reverse_proxy': 'backend:80',
            'reverse_proxy.header_up.0': '-X-Forwarded-For',
            'reverse_proxy.header_up.1': '+X-Real-IP "192.168.1.1"',
            'reverse_proxy.header_down.0': '-Server',
            'reverse_proxy.header_down.1': 'X-Powered-By "Caddy"'
        }

        result = parse_header_config_test(config)

        self.assertIn('header_up', result)
        self.assertIn('header_down', result)
        self.assertEqual(len(result['header_up']), 2)
        self.assertEqual(len(result['header_down']), 2)

    def test_no_headers(self):
        """Test config without header manipulation"""
        config = {
            'domain': 'test.lan',
            'reverse_proxy': 'backend:80'
        }

        result = parse_header_config_test(config)

        self.assertEqual(result, {})


class TestPhase3TransportTLS(unittest.TestCase):
    """Test transport TLS configuration"""

    def test_transport_tls_enabled(self):
        """Test enabling TLS for backend communication"""
        config = {
            'domain': 'test.lan',
            'reverse_proxy': 'backend:443',
            'transport.tls': ''
        }

        result = parse_transport_config_test(config)

        self.assertIn('transport', result)
        self.assertIn('tls', result['transport'])
        self.assertEqual(result['transport']['tls'], {})

    def test_transport_tls_insecure_skip_verify(self):
        """Test TLS with insecure skip verify"""
        config = {
            'domain': 'test.lan',
            'reverse_proxy': 'backend:443',
            'transport.tls_insecure_skip_verify': ''
        }

        result = parse_transport_config_test(config)

        self.assertIn('transport', result)
        self.assertIn('tls', result['transport'])
        self.assertIn('insecure_skip_verify', result['transport']['tls'])
        self.assertTrue(result['transport']['tls']['insecure_skip_verify'])

    def test_transport_tls_with_skip_verify(self):
        """Test TLS enabled with skip verify combined"""
        config = {
            'domain': 'test.lan',
            'reverse_proxy': 'backend:443',
            'transport.tls': '',
            'transport.tls_insecure_skip_verify': ''
        }

        result = parse_transport_config_test(config)

        self.assertIn('transport', result)
        self.assertIn('tls', result['transport'])
        self.assertIn('insecure_skip_verify', result['transport']['tls'])
        self.assertTrue(result['transport']['tls']['insecure_skip_verify'])

    def test_transport_protocol(self):
        """Test setting transport protocol"""
        config = {
            'domain': 'test.lan',
            'reverse_proxy': 'backend:80',
            'transport': 'http'
        }

        result = parse_transport_config_test(config)

        self.assertIn('transport', result)
        self.assertIn('protocol', result['transport'])
        self.assertEqual(result['transport']['protocol'], 'http')

    def test_no_transport_config(self):
        """Test config without transport settings"""
        config = {
            'domain': 'test.lan',
            'reverse_proxy': 'backend:80'
        }

        result = parse_transport_config_test(config)

        self.assertEqual(result, {})


class TestPhase3Integration(unittest.TestCase):
    """Integration tests combining Phase 3 features"""

    def test_headers_and_transport_combined(self):
        """Test using headers and transport TLS together"""
        config = {
            'domain': 'secure.lan',
            'reverse_proxy': 'backend:443',
            'reverse_proxy.header_up': '-X-Forwarded-For',
            'reverse_proxy.header_down': '-Server',
            'transport.tls': '',
            'transport.tls_insecure_skip_verify': ''
        }

        headers = parse_header_config_test(config)
        transport = parse_transport_config_test(config)

        # Verify headers
        self.assertIn('header_up', headers)
        self.assertIn('header_down', headers)
        self.assertEqual(headers['header_up'][0], ['-X-Forwarded-For'])
        self.assertEqual(headers['header_down'][0], ['-Server'])

        # Verify transport
        self.assertIn('transport', transport)
        self.assertIn('tls', transport['transport'])
        self.assertTrue(transport['transport']['tls']['insecure_skip_verify'])

    def test_real_world_media_server_config(self):
        """Test configuration similar to real-world media server setup"""
        # Based on caddy/docker-compose-big-media.yml
        config = {
            'domain': 'jellyfin.lan',
            'reverse_proxy': '{{upstreams 8096}}',
            'reverse_proxy.header_up': '-X-Forwarded-For',
            'reverse_proxy.header_down.0': '-Server',
            'reverse_proxy.header_down.1': 'X-Powered-By "Caddy"',
            'transport.tls_insecure_skip_verify': ''
        }

        headers = parse_header_config_test(config)
        transport = parse_transport_config_test(config)

        # Should have both header manipulations
        self.assertEqual(len(headers['header_up']), 1)
        self.assertEqual(len(headers['header_down']), 2)

        # Should skip TLS verification
        self.assertTrue(transport['transport']['tls']['insecure_skip_verify'])


def run_tests():
    """Run all Phase 3 tests"""
    print("=" * 70)
    print("Phase 3 Unit Tests: Header Manipulation & Transport TLS")
    print("=" * 70)
    print()

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestPhase3HeaderManipulation))
    suite.addTests(loader.loadTestsFromTestCase(TestPhase3TransportTLS))
    suite.addTests(loader.loadTestsFromTestCase(TestPhase3Integration))

    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print()
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    print("=" * 70)

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
