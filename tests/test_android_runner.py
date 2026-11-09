import socket
import sys
import unittest
from pathlib import Path


PYTHON_DIR = Path(__file__).resolve().parents[1] / "app" / "src" / "main" / "python"
sys.path.insert(0, str(PYTHON_DIR))

import android_runner  # noqa: E402


def free_port(socket_type):
    probe = socket.socket(socket.AF_INET, socket_type)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


class AndroidRunnerLifecycleTest(unittest.TestCase):
    def test_embedded_servers_and_tun_worker_start_and_stop(self):
        proxy_port = free_port(socket.SOCK_STREAM)
        dns_port = free_port(socket.SOCK_DGRAM)
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        config = {
            "host": "127.0.0.1",
            "port": proxy_port,
            "username": "local-user",
            "password": "local-pass",
            "upstreamProxy": "",
            "upstreamUsername": "",
            "upstreamPassword": "",
            "printCert": False,
            "dnsHost": "127.0.0.1",
            "dnsPort": dns_port,
            "dnsUpstream": "1.1.1.1:53",
            "fakeIpRange": "198.18.0.0/15",
            "udpOverTcp": True,
        }
        try:
            self.assertTrue(android_runner.start(left.fileno(), config))
            self.assertTrue(android_runner.is_running())
            self.assertTrue(android_runner.stop())
            self.assertFalse(android_runner.is_running())
        finally:
            android_runner.stop()
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
