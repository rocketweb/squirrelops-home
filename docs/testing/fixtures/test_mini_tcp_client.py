import importlib.util
from pathlib import Path
import socket
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("client", Path(__file__).with_name("mini_tcp_client.py"))
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


class ClientTests(unittest.TestCase):
    def test_changed_script_v3_banner(self):
        self.assertEqual(client.BANNER, b"SquirrelOps TCP diagnostic v3\r\n")

    def test_exact_two_unique_high_ports(self):
        self.assertEqual(client.validate_ports([52000, 52001]), [52000, 52001])
        for ports in ([22, 52000], [52000], [52000, 52000], [52000, 65536], [52000, 52001, 52002]):
            with self.subTest(ports=ports), self.assertRaises(RuntimeError):
                client.validate_ports(ports)

    def test_max_six_attempts_interleaved(self):
        self.assertEqual(client.attempts([52000, 52001]), [(n, port) for n in range(1, 4) for port in (52000, 52001)])

    def probe(self, connect=None, reads=None):
        stream = Mock()
        stream.__enter__ = Mock(return_value=stream)
        stream.__exit__ = Mock(return_value=False)
        stream.connect.side_effect = connect
        stream.recv.side_effect = reads
        with patch.object(client.socket, "socket", return_value=stream):
            result = client.probe(52000)
        stream.bind.assert_called_once_with(("192.168.1.7", 0))
        stream.connect.assert_called_once_with(("192.168.1.115", 52000))
        stream.sendall.assert_not_called()
        return result

    def test_connect_timeout_stays_a_connect_failure(self):
        row = self.probe(connect=socket.timeout())
        self.assertFalse(row["connected"])
        self.assertEqual(row["stage"], "connect")

    def test_banner_timeout_does_not_erase_connect_success(self):
        row = self.probe(reads=socket.timeout())
        self.assertTrue(row["connected"])
        self.assertFalse(row["banner_valid"])
        self.assertEqual(row["stage"], "banner")

    def test_fragmented_banner_passes(self):
        row = self.probe(reads=[client.BANNER[:7], client.BANNER[7:]])
        self.assertTrue(row["banner_valid"])

    def test_wrong_or_empty_response_is_not_success(self):
        for reads in ([b""], [b"unexpected\n", b""]):
            self.assertFalse(self.probe(reads=reads)["banner_valid"])

    def test_route_requires_the_authorized_interface_and_source(self):
        client.validate_route([{"dev": "wlp0s20f3", "prefsrc": "192.168.1.7"}])
        for rows in ([], [{"dev": "eth0", "prefsrc": "192.168.1.7"}], [{"dev": "wlp0s20f3", "prefsrc": "192.168.1.9"}]):
            with self.assertRaises(RuntimeError):
                client.validate_route(rows)


if __name__ == "__main__":
    unittest.main()
