import socket
import unittest
from unittest.mock import Mock, patch

import main


class PinnedConnectionTests(unittest.TestCase):
    @patch("main.socket.socket")
    def test_pinned_socket_connects_with_ipv6_sockaddr(self, socket_factory):
        sock = Mock()
        socket_factory.return_value = sock
        address = ("2001:db8::1", 443, 0, 0)

        result = main.create_pinned_socket(socket.AF_INET6, address, 8)

        self.assertIs(result, sock)
        socket_factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout.assert_called_once_with(8)
        sock.connect.assert_called_once_with(address)

    @patch("main.socket.socket")
    def test_pinned_socket_closes_when_connect_fails(self, socket_factory):
        sock = Mock()
        sock.connect.side_effect = OSError("connection failed")
        socket_factory.return_value = sock

        with self.assertRaisesRegex(OSError, "connection failed"):
            main.create_pinned_socket(socket.AF_INET6, ("2001:db8::1", 443, 0, 0), 8)

        sock.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
