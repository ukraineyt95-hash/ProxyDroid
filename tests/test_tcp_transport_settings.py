import asyncio
import struct
import unittest

from app.src.main.python import socks5_proxy as proxy


def tls_record(payload, version=b"\x03\x03"):
    return b"\x16" + version + struct.pack("!H", len(payload)) + payload


def make_client_hello(hostname=b"www.example.com", extra_extensions=b""):
    name = b"\x00" + struct.pack("!H", len(hostname)) + hostname
    name_list = struct.pack("!H", len(name)) + name
    sni_extension = b"\x00\x00" + struct.pack("!H", len(name_list)) + name_list
    extensions = sni_extension + extra_extensions
    hello = (
        b"\x03\x03" + b"\x00" * 32
        + b"\x00"  # empty legacy session id
        + b"\x00\x02\x13\x01"  # one TLS 1.3 cipher suite
        + b"\x01\x00"  # null compression
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return tls_record(handshake, version=b"\x03\x01")


def split_tls_records(data):
    records = []
    offset = 0
    while offset < len(data):
        if offset + 5 > len(data):
            raise AssertionError("incomplete TLS record header")
        size = struct.unpack_from("!H", data, offset + 3)[0]
        end = offset + 5 + size
        if end > len(data):
            raise AssertionError("incomplete TLS record")
        records.append((data[offset:offset + 3], data[offset + 5:end]))
        offset = end
    return records


class ClientHelloTransformationTest(unittest.TestCase):
    def test_complete_client_hello_is_split_across_valid_records(self):
        client_hello = b"\x03\x03" + b"\x00" * 198
        handshake = b"\x01" + len(client_hello).to_bytes(3, "big") + client_hello
        original = tls_record(handshake, version=b"\x03\x01")
        processor = proxy.TLSClientHelloProcessor(fragment_size=64)

        self.assertEqual(processor.feed(original[:3]), b"")
        self.assertEqual(processor.feed(original[3:19]), b"")
        fragmented = processor.feed(original[19:])

        records = split_tls_records(fragmented)
        self.assertGreaterEqual(len(records), 2)
        self.assertEqual(records[0][0], b"\x16\x03\x01")
        self.assertTrue(all(header == b"\x16\x03\x03" for header, _ in records[1:]))
        self.assertEqual(b"".join(payload for _, payload in records), handshake)
        self.assertTrue(processor.done)

    def test_sni_override_rewrites_name_and_lengths_without_fragmenting(self):
        original = make_client_hello()
        processor = proxy.TLSClientHelloProcessor(
            fragment=False, sni_override="front.example.net")
        rewritten = processor.feed(original)

        records = split_tls_records(rewritten)
        self.assertEqual(len(records), 1)
        handshake = records[0][1]
        self.assertEqual(handshake[0], 1)
        self.assertEqual(int.from_bytes(handshake[1:4], "big"), len(handshake) - 4)
        self.assertIn(b"front.example.net", handshake)
        self.assertNotIn(b"www.example.com", handshake)

    def test_sni_override_and_fragmentation_work_together(self):
        processor = proxy.TLSClientHelloProcessor(
            fragment_size=64, fragment=True, sni_override="cf.example.test")
        records = split_tls_records(processor.feed(make_client_hello()))
        handshake = b"".join(payload for _, payload in records)

        self.assertGreaterEqual(len(records), 2)
        self.assertEqual(handshake[0], 1)
        self.assertEqual(int.from_bytes(handshake[1:4], "big"), len(handshake) - 4)
        self.assertIn(b"cf.example.test", handshake)
        self.assertNotIn(b"www.example.com", handshake)

    def test_non_tls_prefragmented_ech_and_psk_client_hellos_are_not_rewritten(self):
        plain = proxy.TLSClientHelloProcessor(
            fragment=False, sni_override="front.example.net")
        self.assertEqual(plain.feed(b"GET / HTTP/1.1\r\n"), b"GET / HTTP/1.1\r\n")

        partial_handshake = b"\x01" + (100).to_bytes(3, "big") + b"x" * 12
        original_partial = tls_record(partial_handshake)
        prefragmented = proxy.TLSClientHelloProcessor(
            fragment=False, sni_override="front.example.net")
        self.assertEqual(prefragmented.feed(original_partial), original_partial)

        ech_extension = b"\xfe\x0d\x00\x02xx"
        original_ech = make_client_hello(extra_extensions=ech_extension)
        ech = proxy.TLSClientHelloProcessor(
            fragment=False, sni_override="front.example.net")
        self.assertEqual(ech.feed(original_ech), original_ech)

        psk_extension = b"\x00\x29\x00\x02xx"
        original_psk = make_client_hello(extra_extensions=psk_extension)
        psk = proxy.TLSClientHelloProcessor(
            fragment=False, sni_override="front.example.net")
        self.assertEqual(psk.feed(original_psk), original_psk)

    def test_invalid_fragment_size_and_sni_are_rejected(self):
        with self.assertRaises(ValueError):
            proxy.TLSClientHelloProcessor(fragment_size=32)
        with self.assertRaises(ValueError):
            proxy.TLSClientHelloProcessor(fragment=False, sni_override="https://bad.example")
        with self.assertRaises(ValueError):
            proxy.TLSClientHelloProcessor(fragment=False, sni_override="1.1.1.1")


class OutgoingSocketTuningTest(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        proxy.configure_transport_options()

    async def test_outgoing_connection_falls_back_to_normal_tcp_if_tfo_is_unavailable(self):
        async def echo(reader, writer):
            try:
                message = await reader.readexactly(5)
                writer.write(message)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        proxy.configure_transport_options(tcp_max_segment_size=512, tcp_fast_open=True)
        try:
            reader, writer = await proxy.open_tcp_connection("127.0.0.1", port, timeout=3)
            writer.write(b"hello")
            await writer.drain()
            self.assertEqual(
                await asyncio.wait_for(reader.readexactly(5), timeout=3), b"hello")
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
