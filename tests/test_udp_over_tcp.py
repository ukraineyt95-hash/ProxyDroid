import asyncio
import struct
import unittest

from app.src.main.python import socks5_proxy as proxy


class EchoDatagramProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        self.transport.sendto(data, address)


class UdpOverTcpTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        loop = asyncio.get_running_loop()
        self.udp_transport, _ = await loop.create_datagram_endpoint(
            EchoDatagramProtocol, local_addr=("127.0.0.1", 0))
        self.udp_port = self.udp_transport.get_extra_info("sockname")[1]
        self.tcp_server = await asyncio.start_server(
            lambda reader, writer: proxy.handle_client(reader, writer, None, None),
            "127.0.0.1", 0)
        self.tcp_port = self.tcp_server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.tcp_server.close()
        await self.tcp_server.wait_closed()
        self.udp_transport.close()

    async def test_udp_round_trip_is_framed_over_the_socks_tcp_stream(self):
        reader, writer = await proxy.socks5_client_handshake(
            "127.0.0.1", self.tcp_port)
        try:
            writer.write(
                b"\x05" + bytes([proxy.UDP_OVER_TCP_COMMAND, 0]) +
                proxy.encode_address("0.0.0.0", 0))
            await writer.drain()
            reply = await asyncio.wait_for(reader.readexactly(3), 2)
            self.assertEqual(reply, b"\x05\x00\x00")
            await asyncio.wait_for(proxy.read_address(reader), 2)

            payload = b"proxy-droid udp-over-tcp"
            frame = proxy.encode_address("127.0.0.1", self.udp_port) + payload
            writer.write(struct.pack("!I", len(frame)) + frame)
            await writer.drain()

            size = struct.unpack("!I", await asyncio.wait_for(
                reader.readexactly(4), 2))[0]
            response = await asyncio.wait_for(reader.readexactly(size), 2)
            host, port, offset = proxy.parse_udp_address(response, 0)
            self.assertEqual(host, "127.0.0.1")
            self.assertEqual(port, self.udp_port)
            self.assertEqual(response[offset:], payload)
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_tun_udp_flow_uses_the_udp_over_tcp_extension(self):
        from ipaddress import IPv4Address

        tunnel = proxy.PseudoTun(mtu=1500)
        engine = proxy.Tun2Socks(
            tunnel.tunnel,
            f"socks5://127.0.0.1:{self.tcp_port}",
            udp_over_tcp=True,
        )
        engine_task = asyncio.create_task(engine.run())
        source = IPv4Address("10.73.0.4").packed
        destination = IPv4Address("127.0.0.1").packed
        payload = b"tun udp payload"
        udp = struct.pack("!HHHH", 42000, self.udp_port, 8 + len(payload), 0) + payload
        packet = engine.make_ip_packet(4, source, destination, 17, udp)
        try:
            await tunnel.inject(packet)
            response_packet = await asyncio.wait_for(tunnel.receive(), 2)
            response = proxy.parse_ip_packet(response_packet)
            self.assertEqual(response["source"], destination)
            self.assertEqual(response["destination"], source)
            source_port, destination_port, length = struct.unpack_from(
                "!HHH", response["payload"], 0)
            self.assertEqual((source_port, destination_port), (self.udp_port, 42000))
            self.assertEqual(response["payload"][8:length], payload)
        finally:
            await engine.close()
            tunnel.close()
            if not engine_task.done():
                engine_task.cancel()
            await asyncio.gather(engine_task, return_exceptions=True)

    async def test_tun_dns_queries_are_redirected_to_the_configured_local_resolver(self):
        from ipaddress import IPv4Address

        tunnel = proxy.PseudoTun(mtu=1500)
        engine = proxy.Tun2Socks(
            tunnel.tunnel,
            f"socks5://127.0.0.1:{self.tcp_port}",
            dns_redirect=("127.0.0.1", self.udp_port),
        )
        engine_task = asyncio.create_task(engine.run())
        source = IPv4Address("10.73.0.4").packed
        dns_address = IPv4Address("10.73.0.2").packed
        query = b"dns query test"
        udp = struct.pack("!HHHH", 44000, 53, 8 + len(query), 0) + query
        packet = engine.make_ip_packet(4, source, dns_address, 17, udp)
        try:
            await tunnel.inject(packet)
            response_packet = await asyncio.wait_for(tunnel.receive(), 2)
            response = proxy.parse_ip_packet(response_packet)
            self.assertEqual(response["source"], dns_address)
            self.assertEqual(response["destination"], source)
            source_port, destination_port, length = struct.unpack_from(
                "!HHH", response["payload"], 0)
            self.assertEqual((source_port, destination_port), (53, 44000))
            self.assertEqual(response["payload"][8:length], query)
        finally:
            await engine.close()
            tunnel.close()
            if not engine_task.done():
                engine_task.cancel()
            await asyncio.gather(engine_task, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
