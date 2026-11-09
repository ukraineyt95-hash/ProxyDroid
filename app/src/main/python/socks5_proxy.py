import argparse
import asyncio
import contextlib
import base64
import datetime
import fnmatch
import hashlib
import ipaddress
import os
import secrets
import socket
import ssl
import struct
import tempfile
import time
from urllib.parse import unquote, urlsplit


UDP_OVER_TCP_COMMAND = 0x80
UDP_OVER_TCP_MAX_FRAME = 65536 + 512


PROBES = {
    ("www.msftconnecttest.com", "/connecttest.txt"): b"Microsoft Connect Test",
    ("ipv6.msftconnecttest.com", "/connecttest.txt"): b"Microsoft Connect Test",
    ("www.msftncsi.com", "/ncsi.txt"): b"Microsoft NCSI",
    ("dns.msftncsi.com", "/ncsi.txt"): b"Microsoft NCSI",
    ("captive.apple.com", "/hotspot-detect.html"): b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
    ("captive.apple.com", "/"): b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
    ("www.apple.com", "/library/test/success.html"): b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
    ("detectportal.firefox.com", "/success.txt"): b"success\n",
    ("detectportal.firefox.com", "/canonical.html"): b"<meta http-equiv=\"refresh\" content=\"0; url=https://support.mozilla.org/kb/captive-portal\"/>\n",
    ("nmcheck.gnome.org", "/check_network_status.txt"): b"NetworkManager is online\n",
    ("networkcheck.kde.org", "/"): b"OK",
    ("connectivity-check.ubuntu.com", "/"): b"",
}


PAC_ENABLED = True
PAC_PATHS = ("/proxy.pac", "/wpad.dat")
PAC_PROXY = None
PAC_SOCKS = True
PAC_BYPASS = ("localhost", "127.0.0.1", "::1", "*.local")
PAC_DEFAULT_PORT = 1080

MUX_CONCURRENCY = 32
RELAY_CHUNK = 256 * 1024
READER_LIMIT = RELAY_CHUNK * 4
WRITE_HIGH = RELAY_CHUNK * 4
WRITE_LOW = RELAY_CHUNK
MUX_FRAME_SIZE = 65536
MUX_WINDOW = 1 << 20
MUX_CONN_GRANT = 1 << 30
WINDOW_REFRESH = RELAY_CHUNK
SOCK_BUF = 0

MKCP_MTU = 1350
MKCP_TTI = 20
MKCP_UPLINK = 50
MKCP_DOWNLINK = 50
MKCP_PORT = 0
MKCP_PEER = None
MKCP_WITH_TCP = False
TRANSPORT_NAMES = None
MKCP_DATA_OVERHEAD = 18
MKCP_ACK_OVERHEAD = 17
MKCP_WINDOW_LIMIT = 2 * 1024 * 1024


def tune_connection(writer):
    transport = getattr(writer, "transport", None)
    if transport is not None:
        try:
            transport.set_write_buffer_limits(high=WRITE_HIGH, low=WRITE_LOW)
        except (AttributeError, ValueError, OSError):
            pass
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except (AttributeError, OSError):
        pass
    if hasattr(socket, "TCP_QUICKACK"):
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        except OSError:
            pass


def configure_performance(chunk=262144, frame_size=65536, window=1 << 20,
                          mux_streams=32, sock_buf=0):
    global MUX_CONCURRENCY, RELAY_CHUNK, READER_LIMIT, WRITE_HIGH, WRITE_LOW
    global MUX_FRAME_SIZE, MUX_WINDOW, WINDOW_REFRESH, SOCK_BUF
    if chunk < 16384 or not 16384 <= frame_size <= 16777215:
        raise ValueError("invalid chunk/frame_size")
    if not 65535 <= window <= 0x7fffffff or mux_streams < 1 or sock_buf < 0:
        raise ValueError("invalid window/mux_streams/sock_buf")
    RELAY_CHUNK = chunk
    READER_LIMIT = max(chunk * 4, 65536)
    WRITE_HIGH = max(chunk * 4, 262144)
    WRITE_LOW = chunk
    WINDOW_REFRESH = chunk
    MUX_CONCURRENCY = mux_streams
    MUX_FRAME_SIZE = frame_size
    MUX_WINDOW = window
    SOCK_BUF = sock_buf


def configure_pac(enabled=True, paths=("/proxy.pac", "/wpad.dat"), proxy=None,
                  socks=True, bypass=("localhost", "127.0.0.1", "::1", "*.local"),
                  default_port=1080):
    global PAC_ENABLED, PAC_PATHS, PAC_PROXY, PAC_SOCKS, PAC_BYPASS, PAC_DEFAULT_PORT
    PAC_ENABLED = enabled
    PAC_PATHS = tuple(paths)
    PAC_PROXY = proxy
    PAC_SOCKS = socks
    PAC_BYPASS = tuple(bypass)
    PAC_DEFAULT_PORT = default_port


def pac_match(target):
    if not PAC_ENABLED:
        return False
    path = urlsplit(target).path if "://" in target else target
    return path.split("?", 1)[0] in PAC_PATHS


def pac_proxy(host_header):
    if PAC_PROXY:
        return PAC_PROXY
    raw = (host_header or "").split(",", 1)[0].strip()
    if raw:
        try:
            parsed = urlsplit("//" + raw)
            host, port = parsed.hostname, parsed.port
        except ValueError:
            host, port = None, None
        if host in ("0.0.0.0", "::", ""):
            host = "127.0.0.1"
        if host:
            port = port or PAC_DEFAULT_PORT
            return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return f"127.0.0.1:{PAC_DEFAULT_PORT}"


def pac_script(host_header=""):
    proxy = pac_proxy(host_header)
    proxy_host = proxy.rsplit(":", 1)[0].strip("[]") if ":" in proxy else proxy
    rules = ["isPlainHostName(host)"]
    seen = set()
    for value in tuple(PAC_BYPASS) + (proxy_host, "*.local", "192.168.*", "10.*"):
        if value in seen:
            continue
        seen.add(value)
        if "*" in value or "?" in value:
            rules.append(f'shExpMatch(host, "{value}")')
        else:
            rules.append(f'host == "{value}"')
    directives = [f"PROXY {proxy}"]
    if PAC_SOCKS:
        directives.append(f"SOCKS5 {proxy}")
    directives.append("DIRECT")
    chain = "; ".join(directives)
    condition = " ||\n        ".join(rules)
    return ("function FindProxyForURL(url, host) {\n"
            f"    if ({condition}) return \"DIRECT\";\n"
            f"    return \"{chain}\";\n"
            "}\n").encode("ascii")


def pac_response(body, method="GET"):
    head = (b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/x-ns-proxy-autoconfig\r\n"
            b"Cache-Control: no-cache, no-store, must-revalidate\r\n"
            b"Pragma: no-cache\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n")
    return head if method == "HEAD" else head + body


def configure_mkcp(mtu=1350, tti=20, uplink=50, downlink=50, port=0,
                   peer=None, with_tcp=False):
    global MKCP_MTU, MKCP_TTI, MKCP_UPLINK, MKCP_DOWNLINK, MKCP_PORT
    global MKCP_PEER, MKCP_WITH_TCP
    if not 576 <= mtu <= 1460 or not 10 <= tti <= 100:
        raise ValueError("invalid mtu/tti")
    if uplink < 1 or downlink < 1 or port < 0:
        raise ValueError("invalid uplink/downlink/port")
    MKCP_MTU = mtu
    MKCP_TTI = tti
    MKCP_UPLINK = uplink
    MKCP_DOWNLINK = downlink
    MKCP_PORT = port
    MKCP_PEER = peer
    MKCP_WITH_TCP = with_tcp


def set_transports(*names):
    global TRANSPORT_NAMES
    TRANSPORT_NAMES = list(names) or None


def create_listener(host, port):
    infos = socket.getaddrinfo(host, port, family=socket.AF_UNSPEC,
                               type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
    last = None
    for family, socktype, proto, _, addr in infos:
        sock = socket.socket(family, socktype, proto)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if SOCK_BUF:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF)
            sock.bind(addr)
            sock.listen(1024)
            return sock
        except OSError as exc:
            last = exc
            sock.close()
    raise last


class H2MuxHPACK:
    static = ((b':authority', b''),
     (b':method', b'GET'),
     (b':method', b'POST'),
     (b':path', b'/'),
     (b':path', b'/index.html'),
     (b':scheme', b'http'),
     (b':scheme', b'https'),
     (b':status', b'200'),
     (b':status', b'204'),
     (b':status', b'206'),
     (b':status', b'304'),
     (b':status', b'400'),
     (b':status', b'404'),
     (b':status', b'500'),
     (b'accept-charset', b''),
     (b'accept-encoding', b'gzip, deflate'),
     (b'accept-language', b''),
     (b'accept-ranges', b''),
     (b'accept', b''),
     (b'access-control-allow-origin', b''),
     (b'age', b''),
     (b'allow', b''),
     (b'authorization', b''),
     (b'cache-control', b''),
     (b'content-disposition', b''),
     (b'content-encoding', b''),
     (b'content-language', b''),
     (b'content-length', b''),
     (b'content-location', b''),
     (b'content-range', b''),
     (b'content-type', b''),
     (b'cookie', b''),
     (b'date', b''),
     (b'etag', b''),
     (b'expect', b''),
     (b'expires', b''),
     (b'from', b''),
     (b'host', b''),
     (b'if-match', b''),
     (b'if-modified-since', b''),
     (b'if-none-match', b''),
     (b'if-range', b''),
     (b'if-unmodified-since', b''),
     (b'last-modified', b''),
     (b'link', b''),
     (b'location', b''),
     (b'max-forwards', b''),
     (b'proxy-authenticate', b''),
     (b'proxy-authorization', b''),
     (b'range', b''),
     (b'referer', b''),
     (b'refresh', b''),
     (b'retry-after', b''),
     (b'server', b''),
     (b'set-cookie', b''),
     (b'strict-transport-security', b''),
     (b'transfer-encoding', b''),
     (b'user-agent', b''),
     (b'vary', b''),
     (b'via', b''),
     (b'www-authenticate', b''))
    huffman_codes = (8184, 8388568, 268435426, 268435427, 268435428, 268435429, 268435430, 268435431, 268435432,
     16777194, 1073741820, 268435433, 268435434, 1073741821, 268435435, 268435436, 268435437, 268435438,
     268435439, 268435440, 268435441, 268435442, 1073741822, 268435443, 268435444, 268435445, 268435446,
     268435447, 268435448, 268435449, 268435450, 268435451, 20, 1016, 1017, 4090, 8185, 21, 248, 2042,
     1018, 1019, 249, 2043, 250, 22, 23, 24, 0, 1, 2, 25, 26, 27, 28, 29, 30, 31, 92, 251, 32764, 32,
     4091, 1020, 8186, 33, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
     110, 111, 112, 113, 114, 252, 115, 253, 8187, 524272, 8188, 16380, 34, 32765, 3, 35, 4, 36, 5, 37,
     38, 39, 6, 116, 117, 40, 41, 42, 7, 43, 118, 44, 8, 9, 45, 119, 120, 121, 122, 123, 32766, 2044,
     16381, 8189, 268435452, 1048550, 4194258, 1048551, 1048552, 4194259, 4194260, 4194261, 8388569,
     4194262, 8388570, 8388571, 8388572, 8388573, 8388574, 16777195, 8388575, 16777196, 16777197,
     4194263, 8388576, 16777198, 8388577, 8388578, 8388579, 8388580, 2097116, 4194264, 8388581, 4194265,
     8388582, 8388583, 16777199, 4194266, 2097117, 1048553, 4194267, 4194268, 8388584, 8388585, 2097118,
     8388586, 4194269, 4194270, 16777200, 2097119, 4194271, 8388587, 8388588, 2097120, 2097121, 4194272,
     2097122, 8388589, 4194273, 8388590, 8388591, 1048554, 4194274, 4194275, 4194276, 8388592, 4194277,
     4194278, 8388593, 67108832, 67108833, 1048555, 524273, 4194279, 8388594, 4194280, 33554412,
     67108834, 67108835, 67108836, 134217694, 134217695, 67108837, 16777201, 33554413, 524274, 2097123,
     67108838, 134217696, 134217697, 67108839, 134217698, 16777202, 2097124, 2097125, 67108840,
     67108841, 268435453, 134217699, 134217700, 134217701, 1048556, 16777203, 1048557, 2097126, 4194281,
     2097127, 2097128, 8388595, 4194282, 4194283, 33554414, 33554415, 16777204, 16777205, 67108842,
     8388596, 67108843, 134217702, 67108844, 67108845, 134217703, 134217704, 134217705, 134217706,
     134217707, 268435454, 134217708, 134217709, 134217710, 134217711, 134217712, 67108846, 1073741823)
    huffman_lengths = (13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28,
     28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6,
     6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
     7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5,
     5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23,
     24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20, 22, 22, 23, 23,
     21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
     26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24, 21,
     21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27,
     26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30)
    huffman_tree = None

    def __init__(self):
        self.dynamic = []
        self.table_size = 4096
        self.used = 0
        if type(self).huffman_tree is None:
            tree = {}
            for symbol, (code, length) in enumerate(zip(self.huffman_codes, self.huffman_lengths)):
                node = tree
                for shift in range(length - 1, -1, -1):
                    node = node.setdefault((code >> shift) & 1, {})
                node[2] = symbol
            type(self).huffman_tree = tree

    def evict(self):
        while self.used > self.table_size:
            name, value = self.dynamic.pop()
            self.used -= len(name) + len(value) + 32

    @staticmethod
    def integer(data, offset, bits):
        if offset >= len(data):
            raise ValueError("truncated HPACK integer")
        mask = (1 << bits) - 1
        value = data[offset] & mask
        offset += 1
        if value == mask:
            shift = 0
            while True:
                if offset >= len(data) or shift > 28:
                    raise ValueError("invalid HPACK integer")
                byte = data[offset]
                offset += 1
                value += (byte & 127) << shift
                if not byte & 128:
                    break
                shift += 7
        return value, offset

    def string(self, data, offset):
        if offset >= len(data):
            raise ValueError("truncated HPACK string")
        huffman = bool(data[offset] & 128)
        size, offset = self.integer(data, offset, 7)
        end = offset + size
        if end > len(data):
            raise ValueError("truncated HPACK string")
        value = data[offset:end]
        if huffman:
            result = bytearray()
            root = self.huffman_tree
            node = root
            tail = 0
            padding = 0
            for byte in value:
                for shift in range(7, -1, -1):
                    bit = (byte >> shift) & 1
                    node = node.get(bit)
                    if node is None:
                        raise ValueError("invalid HPACK Huffman code")
                    tail = (tail << 1) | bit
                    padding += 1
                    symbol = node.get(2)
                    if symbol is not None:
                        if symbol == 256:
                            raise ValueError("HPACK Huffman EOS")
                        result.append(symbol)
                        node = root
                        tail = 0
                        padding = 0
            if padding > 7 or tail != (1 << padding) - 1:
                raise ValueError("invalid HPACK Huffman padding")
            value = bytes(result)
        return value, end

    def entry(self, index):
        if index <= 0 or index > len(self.static) + len(self.dynamic):
            raise ValueError("invalid HPACK index")
        if index <= len(self.static):
            return self.static[index - 1]
        return self.dynamic[index - len(self.static) - 1]

    def decode(self, data):
        result = []
        offset = 0
        total = 0
        while offset < len(data):
            byte = data[offset]
            if byte & 128:
                index, offset = self.integer(data, offset, 7)
                name, value = self.entry(index)
            elif byte & 32 and not byte & 64:
                if result:
                    raise ValueError("late HPACK table update")
                size, offset = self.integer(data, offset, 5)
                if size > 4096:
                    raise ValueError("HPACK table too large")
                self.table_size = size
                self.evict()
                continue
            else:
                indexed = bool(byte & 64)
                index, offset = self.integer(data, offset, 6 if indexed else 4)
                if index:
                    name = self.entry(index)[0]
                else:
                    name, offset = self.string(data, offset)
                value, offset = self.string(data, offset)
                if indexed:
                    self.dynamic.insert(0, (name, value))
                    self.used += len(name) + len(value) + 32
                    self.evict()
            total += len(name) + len(value) + 32
            if total > 65536 or not name or name.lower() != name:
                raise ValueError("invalid H2Mux headers")
            result.append((name.decode("ascii"), value.decode("utf-8")))
        return result

    @staticmethod
    def encode(headers):
        def integer(value):
            if value < 127:
                return bytes([value])
            result = bytearray([127])
            value -= 127
            while value >= 128:
                result.append((value & 127) | 128)
                value >>= 7
            result.append(value)
            return bytes(result)

        result = bytearray()
        for name, value in headers:
            name = name.encode("ascii")
            value = str(value).encode("utf-8")
            result.extend(b"\x00" + integer(len(name)) + name + integer(len(value)) + value)
        return bytes(result)


class H2MuxStream:
    def __init__(self, stream_id, headers, window, receive_window=None):
        self.stream_id = stream_id
        self.headers = headers
        self.reader = asyncio.StreamReader(limit=READER_LIMIT)
        self.send_window = window
        self.receive_window = MUX_WINDOW if receive_window is None else receive_window
        self.credit = 0
        self.send_ready = asyncio.Event()
        self.send_ready.set()
        self.remote_writer = None
        self.task = None
        self.input_ended = False
        self.output_ended = False


class H2Mux:
    def __init__(self, reader, writer, username=None, password=None, authenticated=False, first=b""):
        self.reader = reader
        self.writer = writer
        self.username = username
        self.password = password
        self.authenticated = authenticated
        self.first = first
        self.streams = {}
        self.last_stream = 0
        self.peer_window = 65535
        self.peer_frame_size = MUX_FRAME_SIZE
        self.standard_h2 = False
        self.write_lock = asyncio.Lock()
        self.decoder = H2MuxHPACK()
        self.closed = False

    async def read_frame(self):
        prefix = self.first
        self.first = b""
        raw = prefix + await self.reader.readexactly(9 - len(prefix))
        size = int.from_bytes(raw[:3], "big")
        if size > MUX_FRAME_SIZE:
            raise ValueError("H2Mux frame too large")
        return raw[3], raw[4], int.from_bytes(raw[5:], "big") & 0x7fffffff, await self.reader.readexactly(size)

    @staticmethod
    def frame_bytes(kind, flags, stream_id, data):
        return (len(data).to_bytes(3, "big") + bytes((kind, flags))
                + struct.pack("!I", stream_id) + data)

    async def write_frames(self, frames):
        buf = bytearray()
        for kind, flags, stream_id, data in frames:
            buf.extend(self.frame_bytes(kind, flags, stream_id, data))
        async with self.write_lock:
            if self.closed:
                raise ConnectionError("H2Mux closed")
            self.writer.write(bytes(buf))
            await self.writer.drain()

    async def send_frame(self, kind, flags=0, stream_id=0, data=b""):
        await self.write_frames(((kind, flags, stream_id, data),))

    async def send_headers(self, stream, headers, end=False):
        await self.send_frame(1, 4 | int(end), stream.stream_id, H2MuxHPACK.encode(headers))
        if end:
            stream.output_ended = True

    async def send_data(self, stream, data, end=False):
        offset = 0
        total = len(data)
        while offset < total:
            while stream.send_window <= 0:
                stream.send_ready.clear()
                await stream.send_ready.wait()
            frames = []
            budget = min(total - offset, stream.send_window, RELAY_CHUNK)
            while budget > 0:
                size = min(budget, self.peer_frame_size)
                frames.append((0, 0, stream.stream_id, data[offset:offset + size]))
                offset += size
                budget -= size
                stream.send_window -= size
            await self.write_frames(frames)
        if end and not stream.output_ended:
            await self.send_frame(0, 1, stream.stream_id)
            stream.output_ended = True

    async def release_window(self, stream, size, force=False):
        stream.credit += size
        if not stream.credit or (not force and stream.credit < WINDOW_REFRESH):
            return
        credit = min(stream.credit, 0x7fffffff)
        stream.credit -= credit
        stream.receive_window += credit
        await self.send_frame(8, 0, stream.stream_id, struct.pack("!I", credit))

    async def reset(self, stream_id, code):
        stream = self.streams.pop(stream_id, None)
        if stream is not None:
            stream.reader.feed_eof()
            stream.send_ready.set()
            close_writer(stream.remote_writer)
            if stream.task is not None and stream.task is not asyncio.current_task():
                stream.task.cancel()
                await asyncio.gather(stream.task, return_exceptions=True)
        await self.send_frame(3, 0, stream_id, struct.pack("!I", code))

    def settings(self, payload, handshake=False):
        if len(payload) % 6:
            raise ValueError("invalid H2Mux settings")
        values = dict(struct.iter_unpack("!HI", payload))
        if handshake:
            if values.get(0x42db) != 0xa2e43c8b:
                raise ValueError("invalid H2Mux client magic")
            self.standard_h2 = 4 in values or 5 in values
        if 4 in values:
            window = values[4]
            if window > 0x7fffffff:
                raise ValueError("invalid H2Mux window")
            delta = window - self.peer_window
            self.peer_window = window
            for stream in self.streams.values():
                stream.send_window += delta
                if stream.send_window > 0:
                    stream.send_ready.set()
        if 5 in values:
            size = values[5]
            if not 16384 <= size <= 16777215:
                raise ValueError("invalid H2Mux frame size")
            self.peer_frame_size = min(size, MUX_FRAME_SIZE)

    async def handshake(self):
        settings = b"".join(struct.pack("!HI", key, value) for key, value in (
            (0x42db, 0x1088ebf9), (0xff20, 0), (3, MUX_CONCURRENCY),
            (4, MUX_WINDOW), (5, MUX_FRAME_SIZE),
        ))
        await self.send_frame(4, data=settings)
        kind, flags, stream_id, payload = await self.read_frame()
        if kind != 4 or flags or stream_id:
            raise ValueError("expected H2Mux settings")
        self.settings(payload, handshake=True)
        await self.send_frame(4, 1)
        if self.standard_h2:
            await self.send_frame(8, 0, 0, struct.pack("!I", MUX_CONN_GRANT))
        while True:
            kind, flags, stream_id, payload = await self.read_frame()
            if kind == 8 and not stream_id:
                continue
            if (kind, flags, stream_id, payload) != (4, 1, 0, b""):
                raise ValueError("expected H2Mux settings acknowledgement")
            break

    async def headers(self, flags, stream_id, payload):
        if not stream_id or not stream_id & 1 or stream_id <= self.last_stream:
            raise ValueError("invalid H2Mux stream ID")
        self.last_stream = stream_id
        end = bool(flags & 1)
        if flags & 8:
            if not payload or payload[0] >= len(payload):
                raise ValueError("invalid H2Mux padding")
            payload = payload[1:len(payload) - payload[0]]
        if flags & 32:
            if len(payload) < 5:
                raise ValueError("invalid H2Mux priority")
            payload = payload[5:]
        block = bytearray(payload)
        while not flags & 4:
            kind, flags, next_id, payload = await self.read_frame()
            if kind != 9 or next_id != stream_id:
                raise ValueError("expected H2Mux continuation")
            block.extend(payload)
            if len(block) > 65536:
                raise ValueError("H2Mux header block too large")
        headers = self.decoder.decode(bytes(block))
        if len(self.streams) >= MUX_CONCURRENCY:
            await self.reset(stream_id, 7)
            return
        stream = H2MuxStream(stream_id, headers, self.peer_window, MUX_WINDOW)
        self.streams[stream_id] = stream
        if not self.standard_h2 and MUX_WINDOW > 65535:
            await self.send_frame(8, 0, stream_id, struct.pack("!I", MUX_WINDOW - 65535))
        if end:
            stream.input_ended = True
            stream.reader.feed_eof()
        stream.task = asyncio.create_task(multiplexer(self, stream))

    async def receive_data(self, flags, stream_id, payload):
        if not stream_id:
            raise ValueError("invalid H2Mux DATA stream")
        stream = self.streams.get(stream_id)
        if stream is None:
            await self.reset(stream_id, 5)
            return
        if stream.input_ended:
            await self.reset(stream_id, 5)
            return
        size = len(payload)
        stream.receive_window -= size
        if stream.receive_window < 0:
            await self.reset(stream_id, 3)
            return
        if flags & 8:
            if not payload or payload[0] >= len(payload):
                raise ValueError("invalid H2Mux DATA padding")
            padding = payload[0] + 1
            payload = payload[1:len(payload) - payload[0]]
            stream.receive_window += padding
            await self.send_frame(8, 0, stream_id, struct.pack("!I", padding))
        if payload:
            stream.reader.feed_data(payload)
        if flags & 1:
            stream.input_ended = True
            stream.reader.feed_eof()

    async def run(self):
        try:
            await asyncio.wait_for(self.handshake(), timeout=10)
            while True:
                kind, flags, stream_id, payload = await self.read_frame()
                if kind == 0:
                    await self.receive_data(flags, stream_id, payload)
                elif kind == 1:
                    await self.headers(flags, stream_id, payload)
                elif kind == 3:
                    if not stream_id or len(payload) != 4:
                        raise ValueError("invalid H2Mux reset")
                    stream = self.streams.pop(stream_id, None)
                    if stream is not None:
                        stream.task.cancel()
                        await asyncio.gather(stream.task, return_exceptions=True)
                elif kind == 4:
                    if stream_id or flags & 1 and payload:
                        raise ValueError("invalid H2Mux settings")
                    if not flags & 1:
                        self.settings(payload)
                        await self.send_frame(4, 1)
                elif kind == 6:
                    if stream_id or len(payload) != 8:
                        raise ValueError("invalid H2Mux ping")
                    if not flags & 1:
                        await self.send_frame(6, 1, data=payload)
                elif kind == 7:
                    if stream_id or len(payload) < 8:
                        raise ValueError("invalid H2Mux GOAWAY")
                    break
                elif kind == 8:
                    if len(payload) != 4:
                        raise ValueError("invalid H2Mux window update")
                    increment = int.from_bytes(payload, "big") & 0x7fffffff
                    if not increment:
                        raise ValueError("empty H2Mux window update")
                    if not stream_id:
                        continue
                    stream = self.streams.get(stream_id)
                    if stream is not None:
                        if stream.send_window + increment > 0x7fffffff:
                            await self.reset(stream_id, 3)
                        else:
                            stream.send_window += increment
                            stream.send_ready.set()
                elif kind != 2:
                    raise ValueError("unsupported H2Mux frame")
        except (asyncio.IncompleteReadError, ConnectionError, OSError, TimeoutError):
            pass
        except (ValueError, UnicodeError, struct.error):
            try:
                await self.send_frame(7, data=struct.pack("!II", self.last_stream, 1))
            except (ConnectionError, OSError):
                pass
        finally:
            self.closed = True
            tasks = [stream.task for stream in self.streams.values() if stream.task is not None]
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self.streams.clear()
            close_writer(self.writer)


async def multiplexer(mux, stream):
    remote_writer = None
    tasks = []
    try:
        headers = {}
        regular = False
        for name, value in stream.headers:
            if name.startswith(":"):
                if regular or name in headers:
                    raise ValueError("invalid H2Mux pseudo-header")
            else:
                regular = True
            headers[name] = value
        if mux.username is not None and not mux.authenticated:
            expected = "Basic " + base64.b64encode(f"{mux.username}:{mux.password}".encode()).decode()
            if not secrets.compare_digest(headers.get("proxy-authorization", ""), expected):
                await mux.send_headers(stream, [(':status', '407'), ('proxy-authenticate', 'Basic realm="proxy"')], end=True)
                return
        method = headers.get(":method", "")
        target = headers.get(":authority", headers.get("host", ""))
        if method in ("GET", "HEAD"):
            host, port = split_host_port(target, 80)
            path = headers.get(":path", "/").split("?", 1)[0]
            body = PROBES.get((host.lower(), path))
            if body is None:
                await mux.send_headers(stream, [(":status", "404")], end=True)
                return
            await mux.send_headers(stream, [(":status", "200"), ("content-type", "text/plain; charset=utf-8"), ("content-length", str(len(body))), ("cache-control", "no-cache")])
            await mux.send_data(stream, b"" if method == "HEAD" else body, end=True)
            return
        if method != "CONNECT" or not target:
            await mux.send_headers(stream, [(":status", "400")], end=True)
            return
        host, port = split_host_port(target, 443)
        if not host or not 1 <= port <= 65535:
            raise ValueError("invalid H2Mux target")
        try:
            remote_reader, remote_writer = await open_remote(host, port)
        except (OSError, TimeoutError):
            await mux.send_headers(stream, [(":status", "502")], end=True)
            return
        stream.remote_writer = remote_writer
        await mux.send_headers(stream, [(":status", "200")])

        async def upstream():
            while True:
                data = await stream.reader.read(RELAY_CHUNK)
                if not data:
                    if remote_writer.can_write_eof():
                        remote_writer.write_eof()
                        await remote_writer.drain()
                    await mux.release_window(stream, 0, force=True)
                    break
                remote_writer.write(data)
                await remote_writer.drain()
                await mux.release_window(stream, len(data))

        async def downstream():
            while True:
                data = await remote_reader.read(RELAY_CHUNK)
                if not data:
                    await mux.send_data(stream, b"", end=True)
                    break
                await mux.send_data(stream, data)

        tasks = [asyncio.create_task(upstream()), asyncio.create_task(downstream())]
        await asyncio.gather(*tasks)
    except (ConnectionError, OSError, ValueError):
        if not mux.closed:
            try:
                await mux.reset(stream.stream_id, 2)
            except (ConnectionError, OSError):
                pass
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if mux.streams.get(stream.stream_id) is stream:
            mux.streams.pop(stream.stream_id, None)
        close_writer(remote_writer)
        if remote_writer is not None:
            try:
                await remote_writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def h2mux(reader, writer, username=None, password=None, authenticated=False, first=b""):
    await H2Mux(reader, writer, username, password, authenticated, first).run()


def probe_response(host, path):
    clean_host = host.strip().lower().split(":")[0].strip("[]")
    clean_path = path.split("?")[0] or "/"
    if clean_path.endswith("/generate_204") or clean_path.endswith("/gen_204"):
        return b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    body = PROBES.get((clean_host, clean_path))
    if body is None and clean_host == "connectivity-check.ubuntu.com":
        return b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    if body is None:
        return None
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
        + body
    )


def encode_address(host, port):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raw = host.encode("idna")
        return b"\x03" + bytes([len(raw)]) + raw + struct.pack("!H", port)
    if ip.version == 4:
        return b"\x01" + ip.packed + struct.pack("!H", port)
    return b"\x04" + ip.packed + struct.pack("!H", port)


async def read_address(reader):
    atyp = (await reader.readexactly(1))[0]
    if atyp == 1:
        host = socket.inet_ntoa(await reader.readexactly(4))
    elif atyp == 3:
        size = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(size)).decode("idna")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    else:
        raise ValueError("bad atyp")
    port = struct.unpack("!H", await reader.readexactly(2))[0]
    return host, port


def parse_udp_address(data, offset):
    atyp = data[offset]
    offset += 1
    if atyp == 1:
        host = socket.inet_ntoa(data[offset:offset + 4])
        offset += 4
    elif atyp == 3:
        size = data[offset]
        offset += 1
        host = data[offset:offset + size].decode("idna")
        offset += size
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
        offset += 16
    else:
        raise ValueError("bad atyp")
    port = struct.unpack("!H", data[offset:offset + 2])[0]
    return host, port, offset + 2


async def open_remote(host, port, timeout=20):
    host = resolve_fake_target(host)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, limit=READER_LIMIT), timeout=timeout)
    tune_connection(writer)
    return reader, writer


def close_writer(writer):
    try:
        writer.close()
    except Exception:
        pass


async def relay(reader, writer):
    try:
        while True:
            data = await reader.read(RELAY_CHUNK)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError, asyncio.CancelledError):
        pass
    finally:
        close_writer(writer)


async def half_relay(reader, writer):
    try:
        while True:
            data = await reader.read(RELAY_CHUNK)
            if not data:
                if hasattr(writer, "can_write_eof") and writer.can_write_eof():
                    writer.write_eof()
                    await writer.drain()
                return True
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError, asyncio.CancelledError):
        return False


async def pipe(client_reader, client_writer, remote_reader, remote_writer):
    first = asyncio.create_task(half_relay(client_reader, remote_writer))
    second = asyncio.create_task(half_relay(remote_reader, client_writer))
    done, pending = await asyncio.wait({first, second}, return_when=asyncio.FIRST_COMPLETED)
    graceful = all(task.result() for task in done if not task.cancelled())
    if graceful and pending:
        await asyncio.gather(*pending, return_exceptions=True)
    else:
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
    close_writer(client_writer)
    close_writer(remote_writer)


class UdpPeer(asyncio.DatagramProtocol):
    def __init__(self, owner):
        self.owner = owner
        self.transport = None
        self.client_addr = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if self.owner.transport is None or self.client_addr is None:
            return
        packet = b"\x00\x00\x00" + encode_address(addr[0], addr[1]) + data
        self.owner.transport.sendto(packet, self.client_addr)

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        self.transport = None


class UdpRelay(asyncio.DatagramProtocol):
    def __init__(self, expected_ip):
        self.expected_ip = expected_ip
        self.transport = None
        self.peers = {}
        self.lock = asyncio.Lock()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if self.expected_ip and addr[0] != self.expected_ip:
            local = {"127.0.0.1", "::1"}
            if addr[0] not in local or self.expected_ip not in local:
                return
        if len(data) < 4 or data[0:2] != b"\x00\x00" or data[2] != 0:
            return
        asyncio.ensure_future(self.forward(data, addr))

    async def forward(self, data, client_addr):
        loop = asyncio.get_running_loop()
        try:
            host, port, offset = parse_udp_address(data, 3)
            payload = data[offset:]
            if stun_is_message(payload):
                reply = stun_binding_response(payload, client_addr[0], client_addr[1])
                if reply is not None:
                    self.transport.sendto(b"\x00\x00\x00" + encode_address(host, port) + reply, client_addr)
                return
            host = resolve_fake_target(host)
            infos = await loop.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_DGRAM)
            if not infos:
                return
            infos.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)
            family = infos[0][0]
            sockaddr = infos[0][4]
            key = (sockaddr[0], sockaddr[1])
            async with self.lock:
                peer = self.peers.get(key)
                if peer is None or peer[0].is_closing():
                    transport, protocol = await loop.create_datagram_endpoint(
                        lambda: UdpPeer(self), family=family, remote_addr=sockaddr
                    )
                    peer = (transport, protocol)
                    self.peers[key] = peer
            peer[1].client_addr = client_addr
            peer[0].sendto(payload)
        except Exception:
            pass

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        self.transport = None

    def close(self):
        for transport, protocol in list(self.peers.values()):
            try:
                transport.close()
            except Exception:
                pass
        self.peers.clear()
        if self.transport is not None:
            try:
                self.transport.close()
            except Exception:
                pass
            self.transport = None


async def socks_reply(writer, rep, host="0.0.0.0", port=0):
    writer.write(b"\x05" + bytes([rep, 0]) + encode_address(host, port))
    await writer.drain()


def socks_error_code(exc):
    if isinstance(exc, socket.gaierror):
        return 4
    if isinstance(exc, ConnectionRefusedError):
        return 5
    if isinstance(exc, TimeoutError):
        return 4
    return 1


async def handle_udp_associate(reader, writer):
    loop = asyncio.get_running_loop()
    peer = writer.get_extra_info("peername")
    sockname = writer.get_extra_info("sockname")
    relay_protocol = UdpRelay(peer[0] if peer else None)
    transport, protocol = await loop.create_datagram_endpoint(lambda: relay_protocol, local_addr=("0.0.0.0", 0))
    bound = transport.get_extra_info("sockname")
    bind_host = sockname[0] if sockname and sockname[0] not in ("0.0.0.0", "::") else bound[0]
    try:
        await socks_reply(writer, 0, bind_host, bound[1])
        while await reader.read(RELAY_CHUNK):
            pass
    finally:
        relay_protocol.close()
        close_writer(writer)


class UdpOverTcpPeer(asyncio.DatagramProtocol):
    def __init__(self, writer, write_lock):
        self.writer = writer
        self.write_lock = write_lock
        self.tasks = set()

    def datagram_received(self, data, addr):
        frame = encode_address(addr[0], addr[1]) + data
        task = asyncio.create_task(self.send_frame(frame))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def send_frame(self, frame):
        if self.writer.is_closing():
            return
        try:
            async with self.write_lock:
                self.writer.write(struct.pack("!I", len(frame)) + frame)
                await self.writer.drain()
        except (ConnectionError, OSError):
            pass


async def handle_udp_over_tcp(reader, writer):
    """Serve the ProxyDroid SOCKS5 UDP-over-TCP extension (command 0x80).

    Each stream frame is a four-byte big-endian length followed by a SOCKS
    address and the UDP payload. It is an explicit paired-endpoint extension,
    not a standard SOCKS5 command.
    """
    loop = asyncio.get_running_loop()
    write_lock = asyncio.Lock()
    peers = {}
    try:
        while True:
            header = await reader.readexactly(4)
            size = struct.unpack("!I", header)[0]
            if not 5 <= size <= UDP_OVER_TCP_MAX_FRAME:
                raise ValueError("invalid UDP-over-TCP frame length")
            frame = await reader.readexactly(size)
            host, port, offset = parse_udp_address(frame, 0)
            payload = frame[offset:]
            if len(payload) > 65507:
                continue
            try:
                host = resolve_fake_target(host)
                infos = await loop.getaddrinfo(
                    host, port, family=socket.AF_UNSPEC,
                    type=socket.SOCK_DGRAM)
            except (OSError, ValueError):
                continue
            if not infos:
                continue
            infos.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)
            family, _, _, _, sockaddr = infos[0]
            key = (family, tuple(sockaddr))
            peer = peers.get(key)
            if peer is None or peer[0].is_closing():
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: UdpOverTcpPeer(writer, write_lock),
                    family=family, remote_addr=sockaddr)
                peer = (transport, protocol)
                peers[key] = peer
            peer[0].sendto(payload)
    except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError):
        pass
    finally:
        for transport, protocol in peers.values():
            transport.close()
        for transport, protocol in peers.values():
            pending = list(protocol.tasks)
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)


async def handle_socks5(reader, writer, username, password):
    try:
        nmethods = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(nmethods)
        wanted = 2 if username is not None else 0
        if wanted not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return
        writer.write(bytes([5, wanted]))
        await writer.drain()
        if wanted == 2:
            auth_ver = (await reader.readexactly(1))[0]
            ulen = (await reader.readexactly(1))[0]
            user = (await reader.readexactly(ulen)).decode("utf-8", "ignore")
            plen = (await reader.readexactly(1))[0]
            passwd = (await reader.readexactly(plen)).decode("utf-8", "ignore")
            if auth_ver != 1 or user != username or passwd != password:
                writer.write(b"\x01\x01")
                await writer.drain()
                return
            writer.write(b"\x01\x00")
            await writer.drain()
        header = await reader.readexactly(3)
        if header[0] != 5:
            return
        cmd = header[1]
        host, port = await read_address(reader)
        if cmd == UDP_OVER_TCP_COMMAND:
            await socks_reply(writer, 0)
            await handle_udp_over_tcp(reader, writer)
            return
        if cmd == 3:
            await handle_udp_associate(reader, writer)
            return
        if cmd != 1:
            await socks_reply(writer, 7)
            return
        try:
            remote_reader, remote_writer = await open_remote(host, port)
        except Exception as exc:
            await socks_reply(writer, socks_error_code(exc))
            return
        bound = remote_writer.get_extra_info("sockname")
        if bound:
            await socks_reply(writer, 0, bound[0], bound[1])
        else:
            await socks_reply(writer, 0)
        await pipe(reader, writer, remote_reader, remote_writer)
    except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError):
        pass
    finally:
        close_writer(writer)


async def read_chunked(reader):
    body = bytearray()
    while True:
        line = await reader.readline()
        if not line:
            break
        size = int(line.split(b";")[0].strip() or b"0", 16)
        if size == 0:
            while True:
                trailer = await reader.readline()
                if trailer in (b"\r\n", b"\n", b""):
                    break
            break
        body.extend(await reader.readexactly(size))
        await reader.readexactly(2)
    return bytes(body)


def http_error(writer, code, text, extra=b""):
    body = text.encode()
    writer.write(
        f"HTTP/1.1 {code} {text}\r\n".encode()
        + b"Content-Type: text/plain\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\nConnection: close\r\n"
        + extra
        + b"\r\n"
        + body
    )


def split_host_port(value, default_port):
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        host = value[1:end]
        rest = value[end + 1:]
        return host, int(rest[1:]) if rest.startswith(":") and rest[1:] else default_port
    if value.count(":") == 1:
        host, raw_port = value.rsplit(":", 1)
        return host, int(raw_port) if raw_port else default_port
    return value, default_port


def is_loopback_target(writer, host, port):
    local = writer.get_extra_info("sockname")
    if not local:
        return False
    local_host, local_port = local[0], local[1]
    if port != local_port:
        return False
    if host == local_host:
        return True
    if local_host in ("0.0.0.0", "::") and host in ("127.0.0.1", "localhost", "::1"):
        return True
    if host in ("0.0.0.0", "::") and local_host in ("127.0.0.1", "::1"):
        return True
    return False


async def handle_http(reader, writer, first, username, password, allow_h2mux=True):
    try:
        raw = first + await reader.readuntil(b"\r\n\r\n")
        text = raw.decode("iso-8859-1")
        lines = text.split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) < 2:
            http_error(writer, 400, "Bad Request")
            await writer.drain()
            return
        method = parts[0].upper()
        target = parts[1]
        headers = []
        lookup = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers.append((name.strip(), value.strip()))
            lookup[name.strip().lower()] = value.strip()
        if method in ("GET", "HEAD") and pac_match(target):
            body = pac_script(lookup.get("host", ""))
            writer.write(pac_response(body, method))
            await writer.drain()
            return
        if username is not None:
            expected = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
            if lookup.get("proxy-authorization") != expected:
                http_error(writer, 407, "Proxy Authentication Required", b"Proxy-Authenticate: Basic realm=\"proxy\"\r\n")
                await writer.drain()
                return
        if method == "CONNECT":
            host, port = split_host_port(target, 443)
            if is_loopback_target(writer, host, port):
                http_error(writer, 400, "Bad Request")
                await writer.drain()
                return
            try:
                remote_reader, remote_writer = await open_remote(host, port)
            except Exception:
                http_error(writer, 502, "Bad Gateway")
                await writer.drain()
                return
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await pipe(reader, writer, remote_reader, remote_writer)
            return
        if "://" in target:
            parsed = urlsplit(target)
            host = parsed.hostname or ""
            port = parsed.port or 80
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
        else:
            host, port = split_host_port(lookup.get("host", ""), 80)
            path = target or "/"
        if not host:
            http_error(writer, 400, "Bad Request")
            await writer.drain()
            return
        if is_loopback_target(writer, host, port):
            http_error(writer, 400, "Bad Request")
            await writer.drain()
            return
        if allow_h2mux and lookup.get("upgrade", "").lower() == "h2mux":
            tokens = {value.strip().lower() for value in lookup.get("connection", "").split(",")}
            key = (host.lower(), path.split("?", 1)[0])
            if method != "GET" or "upgrade" not in tokens or key not in PROBES or lookup.get("content-length", "0") != "0" or "transfer-encoding" in lookup:
                http_error(writer, 400, "Bad Request")
                await writer.drain()
                return
            writer.write(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2mux\r\nCache-Control: no-cache\r\n\r\n")
            await writer.drain()
            await h2mux(reader, writer, username, password, authenticated=True)
            return
        if method in ("GET", "HEAD"):
            probe = probe_response(host, path)
            if probe is not None:
                writer.write(probe)
                await writer.drain()
                return
        if "chunked" in lookup.get("transfer-encoding", "").lower():
            body = await read_chunked(reader)
        elif lookup.get("content-length"):
            body = await reader.readexactly(int(lookup["content-length"]))
        else:
            body = b""
        skipped = {"proxy-authorization", "proxy-connection", "connection", "keep-alive", "transfer-encoding", "content-length"}
        out = [f"{method} {path} HTTP/1.1\r\n".encode()]
        has_host = False
        for name, value in headers:
            if name.lower() in skipped:
                continue
            if name.lower() == "host":
                has_host = True
            out.append(f"{name}: {value}\r\n".encode("iso-8859-1"))
        if not has_host:
            out.append(f"Host: {host}:{port}\r\n".encode() if port != 80 else f"Host: {host}\r\n".encode())
        if body or method in ("POST", "PUT", "PATCH"):
            out.append(f"Content-Length: {len(body)}\r\n".encode())
        out.append(b"Connection: close\r\n\r\n")
        out.append(body)
        try:
            remote_reader, remote_writer = await open_remote(host, port)
        except Exception:
            http_error(writer, 502, "Bad Gateway")
            await writer.drain()
            return
        remote_writer.write(b"".join(out))
        await remote_writer.drain()
        await relay(remote_reader, writer)
        close_writer(remote_writer)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, OSError, ValueError):
        pass
    finally:
        close_writer(writer)


async def pac_client(reader, writer, username, password):
    tune_connection(writer)
    try:
        first = await asyncio.wait_for(reader.readexactly(1), timeout=30)
    except Exception:
        close_writer(writer)
        return
    if first == b"\x05":
        await handle_socks5(reader, writer, username, password)
    elif first.isalpha():
        await handle_http(reader, writer, first, username, password, allow_h2mux=False)
    else:
        close_writer(writer)


async def handle_client(reader, writer, username, password):
    tune_connection(writer)
    try:
        first = await asyncio.wait_for(reader.readexactly(1), timeout=30)
    except Exception:
        close_writer(writer)
        return
    if first == b"\x05":
        await handle_socks5(reader, writer, username, password)
    elif first == b"\x00":
        await h2mux(reader, writer, username, password, first=first)
    elif first.isalpha():
        await handle_http(reader, writer, first, username, password)
    else:
        close_writer(writer)


class PseudoTunEndpoint:

    def __init__(self, sock, packet_mode=True, mtu=65535):
        self.socket = sock
        self.packet_mode = packet_mode
        self.mtu = mtu
        self.socket.setblocking(False)
        self.read_lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()
        self.buffer = bytearray()
        self.closed = False

    def fileno(self):
        return self.socket.fileno()

    async def _receive(self, size):
        data = await asyncio.get_running_loop().sock_recv(self.socket, size)
        if not data:
            raise EOFError
        return data

    async def read_packet(self):
        if self.closed:
            raise EOFError
        async with self.read_lock:
            if self.packet_mode:
                packet = await self._receive(self.mtu + 1)
                if len(packet) > self.mtu:
                    raise ValueError("packet exceeds MTU")
                return packet
            while len(self.buffer) < 4:
                self.buffer.extend(await self._receive(65536))
            size = struct.unpack("!I", self.buffer[:4])[0]
            if size < 20 or size > self.mtu:
                self.buffer.clear()
                raise ValueError("invalid packet frame")
            while len(self.buffer) < size + 4:
                self.buffer.extend(await self._receive(min(65536, size + 4 - len(self.buffer))))
            packet = bytes(self.buffer[4:size + 4])
            del self.buffer[:size + 4]
            return packet

    async def write_packet(self, packet):
        if self.closed:
            raise EOFError
        packet = bytes(packet)
        if not 20 <= len(packet) <= self.mtu:
            raise ValueError("invalid packet size")
        data = packet if self.packet_mode else struct.pack("!I", len(packet)) + packet
        async with self.write_lock:
            await asyncio.get_running_loop().sock_sendall(self.socket, data)

    async def read(self):
        return await self.read_packet()

    async def write(self, packet):
        await self.write_packet(packet)

    def close(self):
        if self.closed:
            return
        self.closed = True
        with contextlib.suppress(OSError):
            self.socket.close()


class PseudoTun:

    def __init__(self, mtu=65535):
        packet_mode = True
        try:
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        except (AttributeError, OSError):
            left, right = socket.socketpair()
            packet_mode = False
        for sock in (left, right):
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        self.application = PseudoTunEndpoint(left, packet_mode, mtu)
        self.tunnel = PseudoTunEndpoint(right, packet_mode, mtu)
        self.closed = False

    async def inject(self, packet):
        await self.application.write_packet(packet)

    async def receive(self):
        return await self.application.read_packet()

    def fileno(self):
        return self.application.fileno()

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.application.close()
        self.tunnel.close()


class Socks5ClientError(OSError):
    pass


def parse_proxy_url(value, username=None, password=None):
    raw = value if "://" in value else "socks5://" + value
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in ("socks", "socks5", "socks5h"):
        raise ValueError("only SOCKS5 proxies are supported")
    if not parsed.hostname:
        raise ValueError("proxy host is required")
    user = unquote(parsed.username) if parsed.username is not None else username
    passwd = unquote(parsed.password) if parsed.password is not None else password
    if (user is None) != (passwd is None):
        raise ValueError("proxy username and password must be used together")
    return parsed.hostname, parsed.port or 1080, user, passwd


async def socks5_client_handshake(host, port, username=None, password=None, timeout=20):
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, limit=READER_LIMIT), timeout)
        tune_connection(writer)
        methods = b"\x00\x02" if username is not None else b"\x00"
        writer.write(b"\x05" + bytes([len(methods)]) + methods)
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(2), timeout)
        if reply[0] != 5 or reply[1] == 255:
            raise Socks5ClientError("SOCKS5 authentication method rejected")
        if reply[1] == 2:
            if username is None:
                raise Socks5ClientError("SOCKS5 authentication required")
            user = username.encode("utf-8")
            passwd = password.encode("utf-8")
            if len(user) > 255 or len(passwd) > 255:
                raise ValueError("SOCKS5 credentials are too long")
            writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(passwd)]) + passwd)
            await writer.drain()
            auth = await asyncio.wait_for(reader.readexactly(2), timeout)
            if auth != b"\x01\x00":
                raise Socks5ClientError("SOCKS5 authentication failed")
        elif reply[1] != 0:
            raise Socks5ClientError("unsupported SOCKS5 authentication method")
        return reader, writer
    except Exception:
        if writer is not None:
            close_writer(writer)
        raise


async def socks5_client_request(proxy_host, proxy_port, command, target_host, target_port,
                                username=None, password=None, timeout=20):
    reader, writer = await socks5_client_handshake(
        proxy_host, proxy_port, username, password, timeout)
    try:
        writer.write(b"\x05" + bytes([command, 0]) + encode_address(target_host, target_port))
        await writer.drain()
        header = await asyncio.wait_for(reader.readexactly(3), timeout)
        if header[0] != 5 or header[2] != 0:
            raise Socks5ClientError("invalid SOCKS5 response")
        bound_host, bound_port = await asyncio.wait_for(read_address(reader), timeout)
        if header[1] != 0:
            raise Socks5ClientError(f"SOCKS5 request failed with code {header[1]}")
        return reader, writer, bound_host, bound_port
    except Exception:
        close_writer(writer)
        raise


def internet_checksum(data):
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def transport_checksum(version, source, destination, protocol, data):
    if version == 4:
        pseudo = source + destination + bytes([0, protocol]) + struct.pack("!H", len(data))
    else:
        pseudo = source + destination + struct.pack("!I", len(data)) + b"\x00\x00\x00" + bytes([protocol])
    return internet_checksum(pseudo + data)


def parse_ip_packet(packet):
    if len(packet) < 20:
        raise ValueError("short IP packet")
    version = packet[0] >> 4
    if version == 4:
        header_len = (packet[0] & 15) * 4
        if header_len < 20 or len(packet) < header_len:
            raise ValueError("invalid IPv4 header")
        total = struct.unpack_from("!H", packet, 2)[0]
        if total < header_len or total > len(packet):
            raise ValueError("invalid IPv4 length")
        flags_offset = struct.unpack_from("!H", packet, 6)[0]
        return {
            "version": 4,
            "source": packet[12:16],
            "destination": packet[16:20],
            "protocol": packet[9],
            "payload": packet[header_len:total],
            "header": packet[:header_len],
            "identification": struct.unpack_from("!H", packet, 4)[0],
            "fragment_offset": (flags_offset & 0x1fff) * 8,
            "more_fragments": bool(flags_offset & 0x2000),
            "traffic": packet[1],
        }
    if version == 6:
        if len(packet) < 40:
            raise ValueError("short IPv6 packet")
        size = struct.unpack_from("!H", packet, 4)[0]
        total = 40 + size
        if total > len(packet):
            raise ValueError("invalid IPv6 length")
        protocol = packet[6]
        offset = 40
        while protocol in (0, 43, 60):
            if offset + 2 > total:
                raise ValueError("invalid IPv6 extension")
            following = packet[offset]
            extension_size = (packet[offset + 1] + 1) * 8
            if offset + extension_size > total:
                raise ValueError("invalid IPv6 extension length")
            protocol = following
            offset += extension_size
        if protocol == 44:
            raise ValueError("fragmented IPv6 is not supported")
        return {
            "version": 6,
            "source": packet[8:24],
            "destination": packet[24:40],
            "protocol": protocol,
            "payload": packet[offset:total],
            "header": packet[:offset],
            "identification": 0,
            "fragment_offset": 0,
            "more_fragments": False,
            "traffic": ((packet[0] & 15) << 4) | (packet[1] >> 4),
        }
    raise ValueError("unsupported IP version")


class IPv4Reassembler:

    def __init__(self, timeout=30, maximum=512):
        self.timeout = timeout
        self.maximum = maximum
        self.fragments = {}

    def add(self, info):
        now = time.monotonic()
        for key, value in list(self.fragments.items()):
            if now - value["updated"] > self.timeout:
                self.fragments.pop(key, None)
        key = (info["source"], info["destination"], info["protocol"], info["identification"])
        entry = self.fragments.setdefault(key, {"parts": {}, "header": None, "total": None, "updated": now})
        entry["updated"] = now
        offset = info["fragment_offset"]
        payload = info["payload"]
        if offset + len(payload) > 65535:
            self.fragments.pop(key, None)
            return None
        entry["parts"][offset] = payload
        if offset == 0:
            entry["header"] = info["header"]
        if not info["more_fragments"]:
            entry["total"] = offset + len(payload)
        if len(self.fragments) > self.maximum:
            oldest = min(self.fragments, key=lambda item: self.fragments[item]["updated"])
            self.fragments.pop(oldest, None)
        if entry["header"] is None or entry["total"] is None:
            return None
        cursor = 0
        output = bytearray()
        for start, part in sorted(entry["parts"].items()):
            if start > cursor:
                return None
            overlap = max(0, cursor - start)
            if overlap < len(part):
                output.extend(part[overlap:])
                cursor += len(part) - overlap
            if cursor >= entry["total"]:
                break
        if cursor < entry["total"]:
            return None
        header = bytearray(entry["header"])
        flags = struct.unpack_from("!H", header, 6)[0] & 0x4000
        struct.pack_into("!H", header, 2, len(header) + entry["total"])
        struct.pack_into("!H", header, 6, flags)
        struct.pack_into("!H", header, 10, 0)
        struct.pack_into("!H", header, 10, internet_checksum(bytes(header)))
        self.fragments.pop(key, None)
        return bytes(header) + bytes(output[:entry["total"]])


def parse_tcp_segment(data):
    if len(data) < 20:
        raise ValueError("short TCP segment")
    source_port, destination_port, sequence, acknowledgement, offset_flags, window = struct.unpack_from(
        "!HHIIHH", data, 0)
    header_len = ((offset_flags >> 12) & 15) * 4
    if header_len < 20 or header_len > len(data):
        raise ValueError("invalid TCP header")
    return {
        "source_port": source_port,
        "destination_port": destination_port,
        "sequence": sequence,
        "acknowledgement": acknowledgement,
        "flags": offset_flags & 0x1ff,
        "window": window,
        "options": data[20:header_len],
        "payload": data[header_len:],
    }


def tcp_options(data):
    result = {"mss": None, "window_scale": None, "sack": False, "timestamp": None}
    offset = 0
    while offset < len(data):
        kind = data[offset]
        if kind == 0:
            break
        if kind == 1:
            offset += 1
            continue
        if offset + 2 > len(data):
            break
        size = data[offset + 1]
        if size < 2 or offset + size > len(data):
            break
        value = data[offset + 2:offset + size]
        if kind == 2 and len(value) == 2:
            result["mss"] = struct.unpack("!H", value)[0]
        elif kind == 3 and len(value) == 1:
            result["window_scale"] = min(value[0], 14)
        elif kind == 4 and not value:
            result["sack"] = True
        elif kind == 8 and len(value) == 8:
            result["timestamp"] = struct.unpack("!II", value)
        offset += size
    return result


def sequence_before(left, right):
    return ((left - right) & 0xffffffff) > 0x7fffffff


def sequence_after(left, right):
    return sequence_before(right, left)


def sequence_distance(start, end):
    return (end - start) & 0xffffffff


class TunUdpProtocol(asyncio.DatagramProtocol):

    def __init__(self, owner):
        self.owner = owner
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(self.owner.received(data))

    def error_received(self, exc):
        self.owner.failed = True

    def connection_lost(self, exc):
        self.owner.failed = True


class TunUdpFlow:

    def __init__(self, engine, version, local_address, local_port):
        self.engine = engine
        self.version = version
        self.local_address = local_address
        self.local_port = local_port
        self.reader = None
        self.writer = None
        self.transport = None
        self.protocol = None
        self.monitor = None
        self.lock = asyncio.Lock()
        self.failed = False
        self.closed = False
        self.last_activity = time.monotonic()

    async def connect(self):
        async with self.lock:
            if self.closed:
                raise Socks5ClientError("UDP flow is closed")
            if (self.engine.udp_over_tcp and self.writer is not None and not self.failed) or \
                    (not self.engine.udp_over_tcp and self.transport is not None and not self.failed):
                return
            await self.disconnect()
            if self.engine.udp_over_tcp:
                reader, writer = await socks5_client_handshake(
                    self.engine.proxy_host, self.engine.proxy_port,
                    self.engine.proxy_username, self.engine.proxy_password,
                    self.engine.connect_timeout)
                try:
                    request = (b"\x05" + bytes([UDP_OVER_TCP_COMMAND, 0]) +
                               encode_address("0.0.0.0", 0))
                    writer.write(request)
                    await writer.drain()
                    header = await asyncio.wait_for(
                        reader.readexactly(3), self.engine.connect_timeout)
                    if header[0] != 5 or header[2] != 0:
                        raise Socks5ClientError("invalid UDP-over-TCP response")
                    await asyncio.wait_for(
                        read_address(reader), self.engine.connect_timeout)
                    if header[1] != 0:
                        raise Socks5ClientError(
                            f"SOCKS5 UDP-over-TCP request failed with code {header[1]}")
                except Exception:
                    close_writer(writer)
                    raise
                self.reader = reader
                self.writer = writer
                self.failed = False
                self.monitor = asyncio.create_task(self.watch_stream(reader, writer))
                return

            reader, writer, relay_host, relay_port = await socks5_client_request(
                self.engine.proxy_host, self.engine.proxy_port, 3, "0.0.0.0", 0,
                self.engine.proxy_username, self.engine.proxy_password,
                self.engine.connect_timeout)
            if relay_host in ("0.0.0.0", "::"):
                peer = writer.get_extra_info("peername")
                relay_host = peer[0] if peer else self.engine.proxy_host
            loop = asyncio.get_running_loop()
            try:
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: TunUdpProtocol(self), remote_addr=(relay_host, relay_port))
            except Exception:
                close_writer(writer)
                raise
            tune_udp_socket(transport)
            self.reader = reader
            self.writer = writer
            self.transport = transport
            self.protocol = protocol
            self.failed = False
            self.monitor = asyncio.create_task(self.watch(reader, writer, transport))

    async def watch(self, reader, writer, transport):
        try:
            await reader.read()
        except (ConnectionError, OSError):
            pass
        if self.writer is writer:
            self.failed = True
            if self.transport is transport:
                transport.close()
                self.transport = None
            close_writer(writer)
            self.writer = None
            self.reader = None

    async def watch_stream(self, reader, writer):
        try:
            while self.writer is writer:
                header = await reader.readexactly(4)
                size = struct.unpack("!I", header)[0]
                if not 5 <= size <= UDP_OVER_TCP_MAX_FRAME:
                    raise ValueError("invalid UDP-over-TCP frame length")
                await self.received(await reader.readexactly(size), over_tcp=True)
        except (asyncio.IncompleteReadError, ConnectionError, OSError,
                ValueError, struct.error):
            pass
        if self.writer is writer:
            self.failed = True
            close_writer(writer)
            self.writer = None
            self.reader = None

    async def disconnect(self):
        monitor, self.monitor = self.monitor, None
        if monitor is not None and monitor is not asyncio.current_task():
            monitor.cancel()
        transport, self.transport = self.transport, None
        if transport is not None:
            transport.close()
        writer, self.writer = self.writer, None
        self.reader = None
        if writer is not None:
            close_writer(writer)
        self.failed = False

    async def send(self, destination, destination_port, payload):
        self.last_activity = time.monotonic()
        for attempt in range(2):
            try:
                await self.connect()
                destination = resolve_fake_target(destination)
                if self.engine.udp_over_tcp:
                    frame = encode_address(destination, destination_port) + payload
                    if len(frame) > UDP_OVER_TCP_MAX_FRAME:
                        return
                    self.writer.write(struct.pack("!I", len(frame)) + frame)
                    await self.writer.drain()
                else:
                    packet = b"\x00\x00\x00" + encode_address(destination, destination_port) + payload
                    if len(packet) > 65507:
                        return
                    self.transport.sendto(packet)
                return
            except (ConnectionError, OSError, Socks5ClientError, asyncio.TimeoutError,
                    EOFError, ValueError):
                self.failed = True
                await self.disconnect()
                if attempt:
                    return

    async def received(self, data, over_tcp=False):
        self.last_activity = time.monotonic()
        try:
            if over_tcp:
                host, port, offset = parse_udp_address(data, 0)
            else:
                if len(data) < 4 or data[:3] != b"\x00\x00\x00":
                    return
                host, port, offset = parse_udp_address(data, 3)
            remote = ipaddress.ip_address(host)
            if remote.version != self.version:
                return
            await self.engine.send_udp_packet(
                remote.packed, port, self.local_address, self.local_port, data[offset:])
        except (ValueError, OSError, IndexError, struct.error):
            return

    async def close(self):
        self.closed = True
        await self.disconnect()


class TunDnsProtocol(asyncio.DatagramProtocol):
    def __init__(self, owner):
        self.owner = owner

    def datagram_received(self, data, addr):
        asyncio.create_task(self.owner.received(data))

    def error_received(self, exc):
        self.owner.failed = True

    def connection_lost(self, exc):
        self.owner.transport = None


class TunDnsFlow:
    def __init__(self, engine, version, local_address, local_port, remote_address):
        self.engine = engine
        self.version = version
        self.local_address = local_address
        self.local_port = local_port
        self.remote_address = remote_address
        self.transport = None
        self.failed = False
        self.closed = False
        self.lock = asyncio.Lock()
        self.last_activity = time.monotonic()

    async def connect(self):
        async with self.lock:
            if self.closed:
                raise Socks5ClientError("DNS flow is closed")
            if self.transport is not None and not self.failed:
                return
            await self.disconnect()
            host, port = self.engine.dns_redirect
            if host in ("0.0.0.0", ""):
                host = "127.0.0.1"
            elif host in ("::", "[::]"):
                host = "::1"
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: TunDnsProtocol(self), remote_addr=(host, port))
            self.transport = transport
            self.failed = False

    async def send(self, payload):
        self.last_activity = time.monotonic()
        try:
            await self.connect()
            self.transport.sendto(payload)
        except (ConnectionError, OSError, Socks5ClientError, asyncio.TimeoutError, ValueError):
            self.failed = True
            await self.disconnect()

    async def received(self, data):
        if self.closed:
            return
        self.last_activity = time.monotonic()
        try:
            await self.engine.send_udp_packet(
                self.remote_address, 53, self.local_address, self.local_port, data)
        except (ConnectionError, OSError, ValueError):
            pass

    async def disconnect(self):
        transport, self.transport = self.transport, None
        if transport is not None:
            transport.close()
        self.failed = False

    async def close(self):
        self.closed = True
        await self.disconnect()


class TunTcpFlow:

    def __init__(self, engine, key, info, segment):
        self.engine = engine
        self.key = key
        self.version = info["version"]
        self.local_address = info["source"]
        self.remote_address = info["destination"]
        self.local_port = segment["source_port"]
        self.remote_port = segment["destination_port"]
        self.receive_next = (segment["sequence"] + 1) & 0xffffffff
        self.send_initial = secrets.randbits(32)
        self.send_next = (self.send_initial + 1) & 0xffffffff
        self.send_acked = self.send_initial
        options = tcp_options(segment["options"])
        default_mss = 1220 if self.version == 6 else 536
        self.mss = max(256, min(options["mss"] or default_mss, 1460))
        self.use_window_scale = options["window_scale"] is not None
        self.peer_scale = options["window_scale"] or 0
        self.peer_window = max(segment["window"], self.mss)
        self.use_sack = options["sack"]
        self.use_timestamps = options["timestamp"] is not None
        self.last_peer_timestamp = options["timestamp"][0] if options["timestamp"] else 0
        self.state = "connecting"
        self.reader = None
        self.writer = None
        self.pending = []
        self.out_of_order = {}
        self.out_of_order_size = 0
        self.write_queue = asyncio.Queue()
        self.ready = asyncio.Event()
        self.window_event = asyncio.Event()
        self.window_event.set()
        self.tasks = set()
        self.closed = False
        self.client_finished = False
        self.remote_finished = False
        self.last_activity = time.monotonic()
        self.rto = 1.0
        self.smoothed_rtt = None
        self.rtt_variance = None
        self.tasks.add(asyncio.create_task(self.establish(segment)))
        self.tasks.add(asyncio.create_task(self.retransmit()))

    def track(self, task):
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def current_options(self, syn=False):
        options = bytearray()
        if syn:
            options.extend(b"\x02\x04" + struct.pack("!H", 1220 if self.version == 6 else 1460))
            if self.use_sack:
                options.extend(b"\x04\x02")
            if self.use_window_scale:
                options.extend(b"\x03\x03\x07")
        if self.use_timestamps:
            while len(options) & 3:
                options.append(1)
            options.extend(b"\x08\x0a" + struct.pack("!II", int(time.monotonic() * 1000) & 0xffffffff,
                                                     self.last_peer_timestamp))
        while len(options) & 3:
            options.append(1)
        return bytes(options)

    async def establish(self, first_segment):
        try:
            host = str(ipaddress.ip_address(self.remote_address))
            host = resolve_fake_target(host)
            reader, writer, _, _ = await socks5_client_request(
                self.engine.proxy_host, self.engine.proxy_port, 1, host, self.remote_port,
                self.engine.proxy_username, self.engine.proxy_password,
                self.engine.connect_timeout)
            if self.closed:
                close_writer(writer)
                return
            self.reader = reader
            self.writer = writer
            self.state = "syn-received"
            await self.send_segment(0x12, b"", self.send_initial, True, self.current_options(True))
            self.track(asyncio.create_task(self.write_remote()))
            self.track(asyncio.create_task(self.read_remote()))
            if first_segment["payload"]:
                await self.accept_payload(first_segment["sequence"] + 1,
                                          first_segment["payload"], bool(first_segment["flags"] & 1))
        except (ConnectionError, OSError, asyncio.TimeoutError, ValueError):
            if not self.closed:
                await self.send_reset()
                await self.close()

    async def send_segment(self, flags, payload=b"", sequence=None, tracked=False, options=b""):
        if self.closed:
            return
        sequence = self.send_next if sequence is None else sequence & 0xffffffff
        packet = self.engine.make_tcp_packet(
            self.version, self.remote_address, self.local_address,
            self.remote_port, self.local_port, sequence, self.receive_next,
            flags, 65535, payload, options)
        await self.engine.tun.write_packet(packet)
        self.last_activity = time.monotonic()
        if tracked:
            consumed = len(payload) + (1 if flags & 3 else 0)
            self.pending.append({
                "sequence": sequence,
                "end": (sequence + consumed) & 0xffffffff,
                "packet": packet,
                "sent": time.monotonic(),
                "retries": 0,
            })

    async def send_ack(self):
        await self.send_segment(0x10, b"", self.send_next, False, self.current_options())

    async def send_reset(self):
        with contextlib.suppress(Exception):
            await self.send_segment(0x14, b"", self.send_next, False)

    def update_acknowledgement(self, acknowledgement):
        if sequence_after(acknowledgement, self.send_next):
            return
        if sequence_after(acknowledgement, self.send_acked):
            self.send_acked = acknowledgement
        now = time.monotonic()
        retained = []
        for item in self.pending:
            if not sequence_after(item["end"], acknowledgement):
                if item["retries"] == 0:
                    sample = max(0.001, now - item["sent"])
                    if self.smoothed_rtt is None:
                        self.smoothed_rtt = sample
                        self.rtt_variance = sample / 2
                    else:
                        self.rtt_variance = 0.75 * self.rtt_variance + 0.25 * abs(self.smoothed_rtt - sample)
                        self.smoothed_rtt = 0.875 * self.smoothed_rtt + 0.125 * sample
                    self.rto = min(5.0, max(0.2, self.smoothed_rtt + 4 * self.rtt_variance))
            else:
                retained.append(item)
        self.pending = retained
        self.window_event.set()
        if self.client_finished and self.remote_finished and not self.pending and not self.closed:
            self.track(asyncio.create_task(self.close()))

    async def input(self, segment):
        if self.closed:
            return
        self.last_activity = time.monotonic()
        options = tcp_options(segment["options"])
        if options["timestamp"]:
            self.last_peer_timestamp = options["timestamp"][0]
        if segment["flags"] & 4:
            await self.close()
            return
        if segment["flags"] & 2:
            if self.state == "syn-received" and self.pending:
                await self.engine.tun.write_packet(self.pending[0]["packet"])
            return
        if segment["flags"] & 16:
            self.peer_window = segment["window"] << self.peer_scale
            self.update_acknowledgement(segment["acknowledgement"])
            if self.state == "syn-received" and not sequence_before(
                    segment["acknowledgement"], self.send_initial + 1):
                self.state = "established"
                self.ready.set()
        if self.state not in ("syn-received", "established"):
            return
        if segment["payload"] or segment["flags"] & 1:
            await self.accept_payload(segment["sequence"], segment["payload"], bool(segment["flags"] & 1))

    async def accept_payload(self, sequence, payload, finished):
        sequence &= 0xffffffff
        if sequence_before(sequence, self.receive_next):
            overlap = sequence_distance(sequence, self.receive_next)
            if overlap >= len(payload) + (1 if finished else 0):
                await self.send_ack()
                return
            if overlap < len(payload):
                payload = payload[overlap:]
                sequence = self.receive_next
            else:
                payload = b""
                sequence = self.receive_next
        if sequence != self.receive_next:
            distance = sequence_distance(self.receive_next, sequence)
            if distance <= 4 * 1024 * 1024 and self.out_of_order_size + len(payload) <= 4 * 1024 * 1024:
                previous = self.out_of_order.get(sequence)
                if previous is None or len(payload) > len(previous[0]):
                    if previous is not None:
                        self.out_of_order_size -= len(previous[0])
                    self.out_of_order[sequence] = (payload, finished)
                    self.out_of_order_size += len(payload)
            await self.send_ack()
            return
        await self.consume_payload(payload, finished)
        while self.receive_next in self.out_of_order:
            queued, queued_finished = self.out_of_order.pop(self.receive_next)
            self.out_of_order_size -= len(queued)
            await self.consume_payload(queued, queued_finished)
        await self.send_ack()

    async def consume_payload(self, payload, finished):
        if payload:
            self.receive_next = (self.receive_next + len(payload)) & 0xffffffff
            await self.write_queue.put(payload)
        if finished and not self.client_finished:
            self.receive_next = (self.receive_next + 1) & 0xffffffff
            self.client_finished = True
            await self.write_queue.put(None)
            if self.remote_finished and not self.pending and not self.closed:
                self.track(asyncio.create_task(self.close_after_ack()))

    async def write_remote(self):
        try:
            while not self.closed:
                data = await self.write_queue.get()
                if data is None:
                    if self.writer.can_write_eof():
                        self.writer.write_eof()
                        await self.writer.drain()
                    else:
                        close_writer(self.writer)
                    return
                self.writer.write(data)
                await self.writer.drain()
        except (ConnectionError, OSError):
            if not self.closed:
                await self.send_reset()
                await self.close()

    async def wait_for_window(self):
        while not self.closed:
            in_flight = sequence_distance(self.send_acked, self.send_next)
            allowance = max(0, self.peer_window - in_flight)
            if allowance > 0:
                return min(self.mss, allowance)
            self.window_event.clear()
            try:
                await asyncio.wait_for(self.window_event.wait(), 5)
            except asyncio.TimeoutError:
                await self.send_ack()
        return 0

    async def read_remote(self):
        try:
            await self.ready.wait()
            while not self.closed:
                allowance = await self.wait_for_window()
                if allowance <= 0:
                    return
                data = await self.reader.read(allowance)
                if not data:
                    break
                sequence = self.send_next
                self.send_next = (self.send_next + len(data)) & 0xffffffff
                await self.send_segment(0x18, data, sequence, True, self.current_options())
            if not self.closed and not self.remote_finished:
                self.remote_finished = True
                sequence = self.send_next
                self.send_next = (self.send_next + 1) & 0xffffffff
                await self.send_segment(0x11, b"", sequence, True, self.current_options())
        except (ConnectionError, OSError, asyncio.CancelledError):
            if not self.closed:
                await self.send_reset()
                await self.close()

    async def retransmit(self):
        try:
            while not self.closed:
                await asyncio.sleep(0.1)
                now = time.monotonic()
                if now - self.last_activity > self.engine.tcp_idle_timeout:
                    await self.send_reset()
                    await self.close()
                    return
                for item in list(self.pending):
                    deadline = item["sent"] + min(10.0, self.rto * (2 ** min(item["retries"], 4)))
                    if now < deadline:
                        continue
                    if item["retries"] >= self.engine.retransmit_limit:
                        await self.send_reset()
                        await self.close()
                        return
                    await self.engine.tun.write_packet(item["packet"])
                    item["sent"] = now
                    item["retries"] += 1
                    self.last_activity = now
                    break
        except (ConnectionError, OSError, EOFError, asyncio.CancelledError):
            if not self.closed:
                await self.close()

    async def close_after_ack(self):
        await asyncio.sleep(1)
        await self.close()

    async def close(self):
        if self.closed:
            return
        self.closed = True
        self.state = "closed"
        self.ready.set()
        self.window_event.set()
        self.engine.tcp_flows.pop(self.key, None)
        current = asyncio.current_task()
        for task in list(self.tasks):
            if task is not current:
                task.cancel()
        if self.writer is not None:
            close_writer(self.writer)


class Tun2Socks:

    def __init__(self, tun, proxy, username=None, password=None, connect_timeout=20,
                 tcp_idle_timeout=600, udp_idle_timeout=120, retransmit_limit=8,
                 udp_over_tcp=False, dns_redirect=None):
        if isinstance(tun, PseudoTun):
            tun = tun.tunnel
        self.tun = tun
        self.proxy_host, self.proxy_port, self.proxy_username, self.proxy_password = parse_proxy_url(
            proxy, username, password)
        self.connect_timeout = connect_timeout
        self.tcp_idle_timeout = tcp_idle_timeout
        self.udp_idle_timeout = udp_idle_timeout
        self.retransmit_limit = retransmit_limit
        self.udp_over_tcp = bool(udp_over_tcp)
        self.dns_redirect = dns_redirect
        self.tcp_flows = {}
        self.udp_flows = {}
        self.dns_flows = {}
        self.background_tasks = set()
        self.fragments = IPv4Reassembler()
        self.ip_identification = secrets.randbelow(65536)
        self.running = False
        self.closed = False
        self.cleanup_task = None

    def next_identification(self):
        self.ip_identification = (self.ip_identification + 1) & 0xffff
        return self.ip_identification

    def make_ip_packet(self, version, source, destination, protocol, payload, traffic=0):
        if version == 4:
            header = bytearray(struct.pack(
                "!BBHHHBBH4s4s", 0x45, traffic & 0xff, 20 + len(payload),
                self.next_identification(), 0x4000, 64, protocol, 0, source, destination))
            struct.pack_into("!H", header, 10, internet_checksum(bytes(header)))
            return bytes(header) + payload
        first = (6 << 28) | ((traffic & 0xff) << 20)
        return struct.pack("!IHBB16s16s", first, len(payload), protocol, 64, source, destination) + payload

    def make_tcp_packet(self, version, source, destination, source_port, destination_port,
                        sequence, acknowledgement, flags, window, payload=b"", options=b""):
        if len(options) & 3:
            options += b"\x01" * (4 - (len(options) & 3))
        offset_flags = ((20 + len(options)) // 4 << 12) | (flags & 0x1ff)
        header = bytearray(struct.pack(
            "!HHIIHHHH", source_port, destination_port, sequence & 0xffffffff,
            acknowledgement & 0xffffffff, offset_flags, min(window, 65535), 0, 0) + options)
        checksum = transport_checksum(version, source, destination, 6, bytes(header) + payload)
        struct.pack_into("!H", header, 16, checksum)
        return self.make_ip_packet(version, source, destination, 6, bytes(header) + payload)

    async def send_udp_packet(self, source, source_port, destination, destination_port, payload):
        version = 4 if len(source) == 4 else 6
        length = 8 + len(payload)
        header = bytearray(struct.pack("!HHHH", source_port, destination_port, length, 0))
        checksum = transport_checksum(version, source, destination, 17, bytes(header) + payload)
        struct.pack_into("!H", header, 6, checksum or 0xffff)
        await self.tun.write_packet(
            self.make_ip_packet(version, source, destination, 17, bytes(header) + payload))

    async def handle_tcp(self, info):
        try:
            segment = parse_tcp_segment(info["payload"])
        except ValueError:
            return
        key = (info["version"], info["source"], segment["source_port"],
               info["destination"], segment["destination_port"])
        flow = self.tcp_flows.get(key)
        if flow is None:
            if segment["flags"] & 2 and not segment["flags"] & 16:
                flow = TunTcpFlow(self, key, info, segment)
                self.tcp_flows[key] = flow
            elif not segment["flags"] & 4:
                await self.send_unknown_reset(info, segment)
            return
        await flow.input(segment)

    async def send_unknown_reset(self, info, segment):
        if segment["flags"] & 16:
            sequence = segment["acknowledgement"]
            acknowledgement = 0
            flags = 4
        else:
            sequence = 0
            consumed = len(segment["payload"]) + bool(segment["flags"] & 2) + bool(segment["flags"] & 1)
            acknowledgement = (segment["sequence"] + consumed) & 0xffffffff
            flags = 0x14
        packet = self.make_tcp_packet(
            info["version"], info["destination"], info["source"],
            segment["destination_port"], segment["source_port"], sequence,
            acknowledgement, flags, 0)
        await self.tun.write_packet(packet)

    async def handle_udp(self, info):
        data = info["payload"]
        if len(data) < 8:
            return
        source_port, destination_port, length = struct.unpack_from("!HHH", data, 0)
        if length < 8 or length > len(data):
            return
        payload = data[8:length]
        if destination_port == 53 and self.dns_redirect is not None:
            dns_key = (info["version"], info["source"], source_port,
                       info["destination"])
            dns_flow = self.dns_flows.get(dns_key)
            if dns_flow is None or dns_flow.closed:
                dns_flow = TunDnsFlow(
                    self, info["version"], info["source"], source_port,
                    info["destination"])
                self.dns_flows[dns_key] = dns_flow
            task = asyncio.create_task(dns_flow.send(payload))
            self.background_tasks.add(task)
            task.add_done_callback(self.background_tasks.discard)
            return
        key = (info["version"], info["source"], source_port)
        flow = self.udp_flows.get(key)
        if flow is None or flow.closed:
            flow = TunUdpFlow(self, info["version"], info["source"], source_port)
            self.udp_flows[key] = flow
        destination = str(ipaddress.ip_address(info["destination"]))
        task = asyncio.create_task(flow.send(destination, destination_port, payload))
        self.background_tasks.add(task)
        task.add_done_callback(self.background_tasks.discard)

    async def handle_packet(self, packet):
        try:
            info = parse_ip_packet(packet)
            if info["version"] == 4 and (info["fragment_offset"] or info["more_fragments"]):
                packet = self.fragments.add(info)
                if packet is None:
                    return
                info = parse_ip_packet(packet)
            if info["protocol"] == 6:
                await self.handle_tcp(info)
            elif info["protocol"] == 17:
                await self.handle_udp(info)
        except (ValueError, IndexError, struct.error, OSError):
            return

    async def cleanup(self):
        try:
            while self.running:
                await asyncio.sleep(15)
                now = time.monotonic()
                for key, flow in list(self.udp_flows.items()):
                    if now - flow.last_activity > self.udp_idle_timeout:
                        self.udp_flows.pop(key, None)
                        await flow.close()
                for key, flow in list(self.dns_flows.items()):
                    if now - flow.last_activity > self.udp_idle_timeout:
                        self.dns_flows.pop(key, None)
                        await flow.close()
        except asyncio.CancelledError:
            pass

    async def run(self):
        if self.running:
            raise RuntimeError("tun2socks is already running")
        self.running = True
        self.cleanup_task = asyncio.create_task(self.cleanup())
        try:
            while self.running:
                packet = await self.tun.read_packet()
                await self.handle_packet(packet)
        except (EOFError, ConnectionError, OSError, asyncio.CancelledError):
            pass
        finally:
            await self.close()

    async def close(self):
        if self.closed:
            return
        self.closed = True
        self.running = False
        if self.cleanup_task is not None and self.cleanup_task is not asyncio.current_task():
            self.cleanup_task.cancel()
        flows = list(self.tcp_flows.values())
        datagrams = list(self.udp_flows.values())
        dns_flows = list(self.dns_flows.values())
        self.tcp_flows.clear()
        self.udp_flows.clear()
        self.dns_flows.clear()
        tasks = list(self.background_tasks)
        self.background_tasks.clear()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for flow in flows:
            await flow.close()
        for flow in datagrams:
            await flow.close()
        for flow in dns_flows:
            await flow.close()
        self.tun.close()


async def start_tun2socks(proxy, username=None, password=None, mtu=65535, **options):
    tun = PseudoTun(mtu)
    engine = Tun2Socks(tun.tunnel, proxy, username, password, **options)
    task = asyncio.create_task(engine.run())
    return tun, engine, task


MKCP_ACK = 0
MKCP_DATA = 1
MKCP_TERMINATE = 2
MKCP_PING = 3
MKCP_OPT_CLOSE = 1


def mkcp_segments(buf):
    out = []
    while len(buf) >= 4:
        conv = int.from_bytes(buf[:2], "big")
        cmd, opt = buf[2], buf[3]
        rest = buf[4:]
        if cmd == MKCP_DATA:
            if len(rest) < 14:
                break
            length = int.from_bytes(rest[12:14], "big")
            if len(rest) < 14 + length:
                break
            out.append({"kind": MKCP_DATA, "conv": conv, "opt": opt,
                        "ts": int.from_bytes(rest[0:4], "big"),
                        "num": int.from_bytes(rest[4:8], "big"),
                        "una": int.from_bytes(rest[8:12], "big"),
                        "data": bytes(rest[14:14 + length])})
            buf = rest[14 + length:]
        elif cmd == MKCP_ACK:
            if len(rest) < 13:
                break
            count = rest[12]
            if len(rest) < 13 + count * 4:
                break
            nums = [int.from_bytes(rest[13 + 4 * i:17 + 4 * i], "big")
                    for i in range(count)]
            out.append({"kind": MKCP_ACK, "conv": conv, "opt": opt,
                        "wnd": int.from_bytes(rest[0:4], "big"),
                        "next": int.from_bytes(rest[4:8], "big"),
                        "ts": int.from_bytes(rest[8:12], "big"),
                        "nums": nums})
            buf = rest[13 + count * 4:]
        else:
            if len(rest) < 12:
                break
            out.append({"kind": cmd, "conv": conv, "opt": opt,
                        "una": int.from_bytes(rest[0:4], "big"),
                        "next": int.from_bytes(rest[4:8], "big"),
                        "rto": int.from_bytes(rest[8:12], "big")})
            buf = rest[12:]
    return out


def mkcp_pack_data(conv, opt, ts, num, una, payload):
    return (struct.pack("!HBBIIIH", conv, MKCP_DATA, opt, ts, num, una, len(payload))
            + payload)


def mkcp_pack_ack(conv, opt, wnd, nxt, ts, nums):
    return (struct.pack("!HBBIII", conv, MKCP_ACK, opt, wnd, nxt, ts)
            + bytes((len(nums),))
            + b"".join(struct.pack("!I", n) for n in nums))


def mkcp_pack_cmd(conv, cmd, opt, una, nxt, rto):
    return struct.pack("!HBBIII", conv, cmd, opt, una, nxt, rto)


def _before(n, una):
    return ((n - una) & 0xffffffff) > 0x7fffffff


class MkcpWriter:

    def __init__(self, session):
        self.session = session

    def write(self, data):
        s = self.session
        if s.closed:
            raise ConnectionError("mKCP closed")
        mss = MKCP_MTU - MKCP_DATA_OVERHEAD
        for off in range(0, len(data), mss):
            s.snd_window[s.snd_nxt] = [data[off:off + mss], s.now(), 0, 0]
            s.snd_nxt = (s.snd_nxt + 1) & 0xffffffff

    async def drain(self):
        s = self.session
        while not s.closed and len(s.snd_window) >= s.sending_buffer:
            s.drain_event.clear()
            if len(s.snd_window) < s.sending_buffer:
                break
            try:
                await asyncio.wait_for(s.drain_event.wait(), timeout=30)
            except TimeoutError:
                raise ConnectionError("mKCP flow control stalled")
        if s.closed:
            raise ConnectionError("mKCP closed")

    def close(self):
        self.session.close()

    async def wait_closed(self):
        await self.session.close_event.wait()

    def is_closing(self):
        return self.session.closed

    def can_write_eof(self):
        return False

    def get_extra_info(self, name, default=None):
        if name == "peername":
            return self.session.addr
        if name == "sockname":
            return self.session.hub.local_addr
        return default


class MkcpSession:

    def __init__(self, hub, conv, addr):
        self.hub = hub
        self.conv = conv & 0xffff
        self.addr = addr
        self.start = time.monotonic()
        self.reader = asyncio.StreamReader(limit=READER_LIMIT)
        self.writer = MkcpWriter(self)
        self.closed = False
        self.closing = False
        self.terminating = False
        self.peer_closed = False
        self.last_wall = time.monotonic()
        self.last_ping = 0
        self.snd_nxt = 0
        self.snd_una = 0
        self.snd_window = {}
        self.remote_next = 32
        self.sending_in_flight = self._capacity(MKCP_UPLINK)
        self.sending_buffer = max(16, MKCP_WINDOW_LIMIT // MKCP_MTU)
        self.control_window = self.sending_in_flight
        self.rto = 100
        self.srtt = 0
        self.rttvar = 0
        self.min_rtt = MKCP_TTI
        self.rcv_nxt = 0
        self.rcv_window = {}
        self.receiving_in_flight = self._capacity(MKCP_DOWNLINK)
        self.acklist = {}
        self.drain_event = asyncio.Event()
        self.drain_event.set()
        self.close_event = asyncio.Event()
        self.task = asyncio.create_task(self._updater())

    @staticmethod
    def _capacity(mbps):
        return max(8, mbps * 1024 * 1024 // MKCP_MTU // (1000 // max(1, MKCP_TTI)))

    def now(self):
        return int((time.monotonic() - self.start) * 1000) & 0xffffffff

    def _opt(self):
        return MKCP_OPT_CLOSE if self.terminating else 0

    def _send(self, seg):
        if self.closed:
            return
        self.hub.send(seg, self.addr)

    def _send_cmd(self, cmd):
        self._send(mkcp_pack_cmd(self.conv, cmd, self._opt(),
                                 self.snd_una, self.rcv_nxt, self.rto))

    async def _updater(self):
        try:
            next_tick = time.monotonic()
            while not self.closed:
                delay = max(0.0, next_tick - time.monotonic())
                await asyncio.sleep(delay)
                self.flush()
                next_tick = time.monotonic() + MKCP_TTI / 1000
        except asyncio.CancelledError:
            pass

    def flush(self):
        if self.closed:
            return
        current = self.now()
        if time.monotonic() - self.last_wall > 30:
            self.close()
            return
        self._flush_acks(current)
        self._flush_data(current)
        if (current - self.last_ping) & 0xffffffff >= 3000:
            self._send_cmd(MKCP_PING)
            self.last_ping = current

    def _flush_acks(self, current):
        due = sorted(n for n, v in self.acklist.items() if v[1] <= current)
        if not due:
            return
        gap = max(20, self.rto // 2)
        limit = min(128, (MKCP_MTU - MKCP_ACK_OVERHEAD) // 4)
        for i in range(0, len(due), limit):
            part = due[i:i + limit]
            ts = max(self.acklist[n][0] for n in part)
            self._send(mkcp_pack_ack(self.conv, self._opt(),
                                     self.rcv_nxt + self.receiving_in_flight,
                                     self.rcv_nxt, ts, part))
            for n in part:
                self.acklist[n][1] = current + gap

    def _flush_data(self, current):
        if not self.snd_window:
            return
        cwnd = min(self.sending_in_flight,
                   max(0, self.remote_next - self.snd_una),
                   self.control_window)
        sent = 0
        for num in sorted(self.snd_window):
            if sent and sent >= cwnd:
                break
            seg = self.snd_window[num]
            if seg[3] > current:
                continue
            seg[1] = current
            seg[3] = current + self.rto
            seg[2] += 1
            self._send(mkcp_pack_data(self.conv, self._opt(), current,
                                      num, self.snd_una, seg[0]))
            sent += 1

    def input(self, segments):
        self.last_wall = time.monotonic()
        current = self.now()
        for seg in segments:
            if seg["conv"] != self.conv or self.closed:
                break
            kind = seg["kind"]
            if kind == MKCP_DATA:
                self._acklist_clear(seg["una"])
                idx = (seg["num"] - self.rcv_nxt) & 0xffffffff
                if idx >= self.receiving_in_flight:
                    continue
                if seg["num"] not in self.acklist:
                    self.acklist[seg["num"]] = [seg["ts"], 0]
                if seg["num"] not in self.rcv_window:
                    self.rcv_window[seg["num"]] = seg["data"]
                self._deliver()
            elif kind == MKCP_ACK:
                if seg["wnd"] > self.remote_next:
                    self.remote_next = seg["wnd"]
                self._clear_snd(seg["next"])
                for num in seg["nums"]:
                    if self.snd_window.pop(num, None) is not None:
                        self._update_rto((current - seg["ts"]) & 0xffffffff, current)
                self._refresh_una()
                self.drain_event.set()
            else:
                if kind == MKCP_TERMINATE:
                    self._peer_eof()
                self._clear_snd(seg["next"])
                self._acklist_clear(seg["una"])
                self.drain_event.set()

    def _deliver(self):
        while self.rcv_nxt in self.rcv_window:
            data = self.rcv_window.pop(self.rcv_nxt)
            self.rcv_nxt = (self.rcv_nxt + 1) & 0xffffffff
            if data and not self.reader.at_eof():
                self.reader.feed_data(data)

    def _peer_eof(self):
        if not self.peer_closed:
            self.peer_closed = True
            self.reader.feed_eof()

    def _clear_snd(self, una):
        for num in list(self.snd_window):
            if _before(num, una):
                del self.snd_window[num]
        self._refresh_una()
        self.drain_event.set()

    def _acklist_clear(self, una):
        for num in list(self.acklist):
            if _before(num, una):
                del self.acklist[num]

    def _refresh_una(self):
        self.snd_una = min(self.snd_window) if self.snd_window else self.snd_nxt

    def _update_rto(self, rtt, current):
        if rtt > 0x7fffffff:
            return
        if self.srtt == 0:
            self.srtt, self.rttvar = rtt, rtt // 2
        else:
            delta = abs(rtt - self.srtt)
            self.rttvar = (3 * self.rttvar + delta) // 4
            self.srtt = (7 * self.srtt + rtt) // 8
            self.srtt = max(self.srtt, self.min_rtt)
        rto = self.srtt + (4 * self.rttvar if self.min_rtt < 4 * self.rttvar
                           else self.rttvar)
        self.rto = max(MKCP_TTI, min(rto, 10000) * 5 // 4)

    def close(self):
        if self.closed or self.closing:
            return
        self.closing = True
        asyncio.create_task(self._terminate_later())

    async def _terminate_later(self):
        deadline = time.monotonic() + 30
        while not self.closed and time.monotonic() < deadline and self.snd_window:
            await asyncio.sleep(MKCP_TTI / 1000)
        if self.closed:
            return
        self.terminating = True
        self._send_cmd(MKCP_TERMINATE)
        self.last_ping = self.now()
        for _ in range(15):
            if self.closed:
                return
            await asyncio.sleep(0.2)
            self._send_cmd(MKCP_TERMINATE)
        self._finish()

    def _finish(self):
        if self.closed:
            return
        self.closed = True
        self.task.cancel()
        if not self.reader.at_eof():
            self.reader.feed_eof()
        self.drain_event.set()
        self.close_event.set()
        self.hub.remove(self.conv, self)


def tune_udp_socket(transport):
    sock = transport.get_extra_info("socket")
    if sock is None:
        return
    size = SOCK_BUF or (4 * 1024 * 1024)
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, size)
        except OSError:
            pass


class MkcpServerProtocol(asyncio.DatagramProtocol):

    def __init__(self, handler, username=None, password=None):
        self.handler = handler or (lambda r, w: handle_client(r, w, username, password))
        self.transport = None
        self.local_addr = None
        self.sessions = {}

    def connection_made(self, transport):
        self.transport = transport
        self.local_addr = transport.get_extra_info("sockname")

    def datagram_received(self, data, addr):
        segs = mkcp_segments(data)
        if not segs:
            return
        key = (addr, segs[0]["conv"])
        session = self.sessions.get(key)
        if session is None:
            if segs[0]["kind"] == MKCP_TERMINATE:
                return
            session = MkcpSession(self, key[1], addr)
            self.sessions[key] = session
            asyncio.create_task(self.handler(session.reader, session.writer))
        session.input(segs)

    def send(self, data, addr=None):
        try:
            self.transport.sendto(data, addr)
        except (AttributeError, OSError):
            pass

    def remove(self, conv, session):
        for key, value in list(self.sessions.items()):
            if value is session:
                self.sessions.pop(key, None)

    def error_received(self, exc):
        pass


class MkcpClientProtocol(asyncio.DatagramProtocol):

    def __init__(self, peer):
        self.peer = peer
        self.transport = None
        self.local_addr = None
        self.sessions = {}
        self.next_conv = secrets.randbelow(0x10000)

    def connection_made(self, transport):
        self.transport = transport
        self.local_addr = transport.get_extra_info("sockname")

    def datagram_received(self, data, addr):
        segs = mkcp_segments(data)
        if not segs:
            return
        session = self.sessions.get(segs[0]["conv"])
        if session is not None:
            session.input(segs)

    def send(self, data, addr=None):
        try:
            self.transport.sendto(data)
        except (AttributeError, OSError):
            pass

    def new_session(self):
        conv = self.next_conv
        self.next_conv = (self.next_conv + 1) & 0xffff
        session = MkcpSession(self, conv, self.peer)
        self.sessions[conv] = session
        session._send_cmd(MKCP_PING)
        return session

    def remove(self, conv, session):
        if self.sessions.get(conv) is session:
            self.sessions.pop(conv, None)

    def error_received(self, exc):
        pass


PRINT_CERT = False
UTLS_ALPN = ("h2", "http/1.1")
TLS_COMMON_NAME = "localhost"
TLS_VALID_DAYS = 365
TLS_HANDSHAKE_TIMEOUT = 20

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
           0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def configure_tls(print_cert=False):
    global PRINT_CERT
    PRINT_CERT = bool(print_cert)


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P256_P == 0:
            return None
        lam = (3 * x1 * x1 - 3) * pow(2 * y1, -1, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    return x3, (lam * (x1 - x3) - y1) % _P256_P


def _ec_mul(k, point=_P256_G):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def _ecdsa_sign(digest_int, d):
    while True:
        k = secrets.randbelow(_P256_N - 1) + 1
        r = _ec_mul(k)[0] % _P256_N
        if r == 0:
            continue
        s = pow(k, -1, _P256_N) * (digest_int + r * d) % _P256_N
        if s:
            return r, s


def _der_len(length):
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der(tag, content=b""):
    return bytes([tag]) + _der_len(len(content)) + content


def _der_int(value):
    return _der(0x02, value.to_bytes((value.bit_length() + 8) // 8, "big"))


def _der_oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for arc in parts[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body += bytes(reversed(chunk))
    return _der(0x06, bytes(body))


def _der_time(moment):
    return _der(0x17, moment.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def _der_ext(oid, value, critical=False):
    body = _der_oid(oid) + (_der(0x01, b"\xff") if critical else b"") + _der(0x04, value)
    return _der(0x30, body)


def _pem(label, der):
    body = base64.b64encode(der).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    text = "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(lines), label)
    return text.encode("ascii")


def generate_tls_material(common_name=TLS_COMMON_NAME, days=TLS_VALID_DAYS):
    d = secrets.randbelow(_P256_N - 1) + 1
    qx, qy = _ec_mul(d)
    point = b"\x04" + qx.to_bytes(32, "big") + qy.to_bytes(32, "big")

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    not_before = now - datetime.timedelta(minutes=5)
    not_after = now + datetime.timedelta(days=days)

    name = _der(0x30, _der(0x31, _der(0x30, _der_oid("2.5.4.3") +
                                      _der(0x0C, common_name.encode("utf-8")))))
    sig_alg = _der(0x30, _der_oid("1.2.840.10045.4.3.2"))
    spki = _der(0x30,
                _der(0x30, _der_oid("1.2.840.10045.2.1") + _der_oid("1.2.840.10045.3.1.7")) +
                _der(0x03, b"\x00" + point))
    extensions = _der(0xA3, _der(0x30,
        _der_ext("2.5.29.19", _der(0x30), critical=True) +
        _der_ext("2.5.29.15", b"\x03\x02\x07\x80", critical=True) +
        _der_ext("2.5.29.37", _der(0x30, _der_oid("1.3.6.1.5.5.7.3.1"))) +
        _der_ext("2.5.29.17", _der(0x30,
                                   _der(0x82, common_name.encode("ascii")) +
                                   _der(0x87, bytes([127, 0, 0, 1]))))))

    serial = secrets.randbits(63) | 1
    tbs = _der(0x30,
               _der(0xA0, _der_int(2)) +
               _der_int(serial) +
               sig_alg + name +
               _der(0x30, _der_time(not_before) + _der_time(not_after)) +
               name + spki + extensions)
    r, s = _ecdsa_sign(int.from_bytes(hashlib.sha256(tbs).digest(), "big"), d)
    cert_der = _der(0x30, tbs + sig_alg +
                    _der(0x03, b"\x00" + _der(0x30, _der_int(r) + _der_int(s))))

    ec_key = _der(0x30,
                  _der_int(1) +
                  _der(0x04, d.to_bytes(32, "big")) +
                  _der(0xA0, _der_oid("1.2.840.10045.3.1.7")) +
                  _der(0xA1, _der(0x03, b"\x00" + point)))
    return _pem("CERTIFICATE", cert_der), _pem("EC PRIVATE KEY", ec_key)


_TLS_MATERIAL = None


def get_tls_material():
    global _TLS_MATERIAL
    if _TLS_MATERIAL is None:
        _TLS_MATERIAL = generate_tls_material()
    return _TLS_MATERIAL


def tls_server_context():
    cert_pem, key_pem = get_tls_material()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    paths = []
    try:
        for label, data in (("cert", cert_pem), ("key", key_pem)):
            fd, path = tempfile.mkstemp(prefix="proxy-" + label + "-", suffix=".pem")
            paths.append(path)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        ctx.load_cert_chain(certfile=paths[0], keyfile=paths[1])
    finally:
        for path in paths:
            with contextlib.suppress(OSError):
                os.remove(path)
    return ctx


def utls_client_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(list(UTLS_ALPN))
    return ctx


class TLSConnection:
    transport = None

    def __init__(self, raw_reader, raw_writer, sslobj, incoming, outgoing):
        self._raw_reader = raw_reader
        self._raw_writer = raw_writer
        self._ssl = sslobj
        self._in = incoming
        self._out = outgoing
        self.reader = asyncio.StreamReader(limit=READER_LIMIT)
        self._closed = False
        self._pump_task = None

    async def _flush(self):
        data = self._out.read()
        if data:
            self._raw_writer.write(data)
            await self._raw_writer.drain()

    async def _handshake(self):
        while True:
            try:
                self._ssl.do_handshake()
                break
            except ssl.SSLWantReadError:
                await self._flush()
                data = await self._raw_reader.read(65536)
                if not data:
                    raise ConnectionError("TLS handshake: stream closed")
                self._in.write(data)
        await self._flush()
        self._pump_task = asyncio.create_task(self._pump())

    def _feed(self):
        while True:
            try:
                chunk = self._ssl.read(65536)
            except ssl.SSLWantReadError:
                return True
            except ssl.SSLZeroReturnError:
                return False
            if not chunk:
                return False
            self.reader.feed_data(chunk)

    async def _pump(self):
        try:
            while True:
                data = await self._raw_reader.read(65536)
                if not data:
                    break
                self._in.write(data)
                more = self._feed()
                await self._flush()
                if not more:
                    break
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            self.reader.feed_eof()

    def write(self, data):
        if self._closed:
            raise ConnectionError("TLS connection closed")
        self._ssl.write(data)

    def writelines(self, chunks):
        for chunk in chunks:
            self.write(chunk)

    async def drain(self):
        await self._flush()

    def close(self):
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(ssl.SSLError, OSError, ValueError):
            self._ssl.unwrap()
        data = self._out.read()
        if data:
            with contextlib.suppress(ConnectionError, OSError):
                self._raw_writer.write(data)
        if self._pump_task is not None and not self._pump_task.done():
            self._pump_task.cancel()
        self.reader.feed_eof()
        self._raw_writer.close()

    async def wait_closed(self):
        await self._raw_writer.wait_closed()

    def is_closing(self):
        return self._closed or self._raw_writer.is_closing()

    def can_write_eof(self):
        return False

    def version(self):
        return self._ssl.version()

    def get_extra_info(self, name, default=None):
        return self._raw_writer.get_extra_info(name, default)


async def tls_handshake(raw_reader, raw_writer, context, server_side):
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    sslobj = context.wrap_bio(incoming, outgoing, server_side=server_side,
                              server_hostname=None if server_side else TLS_COMMON_NAME)
    conn = TLSConnection(raw_reader, raw_writer, sslobj, incoming, outgoing)
    await asyncio.wait_for(conn._handshake(), timeout=TLS_HANDSHAKE_TIMEOUT)
    return conn


def tls_server_handler(handler, context):
    async def tls_handler(reader, writer):
        try:
            conn = await tls_handshake(reader, writer, context, server_side=True)
        except Exception:
            close_writer(writer)
            return
        try:
            await handler(conn.reader, conn)
        finally:
            conn.close()
    return tls_handler


DNS_ENABLED = False
FAKE_IP_ENABLED = False
DNS_HOST = "127.0.0.1"
DNS_PORT = 1053
DNS_UPSTREAM = ("1.1.1.1", 53)
DNS_TIMEOUT = 3
FAKE_IP_NETWORK = ipaddress.ip_network("198.18.0.0/15")
FAKE_IP_RANGE = "198.18.0.0/15"
FAKE_IP_TTL = 1
FAKE_IP_MAX = 65536
FAKE_IP_BYPASS = ("localhost", "*.localhost", "*.local", "*.lan", "*.localdomain",
                  "*.home.arpa", "*.internal")
FAKE_POOL = None


class FakeIPPool:

    def __init__(self, network, max_entries=FAKE_IP_MAX):
        self.first = int(network.network_address) + 1
        self.slots = min(max_entries, network.num_addresses - 2)
        self.next = 0
        self.by_name = {}
        self.by_ip = {}

    def allocate(self, name):
        ip = self.by_name.get(name)
        if ip is not None:
            return ip
        ip_int = self.first + self.next % self.slots
        self.next += 1
        old_name = self.by_ip.pop(ip_int, None)
        if old_name is not None:
            self.by_name.pop(old_name, None)
        ip = ipaddress.IPv4Address(ip_int)
        self.by_name[name] = ip
        self.by_ip[ip_int] = name
        return ip

    def lookup(self, ip):
        return self.by_ip.get(int(ipaddress.IPv4Address(ip)))


def configure_dns(enabled=False, fake_ip=False, host="127.0.0.1", port=1053,
                  upstream=("1.1.1.1", 53), fake_range="198.18.0.0/15"):
    global DNS_ENABLED, FAKE_IP_ENABLED, DNS_HOST, DNS_PORT, DNS_UPSTREAM
    global FAKE_IP_NETWORK, FAKE_IP_RANGE, FAKE_POOL
    network = ipaddress.ip_network(fake_range, strict=False)
    if network.version != 4 or network.prefixlen > 30:
        raise ValueError("--fake-ip-range must be IPv4 with prefix /30 or wider")
    if not 1 <= port <= 65535:
        raise ValueError("--dns-port must be 1..65535")
    DNS_ENABLED = bool(enabled or fake_ip)
    FAKE_IP_ENABLED = bool(fake_ip)
    DNS_HOST = host
    DNS_PORT = port
    DNS_UPSTREAM = tuple(upstream)
    FAKE_IP_NETWORK = network
    FAKE_IP_RANGE = str(network)
    FAKE_POOL = FakeIPPool(network) if FAKE_IP_ENABLED else None


def resolve_fake_target(host):
    if FAKE_POOL is None or not isinstance(host, str):
        return host
    try:
        addr = ipaddress.IPv4Address(host)
    except ValueError:
        return host
    if addr not in FAKE_IP_NETWORK:
        return host
    name = FAKE_POOL.lookup(addr)
    return host if name is None else name


def dns_parse_question(data):
    if len(data) < 12:
        return None
    flags, qdcount = struct.unpack(">HH", data[2:6])
    if flags & 0x8000 or qdcount != 1:
        return None
    pos, labels = 12, []
    while True:
        if pos >= len(data):
            return None
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length > 63:
            return None
        label = data[pos + 1:pos + 1 + length]
        if len(label) != length:
            return None
        try:
            labels.append(label.decode("ascii").lower())
        except UnicodeDecodeError:
            return None
        pos += 1 + length
    if pos + 4 > len(data):
        return None
    qtype, qclass = struct.unpack(">HH", data[pos:pos + 4])
    return ".".join(labels), qtype, qclass, pos + 4


def dns_is_fake_name(name):
    if not FAKE_IP_ENABLED or "." not in name:
        return False
    return not any(fnmatch.fnmatch(name, pattern) for pattern in FAKE_IP_BYPASS)


def dns_build_response(query, end, rcode=0, answer=None):
    query_flags = struct.unpack(">H", query[2:4])[0]
    flags = 0x8000 | 0x0080 | (query_flags & 0x0100) | rcode
    records = b""
    if answer is not None:
        records = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, FAKE_IP_TTL, 4) + answer.packed
    header = query[:2] + struct.pack(">HHHHH", flags, 1, 1 if answer is not None else 0, 0, 0)
    return header + query[12:end] + records


class DnsUpstreamOnce(asyncio.DatagramProtocol):
    def __init__(self, query_id, future):
        self.query_id = query_id
        self.future = future

    def datagram_received(self, data, addr):
        if data[:2] == self.query_id and not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc):
        if not self.future.done():
            self.future.set_exception(exc)

    def connection_lost(self, exc):
        if not self.future.done():
            self.future.set_exception(ConnectionError("DNS upstream closed"))


async def dns_forward(query):
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: DnsUpstreamOnce(query[:2], future), remote_addr=DNS_UPSTREAM)
    try:
        transport.sendto(query)
        return await asyncio.wait_for(future, DNS_TIMEOUT)
    finally:
        transport.close()


class DnsServerProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.ensure_future(self.answer(data, addr))

    def send(self, data, addr):
        if self.transport is not None:
            self.transport.sendto(data, addr)

    async def answer(self, query, addr):
        parsed = dns_parse_question(query)
        if parsed is not None:
            name, qtype, qclass, end = parsed
            if FAKE_POOL is not None and qclass == 1 and dns_is_fake_name(name):
                if qtype == 1:
                    self.send(dns_build_response(query, end, answer=FAKE_POOL.allocate(name)), addr)
                    return
                if qtype == 28:
                    self.send(dns_build_response(query, end), addr)
                    return
        try:
            reply = await dns_forward(query)
        except OSError:
            if parsed is None:
                return
            reply = dns_build_response(query, parsed[3], rcode=2)
        self.send(reply, addr)

    def error_received(self, exc):
        pass


STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020


def stun_is_message(data):
    return len(data) >= 20 and (data[0] & 0xC0) == 0 and \
        int.from_bytes(data[4:8], "big") == STUN_MAGIC_COOKIE


def stun_binding_response(data, client_ip, client_port):
    if int.from_bytes(data[:2], "big") != STUN_BINDING_REQUEST:
        return None
    txid = data[8:20]
    xport = client_port ^ (STUN_MAGIC_COOKIE >> 16)
    xaddr = int(ipaddress.IPv4Address(client_ip)) ^ STUN_MAGIC_COOKIE
    value = struct.pack(">BBHI", 0, 1, xport, xaddr)
    attr = struct.pack(">HH", STUN_ATTR_XOR_MAPPED_ADDRESS, len(value)) + value
    return struct.pack(">HHI", STUN_BINDING_SUCCESS, len(attr), STUN_MAGIC_COOKIE) + txid + attr


TRANSPORTS = {}


def register_transport(name):
    def decorator(fn):
        if name in TRANSPORTS:
            raise ValueError("transport already registered: " + name)
        TRANSPORTS[name] = fn
        return fn
    return decorator


def get_transport(name):
    try:
        return TRANSPORTS[name]
    except KeyError:
        raise ValueError("transport not registered: " + name) from None


def select_transports(names=None):
    if names is not None:
        resolved = list(names)
    elif TRANSPORT_NAMES is not None:
        resolved = list(TRANSPORT_NAMES)
    elif MKCP_PEER:
        resolved = ["mkcp-bridge"]
    else:
        resolved = ["mkcp", "tcp"] if MKCP_WITH_TCP else ["mkcp", "pac"]
    if "tcp" in resolved and "pac" in resolved:
        resolved = [name for name in resolved if name != "pac"]
    if DNS_ENABLED and "dns" not in resolved:
        resolved.append("dns")
    return resolved


class Transport:
    def __init__(self, name, servers=(), datagrams=()):
        self.name = name
        self.servers = list(servers)
        self.datagrams = list(datagrams)

    def close(self):
        for srv in self.servers:
            srv.close()
        for udp in self.datagrams:
            udp.close()


def open_mkcp_stream(protocol):
    session = protocol.new_session()
    return session.reader, session.writer


@register_transport("tcp")
async def tcp_transport(host, port, handler, username=None, password=None):
    if SOCK_BUF:
        server = await asyncio.start_server(
            handler, sock=create_listener(host, port), limit=READER_LIMIT)
    else:
        server = await asyncio.start_server(handler, host, port,
                                            limit=READER_LIMIT)
    print(f"SOCKS5/HTTP proxy listening on {host}:{port} "
          f"(chunk={RELAY_CHUNK}, frame={MUX_FRAME_SIZE}, window={MUX_WINDOW}, "
          f"streams={MUX_CONCURRENCY})", flush=True)
    return Transport("tcp", servers=[server])


@register_transport("pac")
async def pac_transport(host, port, handler, username=None, password=None):
    pac_handler = lambda r, w: pac_client(r, w, username, password)
    if SOCK_BUF:
        server = await asyncio.start_server(
            pac_handler, sock=create_listener(host, port), limit=READER_LIMIT)
    else:
        server = await asyncio.start_server(pac_handler, host, port,
                                            limit=READER_LIMIT)
    print(f"PAC endpoint http://{host}:{port}{PAC_PATHS[0]} "
          f"(paths={','.join(PAC_PATHS)})", flush=True)
    return Transport("pac", servers=[server])


@register_transport("dns")
async def dns_transport(host, port, handler, username=None, password=None):
    loop = asyncio.get_running_loop()
    udp, proto = await loop.create_datagram_endpoint(
        DnsServerProtocol, local_addr=(DNS_HOST, DNS_PORT))
    mode = f"fake-ip {FAKE_IP_RANGE}" if FAKE_IP_ENABLED else "forward only"
    print(f"DNS server listening on udp://{DNS_HOST}:{DNS_PORT} "
          f"({mode}, upstream={DNS_UPSTREAM[0]}:{DNS_UPSTREAM[1]})", flush=True)
    return Transport("dns", datagrams=[udp])


@register_transport("mkcp")
async def mkcp_transport(host, port, handler, username=None, password=None):
    loop = asyncio.get_running_loop()
    udp_port = MKCP_PORT or port
    context = tls_server_context()
    if PRINT_CERT:
        print(get_tls_material()[0].decode("ascii").rstrip(), flush=True)
    udp, proto = await loop.create_datagram_endpoint(
        lambda: MkcpServerProtocol(tls_server_handler(handler, context), username, password),
        local_addr=(host, udp_port))
    tune_udp_socket(udp)
    print(f"mKCP/H2Mux listening on udp://{host}:{udp_port} "
          f"(mtu={MKCP_MTU}, tti={MKCP_TTI}ms, up={MKCP_UPLINK}MB/s, "
          f"down={MKCP_DOWNLINK}MB/s, plain)", flush=True)
    return Transport("mkcp", datagrams=[udp])


@register_transport("mkcp-bridge")
async def mkcp_bridge_transport(host, port, handler, username=None, password=None):
    loop = asyncio.get_running_loop()
    if not MKCP_PEER:
        raise ValueError("configure_mkcp(peer=...) is required")
    peer_host, peer_port = split_host_port(MKCP_PEER, port)
    holder = {}

    async def bridge_client(reader, writer):
        tune_connection(writer)
        kcp_reader, kcp_writer = open_mkcp_stream(holder["proto"])
        try:
            tls = await tls_handshake(kcp_reader, kcp_writer, utls_client_context(),
                                      server_side=False)
        except Exception:
            close_writer(kcp_writer)
            close_writer(writer)
            return
        try:
            await pipe(reader, writer, tls.reader, tls)
        finally:
            tls.close()
            kcp_writer.close()

    udp, proto = await loop.create_datagram_endpoint(
        lambda: MkcpClientProtocol((peer_host, peer_port)),
        remote_addr=(peer_host, peer_port))
    tune_udp_socket(udp)
    holder["proto"] = proto
    bridge = await asyncio.start_server(bridge_client, host, port,
                                        limit=READER_LIMIT)
    print(f"mKCP bridge {host}:{port} (TCP) -> "
          f"{peer_host}:{peer_port} (UDP/plain mKCP)", flush=True)
    return Transport("mkcp-bridge", servers=[bridge], datagrams=[udp])


async def run(host="0.0.0.0", port=1080, username=None, password=None):
    handler = lambda reader, writer: handle_client(reader, writer, username, password)
    transports = [await get_transport(name)(host, port, handler, username, password)
                  for name in select_transports()]
    servers = [srv for t in transports for srv in t.servers]
    datagrams = [udp for t in transports for udp in t.datagrams]
    try:
        async with contextlib.AsyncExitStack() as stack:
            for srv in servers:
                await stack.enter_async_context(srv)
            if servers:
                await asyncio.gather(*(srv.serve_forever() for srv in servers))
            else:
                await asyncio.Event().wait()
    finally:
        for t in transports:
            t.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=1080)
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--print-cert", action="store_true",
                        help="print the generated TLS certificate before listening")
    parser.add_argument("--dns-host", default="127.0.0.1")
    parser.add_argument("--dns-port", type=int, default=1053,
                        help="UDP port for the DNS server (53 needs root on Linux/macOS)")
    parser.add_argument("--dns-upstream", default="1.1.1.1:53")
    parser.add_argument("--fake-ip-range", default="198.18.0.0/15")
    args = parser.parse_args()
    if (args.username is None) != (args.password is None):
        parser.error("--username and --password must be used together")
    configure_performance()
    configure_mkcp()
    configure_pac()
    configure_tls(print_cert=args.print_cert)
    try:
        configure_dns(enabled=True, fake_ip=True, host=args.dns_host,
                      port=args.dns_port, upstream=split_host_port(args.dns_upstream, 53),
                      fake_range=args.fake_ip_range)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        asyncio.run(run(args.host, args.port, args.username, args.password))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
