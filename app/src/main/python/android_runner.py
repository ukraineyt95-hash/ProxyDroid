"""Android service bridge for the embedded ProxyDroid SOCKS5 server."""

import asyncio
import contextlib
import ipaddress
import json
import os
import threading

import socks5_proxy as proxy


class AndroidTunEndpoint:
    """Async packet endpoint backed by the fd from VpnService.Builder.establish()."""

    def __init__(self, fd, mtu=1500):
        self.fd = os.dup(int(fd))
        self.mtu = int(mtu)
        self.closed = False
        self.loop = asyncio.get_running_loop()
        with contextlib.suppress(OSError, AttributeError):
            os.set_blocking(self.fd, False)

    async def _wait(self, readable):
        future = self.loop.create_future()

        def ready():
            if not future.done():
                future.set_result(None)

        register = self.loop.add_reader if readable else self.loop.add_writer
        unregister = self.loop.remove_reader if readable else self.loop.remove_writer
        register(self.fd, ready)
        try:
            await future
        finally:
            unregister(self.fd)

    async def read_packet(self):
        while not self.closed:
            try:
                packet = os.read(self.fd, self.mtu + 1)
            except BlockingIOError:
                await self._wait(True)
                continue
            except InterruptedError:
                continue
            if not packet:
                raise EOFError("TUN interface closed")
            if len(packet) > self.mtu:
                raise ValueError("TUN packet exceeds configured MTU")
            return packet
        raise EOFError("TUN interface closed")

    async def write_packet(self, packet):
        if self.closed:
            raise EOFError("TUN interface closed")
        packet = bytes(packet)
        if not 20 <= len(packet) <= self.mtu:
            raise ValueError("invalid TUN packet size")
        while True:
            try:
                written = os.write(self.fd, packet)
                if written != len(packet):
                    raise OSError("partial write to packet-oriented TUN fd")
                return
            except BlockingIOError:
                await self._wait(False)
            except InterruptedError:
                continue

    def close(self):
        if self.closed:
            return
        self.closed = True
        with contextlib.suppress(OSError):
            self.loop.remove_reader(self.fd)
            self.loop.remove_writer(self.fd)
        with contextlib.suppress(OSError):
            os.close(self.fd)


_state_lock = threading.RLock()
_started = threading.Event()
_stop_requested = threading.Event()
_thread = None
_loop = None
_stop_event = None
_running = False
_startup_error = None
_last_error = None


def _loopback_for(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "127.0.0.1" if host.lower() == "localhost" else host
    if address.is_unspecified:
        return "::1" if address.version == 6 else "127.0.0.1"
    return host


def _dns_loopback_for(host):
    if host in ("", "0.0.0.0"):
        return "127.0.0.1"
    if host in ("::", "[::]"):
        return "::1"
    return host


async def _serve(fd, config):
    global _loop, _stop_event, _running, _last_error

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    with _state_lock:
        _loop = loop
        _stop_event = stop_event
    if _stop_requested.is_set():
        stop_event.set()

    host = str(config.get("host", "127.0.0.1")).strip()
    port = int(config.get("port", 1080))
    username = str(config.get("username", "") or "") or None
    password = str(config.get("password", "") or "") or None
    upstream_proxy = str(config.get("upstreamProxy", "") or "").strip()
    upstream_username = str(config.get("upstreamUsername", "") or "") or None
    upstream_password = str(config.get("upstreamPassword", "") or "") or None
    dns_host = str(config.get("dnsHost", "127.0.0.1")).strip()
    dns_port = int(config.get("dnsPort", 1053))
    dns_upstream = proxy.split_host_port(
        str(config.get("dnsUpstream", "1.1.1.1:53")), 53)
    fake_ip_range = str(config.get("fakeIpRange", "198.18.0.0/15")).strip()
    print_cert = bool(config.get("printCert", False))
    udp_over_tcp = bool(config.get("udpOverTcp", False))
    tcp_max_segment_size = int(config.get("tcpMaxSegmentSize", 0) or 0)
    tcp_fast_open = bool(config.get("tcpFastOpen", False))
    fragment_client_hello = bool(config.get("fragmentClientHello", False))
    tls_fragment_size = int(config.get("tlsFragmentSize", 128) or 128)
    sni_override = str(config.get("sniOverride", "") or "").strip()

    if (username is None) != (password is None):
        raise ValueError("SOCKS5 username and password must be set together")
    if (upstream_username is None) != (upstream_password is None):
        raise ValueError("upstream SOCKS5 username and password must be set together")

    proxy.configure_transport_options(
        tcp_max_segment_size=tcp_max_segment_size,
        tcp_fast_open=tcp_fast_open,
        tls_client_hello_fragmentation=fragment_client_hello,
        tls_fragment_size=tls_fragment_size,
    )
    proxy.configure_performance()
    proxy.configure_mkcp()
    proxy.configure_pac()
    proxy.configure_tls(print_cert=print_cert)
    proxy.configure_dns(
        enabled=True,
        fake_ip=True,
        host=dns_host,
        port=dns_port,
        upstream=dns_upstream,
        fake_range=fake_ip_range,
    )

    handler = lambda reader, writer: proxy.handle_client(
        reader, writer, username, password)
    transports = []
    tunnel = None
    engine = None
    server_tasks = []
    engine_task = None
    stop_task = None
    startup_complete = False
    try:
        for name in proxy.select_transports():
            transports.append(await proxy.get_transport(name)(
                host, port, handler, username, password))

        tunnel = AndroidTunEndpoint(fd, mtu=1500)
        if upstream_proxy:
            tunnel_proxy = upstream_proxy
            tunnel_username = upstream_username
            tunnel_password = upstream_password
        else:
            tunnel_host = _loopback_for(host)
            tunnel_proxy = f"socks5://{tunnel_host}:{port}"
            tunnel_username = username
            tunnel_password = password
        engine = proxy.Tun2Socks(
            tunnel,
            tunnel_proxy,
            tunnel_username,
            tunnel_password,
            udp_over_tcp=udp_over_tcp,
            dns_redirect=(_dns_loopback_for(dns_host), dns_port),
            tcp_max_segment_size=tcp_max_segment_size,
            fragment_client_hello=fragment_client_hello,
            tls_fragment_size=tls_fragment_size,
            sni_override=sni_override,
        )

        for transport in transports:
            for server in transport.servers:
                server_tasks.append(asyncio.create_task(server.serve_forever()))
        engine_task = asyncio.create_task(engine.run())
        stop_task = asyncio.create_task(stop_event.wait())
        with _state_lock:
            _running = True
        startup_complete = True
        _started.set()

        done, pending = await asyncio.wait(
            [stop_task, engine_task, *server_tasks],
            return_when=asyncio.FIRST_COMPLETED,
        )
        if stop_task not in done:
            failed = next(iter(done))
            try:
                failed.result()
                reason = "proxy/TUN worker stopped unexpectedly"
            except BaseException as exc:
                reason = f"proxy/TUN worker stopped: {exc}"
            raise RuntimeError(reason)
    finally:
        if stop_task is not None and not stop_task.done():
            stop_task.cancel()
        for task in server_tasks:
            if not task.done():
                task.cancel()
        if engine_task is not None and not engine_task.done():
            engine_task.cancel()
        pending_tasks = [task for task in [stop_task, *server_tasks, engine_task]
                         if task is not None]
        if pending_tasks:
            await asyncio.gather(*pending_tasks, return_exceptions=True)
        if engine is not None:
            with contextlib.suppress(Exception):
                await engine.close()
        for transport in transports:
            transport.close()
        if tunnel is not None:
            tunnel.close()
        with _state_lock:
            _running = False
        if startup_complete:
            _started.set()


def _thread_main(fd, config):
    global _loop, _stop_event, _running, _startup_error, _last_error
    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)
    try:
        event_loop.run_until_complete(_serve(fd, config))
    except BaseException as exc:
        message = f"{type(exc).__name__}: {exc}"
        with _state_lock:
            if not _started.is_set():
                _startup_error = message
            else:
                _last_error = message
    finally:
        with contextlib.suppress(Exception):
            event_loop.run_until_complete(event_loop.shutdown_asyncgens())
        with contextlib.suppress(Exception):
            event_loop.close()
        with _state_lock:
            _running = False
            _loop = None
            _stop_event = None
        _started.set()


def start(fd, config):
    """Start the listeners and TUN loop, blocking only until they are ready."""
    global _thread, _startup_error, _last_error, _running
    if isinstance(config, str):
        config = json.loads(config)
    with _state_lock:
        if _thread is not None and _thread.is_alive():
            raise RuntimeError("ProxyDroid is already running")
        _started.clear()
        _stop_requested.clear()
        _startup_error = None
        _last_error = None
        _running = False
        _thread = threading.Thread(
            target=_thread_main,
            args=(int(fd), dict(config)),
            name="ProxyDroid-python",
            daemon=True,
        )
        thread = _thread
        thread.start()

    if not _started.wait(30):
        stop()
        raise TimeoutError("ProxyDroid startup timed out")
    with _state_lock:
        error = _startup_error
        running = _running
    if error:
        raise RuntimeError(error)
    if not running:
        raise RuntimeError(_last_error or "ProxyDroid failed to start")
    return True


def stop(timeout=10):
    """Stop the Python event loop cleanly and release the duplicated TUN fd."""
    global _thread
    _stop_requested.set()
    with _state_lock:
        loop = _loop
        event = _stop_event
        thread = _thread
    if loop is not None and event is not None:
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(event.set)
    if thread is not None and thread is not threading.current_thread():
        thread.join(timeout)
    return thread is None or not thread.is_alive()


def is_running():
    with _state_lock:
        return bool(_running and _thread is not None and _thread.is_alive())


def last_error():
    with _state_lock:
        return _last_error or _startup_error or ""
