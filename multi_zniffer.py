#!/usr/bin/env python3
"""Merge PTI debug-channel traffic from multiple WSTKs to one Zniffer socket."""

from __future__ import annotations

import argparse
import configparser
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

START = 0x5B
END = 0x5D
PROMPT = b"> "


@dataclass(frozen=True)
class DeviceConfig:
    name: str
    host: str
    source_port: int
    command_port: int
    commands: list[str]
    info: dict[str, str]

    @property
    def label(self) -> str:
        network = self.info.get("network")
        if network:
            return f"{self.name} ({network})"
        return self.name


def parse_hosts(values: Iterable[str]) -> list[str]:
    hosts: list[str] = []
    for value in values:
        item = value.strip()
        if not item or item.startswith("#"):
            continue
        hosts.append(item)
    return hosts


def parse_commands(raw: str) -> list[str]:
    commands: list[str] = []
    for line in raw.splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        commands.append(item)
    return commands


def load_devices_from_config(
    file_path: str,
    default_source_port: int,
    default_command_port: int,
) -> tuple[dict[str, str], list[DeviceConfig]]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(file_path, encoding="utf-8")

    proxy_values: dict[str, str] = {}
    if parser.has_section("proxy"):
        for key, value in parser.items("proxy"):
            proxy_values[key] = value.strip()

    devices: list[DeviceConfig] = []
    for section in parser.sections():
        lowered = section.lower()
        if not (lowered.startswith("device") or lowered.startswith("wstk")):
            continue
        host = parser.get(section, "host", fallback="").strip()
        if not host:
            continue
        name = parser.get(section, "name", fallback=section).strip()
        enabled = parser.getboolean(section, "enabled", fallback=True)
        if not enabled:
            continue
        source_port = parser.getint(
            section, "source_port", fallback=default_source_port
        )
        command_port = parser.getint(
            section, "command_port", fallback=default_command_port
        )
        commands = parse_commands(parser.get(section, "commands", fallback=""))
        info: dict[str, str] = {}
        for key, value in parser.items(section):
            if key in {
                "host",
                "name",
                "enabled",
                "commands",
                "source_port",
                "command_port",
            }:
                continue
            info[key] = value.strip()
        devices.append(
            DeviceConfig(
                name=name,
                host=host,
                source_port=source_port,
                command_port=command_port,
                commands=commands,
                info=info,
            )
        )
    return proxy_values, devices


def load_devices_from_legacy_config(
    file_path: str,
    default_source_port: int,
    default_command_port: int,
) -> tuple[dict[str, str], list[DeviceConfig]]:
    """Parse legacy format:

    host [key=value ...] {
      "command one",
      "command two"
    }
    """
    text = Path(file_path).read_text(encoding="utf-8")
    lines = text.splitlines()
    devices: list[DeviceConfig] = []
    idx = 0

    while idx < len(lines):
        line = lines[idx].strip()
        idx += 1
        if not line or line.startswith("#"):
            continue
        if line.endswith("{"):
            header = line[:-1].strip()
        else:
            continue
        if not header:
            continue

        parts = header.split()
        host = parts[0]
        info: dict[str, str] = {}
        for token in parts[1:]:
            if "=" in token:
                key, value = token.split("=", 1)
                info[key.strip()] = value.strip()
        commands: list[str] = []
        while idx < len(lines):
            item = lines[idx].strip()
            idx += 1
            if item == "}":
                break
            if not item or item.startswith("#"):
                continue
            if item.endswith(","):
                item = item[:-1].rstrip()
            if len(item) >= 2 and item[0] == '"' and item[-1] == '"':
                item = item[1:-1]
            if item:
                commands.append(item)

        devices.append(
            DeviceConfig(
                name=info.get("name", host),
                host=host,
                source_port=int(info.get("source_port", default_source_port)),
                command_port=int(info.get("command_port", default_command_port)),
                commands=commands,
                info=info,
            )
        )

    return {}, devices


def load_hosts(file_path: str | None, cli_hosts: list[str]) -> list[str]:
    hosts = parse_hosts(cli_hosts)
    if file_path:
        content = Path(file_path).read_text(encoding="utf-8")
        hosts.extend(parse_hosts(content.splitlines()))
    seen: set[str] = set()
    unique_hosts: list[str] = []
    for host in hosts:
        if host not in seen:
            unique_hosts.append(host)
            seen.add(host)
    return unique_hosts


def framed_messages(sock: socket.socket):
    """Yield complete debug-channel frames including framing bytes."""
    buf = bytearray()
    while True:
        data = sock.recv(4096)
        if not data:
            return
        buf.extend(data)
        while True:
            try:
                p = buf.index(START)
            except ValueError:
                buf.clear()
                break
            if p > 0:
                del buf[:p]
            if len(buf) < 4:
                break
            length = int.from_bytes(buf[1:3], "little")
            total = length + 2
            if length < 2 or total > 65537:
                del buf[0]
                continue
            if len(buf) < total:
                break
            if buf[total - 1] != END:
                next_start = buf.find(START, 1)
                if next_start > 0:
                    del buf[:next_start]
                else:
                    del buf[:1]
                continue
            frame = bytes(buf[:total])
            del buf[:total]
            yield frame


class MergeProxy:
    def __init__(
        self,
        devices: list[DeviceConfig],
        listen_host: str,
        listen_port: int,
        reconnect_delay: float,
        command_timeout: float,
    ):
        self.devices = devices
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.reconnect_delay = reconnect_delay
        self.command_timeout = command_timeout
        self.stop_event = threading.Event()
        self.client_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.client: socket.socket | None = None

    def log(self, msg: str) -> None:
        print(msg, flush=True)

    def set_client(self, conn: socket.socket | None) -> None:
        with self.client_lock:
            old = self.client
            self.client = conn
        if old is not None and old is not conn:
            try:
                old.close()
            except OSError:
                pass

    def forward_frame(self, frame: bytes, source_host: str) -> None:
        with self.client_lock:
            client = self.client
        if client is None:
            return
        try:
            with self.send_lock:
                client.sendall(frame)
        except OSError as exc:
            self.log(f"[client] disconnected while forwarding from {source_host}: {exc}")
            self.set_client(None)

    def wait_for_prompt(self, sock: socket.socket) -> bool:
        deadline = time.monotonic() + self.command_timeout
        buf = bytearray()
        while time.monotonic() < deadline:
            remaining = max(0.1, deadline - time.monotonic())
            sock.settimeout(remaining)
            try:
                data = sock.recv(1024)
            except socket.timeout:
                continue
            if not data:
                return False
            buf.extend(data)
            if PROMPT in buf:
                return True
            if len(buf) > 4096:
                del buf[:-32]
        return False

    def initialize_device(self, device: DeviceConfig) -> bool:
        try:
            with socket.create_connection(
                (device.host, device.command_port), timeout=self.command_timeout
            ) as cmd_sock:
                self.log(
                    f"[init {device.label}] connected to {device.host}:{device.command_port}"
                )
                # Wake the RAILtest console first and require a prompt.
                cmd_sock.sendall(b"\n")
                if not self.wait_for_prompt(cmd_sock):
                    self.log(f"[init {device.label}] prompt not received after empty line")
                    return False
                for command in device.commands:
                    cmd_sock.sendall(f"{command}\n".encode("utf-8"))
                    if not self.wait_for_prompt(cmd_sock):
                        self.log(
                            f"[init {device.label}] prompt timeout after command: {command}"
                        )
                        return False
                    self.log(f"[init {device.label}] applied command: {command}")
            return True
        except OSError as exc:
            self.log(f"[init {device.label}] command connection error: {exc}")
            return False

    def source_worker(self, device: DeviceConfig) -> None:
        while not self.stop_event.is_set():
            if not self.initialize_device(device):
                if self.stop_event.is_set():
                    return
                time.sleep(self.reconnect_delay)
                continue
            try:
                self.log(
                    f"[source {device.label}] connecting to {device.host}:{device.source_port}"
                )
                with socket.create_connection(
                    (device.host, device.source_port), timeout=10
                ) as sock:
                    sock.settimeout(None)
                    self.log(f"[source {device.label}] connected")
                    for frame in framed_messages(sock):
                        if self.stop_event.is_set():
                            return
                        self.forward_frame(frame, device.label)
                    self.log(f"[source {device.label}] stream closed")
            except OSError as exc:
                self.log(f"[source {device.label}] connection error: {exc}")
            if self.stop_event.is_set():
                return
            time.sleep(self.reconnect_delay)

    def listener(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.listen_host, self.listen_port))
            srv.listen(1)
            srv.settimeout(1.0)
            self.log(
                f"[listener] Zniffer endpoint listening on {self.listen_host}:{self.listen_port}"
            )
            while not self.stop_event.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop_event.is_set():
                        return
                    raise
                self.log(f"[listener] client connected from {addr[0]}:{addr[1]}")
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.set_client(conn)

    def run(self) -> None:
        if not self.devices:
            raise ValueError("No source devices were provided.")

        threads = [
            threading.Thread(target=self.source_worker, args=(device,), daemon=True)
            for device in self.devices
        ]
        listener_thread = threading.Thread(target=self.listener, daemon=True)
        for thread in threads:
            thread.start()
        listener_thread.start()

        self.log(f"[proxy] forwarding from {len(self.devices)} source(s)")
        self.log("[proxy] press Ctrl+C to stop")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.log("[proxy] stopping")
        finally:
            self.stop_event.set()
            self.set_client(None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        default="multi_zniffer.conf",
        help="INI configuration file (default: multi_zniffer.conf)",
    )
    parser.add_argument(
        "--host",
        action="append",
        default=[],
        help="Additional WSTK hostname or IP (repeat for multiple hosts)",
    )
    parser.add_argument(
        "--source-port",
        type=int,
        default=4905,
        help="TCP port used by each WSTK source (default: 4905)",
    )
    parser.add_argument(
        "--listen-host",
        default="0.0.0.0",
        help="Bind address for Zniffer client connection (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=4905,
        help="TCP port exposed for Zniffer client (default: 4905)",
    )
    parser.add_argument(
        "--reconnect-delay",
        type=float,
        default=2.0,
        help="Reconnect delay in seconds for dropped source links (default: 2.0)",
    )
    parser.add_argument(
        "--command-port",
        type=int,
        default=4901,
        help="RAILtest command TCP port (default: 4901)",
    )
    parser.add_argument(
        "--command-timeout",
        type=float,
        default=5.0,
        help="Timeout in seconds waiting for RAILtest prompt (default: 5.0)",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    devices: list[DeviceConfig] = []
    listen_host = args.listen_host
    listen_port = args.listen_port
    source_port = args.source_port
    command_port = args.command_port
    reconnect_delay = args.reconnect_delay
    command_timeout = args.command_timeout

    config_path = Path(args.config)
    if config_path.exists():
        non_empty = [
            line.strip()
            for line in config_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        use_ini = bool(non_empty and non_empty[0].startswith("["))
        if use_ini:
            proxy_values, devices = load_devices_from_config(
                str(config_path),
                default_source_port=source_port,
                default_command_port=command_port,
            )
        else:
            proxy_values, devices = load_devices_from_legacy_config(
                str(config_path),
                default_source_port=source_port,
                default_command_port=command_port,
            )
        listen_host = proxy_values.get("listen_host", listen_host)
        listen_port = int(proxy_values.get("listen_port", str(listen_port)))
        reconnect_delay = float(proxy_values.get("reconnect_delay", str(reconnect_delay)))
        command_timeout = float(proxy_values.get("command_timeout", str(command_timeout)))

    for host in parse_hosts(args.host):
        devices.append(
            DeviceConfig(
                name=host,
                host=host,
                source_port=source_port,
                command_port=command_port,
                commands=[],
                info={},
            )
        )

    deduped: list[DeviceConfig] = []
    seen_hosts: set[str] = set()
    for device in devices:
        if device.host in seen_hosts:
            continue
        seen_hosts.add(device.host)
        deduped.append(device)

    if not deduped:
        raise SystemExit("No valid devices found. Provide --host or create multi_zniffer.conf")

    proxy = MergeProxy(
        devices=deduped,
        listen_host=listen_host,
        listen_port=listen_port,
        reconnect_delay=reconnect_delay,
        command_timeout=command_timeout,
    )
    proxy.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
