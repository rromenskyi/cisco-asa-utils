#!/usr/bin/env python3
"""Cisco ASA blocklist manager and config utility (ASA 5300/5350)."""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sqlite3
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AsaCreds:
    host: str
    username: str
    key_file: str | None
    secret: str

    @classmethod
    def load(cls, args: argparse.Namespace) -> "AsaCreds":
        host = args.host or os.environ.get("ASA_HOST") or _prompt("ASA host")
        user = args.user or os.environ.get("ASA_USER") or _prompt("Username")
        key_file = args.key or os.environ.get("ASA_KEY_FILE")
        if key_file:
            key_file = os.path.expanduser(key_file)
            if not os.path.isfile(key_file):
                sys.exit(f"key file not found: {key_file}")
        secret = os.environ.get("ASA_ENABLE") or getpass.getpass("Enable password: ")
        return cls(host=host, username=user, key_file=key_file, secret=secret)


def _prompt(label: str) -> str:
    value = input(f"{label}: ").strip()
    if not value:
        sys.exit(f"{label} is required")
    return value


@contextmanager
def connect(creds: AsaCreds):
    try:
        from netmiko import ConnectHandler
        from netmiko.exceptions import (
            NetmikoAuthenticationException,
            NetmikoTimeoutException,
        )
    except ImportError:
        sys.exit("netmiko is required for network commands: pip install -r requirements.txt")
    params = {
        "device_type": "cisco_asa",
        "host": creds.host,
        "username": creds.username,
        "secret": creds.secret,
        "use_keys": True,
        "allow_agent": True,
        "fast_cli": False,
    }
    if creds.key_file:
        params["key_file"] = creds.key_file
    try:
        conn = ConnectHandler(**params)
    except NetmikoAuthenticationException:
        sys.exit(f"authentication failed for {creds.username}@{creds.host}")
    except NetmikoTimeoutException:
        sys.exit(f"timeout connecting to {creds.host}")
    try:
        conn.enable()
        conn.send_command("terminal pager 0")
        yield conn
    finally:
        conn.disconnect()


def cmd_backup(args: argparse.Namespace) -> None:
    if args.keep < 1:
        sys.exit("--keep must be >= 1")
    creds = AsaCreds.load(args)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = out_dir / f"{creds.host}-{stamp}.cfg"

    with connect(creds) as conn:
        config = conn.send_command("show running-config", read_timeout=120)

    target.write_text(config)
    print(f"saved {target} ({len(config)} bytes)")
    _rotate_backups(out_dir, creds.host, args.keep)


def _rotate_backups(out_dir: Path, host: str, keep: int) -> None:
    existing = sorted(
        out_dir.glob(f"{host}-*.cfg"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for stale in existing[keep:]:
        stale.unlink()
        print(f"pruned {stale.name}")


def cmd_objects(args: argparse.Namespace) -> None:
    creds = AsaCreds.load(args)
    with connect(creds) as conn:
        output = conn.send_command("show running-config object-group", read_timeout=60)

    hosts = list(_parse_host_objects(output))
    with _open_db(args.db) as db:
        db.execute("DELETE FROM OBJECTS")
        db.executemany("INSERT INTO OBJECTS (ADDR, NAME) VALUES (?, ?)", hosts)
    print(f"stored {len(hosts)} host entries in {args.db}")


def _parse_host_objects(output: str):
    group = None
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        tokens = line.split()
        if len(tokens) >= 3 and tokens[0] == "object-group" and tokens[1] == "network":
            group = tokens[2]
            continue
        if (
            group
            and len(tokens) >= 3
            and tokens[0] == "network-object"
            and tokens[1] == "host"
            and _is_ipv4(tokens[2])
        ):
            yield tokens[2], group


_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _is_ipv4(value: str) -> bool:
    if not _IPV4_RE.match(value):
        return False
    return all(0 <= int(octet) <= 255 for octet in value.split("."))


_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS OBJECTS (
        ADDR CHAR(15) NOT NULL,
        NAME CHAR(50) NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ACTION (
        ADDR   CHAR(15) NOT NULL,
        NAME   CHAR(50) NOT NULL,
        ACTION CHAR(3)  NOT NULL,
        DATE   CHAR(25) NOT NULL,
        STATE  CHAR(1)  NOT NULL DEFAULT 'U'
    )
    """,
)


@contextmanager
def _open_db(path: str):
    db = sqlite3.connect(path)
    try:
        for ddl in _SCHEMA:
            db.execute(ddl)
        yield db
        db.commit()
    finally:
        db.close()


def cmd_ban(args: argparse.Namespace) -> None:
    _enqueue(args, "ADD")


def cmd_unban(args: argparse.Namespace) -> None:
    _enqueue(args, "DEL")


def _enqueue(args: argparse.Namespace, action: str) -> None:
    if not _is_ipv4(args.ip):
        sys.exit(f"invalid IPv4: {args.ip}")
    with _open_db(args.db) as db:
        db.execute(
            "INSERT INTO ACTION (ADDR, NAME, ACTION, DATE) VALUES (?, ?, ?, ?)",
            (args.ip, args.group, action, str(int(time.time()))),
        )
    print(f"queued {action} {args.ip} -> {args.group}")


def cmd_pending(args: argparse.Namespace) -> None:
    with _open_db(args.db) as db:
        rows = db.execute(
            "SELECT ROWID, ADDR, NAME, ACTION, DATE FROM ACTION "
            "WHERE STATE='U' ORDER BY DATE"
        ).fetchall()
    if not rows:
        print("no pending actions")
        return
    for rid, addr, name, action, date in rows:
        print(f"#{rid}\t{action}\t{addr}\t{name}\t{date}")


def cmd_apply(args: argparse.Namespace) -> None:
    with _open_db(args.db) as db:
        rows = db.execute(
            "SELECT ROWID, ADDR, NAME, ACTION FROM ACTION "
            "WHERE STATE='U' ORDER BY DATE"
        ).fetchall()
    if not rows:
        print("nothing to apply")
        return

    by_group: dict[str, list[tuple[int, str, str]]] = {}
    for rid, addr, name, action in rows:
        by_group.setdefault(name, []).append((rid, addr, action))

    cli: list[str] = []
    for group, items in by_group.items():
        cli.append(f"object-group network {group}")
        for _, addr, action in items:
            prefix = "no " if action == "DEL" else ""
            cli.append(f" {prefix}network-object host {addr}")
        cli.append("exit")

    creds = AsaCreds.load(args)
    if not args.yes:
        print("\n".join(cli))
        reply = input(f"apply {len(rows)} actions to {creds.host}? [y/N] ")
        if reply.strip().lower() != "y":
            sys.exit("aborted")

    with connect(creds) as conn:
        conn.send_config_set(cli, read_timeout=120)
        conn.save_config()

    with _open_db(args.db) as db:
        db.executemany(
            "UPDATE ACTION SET STATE='P' WHERE ROWID=?",
            [(rid,) for rid, *_ in rows],
        )
    print(f"applied {len(rows)} action(s)")


def cmd_restore(args: argparse.Namespace) -> None:
    path = Path(args.file)
    if not path.is_file():
        sys.exit(f"no such file: {path}")
    commands = [
        line for line in path.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("!")
    ]
    if not commands:
        sys.exit("nothing to apply")

    creds = AsaCreds.load(args)
    if not args.yes:
        reply = input(f"apply {len(commands)} lines from {path} to {creds.host}? [y/N] ")
        if reply.strip().lower() != "y":
            sys.exit("aborted")

    with connect(creds) as conn:
        result = conn.send_config_set(commands, read_timeout=120)
        conn.save_config()
    print(result)


def build_parser() -> argparse.ArgumentParser:
    conn_args = argparse.ArgumentParser(add_help=False)
    conn_args.add_argument("--host", help="ASA hostname/IP (or $ASA_HOST)")
    conn_args.add_argument("--user", help="SSH username (or $ASA_USER)")
    conn_args.add_argument("--key", help="path to SSH private key (or $ASA_KEY_FILE)")

    parser = argparse.ArgumentParser(description="Cisco ASA blocklist/config utility")
    sub = parser.add_subparsers(dest="command", required=True)

    p_backup = sub.add_parser("backup", parents=[conn_args], help="fetch running-config")
    p_backup.add_argument("--out-dir", default="backups")
    p_backup.add_argument("--keep", type=int, default=10, help="how many backups to retain per host")
    p_backup.set_defaults(func=cmd_backup)

    p_objects = sub.add_parser("objects", parents=[conn_args], help="mirror host network-objects into SQLite")
    p_objects.add_argument("--db", default="ciscoasa.db")
    p_objects.set_defaults(func=cmd_objects)

    p_restore = sub.add_parser("restore", parents=[conn_args], help="apply a config file to the ASA")
    p_restore.add_argument("file")
    p_restore.add_argument("-y", "--yes", action="store_true", help="skip confirmation")
    p_restore.set_defaults(func=cmd_restore)

    default_group = os.environ.get("ASA_BANLIST", "BANLIST")
    for name, func in (("ban", cmd_ban), ("unban", cmd_unban)):
        p = sub.add_parser(name, help=f"queue {name} action in ACTION table")
        p.add_argument("ip")
        p.add_argument("--group", default=default_group, help="object-group name")
        p.add_argument("--db", default="ciscoasa.db")
        p.set_defaults(func=func)

    p_pending = sub.add_parser("pending", help="list queued (STATE='U') actions")
    p_pending.add_argument("--db", default="ciscoasa.db")
    p_pending.set_defaults(func=cmd_pending)

    p_apply = sub.add_parser("apply", parents=[conn_args], help="push pending actions to the ASA")
    p_apply.add_argument("--db", default="ciscoasa.db")
    p_apply.add_argument("-y", "--yes", action="store_true", help="skip confirmation")
    p_apply.set_defaults(func=cmd_apply)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
