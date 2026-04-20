# cisco-asa-utils

A small CLI that drives a Cisco ASA's network object-groups as a **blocklist** —
queue IPs to ban/unban in a local SQLite database, then push them to the ASA in
one shot. Plus a couple of convenience commands (`backup`, `restore`) reused
from the same SSH session plumbing.

This is a **refactor of an ancient personal tool** I wrote in 2013 for Cisco
ASA 5300/5350 appliances: a pair of Perl+Expect scripts with plaintext
credentials hard-coded in the source. Rewritten in Python on top of
[netmiko](https://github.com/ktbyers/netmiko), key-based SSH only, no secrets
in the tree.

## How it works

```
  ban/unban <ip>                apply
 ────────────────►  SQLite  ────────────►  Cisco ASA
                   ACTION                  object-group network BANLIST
                  STATE=U                   network-object host <ip>
                                         (STATE flips to P in the DB)
```

1. `ban` / `unban` inserts a row into `ACTION` with `STATE='U'` (unprocessed).
   No network I/O — safe to call from cron, webhooks, fail2ban, whatever.
2. `pending` lists the queue.
3. `apply` opens one SSH session, batches every `STATE='U'` row by
   object-group, pushes `network-object host …` / `no network-object host …`,
   runs `write memory`, and flips the rows to `STATE='P'`.

The `OBJECTS` table is a separate mirror of what's currently on the device —
`objects` pulls `show running-config object-group` and refreshes it so you can
diff or report against the live state.

## Install

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

## Credentials

SSH authentication is **key-only** (via `ssh-agent` or an explicit `--key` /
`$ASA_KEY_FILE`). The enable secret is read from `$ASA_ENABLE` or prompted
with `getpass` — never echoed, never in `argv`.

```sh
export ASA_HOST=asa.example.com
export ASA_USER=admin
export ASA_KEY_FILE=~/.ssh/id_ed25519   # optional, falls back to ssh-agent
export ASA_ENABLE=...                   # enable secret
export ASA_BANLIST=BANLIST              # default object-group for ban/unban
```

One-time key setup on the ASA side:

```
conf t
username admin attributes
  ssh authentication publickey AAAA... hashed
```

And the object-group that will hold the blocklist, e.g.:

```
object-group network BANLIST
access-list OUTSIDE_IN deny ip object-group BANLIST any
```

## Commands

```sh
# queue IPs (no network I/O, just writes to SQLite)
./ciscoasa.py ban   1.2.3.4
./ciscoasa.py unban 1.2.3.4

# inspect the queue
./ciscoasa.py pending

# push every STATE='U' row to the ASA, flip them to STATE='P'
./ciscoasa.py apply            # prompts with a preview
./ciscoasa.py apply -y         # non-interactive (cron-friendly)

# refresh the local OBJECTS mirror from the device
./ciscoasa.py objects --db ciscoasa.db

# snapshot running-config, keep the 10 most recent per host
./ciscoasa.py backup --out-dir backups --keep 10

# replay a saved config / diff file back onto the ASA
./ciscoasa.py restore path/to/changes.cli
```

## SQLite schema

Preserved from the legacy Perl version so older reports still work:

```sql
CREATE TABLE OBJECTS (
    ADDR CHAR(15) NOT NULL,   -- IPv4 of the host
    NAME CHAR(50) NOT NULL    -- owning object-group name
);

CREATE TABLE ACTION (
    ADDR   CHAR(15) NOT NULL,
    NAME   CHAR(50) NOT NULL,         -- target object-group
    ACTION CHAR(3)  NOT NULL,         -- ADD / DEL
    DATE   CHAR(25) NOT NULL,         -- epoch seconds (string)
    STATE  CHAR(1)  NOT NULL DEFAULT 'U'   -- U=unprocessed, P=processed
);
```
