# <img src="docs/icon.png" width="28" align="top" alt=""> Fairway

**English** · [Русский](README.ru.md)

[![CI](https://github.com/Crasher69/fairway/actions/workflows/ci.yml/badge.svg)](https://github.com/Crasher69/fairway/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Crasher69/fairway)](https://github.com/Crasher69/fairway/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/Crasher69/fairway)](https://goreportcard.com/report/github.com/Crasher69/fairway)
[![License](https://img.shields.io/github/license/Crasher69/fairway)](LICENSE)

A proxy load balancer that works out by itself which of your proxies performs
best for which site, and routes traffic by those measurements. One binary, no
dependencies, web panel built in.

```
fairway -proxy :8080 -admin 127.0.0.1:8081
```

<p align="center"><img src="docs/panel.png" width="900" alt="Fairway panel: proxies for a domain ranked by cost, one of them banned, time-to-first-byte chart"></p>

## Install

### Linux server (systemd)

`install.sh` sets fairway up as a systemd service on RHEL, Rocky, Alma,
Fedora, Debian and Ubuntu. It downloads the release binary for the machine's
architecture and checks it against `SHA256SUMS`, creates the `fairway` system
user, puts the config in `/etc/fairway` and the data in `/var/lib/fairway`,
and starts the service.

```
curl -fsSLO https://raw.githubusercontent.com/Crasher69/fairway/main/install.sh
sudo bash install.sh
```

Defaults: proxy on `:8080`, panel on `127.0.0.1:8081`. The script prints the
panel link with the token and the `ssh -L` command to reach the panel from
your machine. Useful options (full list in `--help`):

```
sudo bash install.sh --proxy :3128                  # another proxy port
sudo bash install.sh --allow-from 203.0.113.0/24    # open the port in firewalld/ufw for one network
sudo bash install.sh --download                     # update to the latest release
sudo bash install.sh --version v0.3.0               # a specific release
sudo bash install.sh --uninstall                    # remove the service, keep config and data
```

An update keeps the ports already in the unit and never touches an existing
config. A fresh install writes a starter config with `allow_direct: false`, so
until you add proxies and rules every request gets a 503 instead of leaving
from the server's own IP (see [Security](#security)).

### Binaries

Prebuilt binaries are on the
[Releases page](https://github.com/Crasher69/fairway/releases/latest):
`fairway-linux-amd64`, `fairway-linux-arm64`, `fairway-windows-amd64.exe`,
`fairway-darwin-arm64` (Apple Silicon), `fairway-darwin-amd64` (Intel Mac).
Static, no dependencies: download and run. The latest build is always
available by a direct link, for example:

```
curl -LO https://github.com/Crasher69/fairway/releases/latest/download/fairway-linux-amd64
chmod +x fairway-linux-amd64
./fairway-linux-amd64 -proxy 127.0.0.1:8080 -admin 127.0.0.1:8081
```

Started this way, fairway keeps `config.json` and `data/` in the current
directory. There is also a [Docker image](#docker), or build from source, see
[Building](#building).

## Quick start

1. **Open the panel.** Use the link with the token from the log
   (`journalctl -u fairway -n 50` for the service). On a server the panel
   listens on loopback only, so forward it first:
   `ssh -L 8081:127.0.0.1:8081 user@server`, then open the link locally.
   Set a password on the Access tab so you do not need the token next time.
2. **Add proxies** on the Proxies tab: one at a time, or a whole purchase
   through the list import (`ip:port:login:password`,
   `socks5://user:pass@host:port` and other common formats).
3. **Make a list** on the Lists tab and tick the proxies it should use.
4. **Add domain rules** on the Domains tab: which list serves which site.
   To balance all traffic, put a list in `defaults.list` or add a `*` rule.
5. **Point clients at the proxy.** Fairway is an HTTP proxy (plain HTTP and
   `CONNECT` for HTTPS):

   ```
   curl -x http://server:8080 https://example.com/
   export HTTPS_PROXY=http://server:8080 HTTP_PROXY=http://server:8080
   ```

   In a browser, set it as the HTTP and HTTPS proxy in the network settings.

After a few requests the Domains view shows which proxies serve each site,
their cost and their traffic share.

## Security

**The proxy port has no client authentication.** Anyone who can reach it can
send traffic through your proxies (and through the server's own IP if
`allow_direct` is on). Before exposing it beyond a trusted network:

- listen on a private interface only: `-proxy 10.0.0.5:8080`;
- or restrict the port in the firewall to your clients' addresses:

  ```
  sudo ufw allow proto tcp from 203.0.113.0/24 to any port 8080          # Ubuntu/Debian
  sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" \
       source address="203.0.113.0/24" port port="8080" protocol="tcp" accept' \
       && sudo firewall-cmd --reload                                      # RHEL family
  ```

  `install.sh --allow-from CIDR` does the same;
- or keep it on `127.0.0.1` and reach it over an SSH tunnel.

**A config created by fairway itself on first start has
`allow_direct: true`**: with no proxies configured it forwards straight from
the host's IP, which is handy on your own machine and an open relay on a
public server. `install.sh` writes a stricter starter config; with the plain
binary or Docker set `"allow_direct": false` before opening the port.

**Docker bypasses ufw:** a port published with `-p 8080:8080` is reachable
from outside even when ufw denies it. Publish it on a specific address
(`-p 10.0.0.5:8080:8080`) or filter in the `DOCKER-USER` chain.

**The panel** listens on `127.0.0.1` by default. If you move it to another
address, fairway warns in the log; set a password and firewall that port.

**The MITM root key** (`data/fairway-ca.key`) lets whoever holds it sign
certificates your whole network trusts; see [MITM](#mitm-see-the-requests).

## How it differs from gost, glider, 3proxy and Squid

Those support lists and rotation, but balance statically: round-robin,
least-conn or hand-written weights. Fairway keeps statistics per
**(domain, proxy) pair** and re-evaluates them on every request.

The practical difference: the same proxy can be fast for one site, half-dead
for another and banned on a third. Fairway sees it and spreads the traffic
accordingly.

## How it chooses

Every metric folds into a single number, the **cost**: how many seconds a
reference 64 KB response would take through this proxy.

```
cost = (connect time + time to first byte) + 64KB / throughput
cost /= (1 - error rate)²
```

Then a lottery weighted by `(1/cost)²`, plus 10% of requests go to
exploration: without it the leader would take all the traffic, and there would
be no way to learn that an outsider has recovered.

**A slow proxy stays in rotation with a low weight. A banned one is switched
off entirely, but only for the domain where it was banned.** Ban signals:
HTTP 403, 429, 451, 407, three consecutive connection failures, or a captcha /
challenge page instead of content (MITM mode). A proxy that accepts the
connection and then never delivers a byte from the target counts as a
connection failure too: the target has to answer within the dial timeout.

**A request that got no reply through one proxy is retried through another**,
up to three proxies in total, and the client does not notice. For tunnels
that covers everything the client sent before the target's first byte (the
TLS handshake included); for plain HTTP, requests without a body. In MITM
mode the upstream is swapped mid-tunnel, because the client speaks TLS to us
rather than to the target. Once a single byte has come back the request is
never retried: it may already have been executed.

Ratings survive a restart (`data/ratings.json`).

## Language

The log and the panel are in English by default. The switch in the panel
header changes the language of both the panel and the log; the choice is
stored in the config as `"language": "ru"` and survives a restart.
Command-line flags are always in English: they are parsed before the config
is read.

## Config

Created on first start, re-read on the fly, no restart needed. A broken edit is
not applied: the previous version stays in service.

```json
{
  "language": "en",
  "defaults": {
    "list": "residential",
    "allow_direct": false,
    "max_conns_per_proxy": 32,
    "ban_duration": "5m"
  },
  "proxies": [
    {
      "name": "p1",
      "scheme": "socks5",
      "host": "1.2.3.4",
      "port": 1080,
      "login": "user",
      "password": "pass",
      "country": "DE",
      "comment": "paid until December"
    },
    {"name": "p2", "scheme": "http", "host": "5.6.7.8", "port": 3128}
  ],
  "lists": [{"name": "residential", "proxies": ["p1", "p2"]}],
  "domains": [
    {"pattern": "example.com", "list": "residential", "max_parallel_proxies": 3},
    {"pattern": "*.example.com", "list": "residential", "mitm": true}
  ]
}
```

Two limits are easy to mix up:

- `max_parallel_proxies` — how many **different** proxies from the list work
  on the domain at the same time;
- `max_conns_per_proxy` — how many connections **one** proxy holds.

`0` means "take from `defaults`", `-1` means "unlimited".

Rules match from specific to general: exact name → longest `*.suffix` →
`*` → `defaults.list`.

With `allow_direct: false` a domain without a rule gets a 503 instead of
silently leaving from your real IP. A missing field means `false`, but the
config fairway writes on first start sets it to `true`; see
[Security](#security).

Supported upstreams: `http://`, `https://`, `socks5://` and `direct`.

## Panel

Listens on `127.0.0.1:8081` by default. Two ways in and both work at once:
the link with a token that fairway prints to the log on start, and a password
set on the Access tab. The password is kept in the config as a PBKDF2 hash and
survives a restart, unlike the token, which is new on every start unless it is
fixed by `-admin-token`.

Per domain it shows which proxies serve it, their latency, throughput, error
share, expected traffic share and status ("ok", "degraded", "banned until
14:32"), a live request log and a latency chart with hover details. A ban can
be lifted with one button without waiting it out. An empty panel shows how to
get started and the proxy address for the browser settings.

Light theme; dark follows the system setting or a button in the header.

Settings are split into tabs: **Proxies** (address, port, login, password,
country, comment; checked rows can be deleted, added to a list or removed from
one in bulk), **Lists** (pick proxies with checkboxes from the ones already
configured; a list can be renamed, references in rules follow) and
**Domains** (rule plus list from a dropdown). Changes are saved to the config
and applied immediately. There is a button to re-read the file if it was
edited by hand.

A provider's connection string — `socks5://user:pass@1.2.3.4:1080` — can be
pasted straight into the address field and is split into fields. A whole
purchase goes into the list import: it understands `ip:port:login:password`
and other common formats, assigns names, skips duplicates and shows which line
failed to parse. Imported proxies can go straight into a list.

Tables have search, and so does the proxy picker for lists: with fifty
upstreams there is no other way.

## MITM: see the requests

Optionally Fairway decrypts HTTPS the way Fiddler or Charles do: it issues
its own root certificate and signs site certificates with it on the fly.

```
fairway -export-ca fairway-ca.crt
```

Import the file into "Trusted Root Certification Authorities" on the machines
of your network (by group policy in a domain). Enabled per rule with
`"mitm": true`.

Why a load balancer needs it: in a tunnel only bytes are visible, and a 403 is
indistinguishable from a slow response. With decryption the real HTTP status
is visible, so a ban is detected precisely. The body is visible too: if the
site returned a Cloudflare, DataDome or Yandex challenge page or a captcha
instead of content, the proxy is banned for that domain just like on a 403,
even though the status was 200.

Good to know in advance:

- **Certificate pinning.** Banking and mobile software checks a specific
  certificate, not the chain — it will not connect through MITM. Set
  `"mitm": false` for such domains, the tunnel stays transparent.
- **Revocation checks.** A private CA has no CRL or OCSP. Browsers do not
  check revocation for private roots, but `curl` on Windows fails with
  `CERT_TRUST_REVOCATION_STATUS_UNKNOWN` — fixed by `--ssl-no-revoke`.
- **Firefox, Java and Python** keep their own certificate stores; the CA
  is added there separately.

The root key (`data/fairway-ca.key`) is the most valuable thing in the
installation: whoever gets it can sign certificates your whole network
trusts. File mode is 0600; do not expose the data directory.

## Docker

```
docker run -d --name fairway \
  -p 8080:8080 -p 127.0.0.1:8081:8081 \
  -v fairway-data:/data \
  ghcr.io/crasher69/fairway
```

Images for `linux/amd64` and `linux/arm64` are published to GitHub Container
Registry on every release. To build locally: `docker build -t fairway .`

The image is built on `scratch`: the binary, root certificates and time
zones. Publish the panel only on `127.0.0.1`. Docker publishes `-p 8080:8080`
on every interface past ufw, and a config created on first start allows
direct traffic: read [Security](#security) before running it on a public
host.

## Performance

On a local stand (everything on one Windows machine, 20 KB responses, one
pass through fairway with a `direct` upstream):

| mode | 100 connections | 500 connections |
|---|---|---|
| CONNECT tunnels | 65,000 req/s, 1.2 GB/s | 61,000 req/s |
| plain HTTP | 37,000 req/s, 700 MB/s | 33,000 req/s |
| MITM (decrypting) | 6,900 req/s, 130 MB/s | 6,700 req/s |

Tunnels cost two goroutines and about 40 KB of heap each; 500 MITM tunnels
take 157 MB because of TLS buffers on both sides. Plain HTTP goes through a
pool of keep-alive connections to the target. The stand is built entirely
from this repository (`cmd/benchtarget`, `cmd/loadgen`); method and details
in [docs/BENCHMARK.md](docs/BENCHMARK.md).

## Building

Only Go is needed — no cgo, no frontend build.

```
go build ./cmd/fairway          # for the current system
./build.sh 1.0.0                # release binaries for linux, windows, macOS
go test ./...
go generate ./cmd/fairway       # redraw the icon (after editing internal/brand)
```

The Windows build carries the icon inside the exe: the resource is built by
our own code in `internal/brand`, without external tools, and is already in
the repository.

## License

[Apache License 2.0](LICENSE). Use, modify and embed in closed products;
contributors explicitly license their patents. Keep the `LICENSE` and
`NOTICE` files when redistributing.
