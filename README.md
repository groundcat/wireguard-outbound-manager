# WireGuard Outbound Manager

WireGuard Outbound Manager (`wgom`) routes host-generated internet traffic through the healthiest WireGuard tunnel without replacing the server's main routes. Replies belonging to inbound connections continue to use the path on which those connections arrived, preserving SSH, web, and other listening services.

It is intended for Debian and Ubuntu servers managed by systemd. It coexists with `iptables-persistent`, nft-backed iptables, and Tailscale without flushing, saving, or taking ownership of their rules.

## Safety model

- `install.sh preflight` and `wgom preflight` are read-only.
- Installation does not start or enable the service.
- Tunnel configuration files must be root-only and are never copied into the repository.
- The main routing tables and existing firewall chains are not modified.
- Rules use dedicated `WGOM_*` chains, policy-table `51888`, priorities `6000/10000/10010`, and marks in `0x6d000000/0xff000000`. The inbound fallback is intentionally ordered after common overlay-network rules such as Tailscale's and before tunnel selection.
- Operation is opportunistic and fail-open. If every fallback is exhausted, policy routes are removed immediately, ordinary direct internet access is restored, and periodic tunnel probing continues.
- Graceful stop removes the interface, policy routes, rules, runtime files, and restores the changed runtime sysctl.
- Firewall ownership is reconciled every health interval, making the service resilient to a ruleset reload.
- Tailscale keeps control through its earlier policy rules. If the standard `cloudflared.service` cgroup is present, documented Cloudflare Tunnel edge networks are installed as `throw` routes ahead of the tunnel default. Those narrow destinations fall through to the main route so Cloudflare-delivered inbound traffic is not carried inside WireGuard.

Read [docs/DESIGN.md](docs/DESIGN.md) before deploying to a remote-only production host.

## Install

```sh
git clone https://github.com/groundcat/wireguard-outbound-manager.git
cd wireguard-outbound-manager
sudo ./install.sh preflight
sudo ./install.sh install
sudo install -o root -g root -m 600 provider.conf /etc/wireguard-outbound-manager/tunnels/provider.conf
sudo wgom preflight
sudo systemctl enable --now wireguard-outbound-manager
```

The installer installs missing packages, tests and builds the Go program, and installs a hardened systemd unit. It records which packages were missing but does not automatically remove packages later, because another application may begin relying on them.

The service capability set permits network administration, health probes, and privileged WireGuard listen ports. This supports hosts whose upstream firewall requires replies to return to a fixed local UDP port such as `443`.

## Operations

```sh
sudo wgom status
sudo journalctl -u wireguard-outbound-manager -f
sudo systemctl stop wireguard-outbound-manager
sudo ./install.sh uninstall
sudo ./install.sh uninstall --purge  # also deletes tunnel configurations
```

The default heartbeat is every 30 seconds. Health uses interface-bound ICMP with Cloudflare Trace HTTPS as a fallback for providers that suppress ICMP. After three consecutive failed probes, all other configurations are tested and the lowest-latency live candidate is activated. If none work, the service reports `waiting`, disconnects WireGuard, restores direct routing, and uses later heartbeat cycles to look for recovery. Cloudflare Trace records the direct and tunneled outbound IPs; a candidate is accepted only when the observed IP changes. Override service arguments with a systemd drop-in if required:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/sbin/wgom run -interval 30s -failures 3 -probe-ip 1.1.1.1
```

## Configuration constraints

Each `.conf` file uses normal `wg-quick` syntax and must contain `Address`, `PrivateKey`, `Endpoint`, and a peer accepting `0.0.0.0/0` (and `::/0` for IPv6 coverage). `Address`, `DNS`, `MTU`, `Table`, and hook directives are stripped before handing the configuration to `wg`; hooks are deliberately never executed. DNS settings are currently not changed, so the host's existing resolver remains in place and its requests follow the tunnel like other traffic.

## Limitations

- The manager covers the host network namespace. Separate container network namespaces require host forwarding and are not yet guarded by the output kill-switch.
- Cloudflare Trace (`https://www.cloudflare.com/cdn-cgi/trace`) must be reachable to verify an egress-IP change. Keep multiple independently reachable configurations.
- Unexpected power loss leaves only runtime kernel state, which disappears on reboot; the service reconstructs state on startup.

## Development

```sh
go test ./...
go vet ./...
go build ./cmd/wgom
```

Never add live WireGuard configurations to Git. Both `*.conf` and `config/*.conf` are ignored.
