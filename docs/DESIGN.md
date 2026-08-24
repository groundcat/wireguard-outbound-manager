# Design and recovery

## Packet paths

For a new locally generated connection, policy rule `10000` selects table `51888`, whose default route is `wgom0`. WireGuard's own UDP socket carries mark `0x6d100000`, so it bypasses that rule and reaches its endpoint through the unchanged main table.

For a connection arriving on a non-tunnel interface, `WGOM_INBOUND` stores connection mark `0x6d000000`. The output mangle hook restores that mark on replies, and priority `6000` selects the main table. This includes SSH and web responses. Existing overlay rules at earlier priorities, including Tailscale's table lookup, retain first refusal so overlay sessions follow their own return path.

When `/sys/fs/cgroup/system.slice/cloudflared.service` exists, table `51888` receives `throw` routes for Cloudflare Tunnel's documented IPv4 edge networks (`198.41.192.0/24`, `198.41.200.0/24`) and IPv6 edge network (`2606:4700:a0::/48`). Those destinations fall through to the main table at route lookup time, keeping tunnel transport direct without relying on late packet marks.

There is no output filter or kill switch. When no tunnel is healthy, the manager removes its policy rules and the unchanged main table provides normal direct connectivity.

## Selection and failure handling

Each configuration is brought up temporarily in an isolated probe table and tested with interface-bound ICMP. If ICMP is suppressed, an interface-bound Cloudflare Trace HTTPS request provides the connectivity result instead. Probe rules use priorities `9000+`, ahead of active-tunnel selection at `10000`, so fallback candidates remain testable while the current tunnel is unhealthy. Successful candidates are ordered by measured elapsed time. The best candidate becomes `wgom0`. Cloudflare Trace then confirms that its egress IP differs from the direct baseline. A heartbeat repeats the probe every 30 seconds; three consecutive failures trigger selection among the remaining candidates. If none work, WireGuard and its policy rules are removed; later heartbeat cycles probe for recovery while direct internet remains available.

## Transactionality

Interface configuration uses a root-only file under `/run`. Failed interface setup deletes the partial interface. Policy setup happens only after a candidate passes a live probe. SIGTERM cleanup deletes only known priorities, table `51888`, `WGOM_*` chains, and `wgom0`; no `iptables-save` operation occurs.

## Emergency recovery

Use a provider console if remote access behaves unexpectedly:

```sh
systemctl stop wireguard-outbound-manager
ip link delete wgom0 2>/dev/null || true
ip -4 rule delete priority 10000 2>/dev/null || true
ip -4 rule delete priority 10010 2>/dev/null || true
ip -4 rule delete priority 6000 2>/dev/null || true
iptables -t filter -D OUTPUT -j WGOM_OUTPUT 2>/dev/null || true
iptables -t filter -F WGOM_OUTPUT 2>/dev/null || true
iptables -t filter -X WGOM_OUTPUT 2>/dev/null || true
```

Stopping the service normally performs IPv4 and IPv6 cleanup automatically.
