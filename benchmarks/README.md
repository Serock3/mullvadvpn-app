# Mullvad app system benchmarks

This is a separate Cargo workspace containing the benchmark definitions for this
repository. The shared runner and temporary result artifacts live in the sibling `benchy`
repository.

Run the default benchmark set through `benchy-cli` from `benchy`, or run a benchmark
directly:

```console
cargo run --release --locked \
  --manifest-path benchmarks/Cargo.toml \
  --package masque-throughput-benchmark
```

## Benchmarks

- `masque-throughput` — UDP iperf3 through the `mullvad-masque-proxy` examples. The
  iperf3 datagrams (1100 bytes) fit inside the MASQUE client MTU.
- `masque-fragmentation` — the same setup with 2200-byte datagrams, forcing the proxy to
  exercise its fragmentation path.
- `wg-over-masque` — a kernel WireGuard tunnel carried over the MASQUE proxy, measured
  with TCP iperf3.

All benchmarks run on the controller host and drive the peer over SSH, mirroring the
GotaTun throughput benchmark in the `gotatun` repository. The proxies under test are
built from this checkout with `cargo build --release --locked -p mullvad-masque-proxy
--example masque-server --example masque-client` and the client is deployed to the peer
from there. The server uses the self-signed example certificate that ships with the
proxy. The current example client does not verify the server certificate; this setup
is suitable only for the isolated benchmark link.

## Measurements

The UDP benchmarks record `throughput.sender`, `throughput.receiver`, `udp.jitter`, and
`udp.lost_percent`, using whichever summaries the installed iperf3 reports. The
WireGuard benchmark records `throughput.sender`, `throughput.receiver`, `cpu.iperf.up`,
and `cpu.iperf.down`, where UP is the peer sending towards the controller.

## Configuration

Configuration is read at runtime:

- `BENCHY_PEER` (default `mole@10.0.0.2`)
- `BENCHY_ALICE_ADDRESS` (default `10.0.0.1`)
- `BENCHY_BOB_ADDRESS` (default `10.0.0.2`)
- `BENCHY_MASQUE_SERVER_PORT` (default `9020`)
- `BENCHY_MASQUE_CLIENT_PORT` (default `9010`)
- `BENCHY_IPERF_PORT` (default `9030`)
- `BENCHY_WIREGUARD_PORT` (default `51821`)
- `BENCHY_INTERFACE` (default `bench0`)
- `BENCHY_DURATION` (default `30` seconds)
- `BENCHY_MASQUE_MTU` (default `1280`)
- `BENCHY_TUNNEL_MTU` (default `1280`)

The controller needs Rust, `iperf3`, `ssh`, `scp`, and, for `wg-over-masque`, the `wg`
tool plus passwordless `sudo` for the narrow `ip` and `wg setconf` operations. The peer
needs `iperf3`, `socat`, `bash`, `wg`, and the same passwordless sudo operations. The
`wg-over-masque` benchmark additionally requires kernel WireGuard on both hosts.

iperf3's TCP control channel cannot traverse the UDP-only proxy, so the UDP benchmarks
relay it directly to the server with `socat` on the peer. WireGuard key material is
generated for each run with `wg genkey`/`wg genpsk`. The temporary local config has
mode `0600` and is deleted after it is applied; the remote config is written inside a
mode `0700` scratch directory and removed during benchmark cleanup.
