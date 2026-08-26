# Moonlight Tailscale for PS Vita

Experimental PS Vita client that runs Vita Moonlight traffic through a static
WireGuard tunnel implemented in user space with lwIP.

The current release is **0.1.8**. It has been tested on a PCH-1001 with video,
audio, controls, and input over a WireGuard gateway.

> [!IMPORTANT]
> This is not a complete Tailscale client. It does not implement Tailscale's
> control plane, node registration, DERP, MagicDNS, or key rotation. The
> current build uses one static WireGuard peer configured on the Vita.

## What it provides

- Vita Moonlight 0.13.2 with a user-space WireGuard/lwIP network path.
- Persistent WireGuard identity generated and stored on the console.
- Static IPv4 peer configuration loaded from `ux0:data/TailscaleVita/`.
- TCP and UDP socket adaptation for Moonlight/GameStream traffic.
- An 8,192-packet WireGuard replay window for reordered streaming traffic.
- Host-side cryptographic, packet, and lwIP self-tests.
- Reproducible dependency pins and patches.

## Console configuration

The application expects:

```text
ux0:data/TailscaleVita/wg-private.key
ux0:data/TailscaleVita/wg-peer.conf
```

`wg-private.key` is a 32-byte private key. Never share or commit it.

The peer file contains only the gateway's public key and a numeric IPv4
endpoint:

```ini
peer_public_key=BASE64_GATEWAY_PUBLIC_KEY
endpoint_ip=203.0.113.10
endpoint_port=51820
```

The tunnel uses `10.77.0.2/24` on the Vita and MTU 1280. The gateway commonly
uses `10.77.0.1/24` and must forward only the required Sunshine ports.

## Build

Requirements:

- Git, CMake, a C11 compiler, and standard Unix build tools;
- [VitaSDK](https://vitasdk.org/) with `VITASDK` exported;
- Vita Moonlight build dependencies such as `libvita2d` and zstd.

```sh
export VITASDK=/path/to/vitasdk
export PATH="$VITASDK/bin:$PATH"
./scripts/build-moonlight.sh
```

The script fetches pinned revisions of Vita Moonlight, wireguard-lwip, and
lwIP, applies the repository patches, builds the VPK, and verifies that no
identity or peer configuration entered the package.

Run host-side tests without VitaSDK:

```sh
./scripts/test-host.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes.

## Current limitation on high-latency links

Sunshine's default `ping_timeout` is 10 seconds. A remote path with roughly
one second of RTT may not finish the sequential RTSP setup before that launch
session expires. On trusted personal hosts, increasing Sunshine's setting to
`ping_timeout = 30000` can provide enough setup time.

## Security

- No private key, peer file, pairing certificate, or user log is included in
  the source tree or VPK.
- The default design uses a restricted gateway instead of exposing Sunshine
  directly to the Internet.
- Logs should be reviewed and sanitized before being attached to an issue.

Please report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## License and trademarks

This project is licensed under the [GNU GPL v3](LICENSE), matching Vita
Moonlight and moonlight-common-c. Third-party notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

This independent project is not affiliated with or endorsed by Tailscale Inc.,
Moonlight, Sunshine, Sony Interactive Entertainment, or their contributors.
Tailscale and other names are trademarks of their respective owners.
