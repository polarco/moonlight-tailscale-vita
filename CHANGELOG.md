# Changelog

## [0.1.8] - 2026-08-25

### Added

- User-space WireGuard/lwIP transport integrated with Vita Moonlight 0.13.2.
- Static peer configuration and persistent on-device identity.
- TCP/UDP socket compatibility layer for Moonlight traffic.
- Host-side WireGuard, IPv4/UDP, and lwIP tests.

### Fixed

- Expanded the WireGuard replay window from 32 to 8,192 packets to tolerate
  reordered streaming traffic.
- Separated authentication and replay rejection diagnostics.
- Added a larger external UDP receive buffer and bounded diagnostic logging.
- Implemented Vita-compatible polling and UDP timeout behavior for RTSP and
  stream startup.

### Security

- The VPK verification step rejects embedded private keys and peer files.
- Dependency revisions are pinned and patches are applied reproducibly.
