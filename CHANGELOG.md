# Changelog

## [Unreleased]

### Added

- Added a strict, length-aware peer parser with stable error codes.
- Added deterministic keepalive/rekey scheduling and bounded per-session
  telemetry without endpoints, keys, certificates, or payloads.
- Added production `socket_shim.c` host coverage with fake lwIP/Vita time.
- Added malicious VPK fixtures, frozen VitaSDK container builds, sanitizers,
  ShellCheck 0.11.0, actionlint 1.7.7, and a sanitized infrastructure
  healthcheck.

### Fixed

- Corrected the replay history to exactly 8,192 positions using a 257-word
  modulo ring: age 8,191 is accepted and age 8,192 is rejected.
- Centralized runtime versioning at `0.2.0-dev` and removed the 0.1.8 build-name,
  SFO, and runtime-log constants.
- Added the narrow OpenSSL 1.0 compatibility surface required by the frozen
  VitaSDK image's cURL archive.

### Release status

- Kept public release 0.1.8 unchanged.
- Classified the locally built 0.2.0-dev VPK as a candidate not physically
  validated.

### Documentation

- Added a dated, evidence-based current-state section that distinguishes
  validated LAN streaming from the still-pending remote smoke test.
- Documented the last remote RTSP failure, the effective 30-second Sunshine
  timeout, and the exact claim that remains unproven.
- Added a gated roadmap for remote smoke, stability/rekey, recovery, candidate
  0.2.0 engineering work, and explicit non-goals.
- Added `ROADMAP.md` as the detailed source of truth for release decisions.

### Presentation

- Added original project artwork and a redesigned GitHub landing page.
- Added build, license, release, and CI badges plus an architecture diagram,
  capability matrix, quick installation path, and clearer project scope.
- Added structured issue forms and a pull request template with prominent
  secret-handling guidance.

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
