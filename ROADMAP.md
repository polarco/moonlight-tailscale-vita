# Moonlight Tailscale roadmap

Last updated: 2026-09-01
Current release: 0.1.8
Local candidate: 0.2.0-dev; no release date committed

## Release truth

Version 0.1.8 is validated on a physical PCH-1001 over a LAN path through the
user-space WireGuard/lwIP gateway. Video, audio, controller input, keyboard
input, pause/resume, and clean teardown have worked in a real stream.

The external high-latency path is not approved. A previous test proved relay
delivery, WireGuard handshake, bidirectional transport, Moonlight HTTP, and
the first RTSP exchanges. Sunshine then closed the pending launch session near
its former 10-second timeout, producing error 104 on the Vita. Sunshine now
logs the effective value `ping_timeout = 30000`; no completed Vita attempt has
yet been recorded after that change.

This distinction controls every public claim and every release decision.

## Gate 1: remote functional smoke

Fixed test profile:

- 960×544;
- 30 FPS;
- 3,000 kb/s;
- frame pacing, remote optimization, and frame invalidation enabled;
- detailed logging disabled unless the first attempt fails.

Required result:

1. Start the application cold on a network outside the Sunshine LAN.
2. Open the Sunshine application list.
3. Start a stream and reach the first frame.
4. Verify video, audio, and at least one controller command.
5. Open and close the keyboard.
6. Keep the stream active for two minutes.
7. Pause/resume once and exit through the in-app Quit action.

Pass criteria:

- no RTSP error 104, 116, reset, or equivalent startup timeout;
- first frame appears;
- video, audio, and input all cross the tunnel;
- pause/resume and teardown complete without a crash;
- authentication or replay rejections do not grow continuously.

## Gate 2: stability and rekey

Run only after Gate 1 passes:

1. Complete three cold starts in succession.
2. Run one continuous stream for at least five minutes.
3. Exercise three pause/resume cycles.
4. Cross the WireGuard rekeys near 100 and 200 seconds.
5. Quit cleanly after every run.

Pass criteria:

- three of three cold starts reach the stream;
- no visible interruption during either rekey;
- no Vita crash, hang, or premature teardown;
- handshake and byte counters continue increasing in both directions.

## Gate 3: recovery

This gate blocks promotion of the local candidate to 0.2.0.

1. Interrupt the Vita hotspot for ten seconds during a stream.
2. Restore the same network.
3. Record whether the stream resumes, returns to the menu, or requires an app
   restart.
4. Repeat once after closing and reopening the application.

## Gate 4: LAN versus remote comparison

Use the same five-minute profile on LAN and remotely. Compare:

- time to first frame;
- video/audio stability;
- poor-connection indications;
- IDR requests, unrecoverable frames, and audio loss;
- WireGuard authentication/replay rejection counts;
- peer byte deltas before and after the session.

Poor quality with intact transport points first to relay latency or jitter.
Growing authentication/replay failures or deterministic shim failures point to
the Vita runtime.

## Decision tree after the next attempt

| Result | Engineering response |
|---|---|
| RTSP and stream pass | Complete Gates 2–4, then prioritize session telemetry |
| Error 104 still occurs near 10 seconds | Reconfirm the effective Sunshine configuration before changing Vita code |
| RTSP passes but no first frame appears | Inspect only the required video/audio UDP path and gateway forwarding |
| Stream works with poor quality | Measure latency/jitter and compare profiles before changing cryptography or bitrate defaults |
| Authentication/replay rejection grows | Reproduce with loss/reordering tests and fix the data path |
| Vita crashes | Collect sanitized application logs first; do not publish memory dumps |

## 0.2.0-dev host scope

Completed in the host-tested candidate:

1. Session telemetry: TX/RX totals, handshakes, rekeys, authentication failures,
   replay rejection, and a bounded end-of-session summary.
2. Peer/configuration parser tests covering valid, absent, truncated, and
   malformed inputs.
3. A socket-shim harness for `fcntl`, non-blocking connection, RTSP EOF,
   `poll`/`select`, and UDP timeout fallback behavior.
4. Replay-window tests for loss, duplicates, reordering, bursts, boundary
   values, and traffic outside the 8,192-packet window.
5. Longer host-side keepalive and rekey tests.
6. A separate workflow using the immutable
   `vitasdk/vitasdk:2026.08-20260815` image, ShellCheck 0.11.0 and actionlint
   1.7.7.
7. VPK verification that requires VPK, ELF and `eboot.bin` from the same build,
   compares the packaged executable byte for byte, and rejects malicious
   archive fixtures.

The local VPK is a **candidate not physically validated**. It must not replace
the public 0.1.8 release or be described as approved.

## Promotion gate: 0.2.0

Promotion requires all of the following on the physical Vita:

1. Install the candidate and read back `eboot.bin` and `param.sfo`.
2. Reach the first frame over the remote path.
3. Verify video, audio, and controller input.
4. Maintain the stream for two minutes.
5. Pass three consecutive cold starts.
6. Stream for five minutes, crossing rekeys near 100 and 200 seconds.
7. Recover after a ten-second hotspot interruption.

No 0.2.0 runtime change is considered approved before those gates pass.

## Non-goals

Version 0.2.0 will not attempt to provide:

- Tailscale control-plane login or device registration;
- DERP, MagicDNS, tailnet ACL management, or automatic key rotation;
- automatic public relay, router, or firewall provisioning;
- embedded private keys, operational peer files, personal endpoints, pairing
  certificates, or Sunshine credentials;
- a universal remote-streaming claim before the gates above pass.

## Safe evidence for issues

Useful evidence includes timestamps, sanitized application logs, session
counter deltas, error codes, and whether each gate step passed. Never publish
private keys, real peer files, pairing certificates, personal endpoints,
credentials, or console memory dumps.
