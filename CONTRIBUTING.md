# Contributing

Contributions are welcome through issues and pull requests.

## Development flow

1. Fork the repository and create a focused branch.
2. Run `./scripts/test-host.sh`.
3. If VitaSDK is available, run `./scripts/build-moonlight.sh`.
4. Do not commit `.deps/`, `build/`, `dist/`, VPKs, keys, peer files, pairing
   data, console dumps, or unsanitized logs.
5. Explain the behavior change and physical Vita validation in the PR.

Keep dependency revisions pinned. Changes to upstream commits or patches must
include the reason, license impact, and reproducibility notes.

By contributing, you agree that your contribution is licensed under GPL-3.0.
