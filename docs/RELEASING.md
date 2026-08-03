# Releasing a3s-sentry

Sentry ships independently versioned Rust, TypeScript, and Python distributions. A tag is a
production action: never use a release tag to test a candidate, never move a published tag, and
never run `git push --tags`.

| Distribution | Version source | Tag | Result |
|---|---|---|---|
| Rust crate, Linux binary, GHCR image | `Cargo.toml` | `vX.Y.Z` | crates.io, GitHub Release, GHCR |
| TypeScript native SDK | `sdk/typescript/package.json` | `ts-vX.Y.Z` | npm |
| Python native SDK | `sdk/python/Cargo.toml` | `python-vX.Y.Z` | PyPI when configured, GitHub Release |

## Prepare the release in commits

The release-preparation commit may live on the feature branch when the feature is ready to ship, or
on a short-lived follow-up branch. Before review:

1. Update the root crate version in `Cargo.toml`.
2. Refresh `Cargo.lock`, `sdk/typescript/Cargo.lock`, and `sdk/python/Cargo.lock`.
3. Keep the TypeScript and Python package versions independent from the root crate version.
4. Move shipped changes from `[Unreleased]` to a dated version in `CHANGELOG.md`.
5. Update the published installation examples in `README.md`.
6. Run the local checks used by CI and the release workflows.

For the `0.8.0` release, the expected versions are:

```text
a3s-sentry                 0.8.0
@a3s-lab/sentry            0.3.0
a3s-sentry-py              0.2.0
```

## Local preflight

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
cargo publish --locked --dry-run
cargo build --release --locked --bin sentry --target x86_64-unknown-linux-musl
target/x86_64-unknown-linux-musl/release/sentry --version

cd sdk/typescript
npm ci
npm run build
npm test
npm pack --dry-run --json
```

The binary version must match the root `Cargo.toml` version. The dry run must package and verify the
new version, not an already-published version.

## GitHub full-platform preflight

Push the candidate commit and open or update its pull request. The `release-preflight` workflow runs
on the pull request without registry credentials and performs no publication. It:

- verifies version metadata, lockfiles, changelog entries, and unused release tags;
- runs Rust formatting, Clippy, tests, and `cargo publish --dry-run`;
- builds and uploads the static Linux musl binary and SHA-256 file;
- builds TypeScript bindings on Linux x64, macOS ARM64, and Windows x64;
- assembles the npm tarball, verifies all three native bindings, and installs it in a clean consumer.

Review the workflow summary and download the retained artifacts before approving the release commit.
After merging the reviewed commit, open **Actions → release-preflight → Run workflow**, select
`main`, and run it once more before creating any tag. A manual run repeats the full preflight and
also authenticates `CARGO_TOKEN` and `NPM_TOKEN` without publishing. Registry credentials are never
exposed to pull-request runs.

## Publish explicitly and sequentially

After the reviewed release commit is on `main`, update local refs and verify that local `main` is
exactly `origin/main`:

```bash
git fetch origin --prune --tags
git switch main
git pull --ff-only origin main
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
```

Record the reviewed commit, create an annotated Rust tag, inspect it, and push only that tag:

```bash
SENTRY_RELEASE_SHA=$(git rev-parse origin/main)
git tag -a v0.8.0 "$SENTRY_RELEASE_SHA" -m "release: a3s-sentry v0.8.0"
git show --no-patch --decorate v0.8.0
git push origin refs/tags/v0.8.0
```

Wait for every `release` job to succeed, then verify crates.io, the Linux GitHub Release asset, and
the versioned and `latest` GHCR images. Only then publish TypeScript from the same reviewed commit:

```bash
git tag -a ts-v0.3.0 "$SENTRY_RELEASE_SHA" \
  -m "release: publish @a3s-lab/sentry 0.3.0"
git show --no-patch --decorate ts-v0.3.0
git push origin refs/tags/ts-v0.3.0
```

Verify all three native build jobs, the publish job, and a clean install of the exact npm version.
Publish Python separately with `python-vX.Y.Z` when its release is in scope.

If publication exposes a defect, fix it in a new patch release. Do not delete, move, or force-push
an existing tag, and do not attempt to overwrite an immutable registry version.
