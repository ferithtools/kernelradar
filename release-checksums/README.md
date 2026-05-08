# Release checksums

In-repository pin of SHA-256 checksums for every published release.

Whenever a binary tarball is uploaded to
`https://github.com/ferithtools/kernelradar/releases/`, the matching
`SHA256SUMS-inner.txt` and `<tarball>.sha256` files in this directory
record the exact bytes the maintainer signed off on.

## Why

GitHub release artifacts are mutable in principle - an attacker who
compromises the maintainer account, the GitHub infrastructure, or
your network path can swap the binary. With the checksums committed
into the source tree, anyone (and any cron job) can verify the
published archive against the value the maintainer pushed at release
time, without trusting GitHub.

## How to verify a downloaded tarball

```bash
VER=v0.1.1
ARCH=linux-x86_64
TARBALL="kernelradar-${VER#v}-${ARCH}.tar.gz"

# 1. Pull the release.
curl -fsSLO "https://github.com/ferithtools/kernelradar/releases/download/${VER}/${TARBALL}"

# 2. Pull the matching pin from this directory.
EXPECTED=$(curl -fsSL "https://raw.githubusercontent.com/ferithtools/kernelradar/${VER}/release-checksums/${VER}/${TARBALL}.sha256" | awk '{print $1}')

# 3. Compare.
ACTUAL=$(sha256sum "$TARBALL" | awk '{print $1}')
if [ "$EXPECTED" = "$ACTUAL" ]; then
    echo "OK - tarball matches in-repo pin"
else
    echo "MISMATCH - do NOT install. Possible tampering."
    exit 1
fi
```

After extracting, you can additionally verify every file inside:

```bash
tar -xzf "$TARBALL"
( cd "kernelradar-${VER#v}-${ARCH}" && sha256sum -c SHA256SUMS )
```

## What's pinned per release

For each `vX.Y.Z` directory:

- `kernelradar-X.Y.Z-linux-<arch>.tar.gz.sha256` - checksum of the
  outer tarball (one line, `<sha> <name>` format produced by
  `sha256sum`).
- `SHA256SUMS-inner.txt` - checksums of every file inside the
  tarball (binary, `.bpf.o` files, `.service`, `LICENSE`, `README`,
  `install.sh`, `config.toml.example`).

A future release will add a `verify-remote.sh` script that
periodically pulls the release artifact and re-checks against this
pin from a different host, alerting on mismatch.
