# Reproducible Builds

Loupe is distributed as a **single signed HTML file** (`loupe.html`). A
reproducible build is the mechanism that lets you — or any third party —
verify that the byte sequence inside that file was produced by the source
tree at a specific commit, **without having to trust the build
infrastructure**.

Given the same commit, `python scripts/build.py` is expected to emit a
byte-identical `docs/index.html`. Two contributors on two machines at the
same commit should get the same SHA-256. The CI build job on every push
rebuilds with the same pinned environment the release pipeline uses, so
an auditor's local rebuild matches the signed release asset byte-for-byte.

`docs/index.html` is **not committed to the repository** — it is only ever
produced by CI (for deployment and signing) or locally by contributors
(for smoke-testing). This document is the recipe for recreating it from
any tagged source tree.

## Who this is for

| Reader | Why you'd read this |
|---|---|
| **Loupe user** who downloaded `loupe.html` and wants to verify it | Run the recipe below, compare your SHA-256 to the release asset |
| **Distributor / packager** (e.g. AUR, Homebrew tap) | Confirm you can rebuild from source and ship the same bytes |
| **Auditor** | Independently verify the source → artefact mapping without trusting our CI |
| **Contributor** | Avoid introducing non-determinism (see "Non-determinism rules" below) |

## The recipe

```sh
# 1. Clone at the exact release tag you want to verify.
git clone https://github.com/Loupe-tools/Loupe
cd Loupe
git checkout v20260420.1402       # substitute the release tag

# 2. Rebuild.
#    The build script auto-derives SOURCE_DATE_EPOCH from HEAD's
#    commit-author timestamp when the env var isn't set, so the
#    explicit export is optional for a plain git checkout — it's
#    included here to mirror exactly what CI does.
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD) \
  TZ=UTC LC_ALL=C.UTF-8 \
  python scripts/build.py

# 3. Compare to the signed release asset you downloaded.
sha256sum docs/index.html loupe.html
```

If both hashes match, the signed `loupe.html` on the release page
corresponds exactly to the source tree at that commit. If they differ,
either the signed asset was rebuilt from a different source state, or
something in your local environment (Python version, line-ending
handling, locale) has perturbed the output — see "Non-determinism rules".

The release workflow records the exact commit hash and `SOURCE_DATE_EPOCH`
it used in every release's notes, so you never have to guess which epoch
was in play.

## What `SOURCE_DATE_EPOCH` controls

| Field | Without `SOURCE_DATE_EPOCH` (non-git archive) | With `SOURCE_DATE_EPOCH` *or* a git checkout |
|---|---|---|
| `LOUPE_VERSION` (embedded in bundle, shown in UI) | `datetime.now()` — local wall clock | `datetime.fromtimestamp(epoch, tz=UTC)` |
| Everything else in the bundle | Byte-identical across builds | Byte-identical across builds |

Only the version string is time-derived. The rest of the bundle is a
deterministic concatenation of files read in a fixed order from
`scripts/build.py`.

When `SOURCE_DATE_EPOCH` is unset, `scripts/build.py` falls back to
`git log -1 --format=%ct HEAD` automatically if the working tree is a
git checkout. This makes `python make.py` in a clone reproducible
without the contributor having to think about the env var. The
wall-clock fallback only kicks in for source archives (ZIP / tarball)
where git metadata is unavailable.

## Non-determinism rules (for contributors)

Any change that adds a time-, host-, locale-, or randomness-derived byte
to `docs/index.html` will break reproducibility. The CI build job
rebuilds with a pinned environment (`TZ=UTC`, `LC_ALL=C.UTF-8`,
`SOURCE_DATE_EPOCH` from HEAD) on every push, so a change that only
looks deterministic on the author's machine but drifts under the CI
environment will show up in the CI build SHA-256 in the job summary
and can be diffed against a local rebuild.

When in doubt, ask: *"if I ran this build on a different machine one
week from now, would the output differ?"*

The rules are short but strict:

- **No `datetime.now()`** in `scripts/build.py` or any generator it runs,
  except the one gated `SOURCE_DATE_EPOCH` fallback that already exists.
- **No file-system iteration order.** When concatenating files,
  enumerate them from an explicit hardcoded list (as `JS_FILES`,
  `CSS_FILES`, `YARA_FILES` do in `build.py`). Never walk a directory
  and trust the OS iteration order.
- **No random IDs, UUIDs, or nonces** written into the bundle. If you
  need a stable identifier, derive it deterministically from file
  contents (e.g. SHA-256 of the input, or the VENDORED.md pin list as
  `scripts/generate_sbom.py` does for the CycloneDX serial number).
- **No machine-local paths** embedded in output. `build.py` already
  reads files with relative paths; keep it that way.
- **No dict/set ordering that relies on hash randomisation.** Modern
  Python preserves insertion order for dicts, but writing sets to the
  bundle is unsafe; sort first.

## What reproducibility does *not* buy you

This is worth being honest about so users don't over-rotate on it.

- **Reproducibility ≠ authenticity.** A matching SHA-256 proves the
  bytes correspond to a source tree, not that the source tree is the
  canonical Loupe release. Always cross-check against the Sigstore
  signature (`loupe.html.sigstore`) anchored to this repo's
  `release.yml` workflow identity — see README § *Verify your download*.
- **Reproducibility ≠ safety.** Loupe's security properties (offline,
  CSP-sandboxed, no eval) come from the source, not from reproducibility.
  See `SECURITY.md` for the threat model.
- **It is not a bootstrap proof.** Building requires Python 3.x on your
  machine; a hostile Python interpreter could produce different bytes.
  Reproducibility from *the same Python* is what this recipe guarantees.

## CI enforcement

The [`ci.yml`](.github/workflows/ci.yml) **Build** job runs on every
push to `main` and on pull requests. It builds with the same pinned
environment the release pipeline uses (`SOURCE_DATE_EPOCH` from HEAD,
`TZ=UTC`, `LC_ALL=C.UTF-8`) and writes the resulting SHA-256 to the
job summary. The built bundle is uploaded as a retained artefact so
reviewers can diff against their own local rebuild from the same
commit. Any PR that perturbs determinism will show a different hash
in its job summary than a clean rebuild from the same commit produces.

The [`release.yml`](.github/workflows/release.yml) workflow is the
canonical build: it rebuilds from source on the runner (never from a
committed artefact), records the commit hash and epoch in the release
notes, and Sigstore-signs the resulting bytes.

## Related documents

- `SECURITY.md` — threat model, CSP, parser sandboxing
- `VENDORED.md` — SHA-256 pins for every third-party library
- `CONTRIBUTING.md` — build order, coding conventions, persistence keys
- `scripts/generate_sbom.py` — CycloneDX 1.5 SBOM from `VENDORED.md`
