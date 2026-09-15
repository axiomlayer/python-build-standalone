# AxiomLayer managed Python integration

This directory is the build-provider boundary between the preserved
`astral-sh/python-build-standalone` fork history and the interpreter installed
for Pyr by `AxiomLayer/dotfiles` PR #49.

`managed-python.json` binds all of the following independently:

- upstream tag `20260901` and commit
  `4bb01f09aaf362c71e891be4a41cb6d6ddf830b3`;
- the exact promotion policy, candidate, and runtime manifest at the full
  dotfiles commit recorded in the contract, preserved as byte-exact snapshots
  because a fork-scoped token cannot read the private control-plane repository;
- all six macOS, Linux, and Windows `install_only` archives, their release
  sizes, archive SHA-256 values, renamed AxiomLayer delivery URLs, and
  extracted interpreter SHA-256 values;
- CPython 3.14.7, `tomllib`, and a working SQLite FTS5 virtual table on every
  native architecture.

The locked Nix check treats every archive and every dotfiles input as a fixed-output
input with an independently checked SHA-256. Native hosted jobs then execute each managed interpreter on its
matching architecture. These jobs only read public build inputs; they have no
publisher credentials, signing permissions, environments, or deployment path.
The workflow runs on every fork change and weekly, so upstream-sync PRs cannot
bypass the provider boundary and removed or corrupted release assets are
detected without waiting for a device install.

Run the contract verifier without Nix:

```console
python3 axiomlayer/verify_managed_python.py contract --verify-git
python3 axiomlayer/verify_managed_python.py artifact --platform darwin-aarch64
```

Run the fixed-output integration check on Linux with Nix:

```console
nix flake check --print-build-logs
```

The inherited upstream workflows are retained for clean history, but their
root jobs are repository-bound to `astral-sh/python-build-standalone`. The
AxiomLayer fork therefore runs only its explicitly named integration workflow;
the inherited release workflow cannot create releases, attestations, mirrors,
or `astral-sh/versions` changes from this fork.

Refresh the three snapshots only from the `consumer.commit` named in
`managed-python.json`, then update both its raw SHA-256 and Nix SRI. A snapshot
whose bytes differ from that contract fails before any interpreter executes.
