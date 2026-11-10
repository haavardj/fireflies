# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Fireflies: a Byzantine-tolerant, scalable group membership protocol and toolkit for peer-to-peer overlays (Håvard Dagenborg, ~2006–2014). Each member keeps a weakly consistent view of all members; redundancy masks Byzantine faults so malicious members can neither declare live members crashed nor crashed members live. The protocol is specified in the ACM TOCS 2015 paper (doi:10.1145/2701418), cited in [README.md](README.md); the code has not yet been checked against it.

Constraints that matter before editing:

- **Python 3.10+.** Ported from Python 2.7 in 2026. Dependencies: Twisted, `cryptography`, pyOpenSSL (via Twisted's TLS). The `setrecon` C++ extension needs a C++ compiler, NTL and GMP (`build-essential libntl-dev libgmp-dev python3-dev` on Ubuntu); SWIG comes from PyPI at build time. The extension does not build on Windows; use WSL/Linux for gossip.
- Licensing: MIT ([LICENCE](LICENCE)), except the set reconciliation C++ in `fireflies/setrecon/` (Agarwal and Trachtenberg, Boston University; GPL v2, [COPYING](fireflies/setrecon/COPYING)). Do not copy code between these and the MIT files. See [README.md](README.md).
- History was converted from SourceForge CVS (2006–2014) with `cvs-fast-export`; CVS tags such as `rel-0-2` are git tags.

## Build and test

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                       # builds fireflies.setrecon._setreconbase (Linux/WSL)
FIREFLIES_NO_EXT=1 pip install -e .    # skip the C++ extension (Windows): everything but gossip works
```

Tests use Twisted Trial:

```sh
python -m twisted.trial fireflies.test                                     # all tests
python -m twisted.trial fireflies.test.test_ring                           # one module
python -m twisted.trial fireflies.test.test_ring.NumberedRingQueryTest.testPred   # one test
```

`test_setrecon` skips itself when the extension is not built. `test_tls` runs real TLS handshakes over loopback. `test_wire` covers the wire format, group state and persistence for both RSA and EC keys.

## Running a group

The tools are console scripts declared in `pyproject.toml` (`[project.scripts]`); their code is in [fireflies/cli/](fireflies/cli/), one module per tool with a `main()`. Key passwords: `--password`, `--nopass`, or a terminal prompt.

1. `ffcanew <path>`: create a group CA. Options `-p` (P_byz, default 0.20), `-s` (max group size, default 1000) and `-e` (tolerance) determine the number of monitoring and gossip rings, which are encoded into the CA certificate's `O=` field as `"<monitoring> <gossip>"` (read back by `Group.nrMonitoringRings()` / `nrGossipingRings()`). Ring-count formulas are in [fireflies/util.py](fireflies/util.py) (`numMembershipRings`, `numGossipRings`).
2. `ffreq` / `ffcasign` / `ffcamember`: request and sign member certificates. A member certificate carries the member's `ip:port` in the `L=` attribute.
3. `fireflyd <store> [<extra stores>...]`: run a member. `--capriv <keyfile>` lets the daemon mint its own certificate from the CA key (testing only). `-b <file>` marks Byzantine members, `--ec` uses EC keys. Default port 14377 (TCP for gossip, UDP for the failure detector).

Store layout (see [fireflies/persist.py](fireflies/persist.py)): `<path>/cacert.pem`, `<path>/private/cakey.pem`, `<path>/private/<keyid>.pem` (PKCS#8 PEM), `<path>/certs/<ip:port>.pem` (`:` becomes `_` on Windows), plus pickled notes and accusations.

## Architecture

Twisted service tree, wired up in [fireflies/cli/fireflyd.py](fireflies/cli/fireflyd.py):

- **`group.Group`** (`MultiService`): the runtime entry point. Holds the CA cert, own key/cert, the `View`, the TLS options (`getTLSOptions()`), and an event bus (`registerEventHandler` with events `member.crash`, `member.recover`, `data.note`, `data.accusation`, `data.certificate`; handlers run via `reactor.callLater(0, ...)`). Also auto-rebuts accusations against itself (`evSelfRebuttal`).
- **`fd.FailureDetector`** (`Service`, child of Group): pings monitoring-ring successors over signed UDP (`PingPong`); after enough unanswered pings it creates and signs an `Accusation`. One `ExpSmoothedTimeoutPolicy` per monitored member holds the adaptive timeout (smoothed loss estimate, threshold from `pMistake`). A pong counts only if it echoes the random nonce of an unanswered ping and is signed by the pinged member (`acceptPong`); rejected pongs increment `stats.pongsRejected`.
- **`gossip.Gossip`** (`Service`, child of Group): TLS gossip with ring neighbours on the gossip rings. Keeps three `setrecon.ReconSet`s (certificates, notes, accusations) mirrored from Group data events and exchanges only the differences via set reconciliation. `gossipsim.py` is a simulation variant of the same. Importing either calls `setrecon.init()`, which can run only once per process.
- **`view.View`**: the member's view. `pRing` (all), `aRing` (live), `fRing` (failed), plus `mRings`, a `RingSet` of `NameHashedRing`s used for monitoring. Contains the accusation rules (`canAccuse`: an accuser must be a valid predecessor of the accused on some monitoring ring) and the rebuttal timer (`Group.tRebuttal`): an accused member that publishes no newer note before the timer fires is declared failed.
- **`state`**: signed data objects. `Member` (wraps a member cert; compares and hashes by identity), `Note` (member-signed, epoch-numbered liveness record with a ring mask enabling/disabling accusations per ring; equality is object identity), `Accusation` (signed by the accuser, bound to the accused's current note; compares by fingerprint).
- **`ring`**: `Ring` (sorted, wraps around), `NameHashedRing` (order by hash of ring number + identity, so each ring gives a different random permutation), `RingSet`, `RankTable`, successor/predecessor relations.
- **`crypto`**: wrappers around `cryptography` that keep M2Crypto-style method names: `Certificate`, `CertificateRequest`, `PrivateKey`, `PublicKey`. RSA-2048 or EC P-256 (TLS 1.3 rules out the P-224 curve used before), SHA-256 signatures. A member's identity is the SHA-256 subjectKeyIdentifier of its public key, as upper-case hex. `Signable` mixin signs `uidstr()`; used by `Note`, `Accusation` and FD messages.
- **`packer`** + **`xdr`**: XDR wire format (`FirefliesPacker`/`Unpacker`) for notes, accusations, certs and setrecon vectors. `xdr.py` replaces the `xdrlib` module removed in Python 3.13.
- **`protocols`**: TLS helpers (`makeSSLCtx` returns Twisted `CertificateOptions` requiring a peer certificate signed by the group CA; `connect`, `listen`), `ReconnectingPeerFactory`, `PeerServerFactory`, and `FirefliesProtocol` (an `Int32StringReceiver` base for gossip). After the handshake, `FirefliesProtocol.handshakeCompleted` maps the peer certificate to a `Member` and checks it is the expected one.
- **`setrecon`**: Python wrapper ([setrecon.py](fireflies/setrecon/setrecon.py)) over the SWIG-generated `setreconbase` (C++ probabilistic set reconciliation in `*.cpp`, interface in `setreconbase.i`). Byte strings cross the boundary as Python `bytes` (`ZZ.toBytes()`, `to_ZZFromBytes()`); the Python-3 comparison operators for `ZZ`/`ZZ_p` are added in `setrecon.py`. Call `setrecon.init()` once before use.
- **`stats`**: global counters registered by index in [fireflies/__init__.py](fireflies/__init__.py) via `addStatistic`; new counters must get a new index there. `__init__.py` also holds `protocol_version`, `defaultConfig` and the `EV_*` event codes.

Ring counts come from the CA certificate, not from config. Changing how they are computed means changing `ffcanew`, not the daemon.
