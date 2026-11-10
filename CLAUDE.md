# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Fireflies: a Byzantine-tolerant, scalable group membership protocol and toolkit for peer-to-peer overlays (Håvard D. Johansen, UiT, ~2006–2014). Each member keeps a weakly consistent view of all members; redundancy masks Byzantine faults so malicious members can neither declare live members crashed nor crashed members live. Design and math are in [doc/fireflies.tex](doc/fireflies.tex) / `doc/fireflies.pdf`.

Legacy code. Constraints that matter before editing:

- **Python 2.7 only** (`print` statements, `except X, e:`, `raise E, msg`, `import new`, `xdrlib`, implicit relative imports). Do not "modernize" syntax piecemeal; it will not run on Python 3 anyway.
- Dependencies: Twisted (+ `zope.interface`), M2Crypto (X509, SSL, RSA/EC), and for the web UI Nevow, numpy, Gnuplot.py. The `setrecon` C++ extension needs SWIG, NTL and GMP.
- Version control was CVS on SourceForge (`CVS/` dirs). This directory is not a git repo. `dd/` is a separate small git repo, unrelated to the code.
- `build/`, `dist/`, `lib/python/`, `_trial_temp/` and `*.pyc`/`*.pyo` are build or install artifacts. Edit only `fireflies/` and `scripts/`.

## Build and test

```sh
python2.7 setup.py build            # builds fireflies.setrecon._setreconbase via SWIG (-c++), links ntl, gmp
python2.7 setup.py install --home=. # what produced lib/python/
python2.7 setup_noext.py build      # pure-Python install, skips the C++ extension
python2.7 setup_32bits.py build     # same as setup.py with -m32
```

Tests use Twisted Trial:

```sh
trial fireflies.test                                   # all tests
trial fireflies.test.test_ring                         # one module
trial fireflies.test.test_ring.NumberedRingQueryTest.testPred   # one test
```

`test_setrecon` needs the compiled `_setreconbase` extension. `test_failuredetection` targets `fireflies/failuredetection.py`, which imports a non-existent `fireflies.channel` module and does not import.

## Running a group

All tools are in [scripts/](scripts/):

1. `ffcanew <path>`: create a group CA. Options `-p` (P_byz, default 0.20), `-s` (max group size, default 1000) and `-e` (tolerance) determine the number of monitoring and gossip rings, which are encoded into the CA certificate's `O=` field as `"<monitoring> <gossip>"` (read back by `Group.nrMonitoringRings()` / `nrGossipingRings()`). Ring-count formulas are in [fireflies/util.py](fireflies/util.py) (`numMembershipRings`, `numGossipRings`).
2. `ffreq` / `ffcasign` / `ffcamember`: request and sign member certificates. A member certificate carries the member's `ip:port`.
3. `fireflyd <store> [<extra stores>...]`: run a member. `--capriv` lets the daemon mint its own certificate from the CA key (testing only). `-s` enables the web stats UI, `-b <file>` marks Byzantine members, `--ec` uses elliptic-curve keys. Default port 14377.
4. `ffrunmany <n> <CA key>`: spawn n local daemons on consecutive ports from 12000. `ffpickbyzantine` picks a Byzantine subset.

Store layout (see [fireflies/persist.py](fireflies/persist.py)): `<path>/cacert.pem`, `<path>/private/cakey.pem`, `<path>/private/<keyid>.pem`, `<path>/certs/<ip:port>.pem`, plus persisted notes and accusations.

## Architecture

Twisted service tree, wired up in [scripts/fireflyd](scripts/fireflyd):

- **`group.Group`** (`MultiService`): the runtime entry point. Holds the CA cert, own key/cert, the `View`, the SSL context, and an event bus (`registerEventHandler` with events `member.crash`, `member.recover`, `data.note`, `data.accusation`, `data.certificate`). Also auto-rebuts accusations against itself (`evSelfRebuttal`).
- **`fd.FailureDetector`** (`Service`, child of Group): pings monitoring-ring successors over signed UDP (`PingPong`); on timeout it creates and signs an `Accusation`. `fd2.py` is an unfinished rewrite; `failuredetection.py` is dead.
- **`gossip.Gossip`** (`Service`, child of Group): TCP+SSL gossip with ring neighbours on the gossip rings. Keeps three `setrecon.ReconSet`s (certificates, notes, accusations) mirrored from Group data events and exchanges only the differences via set reconciliation. `gossipsim.py` is a simulation variant of the same.
- **`view.View`**: the member's view. `pRing` (all), `aRing` (live), `fRing` (failed), plus `mRings`, a `RingSet` of `NameHashedRing`s used for monitoring. Contains the accusation rules (`canAccuse`: an accuser must be a valid predecessor of the accused on some monitoring ring) and the rebuttal timer (`Group.tRebuttal`): an accused member that publishes no newer note before the timer fires is declared failed.
- **`state`**: signed data objects. `Member` (wraps an X509 member cert), `Note` (member-signed, epoch-numbered liveness record with a ring mask enabling/disabling accusations per ring), `Accusation` (signed by the accuser, bound to the accused's current note).
- **`ring`**: `Ring` (sorted, wraps around), `NameHashedRing` (order by hash of ring number + identity, so each ring gives a different random permutation), `RingSet`, `RankTable`, successor/predecessor relations.
- **`crypto`**: cert/key creation (RSA or EC secp224r1), identities derived from the subject key identifier, the `Signable` mixin that `Note`, `Accusation` and FD messages use.
- **`packer`**: XDR-based wire format (`FirefliesPacker`/`Unpacker`) for notes, accusations, certs and setrecon nodes.
- **`protocols`**: SSL connection helpers (`makeSSLCtx`, `connect`, `listen`), `ReconnectingPeerFactory`, `PeerServerFactory`, and `FirefliesProtocol` (an `Int32StringReceiver` base for gossip).
- **`setrecon`**: Python wrapper ([setrecon.py](fireflies/setrecon/setrecon.py)) over the SWIG-generated `setreconbase` (C++ probabilistic set reconciliation in `*.cpp`). Call `setrecon.init()` before use.
- **`stats`**: global counters registered by index in [fireflies/__init__.py](fireflies/__init__.py) via `addStatistic`; new counters must get a new index there. `__init__.py` also holds `protocol_version`, `defaultConfig` and the `EV_*` event codes.
- **`web`**: optional Nevow status UI (`NodeViewer`) with Gnuplot graphs.

Ring counts come from the CA certificate, not from config. Changing how they are computed means changing `ffcanew`, not the daemon.
