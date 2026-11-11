# Fireflies

Fireflies is a membership and gossip service for peer-to-peer overlay networks, written in Python on Twisted. Each member keeps a view of the entire membership and gossips with a small set of neighbours. The protocol tolerates Byzantine members: corrupt members cannot incorrectly modify the views of correct members.

[Paper](https://doi.org/10.1145/2701418) · [Install](#install) · [Running a test group](#running-a-test-group) · [Citing Fireflies](#citing-fireflies) · [Licence](#licence)

## Background

An attacker who controls one computer in an overlay network can control the whole overlay if it can corrupt the mechanism that tracks membership. It can report live members as crashed, keep crashed members in everyone's view, or steer correct members toward itself. Fireflies resists these attacks by placing members on pseudo-random rings that every member can verify, so that corrupt members cannot choose whom they monitor or gossip with.

## Guarantees

With high probability, the views of correct members have these properties:

- **Agreement.** A member in the view of one correct member is, within bounded time, in the view of every correct member.
- **Validity.** The view includes every member that has been correct for long enough and excludes every member that has been crashed for long enough.
- **Connectivity.** The correct members form a connected gossip graph.
- **Scalability.** Each member has a number of gossip neighbours logarithmic in the group size, and the gossip graph has logarithmic diameter.

The attack model assumes that corrupt members cannot break the cryptography, that clocks have bounded drift and messages bounded delay, and that a certificate authority (CA) admits members so that a randomly chosen live member is corrupt with probability at most *p*<sub>corrupt</sub>. Fireflies does not handle network partitions.

## How it works

**Identity.** The CA signs an X.509 certificate for each member. The certificate binds the member's public key to its network address, which Fireflies stores in the subject's `L=` field. The member's identity is its certificate's subjectKeyIdentifier.

**Rings.** Fireflies arranges the members on *k* rings. On ring *r*, members are ordered by a secure hash of their identity concatenated with *r*, so each ring is a different pseudo-random permutation that every member can compute and verify. A member monitors its successors and is monitored by its predecessors, which gives it up to *k* monitors chosen independently of its own identity.

**Signed state.** The view changes only through signed data:

- A *note* is a member's signed statement that it is live. It carries an epoch number and a mask with one bit per ring. Only the most recent note from a member is valid.
- An *accusation* is signed by a monitor and names the accused member's current note.
- A member that receives an accusation starts a local timer. If the accused does not publish a newer note, a *rebuttal*, within 2Δ, the member considers it crashed. Δ is a probabilistic bound on the time to gossip a message to all correct members.

**Accusation rules.** A monitor may accuse a member only on rings where the accused member's mask enables it, and only if it is the member's closest live predecessor on that ring. The second rule lets monitors skip over crashed predecessors without letting a corrupt member accuse arbitrary members. With *k* = 2*t* + 1 rings, a member may disable at most *t* rings. It can switch off the monitors that accuse it falsely, and still keep at least one correct monitor if at most *t* are corrupt.

**Ring count.** The CA picks the smallest *t* such that, with probability ε, no member in a group of *N* has a majority of corrupt monitors among its 2*t* + 1. The number of rings grows logarithmically with *N*. With *p*<sub>corrupt</sub> = 0.20, *N* = 1000 and ε = 0.99, a group needs 41 monitoring rings. The CA writes the monitoring and gossip ring counts into the group certificate, so every member uses the same values.

**Crash detection.** A member pings its successors over UDP. Each ping carries a random nonce, and only a pong that returns the nonce signed by the pinged member counts. This stops corrupt members from forging or replaying pongs to keep a crashed member alive. The number of unanswered pings before an accusation adapts to each link: if a probe succeeds with probability *S*, the threshold τ = log(*P*<sub>mistake</sub>) / log(1 − *S*) bounds the probability of accusing a live member to *P*<sub>mistake</sub>. *S* is estimated by exponential smoothing over the number of pings sent per pong received.

**Gossip.** Notes, accusations and certificates spread by gossip on a separate set of rings. On each gossip ring, a member connects to its closest live successor and accepts a connection only from its closest live predecessor. Corrupt members therefore cannot choose their gossip partners or flood a chosen victim. Gossip partners authenticate each other with their certificates over TLS. Each exchange uses set reconciliation (Minsky and Trachtenberg), so partners send only the items the other side lacks: certificates first, then notes, then accusations, so that each item can be verified on arrival.

## Requirements

- Python 3.10 or later.
- [Twisted](https://twisted.org/), [cryptography](https://cryptography.io/) and pyOpenSSL. pip installs these.
- For gossip: a C++ compiler, [NTL](https://libntl.org/) and [GMP](https://gmplib.org/). On Debian or Ubuntu:

  ```sh
  sudo apt install build-essential libntl-dev libgmp-dev python3-dev
  ```

The set reconciliation extension does not build on Windows. There you can use everything except gossip, or run Fireflies under WSL.

## Install

```sh
git clone https://github.com/haavardj/fireflies.git
cd fireflies
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

Set `FIREFLIES_NO_EXT=1` to skip the C++ extension.

Run the tests with Twisted Trial:

```sh
python -m twisted.trial fireflies.test
```

The set reconciliation tests skip themselves when the extension is not built.

## Running a test group

`pip install` adds five commands: `ffcanew`, `ffreq`, `ffcasign` and `ffcamember` manage a CA, member keys and certificates, and `fireflyd` runs a member. Every command takes `--help`.

The fastest way to a running group puts all keys in the CA's directory. Use it only for testing:

```sh
ffcanew --nopass ca                      # CA key and certificate in ./ca
for port in 15001 15002 15003 15004; do
    ffcamember --password "" -p $port ca 127.0.0.1
done
for port in 15001 15002 15003 15004; do
    fireflyd --nopass -a 127.0.0.1 -p $port ca &
done
```

Each daemon finds the certificate for its own address, loads the matching key and starts monitoring the others. Stop one and the others mark it failed.

`ffcanew` takes `-p` (*p*<sub>corrupt</sub>, default 0.20), `-s` (maximum group size *N*, default 1000) and `-e` (ε, default 0.99), and computes the ring counts from them. `--ec` selects ECDSA P-256 keys instead of RSA-2048.

## Web UI

A member can serve its view as web pages: the members and their status, the monitoring rings, the members it pings with their timeout state, its gossip partners, and its statistics. Install the extra dependencies, then pass `--web` to `fireflyd`:

```sh
pip install -e ".[web]"
fireflyd --nopass -a 127.0.0.1 -p 15001 --web 8001 ca
```

Open <http://127.0.0.1:8001/>. The Graphs page plots member counts, traffic and protocol data over the last hour, sampled every 10 seconds. The UI binds to 127.0.0.1 unless you pass `--web-address`. It has no authentication, so do not expose it to untrusted networks. `/api/members` and `/api/stats` return the same data as JSON.

The UI uses [Klein](https://github.com/twisted/klein), [Jinja2](https://jinja.palletsprojects.com/) and [Chart.js](https://www.chartjs.org/). Klein runs on the Twisted reactor, so pages read the member's state directly, without threads or locks.

## Running a real group

In a real deployment, member keys never leave the member:

```sh
# At the member: create a key and a certificate request.
ffreq m1 cacert.pem 192.0.2.10:14377

# At the CA: sign the request.
ffcasign -o 192.0.2.10:14377.pem ca 192.0.2.10:14377-req.pem

# At the member: install the certificate and start.
cp 192.0.2.10:14377.pem m1/certs/
fireflyd -a 192.0.2.10 m1
```

A new member needs the certificate of at least one existing member to join. Copy some into `<store>/certs/`, or pass other stores as extra arguments to `fireflyd`. The default port is 14377, TCP for gossip and UDP for failure detection.

A store has this layout:

```
<store>/cacert.pem                CA certificate
<store>/private/<identity>.pem    member private key (PKCS#8)
<store>/private/cakey.pem         CA private key (CA only)
<store>/certs/<ip:port>.pem       member certificates
<store>/notes/, accusations/      cached state
```

On Windows, the `:` in certificate file names becomes `_`.

## Using the library

A member is a Twisted service. `Group` holds the view and the member's credentials. The failure detector and gossip attach to it as child services.

```python
from twisted.internet import reactor
from fireflies import crypto, util
from fireflies.group import Group
from fireflies.fd import FailureDetector
from fireflies.gossip import Gossip

# At the CA.
caKey = crypto.makePrivateKey()
caCert = crypto.makeCACert(caKey, "demo",
                           util.numMembershipRings(0.2, 1000),
                           util.numGossipRings(0.2, 1000))

# At the member.
key = crypto.makePrivateKey()
req = crypto.makeRequest("127.0.0.1:14377", key)

# At the CA.
cert = crypto.makeCert(req, caCert, caKey, sn=1)

# At the member.
group = Group(caCert, key, cert)
FailureDetector(group)
Gossip(group)
group.startService()
reactor.run()
```

Add other members with `group.view.addCertificate(cert)`. Subscribe to view changes with `group.registerEventHandler`. The events are `member.crash`, `member.recover`, `data.note`, `data.accusation` and `data.certificate`.

## Citing Fireflies

The protocol, its analysis and an evaluation on PlanetLab are in the paper below. If you refer to Fireflies, please cite it:

> Håvard D. Johansen, Robbert van Renesse, Ymir Vigfusson and Dag Johansen. 2015. Fireflies: A secure and scalable membership and gossip service. *ACM Transactions on Computer Systems* 33, 2, Article 5 (May 2015), 32 pages. [doi:10.1145/2701418](https://doi.org/10.1145/2701418)

```bibtex
@article{johansen2015fireflies,
  author  = {Johansen, H{\aa}vard D. and van Renesse, Robbert and Vigfusson, Ymir and Johansen, Dag},
  title   = {Fireflies: A Secure and Scalable Membership and Gossip Service},
  journal = {ACM Transactions on Computer Systems},
  volume  = {33},
  number  = {2},
  articleno = {5},
  numpages  = {32},
  year    = {2015},
  month   = may,
  doi     = {10.1145/2701418},
}
```

## Licence

Fireflies is under the MIT licence ([LICENCE](LICENCE)), except the set reconciliation code. The files `fireflies/setrecon/*.cpp` and `*.h` are based on the library by Sachin Agarwal and Ari Trachtenberg (Boston University), version 0.998 Beta, modified for Fireflies, and remain under GPL version 2 ([COPYING](fireflies/setrecon/COPYING)). The compiled extension, `fireflies.setrecon._setreconbase`, is therefore GPL, and so is any distribution that includes it.

The web UI bundles Chart.js 4.5.1 (`fireflies/web/static/chart.umd.min.js`), which is under the MIT licence of its contributors ([chart.js-LICENSE.md](fireflies/web/static/chart.js-LICENSE.md)).
