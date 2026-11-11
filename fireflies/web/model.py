"""Snapshots of a member's state for the web UI.

Each function reads the group in the reactor thread and returns plain
dicts and lists, so templates never touch live protocol objects.
"""

import time

import fireflies
from fireflies.group import collectStatistic


def status(member):
    """Return "failed", "accused" or "live"."""
    if member.isFailed():
        return "failed"
    if member.isAccused():
        return "accused"
    return "live"


def short(identity, n=8):
    return identity[:n]


def memberRow(member, me):
    note = member.getNote()
    return {
        "identity": member.identity,
        "short": short(member.identity),
        "name": member.getCommonName(),
        "address": member.getAddress(),
        "status": status(member),
        "epoch": note.epoch if note else None,
        "accusations": len(member.getAccusations()),
        "me": member == me,
    }


def overview(group, started):
    me = group.getMe()
    view = group.view
    members = sorted(view.getAllMembers(), key=lambda m: m.getAddress())
    rows = [memberRow(m, me) for m in members]
    return {
        "group": group.name,
        "version": fireflies.version,
        "me": memberRow(me, me),
        "uptime": int(time.time() - started),
        "monitoringRings": group.nrMonitoringRings(),
        "gossipRings": group.nrGossipingRings(),
        "rebuttal": group.tRebuttal,
        "counts": {
            "all": len(rows),
            "live": sum(1 for r in rows if r["status"] == "live"),
            "accused": sum(1 for r in rows if r["status"] == "accused"),
            "failed": sum(1 for r in rows if r["status"] == "failed"),
        },
        "members": rows,
    }


def member(group, identity):
    """Return details of one member, or None if it is unknown."""
    view = group.view
    try:
        m = view.getMemberByIdentity(identity)
    except KeyError:
        return None
    me = group.getMe()
    note = m.getNote()
    accusations = []
    for a in m.getAccusations():
        try:
            accuser = memberRow(view.getMemberByIdentity(a.accuser), me)
        except KeyError:
            accuser = {"identity": a.accuser, "short": short(a.accuser), "address": "?", "status": "unknown"}
        accusations.append({"accuser": accuser, "epoch": a.epoch, "ring": getattr(a, "ring", None)})

    rings = []
    for r in view.mRings:
        if len(r) < 2 or m not in r:
            continue
        rings.append({
            "nr": r.name,
            "enabled": m.isEnabledOnRing(r),
            "pred": memberRow(r.pred(m), me),
            "succ": memberRow(r.succ(m), me),
        })
    return {
        "member": memberRow(m, me),
        "certificate": m.getCertificate().as_text(),
        "mask": list(note.mask) if note else [],
        "accusations": accusations,
        "rings": rings,
        "rebuttalPending": view.hasActiveTimer(m),
    }


def rings(group):
    """Monitoring rings in ring order."""
    me = group.getMe()
    out = []
    for r in group.view.mRings:
        out.append({"nr": r.name, "members": [memberRow(m, me) for m in r]})
    return out


def monitoring(group):
    """Members this member pings, with their timeout policy, and its
    gossip connections."""
    me = group.getMe()
    out = {"targets": [], "gossip": []}

    fd = _service(group, "fd")
    if fd is not None:
        for m in sorted(getattr(fd, "monitoring", {}), key=lambda m: m.getAddress()):
            policy = fd.policies.get(m)
            out["targets"].append({
                "member": memberRow(m, me),
                "unanswered": policy.nPing if policy else 0,
                "threshold": policy.threshold() if policy else None,
                "avgLoss": policy.avgLoss if policy else None,
                "outstanding": len(fd.outstanding.get(m, ())),
            })

    gossip = _service(group, "gossip")
    if gossip is not None:
        for m, factory in sorted(gossip.neighborPool.items(), key=lambda i: i[0].getAddress()):
            proto = factory.connectedProtocol
            if not (factory.isActive() or proto):
                continue
            out["gossip"].append({
                "member": memberRow(m, me),
                "active": bool(factory.isActive()),
                "direction": ("out" if proto.master else "in") if proto else None,
                "state": getattr(proto, "state", None) if proto else "disconnected",
            })
    return out


def stats(group):
    s = collectStatistic(group)
    out = []
    for name in fireflies.stats.listStatistics():
        doc = fireflies.stats.statistics[name][0]
        value = getattr(s, name)
        shown = "{:,}".format(int(value)) if value == int(value) else "{:,.2f}".format(value)
        out.append({"name": name, "value": value, "shown": shown, "doc": doc})
    return out


def _service(group, name):
    try:
        return group.getServiceNamed(name)
    except KeyError:
        return None
