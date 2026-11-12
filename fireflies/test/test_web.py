"""Web UI: every page renders for a small group."""

import json

from twisted.trial import unittest
from twisted.web.client import Agent, readBody

import fireflies.group
from fireflies import fd
from fireflies.test.helpers import makeCA, makeMember, noteOf
from fireflies.util import reactor

try:
    import fireflies.web.app as webapp
except ImportError:
    webapp = None


class WebUITest(unittest.TestCase):

    def setUp(self):
        if webapp is None:
            raise unittest.SkipTest("klein or jinja2 not installed")
        ca, caKey = makeCA()
        creds = [makeMember(ca, caKey, "127.0.0.1:%d" % (25100 + i), i + 1) for i in range(3)]
        self.groups = [fireflies.group.Group(ca, k, c) for c, k in creds]
        for g in self.groups:
            for other in self.groups:
                if other is not g:
                    g.view.addCertificate(other.getMe().getCertificate())
                    g.view.addNote(noteOf(other.getMe()))
        self.group = self.groups[0]
        fd.FailureDetector(self.group)
        self.port = webapp.listen(self.group, 0)
        self.base = "http://127.0.0.1:%d" % self.port.getHost().port

    def tearDown(self):
        for call in reactor.getDelayedCalls():
            call.cancel()
        return self.port.stopListening()

    async def get(self, path, code=200):
        response = await Agent(reactor).request(b"GET", (self.base + path).encode())
        body = await readBody(response)
        self.assertEqual(response.code, code, path)
        return body.decode("utf-8")

    async def test_pages(self):
        other = self.groups[1].getMe()
        for path in ["/", "/rings", "/monitoring", "/stats", "/member/" + other.identity]:
            body = await self.get(path)
            self.assertIn("Fireflies", body)
        body = await self.get("/member/" + other.identity)
        self.assertIn(other.getAddress(), body)
        self.assertIn("/static/style.css", await self.get("/"))
        self.assertIn("--live", await self.get("/static/style.css"))

    async def test_unknown_member(self):
        await self.get("/member/NOSUCH", code=404)

    async def test_api(self):
        members = json.loads(await self.get("/api/members"))
        self.assertEqual(members["counts"]["all"], 3)
        stats = json.loads(await self.get("/api/stats"))
        self.assertIn("pongsRejected", stats)

    async def test_graphs(self):
        history = self.port.webui.history
        history.sample(now=1000.0)
        self.group.stats.tcpR += 500
        self.group.stats.notesTotal += 3
        history.sample(now=1010.0)
        data = json.loads(await self.get("/api/history"))
        self.assertEqual(data["t"], [1010000])
        self.assertEqual(data["tcp"]["read"], [50.0])          # bytes per second
        self.assertEqual(data["received"]["notes"], [18.0])    # per minute
        self.assertEqual(data["members"]["live"], [3])
        body = await self.get("/graphs")
        self.assertIn("/static/graphs.js", body)
        self.assertIn("Chart.js v4", await self.get("/static/chart.umd.min.js"))
        self.assertIn("/api/history", await self.get("/static/graphs.js"))

    def test_history_needs_two_samples(self):
        history = self.port.webui.history
        history.sample(now=1000.0)
        self.assertEqual(history.series()["t"], [])
