"""Klein application serving a member's state as HTML pages."""

import json
import time
from importlib import resources

from jinja2 import Environment, PackageLoader, select_autoescape
from klein import Klein
from twisted.web.static import File

import fireflies
from fireflies.web import model


class WebUI:
    """Web pages for one member. Request handlers run in the reactor
    thread, like the rest of Fireflies, so they read the group directly."""

    app = Klein()

    def __init__(self, group, refresh=10, history=None):
        self.group = group
        self.refresh = refresh
        self.started = time.time()
        self.history = history or model.History(group)
        self.env = Environment(
            loader=PackageLoader("fireflies.web", "templates"),
            autoescape=select_autoescape(["html"]),
        )

    def render(self, request, template, **context):
        request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
        context.setdefault("refresh", self.refresh)
        context.setdefault("groupName", self.group.name)
        context.setdefault("meAddress", self.group.getMe().getAddress())
        context.setdefault("v", fireflies.version)
        return self.env.get_template(template).render(**context)

    @app.route("/")
    def overview(self, request):
        return self.render(request, "overview.html", page="overview",
                           data=model.overview(self.group, self.started))

    @app.route("/member/<identity>")
    def member(self, request, identity):
        data = model.member(self.group, identity)
        if data is None:
            request.setResponseCode(404)
            return self.render(request, "notfound.html", page=None, identity=identity)
        return self.render(request, "member.html", page=None, data=data)

    @app.route("/rings")
    def rings(self, request):
        return self.render(request, "rings.html", page="rings", rings=model.rings(self.group))

    @app.route("/monitoring")
    def monitoring(self, request):
        return self.render(request, "monitoring.html", page="monitoring",
                           data=model.monitoring(self.group))

    @app.route("/stats")
    def stats(self, request):
        return self.render(request, "stats.html", page="stats", stats=model.stats(self.group))

    @app.route("/graphs")
    def graphs(self, request):
        return self.render(request, "graphs.html", page="graphs", refresh=None,
                           interval=self.history.interval,
                           span=self.history.interval * self.history.samples.maxlen)

    @app.route("/api/history")
    def apiHistory(self, request):
        request.setHeader(b"Content-Type", b"application/json")
        return json.dumps(self.history.series())

    @app.route("/api/members")
    def apiMembers(self, request):
        request.setHeader(b"Content-Type", b"application/json")
        return json.dumps(model.overview(self.group, self.started), indent=1)

    @app.route("/api/stats")
    def apiStats(self, request):
        request.setHeader(b"Content-Type", b"application/json")
        return json.dumps({s["name"]: s["value"] for s in model.stats(self.group)}, indent=1)

    @app.route("/static/", branch=True)
    def static(self, request):
        return File(str(resources.files("fireflies.web") / "static"))


def listen(group, port, interface="127.0.0.1"):
    """Serve the web UI for group on interface:port. The history sampler
    runs as a child service of group, so it starts and stops with it.
    Returns the listening port; its webui attribute is the WebUI."""
    from twisted.internet import reactor
    from twisted.web.server import Site

    ui = WebUI(group)
    ui.history.setServiceParent(group)
    listening = reactor.listenTCP(port, Site(ui.app.resource()), interface=interface)
    listening.webui = ui
    return listening
