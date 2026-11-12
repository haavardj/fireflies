"""Klein application serving a member's state as HTML pages."""

import json
import time
from typing import Any, Callable, TypeVar, cast
from importlib import resources

from jinja2 import Environment, PackageLoader, select_autoescape
from klein import Klein
from twisted.web.server import Request
from twisted.web.static import File

import fireflies
from fireflies.group import Group
from fireflies.util import setServiceParent
from fireflies.web import model

_Handler = TypeVar("_Handler", bound=Callable[..., Any])

_app = Klein()


def route(url: str, branch: bool = False) -> Callable[[_Handler], _Handler]:
    """_app.route with a type pyright can follow."""
    decorator = _app.route(url, branch=branch)  # pyright: ignore[reportUnknownMemberType]  # Klein leaves *args untyped
    return cast(Callable[[_Handler], _Handler], decorator)


def setContentType(request: Request, value: bytes) -> None:
    request.setHeader(b"Content-Type", value)  # pyright: ignore[reportUnknownMemberType]  # untyped in Twisted


class WebUI:
    """Web pages for one member. Request handlers run in the reactor
    thread, like the rest of Fireflies, so they read the group directly."""

    app = _app

    def __init__(self, group: Group, refresh: int = 10, history: "model.History | None" = None) -> None:
        self.group = group
        self.refresh = refresh
        self.started = time.time()
        self.history = history or model.History(group)
        self.env = Environment(
            loader=PackageLoader("fireflies.web", "templates"),
            autoescape=select_autoescape(["html"]),
        )

    def render(self, request: Request, template: str, **context: Any) -> str:
        setContentType(request, b"text/html; charset=utf-8")
        context.setdefault("refresh", self.refresh)
        context.setdefault("groupName", self.group.name)
        context.setdefault("meAddress", self.group.getMe().getAddress())
        context.setdefault("v", fireflies.version)
        return self.env.get_template(template).render(**context)

    @route("/")
    def overview(self, request: Request) -> str:
        return self.render(request, "overview.html", page="overview",
                           data=model.overview(self.group, self.started))

    @route("/member/<identity>")
    def member(self, request: Request, identity: str) -> str:
        data = model.member(self.group, identity)
        if data is None:
            request.setResponseCode(404)
            return self.render(request, "notfound.html", page=None, identity=identity)
        return self.render(request, "member.html", page=None, data=data)

    @route("/rings")
    def rings(self, request: Request) -> str:
        return self.render(request, "rings.html", page="rings", rings=model.rings(self.group))

    @route("/monitoring")
    def monitoring(self, request: Request) -> str:
        return self.render(request, "monitoring.html", page="monitoring",
                           data=model.monitoring(self.group))

    @route("/stats")
    def stats(self, request: Request) -> str:
        return self.render(request, "stats.html", page="stats", stats=model.stats(self.group))

    @route("/graphs")
    def graphs(self, request: Request) -> str:
        return self.render(request, "graphs.html", page="graphs", refresh=None,
                           interval=self.history.interval,
                           span=self.history.interval * self.history.size)

    @route("/api/history")
    def apiHistory(self, request: Request) -> str:
        setContentType(request, b"application/json")
        return json.dumps(self.history.series())

    @route("/api/members")
    def apiMembers(self, request: Request) -> str:
        setContentType(request, b"application/json")
        return json.dumps(model.overview(self.group, self.started), indent=1)

    @route("/api/stats")
    def apiStats(self, request: Request) -> str:
        setContentType(request, b"application/json")
        return json.dumps({s["name"]: s["value"] for s in model.stats(self.group)}, indent=1)

    @route("/static/", branch=True)
    def static(self, request: Request) -> File:
        return File(str(resources.files("fireflies.web") / "static"))


def listen(group: Group, port: int, interface: str = "127.0.0.1") -> Any:
    """Serve the web UI for group on interface:port. The history sampler
    runs as a child service of group, so it starts and stops with it.
    Returns the listening port; its webui attribute is the WebUI."""
    from fireflies.util import reactor
    from twisted.web.server import Site

    ui = WebUI(group)
    setServiceParent(ui.history, group)
    listening = reactor.listenTCP(port, Site(ui.app.resource()), interface=interface)
    listening.webui = ui
    return listening
