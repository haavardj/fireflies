
######################################################################
## Filename:      web.py
## Description:   
## Author:        Haard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Fri Jan 20 12:29:37 2006
## Modified by:   Haard Dagenborg Johansen <haavardj@cs.uit.no>
##  
##         Copyright 2006, University of Tromso, Norway)
##                
## $Id: web.py,v 1.3 2007/07/09 09:00:00 haavardj Exp $
##                
######################################################################

from twisted.web import server, resource
from twisted.internet import reactor, task
import logging, fireflies, StringIO, socket, os.path, datetime
from nevow import appserver, static, loaders, rend
from nevow import tags as T
from math import log, ceil
import Numeric, shutil
from Crypto.Util.number import long_to_bytes, bytes_to_long

templatePath = os.path.join(os.path.dirname(fireflies.__file__), "web/")
masterT = loaders.xmlfile("master.html", templateDir=templatePath)
overviewT = loaders.xmlfile("overview.html", templateDir=templatePath, pattern="content")
ringsT = loaders.xmlfile("rings.html", templateDir=templatePath, pattern="content")
peerT = loaders.xmlfile("peer.html", templateDir=templatePath, pattern="content")
partnersT = loaders.xmlfile("partners.html", templateDir=templatePath, pattern="content")
statsT = loaders.xmlfile("stats.html", templateDir=templatePath, pattern="content")

peerInfoF = loaders.xmlfile("fragments.html", templateDir=templatePath, pattern="peerInfo")
membersF = loaders.xmlfile("fragments.html", templateDir=templatePath, pattern="members")
ringsF = loaders.xmlfile("fragments.html", templateDir=templatePath, pattern="rings")

gossipsubs = None
pingersubs = None

ip2name = {}


import copy, Gnuplot, time, random
class Grapher:

    def __init__(self, group, path, interval, length):
        self.outpath = path
        self.stats = []
        self.group = group
        self.interval = interval
        self.length = length
        self.logger = logging.getLogger()

        # Empty first data
        bogomips = 0
        try:
            lines = file("/proc/cpuinfo").readlines()
        except Exception:
            logging.warning("unable to open /proc/cpuinfo.")
        else:
            while 1:
                if len(lines) == 0:
                    logging.warning("unable to find bogomips value.")
                    break

                line = lines.pop(0)
                if not line.startswith("bogomips"): continue
                bogomips = line.split(":")[1]
                bogomips = bogomips.strip()
                bogomips = float(bogomips)
                logging.info("calculating load using bogomips=%f", bogomips)
                break
        self.bogomips = bogomips
        self.prevData = fireflies.stats.Stats()
        self.prevData.cputime = os.times()[0] * bogomips
        self.prevTime = fireflies.time.time()


        
    def collectData(self):

        newData = fireflies.stats.collect(self.group)
        newData.cputime = os.times()[0] * self.bogomips
        newTime = fireflies.time.time()

        diffData = newData - self.prevData
        diffTime = newTime - self.prevTime
        
        self.prevData = newData
        self.prevTime = newTime
        
        return {
            'stats': diffData,
            'members': len(self.group.view.aRing),
            'failed':  len(self.group.view.fRing),
            'time': newTime,
            'period': diffTime
            }

        
    def update(self):

        # Collect data
        self.stats.append(self.collectData())
        if len(self.stats) > self.length:
            self.stats.pop(0)
            
        Gnuplot.gp.GnuplotOpts.default_term = "png"
        g = Gnuplot.Gnuplot(debug=0)
        g("set terminal png transparent size 780,340")
        g("set xdata time")
        g("set timefmt '%s'")
        #g("set size 1.34,1")
        g('set format x "%d\/%m\\n%H:%M"')
        
        g("set xlabel 'Time (UTC)'")
        xdata = map(lambda x: float(x['time']), self.stats)
        maxr = xdata[-1]
        minr = maxr - (self.interval * self.length)
        g('set xrange ["%f":"%f"]'% (minr, maxr))
        xdata = Numeric.asarray(xdata, Numeric.Float)
        
        g("set output '%s'" %os.path.join(self.outpath, "members.png"))
        g("set ylabel '# members'")
        ydata = map(lambda x: x['members'], self.stats)
        maxr = max(max(ydata), 0.001) * 1.10
        g("set yrange [0:%f]" % maxr) 
        ydata = Numeric.asarray(ydata, Numeric.Float)
        d = Gnuplot.Data(xdata, ydata, using="1:2", with="lines")
        g.plot(d)

        g("set output '%s'" %os.path.join(self.outpath, "udp.png"))
        g("set ylabel 'UDP bytes/second'")
        y1data = map(lambda x: x['stats'].udpW/float(x['period']), self.stats)
        y2data = map(lambda x: x['stats'].udpR/float(x['period']), self.stats)
        maxr = max(max(y1data), max(y2data), 0.01) * 1.10
        g("set yrange [0:%f]" % maxr) 
        y1data = Numeric.asarray(y1data, Numeric.Float)
        y2data = Numeric.asarray(y2data, Numeric.Float)
        d1 = Gnuplot.Data(xdata, y1data, using="1:2", with="lines", title="sent")
        d2 = Gnuplot.Data(xdata, y2data, using="1:2", with="lines", title="received")
        g.plot(d1, d2)

        g("set output '%s'" %os.path.join(self.outpath, "tcp.png"))
        g("set ylabel 'TCP bytes/second'")
        y1data = map(lambda x: x['stats'].tcpW/float(x['period']), self.stats)
        y2data = map(lambda x: x['stats'].tcpR/float(x['period']), self.stats)
        maxr = max(max(y1data), max(y2data), 0.01) * 1.10
        g("set yrange [0:%f]" % maxr) 
        y1data = Numeric.asarray(y1data, Numeric.Float)
        y2data = Numeric.asarray(y2data, Numeric.Float)
        d1 = Gnuplot.Data(xdata, y1data, using="1:2", with="lines", title="sent")
        d2 = Gnuplot.Data(xdata, y2data, using="1:2", with="lines", title="received")
        g.plot(d1, d2)

        g("set output '%s'" %os.path.join(self.outpath, "cpu.png"))
        g("set ylabel 'Mill. Instructions/sec'")
        y1data = map(lambda x: x['stats'].cputime/float(x['period']), self.stats)
        maxr = max(max(y1data), 0.01) * 1.10
        g("set yrange [0:%f]" % maxr) 
        y1data = Numeric.asarray(y1data, Numeric.Float)
        d1 = Gnuplot.Data(xdata, y1data, using="1:2", with="lines", title="load")
        g.plot(d1)

        g("set output '%s'" %os.path.join(self.outpath, "createdacc.png"))
        g("set ylabel '# accusations made per second'")
        ydata = map(lambda x: x['stats'].accusationsCreated/float(x['period']), self.stats)
        maxr = max(max(ydata), 0.001) * 1.10
        g("set yrange [0:%f]" % maxr) 
        ydata = Numeric.asarray(ydata, Numeric.Float)
        d = Gnuplot.Data(xdata, ydata, using="1:2", with="lines")
        g.plot(d)

        #g("set output '%s'" %os.path.join(self.outpath, "exchanges.png"))
        #g("set ylabel '# gossip exchanges per second'")
        #ydata = map(lambda x: x['stats'].exchanges/float(x['period']), self.stats)
        #maxr = max(max(ydata), 0.001) * 1.10
        #g("set yrange [0:%f]" % maxr) 
        #ydata = Numeric.asarray(ydata, Numeric.Float)
        #d = Gnuplot.Data(xdata, ydata, using="1:2", with="lines")
        #g.plot(d)

        g("set output '%s'" %os.path.join(self.outpath, "rebuttals.png"))
        g("set ylabel '# rebuttals per second'")
        ydata = map(lambda x: x['stats'].notesCreated/float(x['period']), self.stats)
        maxr = max(max(ydata), 0.001) * 1.10
        g("set yrange [0:%f]" % maxr) 
        ydata = Numeric.asarray(ydata, Numeric.Float)
        d = Gnuplot.Data(xdata, ydata, using="1:2", with="lines")
        g.plot(d)

        g("set output '%s'" %os.path.join(self.outpath, "tcpopen.png"))
        g("set ylabel '# TCP connections per second'")
        ydata = map(lambda x: x['stats'].tcpOpen/float(x['period']), self.stats)
        maxr = max(max(ydata), 0.001) * 1.10
        g("set yrange [0:%f]" % maxr) 
        ydata = Numeric.asarray(ydata, Numeric.Float)
        d = Gnuplot.Data(xdata, ydata, using="1:2", with="lines")
        g.plot(d)

        g("set output '%s'" %os.path.join(self.outpath, "data.png"))
        g("set ylabel '# per second'")
        y1data = map(lambda x: x['stats'].accusationsTotal/float(x['period']), self.stats)
        y2data = map(lambda x: x['stats'].notesTotal/float(x['period']), self.stats)
        y3data = map(lambda x: x['stats'].certsTotal/float(x['period']), self.stats)
        maxr = max(max(y1data), max(y2data), max(y3data), 0.001) * 1.10
        g("set yrange [0:%f]" % maxr) 
        y1data = Numeric.asarray(y1data, Numeric.Float)
        y2data = Numeric.asarray(y2data, Numeric.Float)
        y3data = Numeric.asarray(y3data, Numeric.Float)
        d1 = Gnuplot.Data(xdata, y1data, using="1:2", with="lines", title="Accusations")
        d2 = Gnuplot.Data(xdata, y2data, using="1:2", with="lines", title="Notes")
        d3 = Gnuplot.Data(xdata, y3data, using="1:2", with="lines", title="Certificates")
        g.plot(d1, d2, d3)
        g.reset()
               

class NodeViewer:
    def __init__(self, group, port=None, interface=None):
        self.group = group
        self.logger = logging.getLogger(group.mcert.address)

        h, p = group.mcert.address.split(":")
        p = int(p) + 1000
        
        if not port:
            self.port = p
        else: self.port = port

        if not interface:
            self.interface= h
        else: self.interface = interface
        
        self.root = RootPage(self.group.me)
        ip2name[h] = socket.getfqdn(h)
        global gossipsubs, pingersubs
        gossipsubs = group.gossiper
        pingersubs = group.pinger
        self.logger.info("Binding HTTP-stat to tcp %s:%d", h, p)
        site = server.Site(self.root)


    def start(self):

        interval = 5 * 60 * 1 # 30 * 1 
        historySize = 48   # 5 * 60*1)

        reactor.listenTCP(self.port, appserver.NevowSite(self.root), interface=self.interface)
        p = os.path.join("/tmp", self.group.mcert.address)
        try:
            os.mkdir(p)
        except os.error:
            pass            
        self.root.child_images = static.File(p)

        self.grapher = Grapher(self.group, p, interval, historySize)
        self.gTask = task.LoopingCall(self.grapher.update)
        self.gTask.start(interval)

    def __del__(self):
        try:
            p = os.path.join("/tmp", self.peer.cert.address)
            shutil.rmtree(p)
        except Exception:
            pass


class MasterPage(rend.Page):
    addSlash = True
    docFactory = masterT
    body = "Fill this please"

    def __init__(self, peer):
        self.peer = peer
        rend.Page.__init__(self)
    
    def render_body(self, context, data):
        return self.body

    def render_badness(self, context, peer):
        t = context.tag.clear()
        b = peer.note.badness
        if b == 0:
            return t[ T.span[" "](_class="correctbox", style="margin-right: 8px;"),  "Correct"]
        elif b == 1:
            return t[ T.span[" "](_class="passivebox", style="margin-right: 8px"),  "Passive"]
        elif b == 2:
            return t[ T.span[" "](_class="activebox", style="margin-right: 8px"),  "Active"]
        else:
            return t[T.span["Unknown"](_class="warning")]

    def render_browselink(self, context, peer):
        t = context.tag()
        h, p = peer.cert.address.split(":")
        p = int(p) + 1000
        return T.a["[browse]"](href="http://%s:%d" % (h, p))

    def render_id(self, context, peer):        
        return context.tag.clear()["%x" % bytes_to_long(peer.id)]
    
    def render_npings(self, context, peer):        
        return context.tag.clear()[peer.nPing]

    def render_version(self, context, peer):
        return context.tag.clear()[fireflies.version]
    
    def render_avgloss(self, context, peer):
        return context.tag.clear()[peer.avgLoss]
    
    def render_status(self, context, peer):
        t = context.tag.clear()
        if not peer.isAccused():
            return t[ T.span[""](_class="livebox", style="margin-right: 8px"),  "Live"]
        elif peer in self.peer.view.fRing:
            return t[ T.span[""](_class="failedbox", style="margin-right: 8px"), "Failed"]
        else:
            if not peer.fdTimer:
                return t["???"]
            else:
                to = datetime.datetime.fromtimestamp(peer.fdTimer.time)
                c = datetime.datetime.now()
                return context.tag.clear()[T.span[""]( _class="accusedbox", style="margin-right: 8px"),  "Failes in %s" % (str(to-c)) ]

    def render_epoch(self, context, peer):        
        return context.tag.clear()[peer.note.epoch]

    def render_mask(self, context, peer):
        assert isinstance(peer, fireflies.members.Member)
        t = context.tag.clear()
        if not peer.note: return t["NA"]
        else: return t[str(peer.note.mask)]     
    
    def render_accused(self, context, peer):
        if peer.isAccused():
            return context.tag.clear()["Yes"]
        else:
            return context.tag.clear()["No"]

    def render_address(self, context, peer):
        ipaddr, port = peer.cert.address.split(":")
        if not ipaddr in ip2name.keys():
            def setip(ip):
                try:
                    ip2name[ip] = socket.getfqdn(ip).lower()
                except Exception: pass
                
            reactor.callInThread(setip, ipaddr)
        else:
            ipaddr = ip2name[ipaddr]
            
        t = context.tag.clear()
        if peer == self.peer:
            t[T.b[ipaddr + ":" + port]]
        else:
            t[ipaddr + ":" + port]
        return t

    def render_peer(self, context, peer):
        t = context.tag.clear()
        s = t #T.span[""]
        #t[s]

        if peer in self.peer.view.fRing:
            st = T.span["."](_class="failedstatus")
        elif peer.isAccused():
            st = T.span["."](_class="accusedstatus")
        else:
            st = T.span["."](_class="livestatus")
        if peer.note.badness == 0:
            bt = T.span["."](_class="correct")
        elif peer.note.badness == 1:
            bt = T.span["."](_class="passive")
        elif peer.note.badness == 2:
            bt = T.span["."](_class="active")

        if peer.note:
            ll = T.span[str(peer.note.epoch)]
        else:
            ll = T,span["-"]
        s[T.span[st, bt](style="background-color: #E9E9FF;"),
          T.a["l"](style="white-space: nowrap; padding-left: 4px;",
                   data=peer,
                   render=self.render_address,
                   href="/%x" % bytes_to_long(peer.id)),
          ll
          ]
        return s
        
    
    def render_peerInfo(self, context, peer):
        return peerInfoF

    def render_rings(self, context, rings):
        return ringsF
    
    def render_members(self, context, members):
        t = context.tag.clear()

        l = list(members)
        #l.sort(lambda x,y: cmp(x.note.cert.address, y.note.cert.address))
        rows = [ T.caption["Total=%s" % len(l)],
                 T.tr[ T.th["S"], T.th["B"], T.th["Address"], T.th["ll"] ] ]
        for peer in l:

            if peer.note:
                ll = T.td[str(peer.note.epoch)]
            else:
                ll = T.td["-"]
            
            
            if peer in self.peer.view.fRing:
                st = T.td[""](_class="failedbox")
            elif peer.isAccused():
                st = T.td[""](_class="accusedbox")
            else:
                st = T.td[""](_class="livebox")
            if not peer.note:                
                bt = T.td["-"]
            elif peer.note.badness == 0:
                bt = T.td[""](_class="correctbox")
            elif peer.note.badness == 1:
                bt = T.td[""](_class="passivebox")
            elif peer.note.badness == 2:
                bt = T.td[""](_class="activebox")

            a = T.td[T.a[""](href="/%x" % bytes_to_long(peer.id), _class="address", data=peer, render=self.render_address)]
            rows.append( T.tr[  st, bt, a, ll])
        return t[T.table[rows](_class="peerlist")]


    def data_peer(self, context, data):
        return self.peer

    def data_mRings(self, context, data):
        return self.peer.view.mRings 

    def data_gRings(self, context, data):
        return self.peer.view.gRings 

    def data_members(self, context, data):
        return self.peer.view.aRing

    def data_failed(self, context, data):
        return self.peer.view.fRing


class PeerPage(MasterPage):
    body = peerT

    def __init__(self, peer, other):
        MasterPage.__init__(self, peer)
        self.other = other

    def data_other(self, context, data):
        return self.other
    
    def render_vaccusations(self, context, peer):

        t = context.tag.clear()
        l = peer.vAccusations
        nrRings = 2 * peer.view.getT() + 1
        
        rows = [
                 T.tr[ T.th["#"], T.th["S"], T.th["B"], T.th["Address"], T.th["LL"]]]
        for x in range(nrRings):
            accus = l.get(x, None)
            if peer.note.mask[x]: enabled = "Y"
            else: enabled = "N"

            if accus != None:
                assert peer == self.peer.view.sn2peer[accus.accused]
                p = self.peer.view.sn2peer[accus.accuser]
                if p in self.peer.view.fRing:
                    st = T.td[""](_class="failedbox")
                elif p.isAccused():
                    st = T.td[""](_class="accusedbox")
                else:
                    st = T.td[""](_class="livebox")
                if p.note.badness == 0:
                    bt = T.td[""](_class="correctbox")
                elif p.note.badness == 1:
                    bt = T.td[""](_class="passivebox")
                elif p.note.badness == 2:
                    bt = T.td[""](_class="activebox")

                a = T.td[T.a[""](href="/%x" % bytes_to_long(p.id), _class="address", data=p, render=self.render_address)]
            else:
                st = bt = T.td[""](_class="nabox")
                a = T.td[""](_class="address", width="100")                
            rows.append( T.tr[ T.td[x](width="1" ), st, bt, a, T.td[enabled](width="1") ])
        return t[T.table[rows](_class="peerlist")]

    def render_paccusations(self, context, peer):

        t = context.tag.clear()
        l = peer.pAccusations
        nrRings = 2 * peer.view.getT() + 1
        
        rows = [T.tr[ T.th["#"], T.th["S"], T.th["B"], T.th["Address"], T.th["LL"]]]
        for x in range(nrRings):
            accus = l.get(x, None)
            if peer.note.mask[x]: enabled = "Y"
            else: enabled = "N"

            if accus != None:
                assert peer == self.peer.view.sn2peer[accus.accused]
                p = self.peer.view.sn2peer[accus.accuser]
                if p in self.peer.view.fRing:
                    st = T.td[""](_class="failedbox")
                elif p.isAccused():
                    st = T.td[""](_class="accusedbox")
                else:
                    st = T.td[""](_class="livebox")
                if p.note.badness == 0:
                    bt = T.td[""](_class="correctbox")
                elif p.note.badness == 1:
                    bt = T.td[""](_class="passivebox")
                elif p.note.badness == 2:
                    bt = T.td[""](_class="activebox")

                a = T.td[T.a[""](href="/%x" % bytes_to_long(p.id), _class="address", data=p, render=self.render_address)]
            else:
                st = bt = T.td[""](_class="nabox")
                a = T.td[""](_class="address", width="100")
                
            rows.append( T.tr[ T.td[x](width="1" ), st, bt, a, T.td[enabled](width="1") ])
        return t[T.table[rows](_class="peerlist")]




    def render_accusationsHistory(self, context, peer):
        t = context.tag.clear()
        l = peer.allAccusations
        rows = [T.caption["Total %d" %len(l)],
            T.tr[ T.th["#"], T.th["S"], T.th["B"], T.th["Address"]]]
        for x in range(len(l)):
            accus = l[x]

            assert peer == self.peer.view.sn2peer[accus.accused]
            p = self.peer.view.sn2peer[accus.accuser]
            if p in self.peer.view.fRing:
                st = T.td[""](_class="failedbox")
            elif p.isAccused():
                st = T.td[""](_class="accusedbox")
            else:
                st = T.td[""](_class="livebox")
            if p.note.badness == 0:
                bt = T.td[""](_class="correctbox")
            elif p.note.badness == 1:
                bt = T.td[""](_class="passivebox")
            elif p.note.badness == 2:
                bt = T.td[""](_class="activebox")

            a = T.td[T.a[""](href="/%x" % bytes_to_long(p.id), _class="address", data=p, render=self.render_address)]
            rows.append( T.tr[ T.td[accus.nr], st, bt, a])
        return t[T.table[rows](_class="peerlist")]    
 

class RootPage(MasterPage):
    body = overviewT
    child_css = static.File(os.path.join(templatePath,"css"))

    #child_logs = static.File(os.path.join(templatePath,"images"))

    def __init__(self, peer):
        MasterPage.__init__(self, peer)

    def child_stats(self, context):
        return StatsPage(self.peer)
    
    def child_rings(self, context):
        return RingsPage(self.peer)
    
    def childFactory(self, context, name):
        try:
            i = long(name, 16)
            peer = self.peer.view.sn2peer[long_to_bytes(i)]
            return PeerPage(self.peer, peer)
        except Exception:
            return None        
        return None
    
    def child_partners(self, context):
        return PartnersPage(self.peer)


class StatsPage(MasterPage):
    body = statsT


class PartnersPage(MasterPage):
    body = partnersT
    def __init__(self, peer):
        MasterPage.__init__(self, peer)

    def render_gossipOut(self, context, peer):
        global gossipsubs
        t = context.tag.clear()
        rows = [
            T.tr[ T.th["#"], T.th["S"],
                  T.th["B"], T.th["Address"], T.th["State"]]]
        for x in range(len(gossipsubs.cFactory.connections)):
            y = gossipsubs.cFactory.connections[x]
            d1 = T.td[x]
            if y:
                p = y.other
                if p in self.peer.view.fRing:
                    d2 = T.td[""](_class="failedbox")
                elif p.isAccused():
                    d2 = T.td[""](_class="accusedbox")
                else:
                    d2 = T.td[""](_class="livebox")
                if p.note.badness == 0:
                    d3 = T.td[""](_class="correctbox")
                elif p.note.badness == 1:
                    d3 = T.td[""](_class="passivebox")
                elif p.note.badness == 2:
                    d3 = T.td[""](_class="activebox")

                d4 = T.td[T.a[""](href="/%x" % bytes_to_long(p.id), _class="address", data=p, render=self.render_address)]
                d5 = T.td[y.state]
            else:
                d2 = d3 = d4 = T.td[""]
                d5 = T.td["Skip"]
            rows.append(T.tr[d1, d2, d3, d4, d5])
        return t[ T.table[ rows](_class="peerlist")]

    def render_gossipIn(self, context, peer):
        global gossipsubs
        t = context.tag.clear()
        rows = [
            T.tr[ T.th["#"], T.th["S"],
                  T.th["B"], T.th["Address"], T.th["State"]]]
        for x in range(len(gossipsubs.sFactory.cons)):
            y = gossipsubs.sFactory.cons[x]
            d1 = T.td[x]
            if y:
                p = y.other
                if p in self.peer.view.fRing:
                    d2 = T.td[""](_class="failedbox")
                elif p.isAccused():
                    d2 = T.td[""](_class="accusedbox")
                else:
                    d2 = T.td[""](_class="livebox")
                if p.note.badness == 0:
                    d3 = T.td[""](_class="correctbox")
                elif p.note.badness == 1:
                    d3 = T.td[""](_class="passivebox")
                elif p.note.badness == 2:
                    d3 = T.td[""](_class="activebox")

                d4 = T.td[T.a[""](href="/%x" % bytes_to_long(p.id), _class="address", data=p, render=self.render_address)]
                d5 = T.td[y.state]
            else:
                d2 = d3 = d4 = T.td[""]
                d5 = T.td["None"]
            rows.append(T.tr[d1, d2, d3, d4, d5])
        return t[ T.table[ rows](_class="peerlist")]

            
    def render_monitor(self, context, peer):
        global pingersubs

        t = context.tag.clear()
        rows = [
            T.tr[ T.th["#"], T.th["S"],
                  T.th["B"], T.th["Address"],
                  T.th["Pings"], T.th["Fails"],
                  T.th["avgL"],
                  T.th["State"]]]

        mons = []
        for x in range(len(self.peer.view.mRings)):
            mon = self.peer.view.mRings[x].succ(self.peer)
            while mon.isAccused():
                if mon.id == self.peer.id: break
                mon = self.peer.view.mRings[x].succ(mon)
            mons.append(mon)
            
        #mons = map( lambda x: x.succ(self.peer), self.peer.view.mRings)
        for x in range(len(mons)):
            y = mons[x]
                
            d1 = T.td[x](align="center")

            if y and y.id != self.peer.id:
                p = y
                if p in self.peer.view.fRing:
                    d2 = T.td[""](_class="failedbox")
                elif p.isAccused():
                    d2 = T.td[""](_class="accusedbox")
                else:
                    d2 = T.td[""](_class="livebox")

                if not p.note:
                    d3 = T.td["?"](_class="failedbox")
                elif p.note.badness == 0:
                    d3 = T.td[""](_class="correctbox")
                elif p.note.badness == 1:
                    d3 = T.td[""](_class="passivebox")
                elif p.note.badness == 2:
                    d3 = T.td[""](_class="activebox")
                else:
                    d3 = T.td["?"](_class="failedbox")

                d4 = T.td[T.a[""](href="/%x" % bytes_to_long(p.id), _class="address", data=p, render=self.render_address)]
                
                if y.note.mask[x] == False:
                    d7 = T.td["disabled"]
                    d5 = d6 = d8 = T.td[""]
                elif y in mons[0:x]:
                    d7 = T.td["dub %d" % mons.index(y)]
                    d5 = d6 = d8 = T.td[""]
                else:
                    d7 = T.td["mon"]

                d5 = T.td[p.nPing]
                pmist = self.peer.group.cacert.config["PMISTAKE"]
                tmin = self.peer.group.cacert.config["TMIN"]
                psucc = min( 1./(p.avgLoss), 1. - pmist**(1./float(tmin)))
                tau = log(pmist) / log(1. - psucc)
                d6 = T.td[int(ceil(tau))]
                d8 = T.td[p.avgLoss]
            else:
                d2 = d3 = d4 = d5 = d8 = d6 = T.td[""]
                d7 = T.td["N/A"]

            d5(align="center")
            d6(align="left")
            rows.append(T.tr[d1, d2, d3, d4, d5, d6, d8, d7])
        return t[ T.table[ rows](_class="peerlist")]




class RingsPage(MasterPage):
    body = ringsT
    def __init__(self, peer):
        MasterPage.__init__(self, peer)


    def render_rings(self, context, rings):
        t = context.tag.clear()
        ringsPerTable = 2
        l = []

        tables = []
        for x in range(len(rings)):
            column = rings[x]
            rows = [ T.caption[x],
                     T.tr[ T.th["S"], T.th["B"], T.th["Address"] ] ]
            for peer in column:

                if peer in self.peer.view.fRing:
                    st = T.td[""](_class="failedbox")
                elif peer.isAccused():
                    st = T.td[""](_class="accusedbox")
                else:
                    st = T.td[""](_class="livebox")
                if peer.note.badness == 0:
                    bt = T.td[""](_class="correctbox")
                elif peer.note.badness == 1:
                    bt = T.td[""](_class="passivebox")
                elif peer.note.badness == 2:
                    bt = T.td[""](_class="activebox")

                a = T.td[T.a[""](href="/%x" % bytes_to_long(peer.id), _class="address", data=peer, render=self.render_address)]
                rows.append( T.tr[  st, bt, a])

                
            tables.append(T.table[rows](_class="ring"))
        return t[tables]
        #
        rn  = range(len(rings))
        for r in rn:
            if r == 0: continue
            elif r % ringsPerTable == 0:
                l.append( rn[r-ringsPerTable: r])
            if r == len(rn)-1:
                l.append( rn[(r-r%ringsPerTable): ])

        for rset in l:
            rows = [T.tr[
                [T.th[x] for x in rset]
                ]]
            for r in range(len(rings[0])):
                column = []
                for c in rset:
                    p = rings[c][r]
                    column.append( T.td[ T.span[""](data=p, render=self.render_peer)])
                    
                rows.append(T.tr[column])
            table = T.table[rows](_class="rings", border="0", cellpadding="0", cellspacing="0")
            t[table]
            rows = []
        return t

