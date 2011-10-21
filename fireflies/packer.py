######################################################################
## Filename:      packer.py
## Description:   Fireflies data (de)-marshalling functions.
## Author:        Haavard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Thu Jan 19 21:26:19 2006
## Modified by:   Haavard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright 2006, Haavard D Johansen (Norway)
##                
## $Id: packer.py,v 1.18 2011/10/21 08:25:22 haavardj Exp $
##                
######################################################################

from fireflies.state import Note, Accusation
from fireflies.crypto import identitySize
from fireflies.util import long_to_bytes, bytes_to_long
import M2Crypto
import xdrlib, new, socket
import struct
import setrecon

SERIAL_LENGTH = identitySize()
HASH_LENGTH = identitySize()

_ctxs = {} 

class Referenceable:    
    def uid(self): pass
    
class Broker:
    def __init__(self):
        self._uid2lobj = {}
        self._lobj2uid = {}
            
    def register(self, uid, lobj):
        if uid in self._uid2lobj:
            assert obj in self._lobj2uid
            raise KeyError(uid, lobj)
        else:
            assert not lobj in self._lobj2uid        
        self._uid2lobj[uid] = lobj
        self._lobj2uid[lobj] = uid

    def resolve(self, uid):
        return self._uid2lobj[uid]
    
    def rresolve(self, obj):
        return self._lobj2uid[obj]
        
def getBroker(ctx=""):
    if not ctx in _ctxs:
        _ctxs[ctx] = Broker()
    b = _ctxs[ctx]
    isinstance(b, Broker)
    return b

def resolve(uid):
    return getBroker().resolve(uid)

def rresolve(obj):
    return getBroker().resolve(obj)

def register(uid, lobj):
    return getBroker().register(uid, lobj)


DATA_CERTIFICATE_ID = 0x1
DATA_NOTE_ID = 0x2
DATA_ACCUSATION_ID = 0x3

cmd2code = {
    'partner': 0x1,
    'accepted': 0x4,
    'gossip': 0x5,
    'authenticate': 0x6,
    'redirect': 0x7,
    'note': 0x8,
    'accusation': 0x9,
    'certificate': 0x10,
    'version': 0x11,
    'data': 0x12,
    'dataRequest':0x13,

    'reconcile': 0x20,
    'reconcile_next': 0x21,
    'reconcile_next_req': 0x22,
    'reconcile_done': 0x27,
    'reconcile_data': 0x28,
    'reconcile_data_req': 0x29,
    'digest_match': 0x2F
    }

code2cmd = {}
for k, v in cmd2code.items():
    code2cmd[v] = k


def PackMessage(cmd, *args):

    p = FirefliesPacker()
    p.pack_fstring(1, chr(cmd2code[cmd]))

    if cmd == "partner":
        note, = args
        p.pack_note(note)

    elif cmd == "authenticate":
        crt, note = args
        p.pack_cert(crt)
        p.pack_note(note)

    elif cmd == "redirect":
        for cert, note in args,:
            p.pack_bool(True)                        
            p.pack_cert(cert)
            p.pack_note(note)
        p.pack_bool(False)            

    elif cmd == "version":
        major, minor, patchl = args
        p.pack_short(major)
        p.pack_short(minor)
        p.pack_short(patchl)

    elif cmd == "reconcile":
        name, digest = args
        p.pack_string(name)
        p.pack_string(digest)

    elif cmd == "digest_match":
        match, = args
        p.pack_bool(match)

    elif cmd == "reconcile_next":
        node_type, hash_vector, extra_hashes, setsize = args
        p.pack_uint(node_type)

        if node_type > 0:
            p.pack_vec_ZZ_p(hash_vector)
        if node_type > 1:
            p.pack_vec_ZZ_p(extra_hashes)
            p.pack_uint(setsize)

    elif cmd == "reconcile_extra":
        vec, size = args
        p.pack_vec_ZZ_p(vec)
        p.pack_uint(size)

    elif cmd == "data":
        data, = args
        if isinstance(data, Accusation):
            p.pack_uint(DATA_ACCUSATION_ID)
            p.pack_accusation(data)
        elif isinstance(data, Note):
            p.pack_uint(DATA_NOTE_ID)
            p.pack_note(data)
        elif isinstance(data, M2Crypto.X509.X509):
            p.pack_uint(DATA_CERTIFICATE_ID)
            p.pack_cert(data)
        else:
            raise ValueError, "Unknown data type", data
        # note, accus, or cert

    elif cmd == "reconcile_data":
        data, = args
        if isinstance(data, Accusation):
            p.pack_uint(DATA_ACCUSATION_ID)
            p.pack_accusation(data)
        elif isinstance(data, Note):
            p.pack_uint(DATA_NOTE_ID)
            p.pack_note(data)
        elif isinstance(data, M2Crypto.X509.X509):
            p.pack_uint(DATA_CERTIFICATE_ID)
            p.pack_cert(data)
        else:
            raise ValueError, "Unknown data type", data
        # note, accus, or cert

    elif cmd in ["reconcile_data_req",]:
        vec, = args
        l = len(vec)
        p.pack_uint(l)
        for x in range(l):                    
            p.pack_ZZ(vec[x].rep())
            
    elif cmd in ["reconcile_next_req",
                 "reconcile_done",
                 "accepted",
                 "dataRequest"]:
        # No arguments.
        pass                
    else:
        raise RuntimeError, "Unknown command."

    return p.get_buffer()

def unpackMessage(data):
    cmd = "N/A"
    p = FirefliesUnpacker(data)
    cmd = code2cmd[ord(p.unpack_fstring(1))]
    args = ()
    if cmd == "partner":
        args = (p.unpack_note(),)

    elif cmd == "authenticate":
        args = (p.unpack_cert(), p.unpack_note())

    elif cmd == "redirect":
        args = []
        while p.unpack_bool():
            args.append( (p.unpack_cert(), p.unpack_note() ))

    elif cmd == "version":
        args = (p.unpack_short(),
                p.unpack_short(),
                p.unpack_short())

    elif cmd == "reconcile":
        args = (p.unpack_string(),
                p.unpack_string()
                )
    elif cmd == "digest_match":
        args = (bool(p.unpack_bool()),)

    elif cmd == "reconcile_next":
        node_type = p.unpack_uint()
        hash_vector = None
        extra_hashes = None
        setsize = -1
        if node_type > 0:
            hash_vector = p.unpack_vec_ZZ_p()
        if node_type > 1:
            extra_hashes = p.unpack_vec_ZZ_p()
            setsize = p.unpack_uint()
        args = (node_type,
                hash_vector,
                extra_hashes,
                setsize)

    elif cmd == "data":
        t = p.unpack_uint()
        if t == DATA_ACCUSATION_ID:
            args = (p.unpack_accusation(),)
        elif t == DATA_NOTE_ID:
            args = (p.unpack_note(),)
        elif t == DATA_CERTIFICATE_ID:
            args = (p.unpack_cert(),)
        else:
            raise ValueError("Unknown data.")

    elif cmd == "reconcile_data":
        t = p.unpack_uint()
        if t == DATA_ACCUSATION_ID:
            args = (p.unpack_accusation(),)
        elif t == DATA_NOTE_ID:
            args = (p.unpack_note(),)
        elif t == DATA_CERTIFICATE_ID:
            args = (p.unpack_cert(),)
        else:
            raise ValueError("Unknown data.")

    elif cmd in ["reconcile_data_req"]:
        l = p.unpack_uint()
        r = []
        for x in range(l):
            r.append(setrecon.to_ZZ_p(p.unpack_ZZ()))
            
        args = (r,)

            
    elif cmd in ["reconcile_done",
                 "accepted",
                 "dataRequest"]:

        # No arguments.
        args = ()
            
    else:
        raise Exception, "unknown command."

    p.done()    
    return cmd, args

    

class FirefliesPacker(xdrlib.Packer):

    def __init__(self):
        xdrlib.Packer.__init__(self)

    def pack_ZZ(self, zz):
        assert isinstance(zz, setrecon.ZZ)
        s = zz.toBytes()
        self.pack_string(s)

    def pack_vec_ZZ_p(self, vec):
        assert isinstance(vec, setrecon.vec_ZZ_p)
        
        l = vec.length()
        self.pack_uint(l)
        for x in range(l):
            zz_p = vec[x]

            # Vector elements might be NULL/None
            assert zz_p != None
            #if not zz_p:
            #    self.pack_fstring(1, chr(0))
            #else:
            self.pack_ZZ(zz_p.rep())
        
    def pack_node(self, node):
        assert False
        self.pack_vec_ZZ_p(node.hash_vector)
        self.pack_vec_ZZ_p(node.extra_hashes)
        self.pack_ZZ(node.start)
        self.pack_ZZ(node.stop)
        self.pack_int(node.node_type)
        self.pack_int(node.setsize)
        
    def pack_identity(self, identity):
        self.pack_string(identity)
        #self.pack_string(long_to_bytes(identity))

    def pack_address(self, address):
        ip, port = address.split(":")
        port = int(port)
        self.pack_fstring(4, socket.inet_aton(ip))
        self.pack_uint(port)        

    def pack_signature(self, signature):
        self.pack_string(signature)

    def pack_short(self, short):
        self.pack_fstring(1, chr(short))

    def pack_mask(self, mask):
        masklen = len(mask)
        assert masklen < 256 and masklen >= 0
        self.pack_fstring(1, chr(masklen))
        
        maskbytes = masklen/8
        if (masklen % 8) != 0:
            maskbytes += 1
        
        b = 0
        for x in range(masklen):
            if mask[x]:
                b += (2**x)                
        s = long_to_bytes(b)
        s = "\0" *(maskbytes - len(s)) + s
        self.pack_fstring(maskbytes,s)
        
    def pack_cert(self, cert):
        assert isinstance(cert, M2Crypto.X509.X509)
        self.pack_string(cert.as_der())
        
    def pack_note(self, note):
        """
        Format of packed notes:
          - identity (size, string)
          - epoch (uint)
          - mask (size, string)
          - signature (size, string)
          - badness
          """
        
        self.pack_identity(note.identity)    
        self.pack_uint(note.epoch)
        self.pack_mask(note.mask)
        self.pack_signature(note.signature)
        self.pack_uint(note.badness)

    def pack_accusation(self, accusation):
        """Format:
        accused   (size, string)
        epoch  (uint)
        nr        (uint)
        accuser   (size, string)
        signature (size, string)
        """
        
        self.pack_identity(accusation.accused)    
        self.pack_uint(accusation.epoch)
        self.pack_uint(accusation.nr)    
        self.pack_identity(accusation.accuser)
        self.pack_signature(accusation.signature)
        
    def pack_objectReference(self, obj, ctx=""):
        broker = getBroker(ctx)
        ref = broker.rresolve(obj)
        self.pack_identity(ref)


class FirefliesUnpacker(xdrlib.Unpacker):

    def __ini__(self, data):
        xdrlib.Unpacker.__init__(self, data)

    def unpack_ZZ(self):
        #l = self.unpack_fstring(1)
        #l = ord(l)
        #if l == 0:
        #    raise ValueError
        #
        #s = self.unpack_fstring(l)
        #return setrecon.to_ZZFromBytes(s)
        s = self.unpack_string()
        return setrecon.to_ZZFromBytes(s)

    def unpack_vec_ZZ_p(self):
        l = self.unpack_uint()
        vec = setrecon.vec_ZZ_p()
        vec.SetLength(l)
        for x in range(l):
            zz = self.unpack_ZZ()
            vec[x] = setrecon.to_ZZ_p(zz)
        return vec

    def unpack_node(self):
        assert False
        node = setrecon.node()
        node.hash_vector = self.unpack_vec_ZZ_p()
        node.extra_hashes = self.unpack_vec_ZZ_p()
        node.start = self.unpack_ZZ()
        node.stop = self.unpack_ZZ()
        node.node_type = self.unpack_int()
        node.setsize = self.unpack_int()
        return node

    def unpack_identity(self):
        return self.unpack_string()
        #return bytes_to_long(self.unpack_string())

    def unpack_address(self):
        ip = socket.inet_ntoa(self.unpack_fstring(4))
        port = self.unpack_uint()
        return "%s:%d" % (ip, port)
        
    def unpack_signature(self):
        return self.unpack_string()

    def unpack_short(self):
        return ord(self.unpack_fstring(1))

    def unpack_mask(self):
        masklen = ord(self.unpack_fstring(1))        
        maskbytes = masklen/8
        if (masklen % 8) != 0:
            maskbytes += 1
        b = bytes_to_long(self.unpack_fstring(maskbytes))
        l = [False]* masklen
        for x in range(masklen):
            if b & 2**x:
                l[x] = True
        return l
                    
    def unpack_cert(self):
        return M2Crypto.X509.load_cert_der_string(self.unpack_string())

    def unpack_note(self):
        identity = self.unpack_identity()
        epoch = self.unpack_uint()
        mask = self.unpack_mask()
        signature = self.unpack_signature()
        badness = self.unpack_uint()
        
        d = {
            'identity': identity,
            'epoch': epoch,
            'mask': mask,
            'signature': signature,
            'badness': badness,
            }

        c = object.__new__(Note)
        c.__setstate__(d)
        #c.__dict__.update(d)
        return c

    def unpack_accusation(self):
        accused = self.unpack_identity()
        epoch = self.unpack_uint()
        nr = self.unpack_uint()
        accuser = self.unpack_identity()
        signature = self.unpack_signature()

        state = {
            'accused': accused,
            'epoch': epoch,
            'nr': nr,
            'accuser': accuser,
            'signature': signature}
        
        c = object.__new__(Accusation)
        c.__setstate__(state)        
        return c

    def unpack_objectByReference(self, ctx=""):
        identity = self.unpack_identity()
        broker = getBroker(ctx)
        return broker.resolve(identity)
        
        
