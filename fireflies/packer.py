# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      packer.py
## Description:   Fireflies data (de)-marshalling functions.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Thu Jan 19 21:26:19 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: packer.py,v 1.6 2007/06/26 08:57:24 haavardj Exp $
##                
######################################################################



from fireflies.members import Note, Accusation
from fireflies.cert import CACertificate, MemberCertificate, serialSize

import xdrlib, new, socket
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
import setrecon

SERIAL_LENGTH = serialSize()
HASH_LENGTH = serialSize()

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
        
    def pack_serial(self, serial):
        self.pack_fstring(SERIAL_LENGTH, serial)

    def pack_address(self, address):
        ip, port = address.split(":")
        port = int(port)
        self.pack_fstring(4, socket.inet_aton(ip))
        self.pack_uint(port)
        
    def pack_rsapubkey(self, key):
        state = key.__getstate__()
        n = state['n']
        e = state['e']
        self.pack_string(long_to_bytes(n))
        self.pack_string(long_to_bytes(e))

    def pack_signature(self, signature):
        self.pack_string(long_to_bytes(signature))

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
        """
        Format of packed certificate:
         address
         rsa key
         sign
         """
        self.pack_address(cert.address)
        self.pack_rsapubkey(cert.key)
        self.pack_signature(cert.signature)
        
    def pack_note(self, note):
        """
        Format of packed notes:
          - serial (size, string)
          - epoch (uint)
          - mask (size, string)
          - signature (size, string)
          - badness
          """
        
        self.pack_serial(note.serial)    
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
        
        self.pack_serial(accusation.accused)    
        self.pack_uint(accusation.epoch)
        self.pack_uint(accusation.nr)    
        self.pack_serial(accusation.accuser)
        self.pack_signature(accusation.signature)



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

    def unpack_serial(self):
        return self.unpack_fstring(SERIAL_LENGTH)

    def unpack_address(self):
        ip = socket.inet_ntoa(self.unpack_fstring(4))
        port = self.unpack_uint()
        return "%s:%d" % (ip, port)
        
    def unpack_rsapubkey(self):
        n = bytes_to_long(self.unpack_string())
        e = bytes_to_long(self.unpack_string())
        return RSA.construct((n,e))

    def unpack_signature(self):
        return bytes_to_long(self.unpack_string())

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
        address = self.unpack_address()
        key = self.unpack_rsapubkey()
        signature = self.unpack_signature()
        d = {
            'address': address,
            'key': key,
            'signature': signature
            }

        c = object.__new__(MemberCertificate)
        c.__setstate__(d)
        return c

    def unpack_note(self):
        serial = self.unpack_serial()
        epoch = self.unpack_uint()
        mask = self.unpack_mask()
        signature = self.unpack_signature()
        badness = self.unpack_uint()
        
        d = {
            'serial': serial,
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
        accused = self.unpack_serial()
        epoch = self.unpack_uint()
        nr = self.unpack_uint()
        accuser = self.unpack_serial()
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

