# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      ring.py
## Description:   Ring classes.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Tue Jan 24 10:39:41 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006,2007, Håvard D Johansen (Norway)
##                
## $Id: ring.py,v 1.4 2007/06/21 07:37:14 haavardj Exp $
##                
######################################################################

import bisect

def __ringIterator(ring, start=0):
    for x in range(len(ring)):
        yield ring[x]
        
def __ringTraverse(ring, idx):
    l = len(ring)
    idx = (start + 1) % l
    while 1:
        yield ring[idx]
        idx = (idx + 1) % l
        if idx == start: break


class Ring(object):    
    """A ring is a finite field of items. A ring is similar to Python
    list but items are kept sorted according to their sort
    key. Inserting two items with the same key will raise a ValueError
    exception.
    
    This implementation uses the return value of the items hash
    function as the sort keys. To use a different sort key,
    re-implement the _sortKey method in a subclass. Keys can be any
    object that implements a __hash__ and __cmp__ method, and is
    unique to each object.    
    """

    def __init__(self):
        self.__keylist = []
        self.__key2itm = {}

    def _sortKey(self, item):
        """Return item's sorting. 
        
        This implementation uses the item's hash function return value
        as a key. Reimplement this method in a subclass to use other
        sort keys."""
        return hash(item)

    def __iterate__(self):
        """Iterate the ring starting at the lowest number.
        
        The ring should not be modified during iteration."""
        return __ringIterator(self, 0)

    def traverse(self, item):
        """Iterates the ring starting at item's successor."""
        idx = self.__keylist.index(self._sortKey(item))        
        return __ringIterator(self, idx)

    def __len__(self):
        """Return the number of items in the ring."""
        return len(self.__keylist)
        
    def __getitem__(self, idx):
        """Return the item with the sort key idx."""
        key = self.__keylist[idx]
        return self.__key2itm[key]
        
    def __contains__(self, item):
        """Return True if item is in the ring."""
        
        key = self._sortKey(item)
        return key in self.__key2itm

    def index(self, item):
        """Return the item's index in the ring. 

        Raises ValueError if the item is not in the ring."""

        key = self._sortKey(item)
        try:
            return self.__keylist.index(key)
        except ValueError:
            raise ValueError, "Item %s not in ring" % str(item)
        
    def insert(self, item):
        """Insert item into the ring. 

        Raises ValueError if the item is already in the ring. Return index
        where item was inserted."""

        key = self._sortKey(item)
        if key in self.__key2itm:
            raise ValueError, "Item %s already in list" % (str(item))        
        idx = bisect.bisect_right(self.__keylist, key)
        self.__keylist.insert(idx, key)
        self.__key2itm[key] = item
        return idx

    def remove(self, item):
        """Remove item from the ring. 

        Raises ValueError if the item is not in the ring."""
        
        try:
            del self[self.index(item)]
        except ValueError:
            raise ValueError, "Item %s not in ring" % str(item)
        
    def __delitem__(self, idx):
        key = self.__keylist[idx]
        del self.__keylist[idx]
        del self.__key2itm[key]
    
    def isBetween(self, pred, item, succ):
        """Retur True if item lies between (intercepts) pred and succ on the ring.

        Please note the following semantic:

          - An item lies between itself. That is, if pred == itm == succ, True is
          returned.

          - Nothing (else) lies between an item and itself. That is, if
          pred == succ, but item != pred and item != succ this method returns False.
          
          - An item is always between itself and any other item. That
          is, if pred == item, or succ == item but pred != succ, this method
          returns True.

          - Raises a ValueError if succ, pred, or item is not in the ring.          
        """
        
        li = self.index(pred)
        bi = self.index(item)
        hi = self.index(succ)
        if li == bi and bi == hi: return True 
        
        if hi > li:
            if bi <= li or bi >= hi: return False
            else: return True
        elif hi < li:
            if bi > li or bi < hi: return True
            else: return False
        else:
            return False
        
    def betweenSucc(self, start, stop):
        """Return all clockwise items between (but not including) start item and stop item."""
        lst = []
        s = self.succ(item)
        while s:
            if s == stop: break
            lst.append(s)
            s = self.succ(s)
        return lst        
                
    def betweenPred(self, start, stop):
        """Return all counter-clockwiste items between (but not including) start and stop."""
        lst = []
        s = self.pred(item)
        while s:
            if s == stop: break
            lst.append(s)
            s = self.pred(s)
        return lst        

    def collectPred(self, start, stopFunc):
        """"Return a list of all items counter-clock wise in the ring from
        (but excluding) start item to (but excluding) the first item where
        stopFunc(item) evaluates to True."""

        lst = []
        s = self.pred(start)
        while s:
            if stopFunc(s): break
            lst.append(s)
            s = self.ped(s)
        return lst        
        
    def collectSucc(self, start, stopFunc):
        """"Return a list of all items clock wise in the ring from (but excluding)
        start item to (but excluding) the first item where stopFunc(item)
        evaluates to True."""
        
        lst = []
        s = self.succ(start)
        while s:
            if s == stop: break
            lst.append(s)
            s = self.succ(s)
        return lst            
        
    def succ(self, item, func=lambda x: True):
        """Return the first successor of item for which func evaluates
        to True. itm is never evaluated. The default func always evaluates to True.

        Raises ValueError if item is not in the ring. 

        Returns None if func never evaluates to True.
        
        """
        l = len(self.__keylist)
        key = self._sortKey(item)
        idx1 = idx = self.__keylist.index(key)     
        idx = (idx + 1) % l
        key = self.__keylist[idx]
        while not func(self.__key2itm[key]):
            if idx == idx1: return None            
            idx = (idx + 1) % l
            key = self.__keylist[idx]       
        return self.__key2itm[key]
    
    def pred(self, item, func=lambda x: True):
        """Returns the first predecessor of item for which func evaluates to
        True. itm is never evaluated. The default func always evaluates to True.

        Raises ValueError if item is not in the ring. 

        Returns None if func never evaluates to True.
        """

        l = len(self.__keylist)
        key = self._sortKey(item)
        idx1 = idx = self.__keylist.index(key)
        idx = (idx - 1) % l
        key = self.__keylist[idx]
        while not func(self.__key2itm[key]):
            if idx == idx1: return None            
            idx = (idx - 1) % l
            key = self.__keylist[idx]                       
        return self.__key2itm[key]
    
    
class NumberedRing(Ring):
    """A numbered ring that will sort item differently for different ring numbers."""
    def __init__(self, nr):
        super(NumberedRing, self).__init__()
        self.nr = nr
        
    def _sortKey(self, item):
        return hash(hash(item) + hash(self.nr))  

class NumberedSetOfRings(object):
    """A set of numbered rings. The constructor to the ring accept a
    number as a parameter. The contained rings should not be modified by directly."""
    
    ringClass = NumberedRing
    
    def __init__(self, num):
        self.__rings = []
        for x in range(num):
            self.__rings.append(self.ringClass(x))
        
    def __iter__(self):
        """Iterate over all rings."""
        return iter(self.__rings)
    
    def __getitem__(self, key):
        """Return a ring by index key."""
        return self.__rings[key]
    
    def __len__(self):
        """Return the number of rings."""
        return len(self.__rings)
    
    def __contains__(self, itm):
        return itm in self.__rings[0]

    def setLength(self, num):
        while num < len(self):
            self.__rings.pop(-1)
        while num > len(self):
            newRing = self.ringClass(len(self.__rings))
            for member in self.__rings[0]: 
                newRing.insert(member)
            self.__rings.append(newRing)

    def succ(self, itm, func=lambda x: True):
        """Return for each ring the first successor of itm for which func evaluates to true."""
        return map(lambda x: x.succ(itm, func), self.__rings)

    def pred(self, itm, func=lambda x: True):        
        """Return for each ring the first predecessor of itm for which func evaluates to true."""
        return map(lambda x: x.pred(itm, func), self.__rings)
    
    def insert(self, itm):
        """Insert itm in all rings."""
        for ring in self.__rings: ring.insert(itm)
        
    def remove(self, itm):
        """Remove itm from all rings."""        
        for ring in self.__rings: ring.insert(itm)