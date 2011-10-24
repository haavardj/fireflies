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
## $Id: ring.py,v 1.21 2011/10/24 08:59:17 haavardj Exp $
##                
######################################################################

import bisect, sha

def _ringIterator(ring, start=0):
    for x in ring.items()[start:]:
        yield x
        
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
        """Return item's sorting key.
        
        This implementation uses the item's hash function return value
        as a key. Reimplement this method in a subclass to use other
        sort keys."""
        return item.identity()

    def __iter__(self):
        """Iterate the ring starting at the lowest number.
        
        The ring should not be modified during iteration."""
        return _ringIterator(self, 0)

    
    def traverse(self, item):
        """Iterates the ring starting at item's successor."""
        idx = self.__keylist.index(self._sortKey(item))        
        return __ringIterator(self, idx)

    def __len__(self):
        """Return the number of items in the ring."""
        return len(self.__keylist)
        
    def __getitem__(self, idx):
        """Return the item with the sort key idx."""
        #key = self.__keylist[idx]
        return self.__key2itm[idx]
        
    def __contains__(self, item):
        """Return True if item is in the ring."""
        
        key = self._sortKey(item)
        return key in self.__key2itm
    
    def items(self):
        return self.__key2itm.values()

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
        """Return True if item lies between (intercepts) pred and succ on the ring according to the succesor relationship.

        Please note the following semantic:

          - Rule 1: An item never intercepts a range contining itself. That is, if either pred or succ is item, False is returned.

          - Rule: Nothing lies between an item and and itself. That is, if pred == succ, then 
          this method always returns False.
                    
          - Raises a ValueError if succ, pred, or item is not in the ring.          
        """
        
        li = self.index(pred)
        bi = self.index(item)
        hi = self.index(succ)
        
        #Rule 1: An item always lies between itself. 
        if li == bi or hi == bi:
            return False         
        
        if li < hi:
            if li < bi and bi < hi: return True 
            else: return False
        elif hi < li:            
            if bi < hi or li < bi: return True
            else: return False
        else: # hi == li
            #Rule: Nothing lies between an item and itself (a null range).
            return False
       
    def betweenSucc(self, start, stop):
        """Return all clockwise items between (but not including) start item and stop item."""
        lst = []
        s = self.succ(item)
        while s:
            if s.identity() == stop.identity(): break
            lst.append(s)
            s = self.succ(s)
        return lst        
                
    def betweenPred(self, start, stop):
        """Return all counter-clockwiste items between (but not including) start and stop."""
        lst = []
        s = self.pred(item)
        while s:
            if s.identity() == stop.identity(): break
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
            if s.identity() == start.identity(): break
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
            if s.identity() == start.identity(): break
            if stopFunc(s): break
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
    
    def rank(self, item, dest):
        """Rank is defined as the number of items between item and dest."""
        
        idxItem = self.index(item)
        idxDest = self.index(dest)
        
        if idxDest < idxItem:
            return len(self) - idxItem + idxDest
        else:
            return idxDest - idxItem


class NamedRing(Ring):
    """A ring with a name/identity."""
    
    def __init__(self, name):
        self.name = name
        Ring.__init__(self)
        
    def identity(self):
        return self.name
    
import sha
class NameHashedRing(NamedRing):
    """A named ring that will sort items differently for different ring names."""
    
    mRingIDCache = {}    
        
    def _sortKey(self, item):
        iId = item.identity()
        try:
            return NameHashedRing.mRingIDCache[iId][self.identity()]
        except KeyError:
            ids = NameHashedRing.mRingIDCache.get(iId, {})
            idOnRing = sha.new("%s-%s" % (iId, self.identity())).digest()
            ids[self.identity()] = idOnRing
            NameHashedRing.mRingIDCache[iId] = ids
            return idOnRing

        
class RingSet:
    """A set of rings. The constructor to the ring accept a
    number as a parameter. The contained rings should not be modified directly."""
         
    def __init__(self):
        self._items = []
        self._rings = []

    def succ(self, itm, func=lambda x: True):
        """Return for each ring the first successor of itm for which func evaluates to true."""
        return map(lambda x: x.succ(itm, func), self._rings)

    def pred(self, itm, func=lambda x: True):        
        """Return for each ring the first predecessor of itm for which func evaluates to true."""
        return map(lambda x: x.pred(itm, func), self._rings)
    
    def insertItem(self, itm):
        """Insert itm in all rings."""
        if itm in self._items: raise ValueError("Item exist")
        self._items.append(itm)
        for ring in self._rings: ring.insert(itm)
        
#    def removeItem(self, itm):
#        """Remove itm from all rings."""        
#        self._items.remove(itm)
#        for ring in self: ring.remove(itm)
                     
    def insertRing(self, ring):
        """Insert itm in all rings. Items in ring will be merged with contained items."""
        for itm in ring:
            if itm not in self._items: self.insertItem(itm)
        for itm in self._items:
            if itm not in ring: ring.insert(itm)            

        self._rings.append(ring)
        
    def getRings(self):
        """Return a list of all contained rings."""
        return self._rings
    
    def getItems(self):
        """Return a list of all contained items."""
        return self._items

    def hasItem(self, item):
        return item in self.getItems()
    
    def hadRing(self, ring):
        return ring in self.getRings()
    
    def itemCount(self):
        return len(self.getItems())
           
    
class Relation:
    """A rule determining if item relate to otherItem in some manner on one particular ring.
    Implement relational rule in the isValid method in subclasses.""" 
    
    def __init__(self, item, otherItem, ring):
        self.item, self.otherItem, self.ring = item, otherItem, ring
        
    def isValid(self):   
        raise NotImplementedError
    
    def rank(self):
        """Return the rank of the items relative to each other."""
        return self.ring.rank(self.item, self.otherItem)
        
    def __cmp__(self, other):
        """Compare rank. Note: this might be semantically bad idea since objects
        might have differend otherItem and ring attributes."""

        return cmp(self.rank(), other.rank())

class SuccessorRelation(Relation):
    """Rule determining if two an item is the successor of another item in a ring."""
    
    def isValid(self):
        return self.ring.succ(item) == self.otherItem
                
class PredecessorRelation(Relation):
    """Rule determining if two an item is the predecessor of another item in a ring."""
    
    def isValid(self):
        return self.ring.pred(item) == self.otherItem

        