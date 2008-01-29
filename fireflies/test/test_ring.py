#import unittest
from fireflies import ring

from twisted.trial import unittest
from zope.interface import implements
from fireflies.interfaces import IIdentifiableObject
import random

def main():
    unittest.main()

    
class RingObject(object):
    
    implements(IIdentifiableObject)
    
    def __init__(self, sn):
        self.sn = sn
        
    def identity(self):
        return self.sn

    def __cmp__(self, other):
        return cmp(self.identity(), other.identity())

    def __str__(self):
        return str(self.sn)
    
    __repr__ = __str__

class TestRing(ring.Ring):
    
    def _sortKey(self, item):        
        return item.sn


class RingModificationTest(unittest.TestCase):
    
    def testInsertRemove(self):
        objs = [RingObject(x) for x in range(200)]             
        ring = TestRing()
        
        seq = list(objs)
        random.shuffle(seq)
        for obj in seq:
            ring.insert(obj)
            self.failUnless(obj in ring)
                    
        random.shuffle(seq)
        for obj in seq:
            self.failUnless(obj in ring)            
            self.failUnlessRaises(ValueError, ring.insert, obj)

        random.shuffle(seq)
        for obj in seq:
            ring.remove(obj)
            self.failIf(obj in ring)
            self.failUnlessRaises(ValueError, ring.remove, obj)
            
        for obj in seq:
            self.failIf(obj in ring)
    
class RingQueryTest(unittest.TestCase):
    
    def setUp(self):
        self.objs = [RingObject(x) for x in range(200)]             
        self.ring = TestRing()
        self.seq = list(self.objs)
        random.shuffle(self.seq)
        for obj in self.seq: self.ring.insert(obj)        

        
    def testPredSuccWraparound(self):
        first = self.objs[0]
        last = self.objs[-1]
        self.failUnlessEqual(self.ring.succ(last), first)
        self.failUnlessEqual(self.ring.pred(first), last)

    def testPredSuccLambda(self):
        first = self.objs[3]
        last = self.objs[5]
        self.failUnlessEqual(self.ring.succ(first, lambda x: self.ring.index(x) % 2 == 1), last)
        self.failUnlessEqual(self.ring.pred(last, lambda x: self.ring.index(x) % 2  == 1 ), first)        
        self.failIfEqual(self.ring.pred(last, lambda x: self.ring.index(x) % 2  == 1 ), last)        
        
    def testRandomPredSucc(self):
        o = random.choice(self.objs)
        self.failUnlessEqual(self.ring.pred(self.ring.succ(o)), o)
        self.failUnlessEqual(self.ring.succ(self.ring.pred(o)), o)

    def testIndex(self):
        for obj in self.seq:
            self.failUnlessEqual(self.ring.index(obj), obj.sn)
        
    def testItemBetweenFirstAndLast(self):
        first = self.objs[0]
        last = self.objs[-1]
        middle = self.objs[10]
        
        self.failUnless(self.ring.isBetween(first, middle, last))
        self.failUnless(self.ring.isBetween(last, first, middle))
        self.failIf(self.ring.isBetween(last, middle, first))
        
    def testNotingIsBetweenItemAndItself(self):
        middle = self.objs[10] 
        
        for obj in self.objs:
            val = self.ring.isBetween(middle, obj, middle)
            if obj == middle: 
                self.failUnless(val)
            else:
                self.failIf(val)
        
    def testItemAlwaysBetweenItselfAndOther(self):
        middle = self.objs[50] 
        
        for obj in self.objs:
            self.failUnless(self.ring.isBetween(middle, middle, obj), 
                            "not between %s - %s - %s" %(middle, middle, obj))
            self.failUnless(self.ring.isBetween(obj, middle, middle),
                            "not between %s - %s - %s" %(obj, middle, middle))



                
if __name__ == "__main__":
    main()
