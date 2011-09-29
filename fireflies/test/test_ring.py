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
    
    numMembers = 200
    
    def setUp(self):
        self.objs = [RingObject(x) for x in range(self.numMembers)]             
        self.ring = TestRing()
        self.seq = list(self.objs)
        random.shuffle(self.seq)
        for obj in self.seq: self.ring.insert(obj)        

        
    def testSucc(self):                
        start = current = random.choice(self.ring)
        current = self.ring.succ(current)
        for x in range(len(self.objs)-1):
            self.failUnlessEqual(self.ring.pred(self.ring.succ(current)), current)
            self.failIfEqual(start, current)
            current = self.ring.succ(current)            
        self.failUnlessEqual(start,current)

    def testPred(self):
        start = current = random.choice(self.ring)
        current = self.ring.pred(current)
        for x in range(len(self.objs)-1):
            self.failUnlessEqual(self.ring.succ(self.ring.pred(current)), current)
            self.failIfEqual(start, current)
            current = self.ring.pred(current)            
        self.failUnlessEqual(start,current)
        
    def testRuleSuccLambdaNeverTrue(self):
        o = random.choice(self.objs)        
        self.failUnlessEqual(None, self.ring.succ(o, lambda x: False)) 
        
    def testIndex(self):        
        for x in range(len(self.ring)):
            o = self.ring[x]
            self.failUnlessEqual(x, self.ring.index(o))
        
    def testPredSuccWraparound(self):
        first = self.objs[0]
        last = self.objs[-1]
        self.failUnlessEqual(self.ring.succ(last), first)
        self.failUnlessEqual(self.ring.pred(first), last)        
        
    def testPredSucc(self):
        for o in self.ring:
            self.failUnlessEqual(self.ring.pred(self.ring.succ(o)), o)
            self.failUnlessEqual(self.ring.succ(self.ring.pred(o)), o)

    def testIndex(self):
        for obj in self.seq:
            self.failUnlessEqual(self.ring.index(obj), obj.sn)
        
    def testItemBetweenFirstAndLast(self):
        
        if len(self.objs) < 3:
            return 

        first = self.ring[0]
        last = self.ring.pred(first)

        self.failUnlessEqual(self.ring.index(first), 0)        
        self.failUnlessEqual(self.ring.index(last), len(self.ring)-1)        
        
    
        middle = self.ring[random.randint(1,len(self.ring)-2)]
        
        self.failUnless(self.ring.isBetween(first, middle, last))
        self.failUnless(self.ring.isBetween(last, first, middle))
        self.failIf(middle != first and middle != last and self.ring.isBetween(last, middle, first))
    
    def testItemBetween(self):
        
        for j in self.ring:
            i = self.ring.pred(j)
            k = self.ring.succ(j)
                    
        if len(self.ring) < 3:
            self.failIf(self.ring.isBetween(i, j, k))
            self.failIf(self.ring.isBetween(j, k, i))
            self.failIf(self.ring.isBetween(k, i, j))            

            self.failIf(self.ring.isBetween(k, j, i)  )
            self.failIf(self.ring.isBetween(j, i, k)  )
            self.failIf(self.ring.isBetween(i, k, j)  )
        else:
            
            self.failUnless(self.ring.isBetween(i, j, k))
            self.failUnless(self.ring.isBetween(j, k, i))
            self.failUnless(self.ring.isBetween(k, i, j))            
            
            self.failIf(self.ring.isBetween(k, j, i)  )
            self.failIf(self.ring.isBetween(j, i, k)  )
            self.failIf(self.ring.isBetween(i, k, j)  )
    
        
    def testNothingIsBetweenItemAndItself(self):
        
        for i in self.ring:        
            for j in self.objs:
                self.failIf(self.ring.isBetween(i, j, i))
        
    def testItemNeverBetweenItselfAndOther(self):
        middle = random.choice(self.objs)
        
        for obj in self.objs:
            self.failIf(self.ring.isBetween(middle, middle, obj), 
                            "not between %s - %s - %s" %(middle, middle, obj))
            self.failIf(self.ring.isBetween(obj, middle, middle),
                            "not between %s - %s - %s" %(obj, middle, middle))


    def testRank(self):
        r = self.ring
        start = current = random.choice(self.objs)        
        x = 0
        while 1:        
            rnk = r.rank(start, current)
            self.failUnlessEqual(x, rnk)
            x += 1
            current = r.succ(current)
            if current == start:
                break

     
class NumberedRingQueryTest(RingQueryTest):
    
    def setUp(self):
        self.objs = [RingObject(x) for x in range(200)]
        self.ring = ring.NamedRing(21789)
        self.seq = list(self.objs)
        random.shuffle(self.seq)
        for obj in self.seq: self.ring.insert(obj)        

class RingQuery10MembersTest(RingQueryTest, unittest.TestCase):  
    numMembers = 10                  
        
class RingQuery3MembersTest(RingQueryTest, unittest.TestCase):  
    numMembers = 3
        
class RingQuery2MembersTest(RingQueryTest, unittest.TestCase):  
    numMembers = 2

class RingQuery1MembersTest(RingQueryTest, unittest.TestCase):  
    numMembers = 1

            
class BasicRingSetTest(unittest.TestCase):
    
    def setUp(self):
        self.rings = ring.RingSet()
        
        for x in range(10):
            self.rings.insertRing(ring.NamedRing(x))

        self.objs = [RingObject(x) for x in range(200)]           
        random.shuffle(self.objs)
        for obj in self.objs: self.rings.insertItem(obj)  
    
    def testAllItemsArePresent(self):
        for o in self.objs:
            self.failUnless(o in self.rings.getItems())
            for r in self.rings.getRings():
                self.failUnless(o in r)
        

class MergedRingSetTest(BasicRingSetTest):           

    def setUp(self):
        self.rings = ring.RingSet()
        
        for x in range(0,5):
            self.rings.insertRing(ring.NamedRing(x))

        self.objs = [RingObject(x) for x in range(200)]           
        random.shuffle(self.objs)
        for obj in self.objs: self.rings.insertItem(obj)  

        for x in range(5,10):
            self.rings.insertRing(ring.NamedRing(x))

        
    
if __name__ == "__main__":
    main()
