#import unittest
from fireflies import ring

from twisted.trial import unittest
from zope.interface import implementer
from fireflies.interfaces import IIdentifiableObject
import functools
import random
from functools import reduce



@implementer(IIdentifiableObject)
@functools.total_ordering
class RingObject(object):

    def __init__(self, sn):
        self.sn = sn

    def identity(self):
        return self.sn

    def __eq__(self, other):
        return self.identity() == other.identity()

    def __lt__(self, other):
        return self.identity() < other.identity()

    def __hash__(self):
        return hash(self.sn)

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
            self.assertTrue(obj in ring)
                    
        random.shuffle(seq)
        for obj in seq:
            self.assertTrue(obj in ring)            
            self.assertRaises(ValueError, ring.insert, obj)

        random.shuffle(seq)
        for obj in seq:
            ring.remove(obj)
            self.assertFalse(obj in ring)
            self.assertRaises(ValueError, ring.remove, obj)
            
        for obj in seq:
            self.assertFalse(obj in ring)
                    
    
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
            self.assertEqual(self.ring.pred(self.ring.succ(current)), current)
            self.assertNotEqual(start, current)
            current = self.ring.succ(current)            
        self.assertEqual(start,current)

    def testPred(self):
        start = current = random.choice(self.ring)
        current = self.ring.pred(current)
        for x in range(len(self.objs)-1):
            self.assertEqual(self.ring.succ(self.ring.pred(current)), current)
            self.assertNotEqual(start, current)
            current = self.ring.pred(current)            
        self.assertEqual(start,current)
             
    def testRuleSuccLambdaNeverTrue(self):
        o = random.choice(self.objs)        
        self.assertEqual(None, self.ring.succ(o, lambda x: False)) 
        
    def testIndex(self):        
        for x in range(len(self.ring)):
            o = self.ring[x]
            self.assertEqual(x, self.ring.index(o))
        
    def testPredSuccWraparound(self):
        first = self.ring[0]
        last = self.ring[-1]
        self.assertEqual(self.ring.succ(last), first)
        self.assertEqual(self.ring.pred(first), last)        
        
    def testPredSucc(self):
        for o in self.ring:
            self.assertEqual(self.ring.pred(self.ring.succ(o)), o)
            self.assertEqual(self.ring.succ(self.ring.pred(o)), o)
              
    def testItemBetweenFirstAndLast(self):
        
        if len(self.objs) < 3:
            return 

        first = self.ring[0]
        last = self.ring.pred(first)

        self.assertEqual(self.ring.index(first), 0)        
        self.assertEqual(self.ring.index(last), len(self.ring)-1)        
        middle = self.ring[random.randint(1,len(self.ring)-2)]
        self.assertTrue(self.ring.isBetween(first, middle, last))
        self.assertTrue(self.ring.isBetween(last, first, middle))
        self.assertFalse(middle != first and middle != last and self.ring.isBetween(last, middle, first))
    
    def testItemBetween(self):
        
        for j in self.ring:
            i = self.ring.pred(j)
            k = self.ring.succ(j)

            if len(self.ring) < 3:
                self.assertFalse(self.ring.isBetween(i, j, k))
                self.assertFalse(self.ring.isBetween(j, k, i))
                self.assertFalse(self.ring.isBetween(k, i, j))

                self.assertFalse(self.ring.isBetween(k, j, i))
                self.assertFalse(self.ring.isBetween(j, i, k))
                self.assertFalse(self.ring.isBetween(i, k, j))
            else:
                self.assertTrue(self.ring.isBetween(i, j, k))
                self.assertTrue(self.ring.isBetween(j, k, i))
                self.assertTrue(self.ring.isBetween(k, i, j))

                self.assertFalse(self.ring.isBetween(k, j, i))
                self.assertFalse(self.ring.isBetween(j, i, k))
                self.assertFalse(self.ring.isBetween(i, k, j))
        
    def testNothingIsBetweenItemAndItself(self):
        
        for i in self.ring:        
            for j in self.objs:
                self.assertFalse(self.ring.isBetween(i, j, i))
        
    def testItemNeverBetweenItselfAndOther(self):
        middle = random.choice(self.objs)
        
        for obj in self.objs:
            self.assertFalse(self.ring.isBetween(middle, middle, obj), 
                            "not between %s - %s - %s" %(middle, middle, obj))
            self.assertFalse(self.ring.isBetween(obj, middle, middle),
                            "not between %s - %s - %s" %(obj, middle, middle))

    def testRank(self):
        r = self.ring
        base = current = random.choice(self.objs)        
        x = 0
        self.assertEqual(0, self.ring.rank(base, base))
        while 1:        
            self.assertEqual(x, r.rank(current, base))
            x += 1
            current = r.succ(current)
            if current == base:
                break

     
class RingQuery10MembersTest(RingQueryTest, unittest.TestCase):  
    numMembers = 10                  
        
class RingQuery3MembersTest(RingQueryTest, unittest.TestCase):  
    numMembers = 3
        
class RingQuery2MembersTest(RingQueryTest, unittest.TestCase):  
    numMembers = 2

class RingQuery1MembersTest(RingQueryTest, unittest.TestCase):  
    numMembers = 1


class NamedHashedRingQueryTest(RingQueryTest):    
    def setUp(self):
        self.objs = [RingObject(x) for x in range(self.numMembers)]
        self.ring = ring.NameHashedRing(2)
        self.seq = list(self.objs)
        random.shuffle(self.seq)
        for obj in self.seq: self.ring.insert(obj)    
        
class NamedHashedRingQuery10MembersTest(NamedHashedRingQueryTest, unittest.TestCase):  
    numMembers = 10                  

class NamedHashedRingQuery3MembersTest(NamedHashedRingQueryTest, unittest.TestCase):  
    numMembers = 10                  

class NamedHashedRingQuery2MembersTest(NamedHashedRingQueryTest, unittest.TestCase):  
    numMembers = 10                  

class NamedHashedRingQuery1MembersTest(NamedHashedRingQueryTest, unittest.TestCase):  
    numMembers = 10                  




class RingSetTest(unittest.TestCase):
    
    nrrings = 10
    nrobjs = 200
    
    def setUp(self):
        self.rings = ring.RingSet()
        
        for x in range(self.nrrings):
            self.rings.insertRing(ring.NameHashedRing(x))

        self.objs = [RingObject(x) for x in range(self.nrobjs)]           
        random.shuffle(self.objs)
        for obj in self.objs: self.rings.insertItem(obj)  
    
    def testAllItemsArePresent(self):
        for o in self.objs:
            self.assertTrue(o in self.rings.getItems())
            for r in self.rings.getRings():
                self.assertTrue(o in r)

    def testProtoctedInsert(self):
        obj = RingObject(self.nrobjs+1)
        self.assertRaises(TypeError, self.rings[0].insert, obj)
                        
class MergedRingSetTest(RingSetTest):           

    def setUp(self):
        self.rings = ring.RingSet()
        
        for x in range(0,5):
            self.rings.insertRing(ring.NameHashedRing(x))

        self.objs = [RingObject(x) for x in range(200)]           
        random.shuffle(self.objs)
        for obj in self.objs: self.rings.insertItem(obj)  

        for x in range(5,10):
            self.rings.insertRing(ring.NameHashedRing(x))

class RankTableTest(unittest.TestCase):
    
    def setUp(self):
        self.rings = ring.RingSet()
        
        for x in range(10):
            self.rings.insertRing(ring.NameHashedRing(x))

        self.objs = [RingObject(x) for x in range(200)]           
        random.shuffle(self.objs)
        for obj in self.objs: self.rings.insertItem(obj)  
        
    def testRankToSelfIsZero(self):
        base = random.choice(self.objs)
        rt = ring.RankTable(base, base, self.rings)
        for v in rt:
            self.assertEqual(0, v)
    
    def testRankSuccessor(self):        
        base = random.choice(self.objs)
        rts = [ring.RankTable(x.succ(base), base, self.rings) for x in self.rings]
        for nr, rt in enumerate(rts):
            self.assertEqual(1, rt[nr])
        
    def testRankPredecessor(self):
        base = random.choice(self.objs)
        rts = [ring.RankTable(x.pred(base), base, self.rings) for x in self.rings]
        for nr, rt in enumerate(rts):
            self.assertEqual(self.rings[0].maxrank, rt[nr])
    
    def testRankAddition(self):
        base = random.choice(self.objs)
        rts = [ring.RankTable(x.pred(base), base, self.rings) for x in self.rings]

        # rts[nr] holds base's predecessor on ring nr, which has the
        # maximum rank on that ring. The sum takes the maximum per ring.
        maxrank = self.rings[0].maxrank

        r0 = ring.RankTable(None, base, self.rings)
        for r in rts:
            r0 = r0 + r
        self.assertEqual(list(r0), [maxrank] * len(self.rings))

        r0 = ring.RankTable(None, base, self.rings)
        for r in rts:
            r0 += r
        self.assertEqual(list(r0), [maxrank] * len(self.rings))

        r0 = reduce(lambda x, y: x+y, rts)
        self.assertEqual(list(r0), [maxrank] * len(self.rings))

    def testRankSubtraction(self):
        base = random.choice(self.objs)
        rts = [ring.RankTable(x.pred(base), base, self.rings) for x in self.rings]
        r0 = reduce(lambda x, y: x - y, rts)
        self.assertIsNotNone(r0)
        for nr in range(len(self.rings)):
            self.assertEqual(r0[nr], min(rt[nr] for rt in rts))


class RingHelperTest(unittest.TestCase):
    """traverse, betweenSucc, betweenPred and the relations, on a ring
    ordered 0, 1, ..., 9."""

    def setUp(self):
        self.ring = TestRing()
        self.objs = [RingObject(x) for x in range(10)]
        for obj in self.objs:
            self.ring.insert(obj)

    def sns(self, items):
        return [x.sn for x in items]

    def testTraverse(self):
        self.assertEqual(self.sns(self.ring.traverse(self.objs[7])), [8, 9, 0, 1, 2, 3, 4, 5, 6])

    def testTraverseSingleItem(self):
        r = TestRing()
        r.insert(self.objs[0])
        self.assertEqual(list(r.traverse(self.objs[0])), [])

    def testBetweenSucc(self):
        self.assertEqual(self.sns(self.ring.betweenSucc(self.objs[8], self.objs[2])), [9, 0, 1])
        self.assertEqual(self.ring.betweenSucc(self.objs[3], self.objs[4]), [])

    def testBetweenPred(self):
        self.assertEqual(self.sns(self.ring.betweenPred(self.objs[2], self.objs[8])), [1, 0, 9])
        self.assertEqual(self.ring.betweenPred(self.objs[4], self.objs[3]), [])

    def testBetweenStopNotInRing(self):
        self.assertRaises(ValueError, self.ring.betweenSucc, self.objs[0], RingObject(99))
        self.assertRaises(ValueError, self.ring.betweenPred, self.objs[0], RingObject(99))

    def testRelations(self):
        a, b, c = self.objs[4], self.objs[5], self.objs[6]
        self.assertTrue(ring.SuccessorRelation(a, b, self.ring).isValid())
        self.assertFalse(ring.SuccessorRelation(a, c, self.ring).isValid())
        self.assertTrue(ring.PredecessorRelation(b, a, self.ring).isValid())
        self.assertFalse(ring.PredecessorRelation(c, a, self.ring).isValid())

    def testSuccReturnsItemWhenOnlyItMatches(self):
        me = self.objs[3]
        self.assertIs(self.ring.succ(me, lambda x: x is me), me)
        self.assertIsNone(self.ring.succ(me, lambda x: False))
