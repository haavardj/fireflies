from twisted.trial import unittest
import random

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fireflies import setrecon
else:
    try:
        from fireflies import setrecon
    except ImportError:
        setrecon = None

try:
    import pydot  # pyright: ignore[reportMissingImports]
except ImportError:
    pydot = None

bitsize = 160
if setrecon is not None and not setrecon.initialized:
    setrecon.init(bitsize, 10)


class SequentialTest(unittest.TestCase):

    if setrecon is None:
        skip = "The setrecon C++ extension is not built."

    commonSize = 300
    diffASize = 10
    diffBSize = 10
    pFactor = 10
    
    def setUp(self):
        
        self.common = set(range(0,self.commonSize))
        self.diffA = set(range(self.commonSize, self.commonSize + self.diffASize) )
        self.diffB = set(range(self.commonSize + self.diffASize, self.commonSize + self.diffASize  +self.diffBSize))
        self.setA = setrecon.ReconSet(self.pFactor, 5)
        self.setB = setrecon.ReconSet(self.pFactor, 5)        
        
        for x in self.common:
            self.common.add(x)
            self.setA.add(x)
            self.setB.add(x)
        for x in self.diffA:
            self.setA.add(x)
        for x in self.diffB:
            self.setB.add(x)


    def testDiff(self):
         
        aMissing, bMissing = setrecon.diffs(self.setA, self.setB)
        self.assertEqual(aMissing, self.diffB)#, "\n%s\n%s" %( aMissing-self.diffA , self.diffA - aDiff) )
        self.assertEqual(bMissing, self.diffA)#, "\n%s\n%s" %( bDiff-self.diffB , self.diffB - bDiff) )

        bMissing, aMissing = setrecon.diffs(self.setB, self.setA)
        self.assertEqual(aMissing, self.diffB)#, "\n%s\n%s" %( aMissing-self.diffA , self.diffA - aDiff) )
        self.assertEqual(bMissing, self.diffA)#, "\n%s\n%s" %( bDiff-self.diffB , self.diffB - bDiff) )
        
        if pydot is not None:
            d = setrecon.dottySet(self.setA)
            d = setrecon.dottySet(self.setB)

    def testSetMembership(self):

        for v in self.common:
            self.assertTrue(v in self.setA)
            self.assertTrue(v in self.setB)

        for v in self.diffA:
            self.assertTrue(v in self.setA)
            self.assertFalse(v in self.setB)

        for v in self.diffB:
            self.assertTrue(v in self.setB)
            self.assertFalse(v in self.setA)
        

    def testReconciliation(self):
        
        pA = setrecon.Reconciliation(self.setA)
        pB = setrecon.Reconciliation(self.setB)

        for nA in pA.run():
            nB = next(pB)
            pA.update(nB)
            pB.update(nA)
            
        pB.requestByHashes(pA.meMissing)
        pA.requestByHashes(pB.meMissing)            
        self.assertEqual(pB.otherMissing, self.diffB)
        self.assertEqual(pA.otherMissing, self.diffA)    

class RandomSetTest(SequentialTest):
        
    def setUp(self):        
        self.common = set()
        self.diffA = set()
        self.diffB = set()
        self.setA = setrecon.ReconSet(3, 5)
        self.setB = setrecon.ReconSet(3, 5)        
        
        for x in range(self.commonSize): 
            v = random.randint(30, 2**bitsize)
            self.common.add(v)
            self.setA.add(v)
            self.setB.add(v)
            
        for x in range(self.diffASize): 
            while 1:
                v = random.randint(30, 2**bitsize)
                if v in self.common: continue
                self.diffA.add(v)
                self.setA.add(v)
                break

        for x in range(self.diffBSize): 
            while 1:
                v = random.randint(30, 2**bitsize)
                if v in self.common: continue
                if v in self.diffA: continue
                self.diffB.add(v)
                self.setB.add(v)
                break
            

class MonsterRandomSetTest(SequentialTest):
    commonSize = 1000
    diffASize = 100
    diffBSize = 150
    pFactor = 10
    
    skip = "This test take a some time to run. Enable for extra testing."