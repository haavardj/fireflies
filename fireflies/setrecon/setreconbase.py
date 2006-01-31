# This file was created automatically by SWIG 1.3.27.
# Don't modify this file, modify the SWIG interface instead.

import _setreconbase

# This file is compatible with both classic and new-style classes.
def _swig_setattr_nondynamic(self,class_type,name,value,static=1):
    if (name == "this"):
        if isinstance(value, class_type):
            self.__dict__[name] = value.this
            if hasattr(value,"thisown"): self.__dict__["thisown"] = value.thisown
            del value.thisown
            return
    method = class_type.__swig_setmethods__.get(name,None)
    if method: return method(self,value)
    if (not static) or hasattr(self,name) or (name == "thisown"):
        self.__dict__[name] = value
    else:
        raise AttributeError("You cannot add attributes to %s" % self)

def _swig_setattr(self,class_type,name,value):
    return _swig_setattr_nondynamic(self,class_type,name,value,0)

def _swig_getattr(self,class_type,name):
    method = class_type.__swig_getmethods__.get(name,None)
    if method: return method(self)
    raise AttributeError,name

import types
try:
    _object = types.ObjectType
    _newclass = 1
except AttributeError:
    class _object : pass
    _newclass = 0
del types


class node(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, node, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, node, name)
    def __repr__(self):
        return "<%s.%s; proxy of C++ node instance at %s>" % (self.__class__.__module__, self.__class__.__name__, self.this,)
    def __init__(self, *args):
        _swig_setattr(self, node, 'this', _setreconbase.new_node(*args))
        _swig_setattr(self, node, 'thisown', 1)
    def __del__(self, destroy=_setreconbase.delete_node):
        try:
            if self.thisown: destroy(self)
        except: pass

    __swig_setmethods__["hash_vector"] = _setreconbase.node_hash_vector_set
    __swig_getmethods__["hash_vector"] = _setreconbase.node_hash_vector_get
    if _newclass:hash_vector = property(_setreconbase.node_hash_vector_get, _setreconbase.node_hash_vector_set)
    __swig_setmethods__["extra_hashes"] = _setreconbase.node_extra_hashes_set
    __swig_getmethods__["extra_hashes"] = _setreconbase.node_extra_hashes_get
    if _newclass:extra_hashes = property(_setreconbase.node_extra_hashes_get, _setreconbase.node_extra_hashes_set)
    __swig_setmethods__["valids"] = _setreconbase.node_valids_set
    __swig_getmethods__["valids"] = _setreconbase.node_valids_get
    if _newclass:valids = property(_setreconbase.node_valids_get, _setreconbase.node_valids_set)
    __swig_setmethods__["start"] = _setreconbase.node_start_set
    __swig_getmethods__["start"] = _setreconbase.node_start_get
    if _newclass:start = property(_setreconbase.node_start_get, _setreconbase.node_start_set)
    __swig_setmethods__["stop"] = _setreconbase.node_stop_set
    __swig_getmethods__["stop"] = _setreconbase.node_stop_get
    if _newclass:stop = property(_setreconbase.node_stop_get, _setreconbase.node_stop_set)
    __swig_setmethods__["node_type"] = _setreconbase.node_node_type_set
    __swig_getmethods__["node_type"] = _setreconbase.node_node_type_get
    if _newclass:node_type = property(_setreconbase.node_node_type_get, _setreconbase.node_node_type_set)
    __swig_setmethods__["setsize"] = _setreconbase.node_setsize_set
    __swig_getmethods__["setsize"] = _setreconbase.node_setsize_get
    if _newclass:setsize = property(_setreconbase.node_setsize_get, _setreconbase.node_setsize_set)
    __swig_setmethods__["child"] = _setreconbase.node_child_set
    __swig_getmethods__["child"] = _setreconbase.node_child_get
    if _newclass:child = property(_setreconbase.node_child_get, _setreconbase.node_child_set)
    __swig_setmethods__["intree"] = _setreconbase.node_intree_set
    __swig_getmethods__["intree"] = _setreconbase.node_intree_get
    if _newclass:intree = property(_setreconbase.node_intree_get, _setreconbase.node_intree_set)
    def ref_count(*args): return _setreconbase.node_ref_count(*args)
    def ref(*args): return _setreconbase.node_ref(*args)
    def unref(*args): return _setreconbase.node_unref(*args)
    def getChild(*args): return _setreconbase.node_getChild(*args)
    def isTerminal(*args): return _setreconbase.node_isTerminal(*args)
    def terminal_data(*args): return _setreconbase.node_terminal_data(*args)
    def printNode(*args): return _setreconbase.node_printNode(*args)
    def hasChild(*args): return _setreconbase.node_hasChild(*args)

class nodePtr(node):
    def __init__(self, this):
        _swig_setattr(self, node, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, node, 'thisown', 0)
        self.__class__ = node
_setreconbase.node_swigregister(nodePtr)


difference_set = _setreconbase.difference_set
class reconciled_set(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, reconciled_set, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, reconciled_set, name)
    def __repr__(self):
        return "<%s.%s; proxy of C++ reconciled_set instance at %s>" % (self.__class__.__module__, self.__class__.__name__, self.this,)
    def get_tree(*args): return _setreconbase.reconciled_set_get_tree(*args)
    __swig_setmethods__["dataStart"] = _setreconbase.reconciled_set_dataStart_set
    __swig_getmethods__["dataStart"] = _setreconbase.reconciled_set_dataStart_get
    if _newclass:dataStart = property(_setreconbase.reconciled_set_dataStart_get, _setreconbase.reconciled_set_dataStart_set)
    def __init__(self, *args):
        _swig_setattr(self, reconciled_set, 'this', _setreconbase.new_reconciled_set(*args))
        _swig_setattr(self, reconciled_set, 'thisown', 1)
    def __del__(self, destroy=_setreconbase.delete_reconciled_set):
        try:
            if self.thisown: destroy(self)
        except: pass

    def add_element(*args): return _setreconbase.reconciled_set_add_element(*args)
    def del_element(*args): return _setreconbase.reconciled_set_del_element(*args)
    def printTree(*args): return _setreconbase.reconciled_set_printTree(*args)
    __swig_getmethods__["init"] = lambda x: _setreconbase.reconciled_set_init
    if _newclass:init = staticmethod(_setreconbase.reconciled_set_init)
    def reconcile(*args): return _setreconbase.reconciled_set_reconcile(*args)
    def internal2external(*args): return _setreconbase.reconciled_set_internal2external(*args)
    def external2internal(*args): return _setreconbase.reconciled_set_external2internal(*args)
    __swig_setmethods__["p"] = _setreconbase.reconciled_set_p_set
    __swig_getmethods__["p"] = _setreconbase.reconciled_set_p_get
    if _newclass:p = property(_setreconbase.reconciled_set_p_get, _setreconbase.reconciled_set_p_set)
    __swig_setmethods__["k"] = _setreconbase.reconciled_set_k_set
    __swig_getmethods__["k"] = _setreconbase.reconciled_set_k_get
    if _newclass:k = property(_setreconbase.reconciled_set_k_get, _setreconbase.reconciled_set_k_set)
    def __contains__(*args): return _setreconbase.reconciled_set___contains__(*args)

class reconciled_setPtr(reconciled_set):
    def __init__(self, this):
        _swig_setattr(self, reconciled_set, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, reconciled_set, 'thisown', 0)
        self.__class__ = reconciled_set
_setreconbase.reconciled_set_swigregister(reconciled_setPtr)

reconciled_set_init = _setreconbase.reconciled_set_init

class ZZ(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, ZZ, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, ZZ, name)
    def __repr__(self):
        return "<%s.%s; proxy of C++ ZZ instance at %s>" % (self.__class__.__module__, self.__class__.__name__, self.this,)
    def __del__(self, destroy=_setreconbase.delete_ZZ):
        try:
            if self.thisown: destroy(self)
        except: pass

    def kill(*args): return _setreconbase.ZZ_kill(*args)
    def SetSize(*args): return _setreconbase.ZZ_SetSize(*args)
    def size(*args): return _setreconbase.ZZ_size(*args)
    def SinglePrecision(*args): return _setreconbase.ZZ_SinglePrecision(*args)
    def WideSinglePrecision(*args): return _setreconbase.ZZ_WideSinglePrecision(*args)
    def __init__(self, *args):
        _swig_setattr(self, ZZ, 'this', _setreconbase.new_ZZ(*args))
        _swig_setattr(self, ZZ, 'thisown', 1)
    __swig_getmethods__["zero"] = lambda x: _setreconbase.ZZ_zero
    if _newclass:zero = staticmethod(_setreconbase.ZZ_zero)
    def __str__(*args): return _setreconbase.ZZ___str__(*args)
    def __add__(*args): return _setreconbase.ZZ___add__(*args)
    def __sub__(*args): return _setreconbase.ZZ___sub__(*args)
    def __neg__(*args): return _setreconbase.ZZ___neg__(*args)
    def __mul__(*args): return _setreconbase.ZZ___mul__(*args)
    def __div__(*args): return _setreconbase.ZZ___div__(*args)
    def __pow__(*args): return _setreconbase.ZZ___pow__(*args)
    def toInt(*args): return _setreconbase.ZZ_toInt(*args)
    def toLong(*args): return _setreconbase.ZZ_toLong(*args)
    def __cmp__(*args): return _setreconbase.ZZ___cmp__(*args)
    def NumBytes(*args): return _setreconbase.ZZ_NumBytes(*args)
    def toBytes(*args): return _setreconbase.ZZ_toBytes(*args)

class ZZPtr(ZZ):
    def __init__(self, this):
        _swig_setattr(self, ZZ, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, ZZ, 'thisown', 0)
        self.__class__ = ZZ
_setreconbase.ZZ_swigregister(ZZPtr)

ZZ_zero = _setreconbase.ZZ_zero


to_ZZFromBytes = _setreconbase.to_ZZFromBytes
class ZZ_p(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, ZZ_p, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, ZZ_p, name)
    def __repr__(self):
        return "<%s.%s; proxy of C++ ZZ_p instance at %s>" % (self.__class__.__module__, self.__class__.__name__, self.this,)
    __swig_getmethods__["init"] = lambda x: _setreconbase.ZZ_p_init
    if _newclass:init = staticmethod(_setreconbase.ZZ_p_init)
    def __init__(self, *args):
        _swig_setattr(self, ZZ_p, 'this', _setreconbase.new_ZZ_p(*args))
        _swig_setattr(self, ZZ_p, 'thisown', 1)
    def __del__(self, destroy=_setreconbase.delete_ZZ_p):
        try:
            if self.thisown: destroy(self)
        except: pass

    __swig_getmethods__["modulus"] = lambda x: _setreconbase.ZZ_p_modulus
    if _newclass:modulus = staticmethod(_setreconbase.ZZ_p_modulus)
    def __hash__(self):
      return hash(str(self))

    def __str__(*args): return _setreconbase.ZZ_p___str__(*args)
    def __add__(*args): return _setreconbase.ZZ_p___add__(*args)
    def __sub__(*args): return _setreconbase.ZZ_p___sub__(*args)
    def __neg__(*args): return _setreconbase.ZZ_p___neg__(*args)
    def __mul__(*args): return _setreconbase.ZZ_p___mul__(*args)
    def __div__(*args): return _setreconbase.ZZ_p___div__(*args)
    def __pow__(*args): return _setreconbase.ZZ_p___pow__(*args)
    def __eq__(*args): return _setreconbase.ZZ_p___eq__(*args)
    def __neq__(*args): return _setreconbase.ZZ_p___neq__(*args)
    def rep(*args): return _setreconbase.ZZ_p_rep(*args)

class ZZ_pPtr(ZZ_p):
    def __init__(self, this):
        _swig_setattr(self, ZZ_p, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, ZZ_p, 'thisown', 0)
        self.__class__ = ZZ_p
_setreconbase.ZZ_p_swigregister(ZZ_pPtr)

to_ZZ = _setreconbase.to_ZZ

ZZ_p_init = _setreconbase.ZZ_p_init

ZZ_p_modulus = _setreconbase.ZZ_p_modulus

class vec_ZZ_p(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, vec_ZZ_p, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, vec_ZZ_p, name)
    def __repr__(self):
        return "<%s.%s; proxy of C++ vec_ZZ_p instance at %s>" % (self.__class__.__module__, self.__class__.__name__, self.this,)
    def length(*args): return _setreconbase.vec_ZZ_p_length(*args)
    def SetLength(*args): return _setreconbase.vec_ZZ_p_SetLength(*args)
    def __init__(self, *args):
        _swig_setattr(self, vec_ZZ_p, 'this', _setreconbase.new_vec_ZZ_p(*args))
        _swig_setattr(self, vec_ZZ_p, 'thisown', 1)
    def __del__(self, destroy=_setreconbase.delete_vec_ZZ_p):
        try:
            if self.thisown: destroy(self)
        except: pass

    def __iter__(self):

      def _():
        for x in range(len(self)):
          yield(self[x])
      return _()

    def __str__(self):
      #return "%s mod %d" %(str( map(lambda x: x.rep().toInt(), self)), ZZ_p.modulus().toInt())
      return "%s" %(str( map(lambda x: x.rep().toInt(), self)))
      
    def __getitem__(*args): return _setreconbase.vec_ZZ_p___getitem__(*args)
    def __setitem__(*args): return _setreconbase.vec_ZZ_p___setitem__(*args)
    def __contains__(*args): return _setreconbase.vec_ZZ_p___contains__(*args)
    def __len__(*args): return _setreconbase.vec_ZZ_p___len__(*args)
    def append(*args): return _setreconbase.vec_ZZ_p_append(*args)

class vec_ZZ_pPtr(vec_ZZ_p):
    def __init__(self, this):
        _swig_setattr(self, vec_ZZ_p, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, vec_ZZ_p, 'thisown', 0)
        self.__class__ = vec_ZZ_p
_setreconbase.vec_ZZ_p_swigregister(vec_ZZ_pPtr)

to_ZZ_p = _setreconbase.to_ZZ_p



