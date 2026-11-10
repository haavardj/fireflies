//====================================================================
// Filename:      setreconbase.i
// Description:   SWIG wrapper for set-recon.
// Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
// Modified at:   Wed Jan 25 13:59:34 2006
// Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
//
// Licence: MIT (see the LICENCE file at the top of the repository).
//
//         Copyright© 2006, University of Tromsø (Norway)
//                
// $Id: setreconbase.i,v 1.2 2006/01/31 14:00:34 haavardj Exp $
//                
//====================================================================


%module setreconbase
%include "typemaps.i"
%include "cstring.i"

%feature("ref") node ""//"if ($this!=NULL) $this->ref();"
%feature("unref") node ""// if ($this!=NULL) $this->unref();"


%{
#include "reconciled_set.h"
#include "prob_reconcile.h"
#include "prob_recon_support.h"
#include "node.h"

#include <iostream>
#include <string>
#include <sstream>

#include <NTL/ZZ.h>
#include <NTL/tools.h>
%}


//%typemap(newfree) node *{
//    $1->unref();
//  }




class node
{

public:

  node(reconciled_set *base, vec_ZZ_p& subset_pp, ZZ strt, ZZ stp);
  ~node();
  vec_ZZ_p hash_vector;
  vec_ZZ_p extra_hashes;
  vec_ZZ_p valids;
  ZZ start, stop;
  short int node_type;
  long setsize;
  node **child;
  bool intree;
  int ref_count();
  int ref();
  int unref();

  node *getChild(int nr);
  bool isTerminal(); 

  //%newobject terminal_data;
  vec_ZZ_p terminal_data();
  void printNode(int level);
};

%extend node{    
    bool hasChild(int nr){
      if (self->child[nr] == NULL) return(false);
      else return (true);
    }
  };


//%newobject difference_set;
vec_ZZ_p difference_set(vec_ZZ_p set1, vec_ZZ_p set2);

%typemap(argout) vec_ZZ_p& retValue {
     PyObject *o, *o2, *o3;

     vec_ZZ_p * resultptr;
     resultptr = new vec_ZZ_p(static_cast<vec_ZZ_p & >(*$1));
     o = SWIG_NewPointerObj((void *)(resultptr), SWIGTYPE_p_vec_ZZ_p, 1);
     
     if ((!$result) || ($result == Py_None)) {
       $result = o;
     } 
     else {
       if (!PyTuple_Check($result)) {
	 PyObject *tmp = $result;
	 $result = PyTuple_New(1);
	 PyTuple_SetItem($result, 0, tmp);
       }
       
       o3 = PyTuple_New(1);
       PyTuple_SetItem(o3,0,o);
       o2 = $result;
       $result = PySequence_Concat(o2,o3);
       Py_DECREF(o2);
       Py_DECREF(o3);
     }
   }
   
%typemap(in,numinputs=0) vec_ZZ_p& retValue(vec_ZZ_p temp) {
  $1 = &temp;
 }




class reconciled_set
{

public:

  %newobject get_tree;
  node *get_tree();

  ZZ_p dataStart;
  reconciled_set(int p, int k); 
  ~reconciled_set();
  void add_element(char *);
  void add_element(ZZ_p el);
  void del_element(ZZ_p el);
  void printTree();

  static void init(int bz, int mbar);

  int reconcile(
		vec_ZZ_p HASamplevalues,
		vec_ZZ_p A_EVALS,
		long asize,
		vec_ZZ_p HBSamplevalues, 
		vec_ZZ_p B_EVALS, 
		long bsize, 
		vec_ZZ_p validationpoints,
		vec_ZZ_p& retValue, 
		vec_ZZ_p& retValue
		);

  vec_ZZ_p internal2external(vec_ZZ_p v);
  ZZ_p internal2external(ZZ_p n);
  ZZ_p external2internal(ZZ_p n);
  vec_ZZ_p external2internal(vec_ZZ_p v);
  int p;  
  int k;  


private:
  static int mbar;  
  static int bitsize;
  static int field_bits;
  static ZZ field_size; 
  static ZZ max;      
};


%extend reconciled_set {


  bool __contains__(ZZ_p el)
  {
    vec_ZZ_p data;
    node *n;
    ZZ_p mEl;
    int l;
    
    mEl = el + self->dataStart;
    n = self->get_tree();
    assert(n->intree == true);
    assert(n->ref_count() > 0);
    if (n == NULL) return false;
    data = n->terminal_data();
 
    l = data.length();    
    for (int x = 0; x < l; x++){
      if (data[x] == mEl) return true;
    }

    return false;
  }
};


class ZZ
{
public:
  
  ZZ();
  ~ZZ();
  void kill();
  void SetSize(long k);
  long size() const;
  long SinglePrecision() const;
  long WideSinglePrecision() const;
  ZZ(const ZZ& a);
  static const ZZ& zero();

};

%extend ZZ {

  %newobject __str__;
  %cstring_bounded_output(char *buff, 1024);
  void __str__(char *buff){    
    std::ostringstream o ( std::ios::out) ;
    o << *self;
    strncpy(buff, o.str().c_str(), 1024);
  }

  //%newobject __add__;
  ZZ __add__(ZZ *other)
  {
    ZZ val;
    add(val, *self, *other);
    return val;
  }

  //%newobject __del__;
  ZZ __sub__(ZZ *other)
  {
    ZZ val;
    sub(val, *self, *other);
    return val;
  }

  //%newobject __neg__;
  ZZ __neg__()
  {
    ZZ val;
    negate(val, *self);
    return val;
  }

  //%newobject __mul__;
  ZZ __mul__(ZZ *other)
  {
    ZZ val;
    mul(val, *self, *other);
    return val;
  }
  
  //%newobject __div__;
  ZZ __div__(ZZ *other)
  {
    ZZ val;
    div(val, *self, *other);
    return val;
  }

  //%newobject __pow__;
  ZZ __pow__(long e)
  {
    ZZ val;
    power(val, *self, e);
    return val;
  }

  int toInt()
  {
    return to_int(*self);
  }

  long toLong()
  {
    return to_long(*self);
  }

  long __cmp__(ZZ *other)
  {
    return compare(*self, *other);
  }

  long __cmp__(long other)
  {
    return compare(*self, other);
  }


  long NumBytes()
  {
    return NumBytes(*self); 
  }

  // Little-endian bytes of the number, as a Python bytes object.
  PyObject *toBytes()
  {
    long n = NumBytes(*self);
    std::string buf(n, '\0');
    if (n > 0)
      BytesFromZZ((unsigned char *) &buf[0], *self, n);
    return PyBytes_FromStringAndSize(buf.data(), n);
  }


};


// Inverse of ZZ.toBytes(). Takes a Python bytes object; the Python
// wrapper in setrecon.py checks the type.
%inline{

  ZZ _to_ZZFromBytes(PyObject *obj)
  {
    char *buf = NULL;
    Py_ssize_t len = 0;
    if (PyBytes_AsStringAndSize(obj, &buf, &len) < 0) {
      PyErr_Clear();
      len = 0;
    }
    return ZZFromBytes((unsigned char *) buf, (long) len);
  }
};

//ZZ ZZFromBytes(const unsigned char *STRING, long LENGTH);

//%newobject to_ZZ;
ZZ to_ZZ(char *);
ZZ to_ZZ(int);
ZZ to_ZZ(long);



class ZZ_p
{
public:
  static void init(const ZZ&);
  ZZ_p();
  ~ZZ_p();
  static const ZZ& modulus();

  %pythoncode %{
    def __hash__(self):
      return hash(str(self))
    %};

  
  
};

%extend ZZ_p {

  %cstring_bounded_output(char *buff, 1024);
  void __str__(char *buff){    
    std::ostringstream o ( std::ios::out) ;
    o << *self;
    strncpy(buff, o.str().c_str(), 1024);
  }

  //%newobject __add__;
  ZZ_p __add__(ZZ_p *other)
  {
    ZZ_p val;
    add(val, *self, *other);
    return val;
  }

  ZZ_p __add__(long other)
  {
    ZZ_p val;
    add(val, *self, other);
    return val;
  }

  //%newobject __sub__;
  ZZ_p __sub__(ZZ_p *other)
  {
    ZZ_p val;
    sub(val, *self, *other);
    return val;
  }

  ZZ_p __sub__(long other)
  {
    ZZ_p val;
    sub(val, *self, other);
    return val;
  }

  //%newobject __neg__;
  ZZ_p __neg__()
  {
    ZZ_p val;
    negate(val, *self);
    return val;
  }

  //%newobject __mul__;
  ZZ_p __mul__(ZZ_p *other)
  {
    ZZ_p val;
    mul(val, *self, *other);
    return val;
  }

  ZZ_p __mul__(long other)
  {
    ZZ_p val;
    mul(val, *self, other);
    return val;
  }
  
  //%newobject __div__;
  ZZ_p __div__(ZZ_p *other)
  {
    ZZ_p val;
    div(val, *self, *other);
    return val;
  }

  //%newobject __pow__;
  ZZ_p __pow__(long e)
  {
    ZZ_p val;
    power(val, *self, e);
    return val;
  }

  long __eq__(ZZ_p *other)
  {
    return operator==(*self, *other);
  }

  long __eq__(long other)
  {
    return operator==(*self, other);
  }


  long __neq__(ZZ_p *other)
  {
    return operator!=(*self, *other);
  }

  long __neq__(long other)
  {
    return operator!=(*self, other);
  }

  //%newobject rep;
  ZZ rep()
  {
    ZZ a;
    a = rep(*self);
    return a;
  }
};

//%newobject to_ZZ_p;
ZZ_p to_ZZ_p(const ZZ& a);
ZZ_p to_ZZ_p(long a);


class vec_ZZ_p
{

public:
  long length();
  void SetLength(long n);

  vec_ZZ_p(const vec_ZZ_p &a);
  vec_ZZ_p();
  ~vec_ZZ_p(); 

  %pythoncode %{
    def __iter__(self):

      def _():
        for x in range(len(self)):
          yield(self[x])
      return _()

    def __str__(self):
      #return "%s mod %d" %(str( map(lambda x: x.rep().toInt(), self)), ZZ_p.modulus().toInt())
      return "%s" %(str([x.rep().toInt() for x in self]))
      %}
};

%extend vec_ZZ_p{
  ZZ_p __getitem__(int i)
  {
    return (*self)[i]; //->operator[](i);
  }

  void __setitem__(int i, ZZ_p val)
  {
    (*self)[i] = val; //self->operator[](i) = val;
  }

  bool __contains__(ZZ_p &val)
  {
    int l = self->length();
    //std::cout << "l=" << l << "\n";
    for (int x = 0; x < l; x++){
      //std::cout << x << " " << self->operator[](x) << "\n";
      if ((*self)[x] == val) return true;
    }
    return false;
  }

  long __len__()
  {
    return self->length();
  }

  void append(ZZ_p& v)
  {
    append(*self, v);
  }

};
