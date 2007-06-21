//====================================================================
// Filename:      node.h
// Description:   
//
// Initial implementation by: Sachin Agarwal, ska@bu.edu
//               modified by: Ari Trachtenberg, trachten@bu.edu
//                   Version: 0.998 Beta
//                      Date: 06/23/2004
// Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
// Modified at:   Mon Jan 16 18:43:40 2006
// Licence: GPL (see LICENSE file).
//  
//                
// $Id: node.h,v 1.3 2007/06/21 07:17:48 haavardj Exp $
//                
//====================================================================


#ifndef NODE
#define NODE

// A node in the partition tree
#include "NTL/matrix.h"
#include "NTL/mat_ZZ_p.h"
#include "NTL/vec_ZZ.h"
#include "NTL/ZZ.h"
#include "NTL/ZZ_p.h"
#include "NTL/vec_ZZ_p.h"
#include <math.h>
#include "NTL/vec_vec_ZZ_p.h"
#include "NTL/ZZ_pX.h"
#include "NTL/ZZ_pXFactoring.h"
#include "prob_recon_support.h"
#include "reconciled_set.h"
#include "constants.h"

class reconciled_set;


class node
/* This class defines nodes in the partition-tree data structure used
   to amortize the computational cost of characteristic polynomial
   evaluations over insertions and deletions into the database.
*/

{
  friend class reconciled_set;

  
 public:

  node *delete_from_tree(ZZ_p element_to_delete);
  int ref(){
    return add_ref();
  }
  
  int unref() {
    assert(refc > 0);
    if (ref_count() == 0 || del_ref() == 0 ) {
      assert(intree == false);
      delete this;
      return 0;
    }
    return ref_count();
  }
  
  int refc;
  int add_ref() {refc++; return refc;}
  int del_ref() {refc--; return refc;}
  int ref_count() {return refc;}

  bool intree;
  
  vec_ZZ_p hash_vector;
  vec_ZZ_p extra_hashes; //For verifying interpolation
  vec_ZZ_p valids;       // validation points for the rational function - deviation from theory, as these should be randomly chosen for each synchronization (?)  
  ZZ start,stop;
  short int node_type;
  long setsize;

  reconciled_set *base;
  node *parent;
  node** child;

  void printNode(int level);
  bool isTerminal();
  node *getChild(int nr);

  //node(reconciled_set *base);  
  node(reconciled_set *base, vec_ZZ_p& subset_pp, ZZ strt, ZZ stp);

  /* Constructor for node
     R: Subset in vector space whose hashes have to be stored, samplepoints, number of subpartitions
     E: Creates node
     M:
  */
  
  ~node();  
  
  /*
    R: The root of the tree, p is the partition factor
    E: Returns the terminal elements of the tree in form of a vec_ZZ_p
  */  
  vec_ZZ_p terminal_data();

};

#endif
