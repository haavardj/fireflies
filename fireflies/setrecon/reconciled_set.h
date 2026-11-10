//====================================================================
// Filename:      reconciled_set.h
// Description:   
//
// Initial implementation by: Sachin Agarwal, ska@bu.edu
//               modified by: Ari Trachtenberg, trachten@bu.edu
//                   Version: 0.998 Beta
//                      Date: 06/23/2004
// Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
// Modified at:   Mon Jan 16 18:46:32 2006
// Licence: GPL (see LICENSE file).
//  
//                
// $Id: reconciled_set.h,v 1.2 2006/01/31 13:57:01 haavardj Exp $
//                
//====================================================================

#ifndef RECONCILED_SET
#define RECONCILED_SET
/*  RECONCILED_SET
**  A data structure for holding set elements that can be
**  quickly reconciled with other reconciled_set's.
**
** %M:  sets and resets NTL's random number seed often
*/

#include <sys/types.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include "NTL/matrix.h"
#include "NTL/mat_ZZ_p.h"
#include "NTL/vec_ZZ.h"
#include "NTL/ZZ.h"
#include "NTL/ZZ_p.h"
#include "NTL/vec_ZZ_p.h"
#include "NTL/vec_vec_ZZ_p.h"
#include "NTL/ZZ_pX.h"
#include "NTL/ZZ_pXFactoring.h"

#include "node.h"
#include "constants.h"

class node;

class reconciled_set {

public:
  static void init(int bz, int mbar);
  
  reconciled_set(int pp, int kk); 
  ~reconciled_set();
	
  // MANIPULATION
  node *get_tree();
  void printTree();

  void add_element(ZZ_p el);
  void add_element(char *el);
  void del_element(ZZ_p el);  
  //node *create_node();

  int reconcile(
		vec_ZZ_p HASamplevalues,
		vec_ZZ_p A_EVALS,
		long asize,
		vec_ZZ_p HBSamplevalues, 
		vec_ZZ_p B_EVALS, 
		long bsize, 
		vec_ZZ_p validationpoints,
		vec_ZZ_p& dnom, 
		vec_ZZ_p& numer
		);
    
    //int reconcile(node* rootA, vec_ZZ_p HBSamplevalues, vec_ZZ_p B_EVALS, long bsize, vec_ZZ_p& dnom, vec_ZZ_p& numer);
    //int reconcile(node* rootA, node* rootB, vec_ZZ_p& dnom, vec_ZZ_p& numer);


  // i gets mapped to dataStart+i to avoid colisions with the sample
  // evaluations
  ZZ_p dataStart;        

  /* Convert between internal and external number representation*/
  vec_ZZ_p internal2external(vec_ZZ_p v);
  ZZ_p internal2external(ZZ_p n);

  ZZ_p external2internal(ZZ_p n);
  vec_ZZ_p external2internal(vec_ZZ_p v);





  /*  
      The field is divided as follows:
      **  -(mbar-1)/2 .. mbar/2             : sample evaluations for even mbar (-mbar/2 .. (mbar-1)/2 for odd mbar)
      **  mbar/2+1 .. 2^bit_size + mbar/2+1 : data values
      **  2^bit_size + mbar/2+2 .. -mbar/2  : random evaluations      
  */
  int p;                // number of partitions per node
  int k;                // redundancy factor (determines probability of error)

 private:


  static int mbar;              // maximum number of differences to reconcile (i.e. recovery bound)
  static int bitsize;           // number of bits per vector
  static int field_bits;         // the number of bits needed to represent fieldsize
  static ZZ field_size;          // size of the underlying filed; a prime number in this case
  static ZZ max;                // the maximum element in the field, = fieldsize - 1


  vec_ZZ_p samples;      // sample points on which char poly is evaluated
  vec_ZZ_p *powSamples;  // powers of the sample points in the chosen finite field
  node* pTree;           // the partition tree containing char poly evaluations

  

  void deletetree(node*& root);  

  /* 
     R: 
     ** * set - whose characteristic polynomial has to be computed and stored in the node
     ** * samplepoints - in order to calculate the evaluations
     ** * p - Number of children the node will have incase there is a need  to further partition
     ** * start - the lower end (inclusive) of the sub-field's region 
     ** * stop - the upper end (inclusive) of the sub-field's region
     ** E: Nodes of partition tree
     ** M: Node --> partition tree
  */  
  node* recurse_make(vec_ZZ_p set, ZZ start,ZZ stop);
	

  /* %R: RF is a vector of values of the rational function evaluations
     at the sample points (i.e. RF[i] = f_i = rational function at
     i'th sample point rank is the rank of the LHS matrix in the
     system to be solved d is difference in set size |S_A| - |S_B| %E:
     Constructs the rhs for the vandrmonde matrix - i.e. the bmatrix
  */
  vec_ZZ_p construct_RHS_constant_vector(vec_ZZ_p& RF,long& rank,long& d);


  /* %R: RF is a vector of values of the rational function evaluations
     at the sample points (i.e. RF[i] = f_i = rational function at
     i'th sample point bmatrix if the right-hand-side of the linear
     system to be solved (size = mbar x 1) d is difference in set size
     |S_A| - |S_B| %E: Constructs and returns a Vandermonde matrix
     needed to interpolate the rational function; performs some row
     operations to optimize performance
  */
  mat_ZZ_p construct_vandermonde_matrix(const vec_ZZ_p& RF, const vec_ZZ_p& bmatrix, const long d);


  //  ... tree procuedures
  long position_of_child(ZZ_p element_to_add,ZZ start, ZZ stop, ZZ d);
  // computes the proper subdivision in which to put element_to_add within start ... stop
  long position_of_child(ZZ_p element_to_add,ZZ start, ZZ stop);
  // computes the proper subdivision in which to put element_to_add within start ... stop, if d is not known


  void add_to_tree(node*& root, ZZ_p& element_to_add);
  void delete_from_tree(node*& root, ZZ_p element_to_delete);

  friend class node;
};



/*
	R: 2 sets whose differences has to be found
	E: Returns set2\set1
	M: 
	Date: 28th Nov 2002
*/
vec_ZZ_p difference_set(vec_ZZ_p set1, vec_ZZ_p set2);

#endif
