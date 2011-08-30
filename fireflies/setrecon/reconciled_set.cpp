//====================================================================
// Filename:      reconciled_set.cpp
// Description:   
//
// Initial implementation by: Sachin Agarwal, ska@bu.edu
//               modified by: Ari Trachtenberg, trachten@bu.edu
//                   Version: 0.998 Beta
//                      Date: 06/23/2004
// Modified by:   H�rd Dagenborg Johansen <haavardj@cs.uit.no>
// Modified at:   Wed Jan 25 14:20:08 2006
// Licence: GPL (see LICENSE file).
//  
//                
// $Id: reconciled_set.cpp,v 1.3 2011/08/30 13:55:51 haavardj Exp $
//                
//====================================================================

#include <time.h>
#include <math.h>

#include "constants.h"
#include "prob_recon_support.h"
#include "prob_reconcile.h"
#include "node.h"
#include "reconciled_set.h"

#define RECONCILESUCCESS 1
#define RECONCILEFAILED 0

int reconciled_set::bitsize=0;
int reconciled_set::mbar = 0;   
int reconciled_set::field_bits = 0;
ZZ reconciled_set::field_size = ZZ_zero;
ZZ reconciled_set::max = ZZ_zero;



void reconciled_set::init(int bz, int mm)
{
  bitsize = bz;
  mbar = mm; 

  // Make this odd to optimize matrix back substitution
  if (!(mbar%2)) mbar++; 
  
  field_size = NextPrime( 3*power(ZZ_two, bitsize-1) + mbar);
  ZZ_p::init( field_size);

  field_bits = (int) ceil(log(field_size)/log(2));
  max = field_size -1; 
  }


reconciled_set::reconciled_set(int pp, int kk) 
{
  
  p = pp; 
  k = kk; 
  dataStart = to_ZZ_p(mbar/2 + 1);
  samples = compute_samplepoints(mbar, to_ZZ_p(max));
  powSamples = new vec_ZZ_p[samples.length()];
  for (int i=0; i<samples.length(); i++)  // for various samples
    for (int pow=0; pow<=mbar; pow++)      // and various powers
      append(powSamples[i],power(samples[i],pow));  // compute the corresponding power
    
  pTree = recurse_make(vec_ZZ_p(),  ZZ_zero, max);
  pTree->intree = true;
}	


reconciled_set::~reconciled_set()
{
  for (int ii=0; ii<samples.length(); ii++)
    powSamples[ii].kill();
  delete[] powSamples;
  deletetree(pTree);
  pTree->unref();
  samples.kill();
}


void reconciled_set::printTree()
{
  pTree->printNode(0);
}


void reconciled_set::deletetree(node*& root)
{
  if(root!=NULL)
    {
      root->intree = false;
      //long ii;
      //root->hash_vector.kill();
      //root->extra_hashes.kill();
      for(int ii=0;ii<p;ii++)
	{
	  deletetree(root->child[ii]);
	}
      //delete [] root->child;
      //delete root;
      //root->intree = false;
      //root->unref();
    }
}

/*
 * Computes the proper subdivision in which to put element_to_add
 * within start ... stop
 */
long reconciled_set::position_of_child(ZZ_p element_to_add,ZZ start, ZZ stop,  ZZ d)
{
  long position = to_long(((rep(element_to_add)-start)/d));
  if (position >= p) 
    position = p-1;
  return position;
}

/* 
 * Computes the proper subdivision in which to put element_to_add
 * within start ... stop
 */
long reconciled_set::position_of_child(ZZ_p element_to_add,ZZ start, ZZ stop)
{
  ZZ d = (stop-start)/to_ZZ(p);
  if (d<1) d = ZZ_one;
  return position_of_child(element_to_add,start,stop, d);
}



node* reconciled_set::recurse_make(vec_ZZ_p set, ZZ start,ZZ stop)
/* R: set - whose characteristic polynomial has to be computed and stored in the node
   p - Number of children the node will have in case there is a need  to further partition
   start - the lower end (inclusive) of the sub-field's region 
   stop - the upper end (inclusive) of the sub-field's region
   E: Nodes of partition tree
   M: Node --> partition tree
*/
{
  node* temppointer;
  temppointer = new node(this, set, start, stop);
  temppointer->ref();

  if (temppointer->node_type == NODE_TYPE_NON_TERMINAL){
    long index;
    ZZ n,d;    
    vec_ZZ_p* subsets;

    subsets = new vec_ZZ_p[p];
    d = (stop-start)/to_ZZ(p);

    if (d < 1)
      d = ZZ_one;
    
    for(long jj=0; jj<set.length(); jj++){	  
      index = position_of_child(set[jj], start, stop, d);
      append(subsets[index],set[jj]);
      clear(set[jj]); // save memory
    }
    set.kill();
      
    ZZ temp = start;
    ZZ newstart;
    ZZ newstop;
      
    for(long jj=0; jj<p; jj++){
      newstart = temp;
      temp = temp+d;
      newstop = temp-1;
      
      if(jj==(p-1)) newstop = stop;
      if (subsets[jj].length() != 0){
	temppointer->child[jj]= recurse_make(subsets[jj], newstart, newstop);
	temppointer->child[jj]->intree = true;
	subsets[jj].kill();
      }
      else{
	temppointer->child[jj]=NULL;
      }
    }
    assert(temppointer->node_type == NODE_TYPE_NON_TERMINAL);
    //assert(temppointer->setsize == temppointer->terminal_data().length());
    assert(temppointer->hash_vector.length() == mbar);    
    delete [] subsets;    
  }  
  return(temppointer);
}


void reconciled_set::add_to_tree(node*& root, ZZ_p& element_to_add)
// adds element_to_add to the tree rooted at "root"
{
  long ii;
  if(root->node_type == NODE_TYPE_TERMINAL) //Terminal Node
    {      
      if(root->setsize < mbar) //Space in the terminal node - don't need to convert to internal node
	{
	  append(root->hash_vector,element_to_add);
	  root->setsize+=1;
	}
      else //Need to make this an internal node...
	{
	  vec_ZZ_p set_vector = root->hash_vector; //Save the set.
	  append(set_vector, element_to_add);
	  ZZ start = root->start;
	  ZZ stop = root->stop;
	  root->intree = false;
	  root->unref();
	  root = recurse_make(set_vector, start, stop);
	  root->intree = true;

	}
    }
  else // Non terminal node
    {

      
      for(ii=0; ii < mbar; ii++)
	root->hash_vector[ii] *= (samples[ii]-element_to_add); //Updating sample point evaluations
      
      for(ii=0; ii < root->valids.length(); ii++)
	root->extra_hashes[ii] *= (root->valids[ii]-element_to_add); //Updating validation point evaluations
        
      long position = position_of_child(element_to_add, root->start, root->stop);
      
      if (root->child[position] == NULL) //Need to compute its range to create the node 
	{
	  ZZ d = (root->stop - root->start)/to_ZZ(p);
	  if (d<1) 
	    d = ZZ_one; //to_ZZ("1");
	  
	  ZZ st = root->start + position*d;
	  ZZ stp = st+d-1;
	  if(position==(p - 1)) 
	    stp = root->stop;
	  
	  vec_ZZ_p subset_pp;
	  subset_pp.SetLength(1);
	  subset_pp[0]=element_to_add;
	  root->child[position] = new node(this, subset_pp, st, stp);
	  root->child[position]->ref();
	  root->child[position]->intree = true;
	  root->setsize +=1;
	}
      else{
	add_to_tree(root->child[position], element_to_add);
	root->setsize +=1;
      }
    }
}

void reconciled_set::delete_from_tree(node*& root, ZZ_p element_to_delete)
/*
  R: 
  E: Deletes the element_to_delete from the tree root
  M: root
  Data: 12th Dec 2002
  Note: Suggest incorprating element _to_delete not in tree error condition gracefully.
*/
{
  assert(root->setsize > 0);
  //assert(root->setsize == root->terminal_data().length());

  if (root->node_type == NODE_TYPE_NON_TERMINAL){    
    assert(root->hash_vector.length() == mbar);
    if((root->setsize-1) > mbar) {

      //FIXME ? was mbar + 1

      //Dont need to convert to a terminal node.
      for(int ii=0; ii < mbar; ii++){
	root->hash_vector[ii] /= (samples[ii]-element_to_delete);
      }
      for(int ii=0;ii<root->valids.length();ii++){
	root->extra_hashes[ii] /= (root->valids[ii]-element_to_delete);
      }
      long position = position_of_child(element_to_delete, root->start, root->stop);
      delete_from_tree(root->child[position], element_to_delete);
      root->setsize -= 1;
    }

    else{
      
      //Need to convert to a terminal node
      vec_ZZ_p allelements = root->terminal_data();
      vec_ZZ_p newset;
      long alllength = allelements.length();
      newset.SetLength(alllength-1);      

      long ctr = 0;
      for(int ii = 0 ;ii < alllength; ii++) {

	//Weeding out the element to be deleted
	if (allelements[ii] != element_to_delete)
	  newset[ctr++] = allelements[ii];
      }
      
      assert(alllength == (newset.length() + 1));		  
      ZZ start = root->start;
      ZZ stop = root->stop;
      deletetree(root);
      root->intree = false;
      root->unref();

      root = recurse_make(newset, start, stop);
      root->intree = true;

      assert(root->node_type == NODE_TYPE_TERMINAL);
    }
  }
  else {

    assert(root->hash_vector.length() <=  mbar);
    
    if((root->setsize-1)==0){

      /* The node needs to be deleted since this one element is
	 the element to be deleted. */
      deletetree(root);
      root->intree = false;
      root->unref();

      root = recurse_make(vec_ZZ_p(),  ZZ_zero, max);
      root->intree = true;
    }
    else{

      assert(root->setsize == root->hash_vector.length());
      long l = root->hash_vector.length();
      vec_ZZ_p tempset;
      tempset.SetLength(l-1);
      long ctr=0;

      
      //Weeding out the element to be deleted.      
      for(int ii = 0 ; ii < l; ii++){
	
	if (root->hash_vector[ii]!=element_to_delete){	      
	  tempset[ctr++] = root->hash_vector[ii];  
	  assert(ctr <= (l-1));
	}
      }
      assert(ctr == (l-1));
      root->hash_vector = tempset;
      root->setsize -= 1;
      assert(root->hash_vector.length() == root->setsize);
    }
  }
}



void reconciled_set::add_element(ZZ_p el) {

  ZZ_p v = external2internal(el);
  // element has to be adjusted as in reconciled_set::reconciled_set
  add_to_tree(pTree,  v);
}

void reconciled_set::add_element(char *el) {
  
  ZZ_p x;
  x = external2internal(to_ZZ_p(to_ZZ(el)));
  add_to_tree(pTree,  x);  
}


void reconciled_set::del_element(ZZ_p el) {

  delete_from_tree(pTree, external2internal(el));
  if (pTree == NULL){
    pTree = recurse_make(vec_ZZ_p(),  ZZ_zero, max);
    pTree->intree = true;
  }
}



/*
 * Constructs the rhs for the Vandermonde matrix - the bmatrix .
 *
 * RF -- is the Rational Function Matrix. 
 * Rank -- is the rank of the LHS Matrix.
 */
vec_ZZ_p reconciled_set::construct_RHS_constant_vector(vec_ZZ_p& RF,long& rank, long& d)
{
  vec_ZZ_p rtnvalue;
  long mabar=calc_mabar(mbar, d);
  long mbbar=calc_mbbar(mbar, d);
  
  //long mbbar=mbar-mabar;
  rtnvalue.SetLength(rank);
  for(int ii=0; ii < rank; ii++)
    rtnvalue[ii] = RF[ii]*powSamples[ii][mbbar]-powSamples[ii][mabar];
  // i.e.  RF[ii]*power(samplepoints[ii],mbbar)-power(samplepoints[ii],mabar);

  return rtnvalue;
}


/*
 * This function constructs the Vandemonde Matrix.  
 *
 * RF -- is the Rational function vector (all the fi).  
 * bmatrix -- is the RHS Matrix of size m bar.
 */
mat_ZZ_p reconciled_set::construct_vandermonde_matrix(const vec_ZZ_p& RF, const vec_ZZ_p& bmatrix, const long d)  
{
  long mabar = calc_mabar(mbar, d);
  long mbbar = calc_mbbar(mbar, d);
  vec_vec_ZZ_p returnmatrix;
  mat_ZZ_p mat_rtn;

  returnmatrix.SetLength(mbar);

  for(int ii=0; ii < mbar; ii++)
    {
      returnmatrix[ii].SetLength(mabar+mbbar+1); 
  
      for(int jj=0; jj<  mabar; jj++)
	{
	  returnmatrix[ii][jj]=powSamples[ii][mabar-jj-1];
	}
      for(int jj=0; jj < mbbar; jj++)
	{
	  returnmatrix[ii][jj+mabar]= -RF[ii]*powSamples[ii][mbbar-jj-1];
	}
      //Augumented matrix
      returnmatrix[ii][mabar+mbbar]=bmatrix[ii]; 
    }
  
  // + 1 is for the B matrix
  mat_rtn.SetDims(mbar, mabar+mbbar+1);
  MakeMatrix(mat_rtn, returnmatrix);
  return mat_rtn;
}

node * reconciled_set::get_tree()
{
  return pTree;
}




int reconciled_set::reconcile(
			      vec_ZZ_p HASamplevalues,
			      vec_ZZ_p A_EVALS,
			      long asize,
			      vec_ZZ_p HBSamplevalues, 
			      vec_ZZ_p B_EVALS, 
			      long bsize, 
			      vec_ZZ_p validationpoints,
			      vec_ZZ_p& dnom, vec_ZZ_p& numer)
/*
  Function to run the basic reconciliation algorithm.
  M: returnvalue - returns 0 if reconciliation is unsuccessful
  E:
*/

{
  long ii,jj;
  

  //assert(rootA->intree == true);
  //  assert(rootA->node_type == NODE_TYPE_NON_TERMINAL);

  // initialize local variables
  //vec_ZZ_p& HASamplevalues=rootA->hash_vector;
  //vec_ZZ_p& A_EVALS=rootA->extra_hashes;
  //vec_ZZ_p& validationpoints=rootA->valids;

  //long asize=rootA->setsize;
  vec_ZZ_p RF; //Rational function at sample points fits
  vec_ZZ_p bvector; //RHS of Vandemonde equation
  vec_ZZ_p bredvector; //The reduced RHS of the Vandermonde matrix size = rank
  ZZ_p fieldminus1; // holds p-1 for GF(p)
  long mbar = HASamplevalues.length(); 
  
  long d = asize-bsize; //Calculate d =|A|-|B|
  if (d>mbar || d < -mbar) // then too many differences ... hopeless
    return 0;	
  
  ZZ tempzz = ZZ_p::modulus();
  conv(fieldminus1, tempzz-1); //Setting up the value of fieldminus1
  
  //Calculate the Rational RF function at the sample points. m bar Rational functions for m bar Sample points
  RF.SetLength(mbar);
  for(ii=0;ii<mbar;ii++)
    {
      RF[ii]=HASamplevalues[ii]/HBSamplevalues[ii];
    }

  vec_ZZ_p HBData;
  HBData.SetLength(bsize); //This is a redundant albatross. Just to minimise perturbation in palm program
  bvector.SetLength(mbar); //This vector holds the RHS of the Vandermonde Equations (As in MATRIX FORM)
  bvector=construct_RHS_constant_vector(RF,mbar,d);  //Computing bvector. Note mbar,mbar argument since rank=mbar so far
  mat_ZZ_p vmatrix;//This will hold the Vandermonde matrix
  vmatrix = construct_vandermonde_matrix(RF,bvector,d);//Constructing the Vandemonde Matrix

  
  long mabar=calc_mabar(mbar, d);
  long mbbar=calc_mbbar(mbar, d);;
  long rank=gauss(vmatrix); //, mbar); //GAUSSIAN ELIMINATION
  //std::cout << "oldrank= " << rank << "\n";
  //std::cout << "vmatrix= " << vmatrix << "\n";
  if (rank > (mabar + mbbar)){
    rank = mabar + mbbar; 
  }
  bvector.SetLength(rank); //Take only the rank number of bvector constituents
  
  mat_ZZ_p vredmatrix;// Vandermonde Reduced Matrix using only rank*rank dimensions
  vredmatrix.SetDims(rank,rank);
  //vredmatrix.SetDims(rank, rank);
  //for (int i = 0; i < rank; i++)
  //  for (int j = 0; j < rank; j++)
  //    vredmatrix[i][j] = vmatrix[i][j];

  vredmatrix = makeA(vmatrix, rank, mbar); //Make the VanderMonde Matrix with size Rank*Rank

  bredvector.SetLength(rank);
  bredvector = makeB(vmatrix, rank, mbar, d);
  vmatrix.kill();
  
  //Now Solving the Vandemonde Matrix by Back Substitution
  vec_ZZ_p coeff_vector; //Holds the solution
  //long mbbar=calc_mbbar(mbar,d);
  coeff_vector.SetLength(mabar+mbbar);
  
  coeff_vector=backsubstitutesolve(vredmatrix,bredvector,rank,mabar+mbbar);
  vredmatrix.kill(); //Get rid of the huge chunk
  bredvector.kill();
  vec_ZZ_p coeffP;
  vec_ZZ_p coeffQ;
  
  if(rank >mabar)
    {
      coeffP.SetLength(mabar+1); //+1 is added beacuse the polynomial is monic and we need to add this fact as the highest degree term p0
      coeffQ.SetLength(1+mabar+mbbar-mabar); //Adding 1 for q0
    }
  else
    {
      coeffP.SetLength(mabar+1);
      coeffQ.SetLength(1+mbbar);
    }
  
  long Plength=coeffP.length(); //Sizes of P & Q
  long Qlength=coeffQ.length();
  
  coeffP[Plength-1]=1; //Setting the coeff corresponding to the highest power = 1 (Monic)
  coeffQ[Qlength-1]=1;
  
  for(ii=0;ii<Plength-1;ii++) //Getting the other coefficients from the Solution to the VanderMonde Equations. p1 = index 0, p2 = index 1 etc.
    coeffP[ii]=coeff_vector[Plength-2-ii]; //Plengh was added a +1 becasue of p0 not being included.
  for(jj=0;jj<Qlength-1;jj++)
    coeffQ[jj]=coeff_vector[mabar+mbbar-jj-1];
  
  
  ZZ_pX P; //These are the ZZ_pX avatars of coeffP & CoeffQ ( which in turn are of type vec_ZZ_p )
  ZZ_pX Q;
  conv(P,coeffP);//Convert coefficients to polynomials
  conv(Q,coeffQ);
  coeffP.kill();
  coeffQ.kill();

  ZZ_pX gcdvalue;
  gcdvalue= GCD(P,Q); //GCD calculation

  P=P/gcdvalue; //Reducing by getting rid of common factors
  Q=Q/gcdvalue;
   
  vec_ZZ_p numerator;
  vec_ZZ_p denominator;

  int rtnbool=0;
  if (match_value(P, Q, A_EVALS, validationpoints, B_EVALS)==0)
    {
      ;
    }
  else
    {
      rtnbool=1;
      numerator.SetLength(Plength-deg(gcdvalue));
      denominator.SetLength(Qlength-deg(gcdvalue));
      
      FindRoots(numerator,P); //Factorize P - Numerator
      
      FindRoots(denominator,Q); //Factorize Q - Denominator
      
      dnom=internal2external(denominator);
      numer=internal2external(numerator);
    }
  numerator.kill();
  denominator.kill();

  return rtnbool;
}




vec_ZZ_p reconciled_set::internal2external(const vec_ZZ_p v)
{
  vec_ZZ_p r = v;
  for (int i = 0; i < r.length(); i++)
    r[i] -= dataStart;
  return r;
}

vec_ZZ_p reconciled_set::external2internal(const vec_ZZ_p v)
{
  vec_ZZ_p r = v;
  for (int i = 0; i < r.length(); i++)
    r[i] += dataStart;
  return r;
}

ZZ_p reconciled_set::internal2external(const ZZ_p v)
{
  return v - dataStart;
}

ZZ_p reconciled_set::external2internal(const ZZ_p v)
{
  return v + dataStart;
}



/*
  R: 2 sets whose differences has to be found
  E: Returns set2\set1
  M: 
  Date: 28th Nov 2002
*/
vec_ZZ_p difference_set(vec_ZZ_p set1, vec_ZZ_p set2)

{
  long ii,jj;
  
  int flag=1;
  vec_ZZ_p returnset;
  returnset.SetLength(0);
  for(ii=0;ii<set2.length();ii++)
    {
      flag = 1;
      for (jj=0;jj<set1.length();jj++)
	if(set2[ii]==set1[jj])
	  {
	    flag = 0;
	    break;
	  }
      if (flag) append(returnset, set2[ii]);
    }
  return returnset;
}
