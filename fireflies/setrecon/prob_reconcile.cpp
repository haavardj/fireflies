//====================================================================
// Filename:      prob_reconcile.cpp
// Description:   
//
// Initial implementation by: Sachin Agarwal, ska@bu.edu
//               modified by: Ari Trachtenberg, trachten@bu.edu
//                   Version: 0.998 Beta
//                      Date: 06/23/2004
// Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
// Modified at:   Mon Jan 16 18:45:30 2006
// Licence: GPL version 2 (see COPYING in this directory).
//  
//                
// $Id: prob_reconcile.cpp,v 1.1.1.1 2006/01/20 12:41:27 haavardj Exp $
//                
//====================================================================

#include "prob_recon_support.h"
#include "node.h"
#include "reconciled_set.h"

/*This is the native basic set reconciliation procedure */

int reconcile_aux(reconciled_set* base, node* rootA, node* rootB, vec_ZZ_p& dnom, vec_ZZ_p& numer)
/*
  Function to run the basic reconciliation algorithm.
  R: base contains the base class which contains, among other things, sample points and evaluations of powers of these sample points
  M: returnvalue - returns 0 if reconciliation is unsuccessful
  E:
*/

{
  long ii,jj;
  
  // initialize local variables
  vec_ZZ_p& HASamplevalues=rootA->hash_vector;
  vec_ZZ_p& A_EVALS=rootA->extra_hashes;
  vec_ZZ_p& HBSamplevalues=rootB->hash_vector;
  vec_ZZ_p& B_EVALS=rootB->extra_hashes;
  vec_ZZ_p& validationpoints=rootA->valids;
  long asize=rootA->setsize;
  long bsize=rootB->setsize;
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
  bvector=base->construct_RHS_constant_vector(RF,mbar,d);  //Computing bvector. Note mbar,mbar argument since rank=mbar so far
  mat_ZZ_p vmatrix;//This will hold the Vandermonde matrix
  vmatrix = base->construct_vandermonde_matrix(RF,bvector,d);//Constructing the Vandemonde Matrix
  
  long mabar=calc_mabar(mbar,d);
  long mbbar=calc_mbbar(mbar,d);;
  long rank=gauss(vmatrix,mbar); //GAUSSIAN ELIMINATION
  if (rank > mabar+mbbar) rank = mabar+mbbar; //TRY
  
  bvector.SetLength(rank); //Take only the rank number of bvector constituents
  
  mat_ZZ_p vredmatrix;// Vandermonde Reduced Matrix using only rank*rank dimensions
  vredmatrix.SetDims(rank,rank);
  vredmatrix = makeA(vmatrix,rank,mbar); //Make the VanderMonde Matrix with size Rank*Rank
  
  bredvector.SetLength(rank);
  bredvector = makeB(vmatrix,rank,mbar,d);
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
  returnvalue=numerator; //This is simply to define returnvalue = [] initially
  //   vec_ZZ_p returnvalue;
  int rtnbool=0;
  if (match_value(P,Q,A_EVALS,validationpoints,B_EVALS)==0) ;
  else
    {
      rtnbool=1;
      // cout <"\n B I N G O !!! Match!!! \n";
      numerator.SetLength(Plength-deg(gcdvalue));
      denominator.SetLength(Qlength-deg(gcdvalue));
      
      FindRoots(numerator,P); //Factorize P - Numerator
      
      FindRoots(denominator,Q); //Factorize Q - Denominator
      
      //cout<<"A Data not in B: "<<numerator;
      //cout<<"\n\nB data not in A: "<<denominator;
      // cout <<"\n";
      dnom=denominator;
      numer=numerator;
    }
  //cout <<"\nreconcile() Returning: "<<returnvalue;
  numerator.kill();
  denominator.kill();

  return rtnbool;
}

