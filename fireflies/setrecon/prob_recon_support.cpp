//====================================================================
// Filename:      prob_recon_support.cpp
// Description:   
//
// Initial implementation by: Sachin Agarwal, ska@bu.edu
//               modified by: Ari Trachtenberg, trachten@bu.edu
//                   Version: 0.998 Beta
//                      Date: 06/23/2004
// Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
// Modified at:   Mon Jan 16 18:46:06 2006
// Licence: GPL (see LICENSE file).
//  
//                
// $Id: prob_recon_support.cpp,v 1.1 2006/01/20 12:41:27 haavardj Exp $
//                
//====================================================================

// This is the probabilistic reconciliation emulation program.

// WORKS WITH PALM FEB 27th 2001

/* Set Reconciliation Implementation*/
// Include Files
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
#include <stdlib.h>
#include <time.h>
#include "prob_recon_support.h"


vec_ZZ_p compute_samplepoints(const long numberof,const ZZ_p fieldminus1)
// This function calculates Sample points and stores the result in a vector which is returned by the function.
// number_of - Number of desired sample points.
//fieldminus1 - for a field chosen to be over prime p, fieldminus1 = p-1.
{
  vec_ZZ_p temp;
  temp.SetLength(numberof);
  for(long ii=0;ii<numberof;ii++) //Setting samplepoints to 0,-1,1,-2,2 .....
    {
      if ((ii % 2)==0) temp[ii]=ii/2;
      else temp[ii]=fieldminus1-ii/2;
      if (ii  == 0) temp[ii]=0;
    }
	// std::cout << (rep(fieldminus1)+1) << ": " << temp << endl << endl;
  return temp;
}


vec_ZZ_p compute_validationpoints(const int mbar, const int numpoints, const ZZ start, const ZZ stop, ZZ seed)
/*
	R: the value of mbar and the number of validation points
	   validation points are chosen uniformly at random in the range start ... stop inclusive
     0 <= start <= stop <= ZZ_p::modulus - 1
	E: Validation points so they dont clash with the sample points
	M:
*/
{
	vec_ZZ_p returnvector;
	returnvector.SetLength(numpoints);
	SetSeed(seed); // reset the random number seed to its default state (so that valids is consistent among clients) --- nodes on different machines must have consistent random numbers
	for(long ii=0;ii<numpoints;ii++)
		returnvector[ii]= to_ZZ_p(RandomBnd(stop-start)+start);
	return returnvector;
}

vec_ZZ_p calc_poly(vec_ZZ_p& set, vec_ZZ_p& samplepoints)
//  This function calculates the polynomial formed by the elements of "set" at the "sample points" and returns the vector containing the
// evaluated set polynomials at each sample point. Characteristic Polynomial evaluations.

{
  long samplepointvectorsize=samplepoints.length();
  ZZ_p temp;
  vec_ZZ_p polyval;
  polyval.SetLength(samplepointvectorsize);
  for(long ii=0;ii<samplepointvectorsize;ii++)
    {
      conv(temp,to_ZZ("1"));
      for(long jj=0;jj<set.length();jj++)
      {
		temp*=(samplepoints[ii]-set[jj]);
      }
      polyval[ii]=temp;
    }

  return polyval;
}




long calc_diff_ma_mb(vec_ZZ_p& A, vec_ZZ_p& B)
//This function calculates "d" = |Sa|-|Sb|
{
  long temp = A.length()-B.length();
  return temp;
}

long calc_mabar(long mbar,long d)
// This Function calculates ma_bar based on mbar and d
//It returns the floor value

{
  long rtnvalue;
  if((mbar+d)%2!=0)
     rtnvalue=(mbar+d-1)/2;

  else
     rtnvalue=(mbar+d)/2;
  if (rtnvalue<=0) rtnvalue=1; //Added this in the part2 program to take care of parasitic case mbar=1.
   return rtnvalue;

}



long calc_mbbar(long mbar,long d)
// This Function calculates mb_bar based on mbar and d. Similar to the calc_mabar function.
{
   long rtnvalue;
   if((mbar-d)%2!=0)
      rtnvalue=(mbar-d-1)/2;
  else
      rtnvalue=(mbar-d)/2;
   if (rtnvalue<0) rtnvalue=0; //Added this in the part2 program to prevent negative problems
return rtnvalue;
}

mat_ZZ_p makeA(mat_ZZ_p vmat,long rank,long mbar)
//Reducing the A matrix into rank*rank size. (This is done after Gauss elimination
{
  long ii,jj;

  vec_vec_ZZ_p tempmat;
  mat_ZZ_p tmat;
  tempmat.SetLength(rank);

  for(ii=0; ii<rank;ii++){
    
    tempmat[ii].SetLength(rank);
    for(jj=0; jj<rank; jj++)
      {
	tempmat[ii][jj]=vmat[ii][jj];
      }
  }
  
  tmat.SetDims(rank,rank);
  
  MakeMatrix(tmat,tempmat);
  return tmat;
}




vec_ZZ_p makeB(mat_ZZ_p& vmatrix,long& rank,long& mbar,long& d)
//Reducing the B matrix into rank*1 size
{
  long ii;

  long mabar=calc_mabar(mbar,d);
  long mbbar=calc_mbbar(mbar,d);
  //std::cout <<"\n MBAR = "<<mbar;
  vec_ZZ_p temp;
  temp.SetLength(rank);
  for (ii=0;ii<rank;ii++)
     temp[ii]=vmatrix[ii][mabar+mbbar];
  return temp;
}



vec_ZZ_p backsubstitutesolve(mat_ZZ_p& mat, vec_ZZ_p& bvec, long rank,long totalcoeffs)
//Solve by back substitution - mat is the LHS rank*rank matrix. bvec is the RHS rank size matrix
{
  vec_ZZ_p rtntemp;

  long ii,jj;

  rtntemp.SetLength(totalcoeffs);
  //rtntemp.SetLength(rank);
  for(ii=rank-1;ii>=0;ii--)
    {
      if (mat[ii][ii] == 0){
	//std::cout << "mat[ii][ii]==0, substituting with 1.\n";
	rtntemp[ii] = 1;
	mat[ii][ii] = 1;
      }else{
	//assert(mat[ii][ii] != 0);
	rtntemp[ii]=bvec[ii]/mat[ii][ii];
      }
      for(jj=0;jj<rank;jj++)
	{
	  bvec[jj]=bvec[jj]-rtntemp[ii]*mat[jj][ii];
	}
    }
  for(ii=rank;ii<totalcoeffs;ii++) //Setting the other coeffs - from index mbar-rank upto mbar to 0
    rtntemp[ii]=0;
  return rtntemp;
}



int match_value(ZZ_pX& PX,ZZ_pX& QX,vec_ZZ_p& PCEVALS,vec_ZZ_p& EXTRASPS,vec_ZZ_p& EXTRAEVALS)
/* This function returns 0 if more Sample Points are needed, else returns a 1 if no more sample points are needed */

{
  long ii;
  //std::cout << "match_value\n"; 
  //std::cout << "EXTRAEVALSE= " << EXTRAEVALS <<"\n"; 
  long num_of_points = EXTRASPS.length();
  //std::cout << "extrapoints.length= " << num_of_points << "\n";
  int returnvalue=1;
  ZZ_p p,q;
  for(ii=0;ii<num_of_points;ii++)
    {
      //std::cout << "ii= " << ii << "\n"; 
      p = eval(PX, EXTRASPS[ii]);
      q = eval(QX, EXTRASPS[ii]);
      //std::cout <<q;
      //std::cout << "p= " << p << "\n";
      //std::cout << "q= " << q << "\n"; 
      if (q !=0)
	{
	  //std::cout << "1.1\n"; 
	  //std::cout << "EXTRAEVALSE= " << EXTRAEVALS <<"\n"; 
	  if(EXTRAEVALS[ii]==0)
	    {
	      //std::cout << "1.1.1\n"; 
	      returnvalue=0;
	      break;
	    }
	  //std::cout << "1.2\n"; 
	  if (p/q != PCEVALS[ii]/EXTRAEVALS[ii])
	    {
	      //std::cout << "1.2.1\n"; 
	      returnvalue=0;
	      //      std::cout << "\nBreak1";
	      break;
	    }
	  // std::cout << "\nNo break";
	}
        else
	  {
	    //std::cout << "2.1\n"; 
	    if (EXTRAEVALS[ii]!=0)
	      {
		//std::cout << "2.1.1\n"; 
		returnvalue=0;
		break;
	      }
	  }
    }
  return returnvalue;
}

void reconstruct(vec_ZZ_p& B,long& mm,long& old_mm)
{
	long ii;

	vec_ZZ_p newvector;
	std::cout <<"\nNeed new_mbar-old_mbar more char. polynomial evaluations of Host B (PDA): (Enter "<< mm-old_mm << " more at the appropriate sample points:\n";
	
	std::cin >> newvector;
       
        for(ii=old_mm;ii<mm;ii++)     
               B[ii]=newvector[ii-old_mm];
}

ZZ prime_to_use()
  /* R: User Input of the bitsize of data being reconciled
     E: Returns a suitable prime number to construct the finite field and init ZZ_p
     M: 
  */
{
  	  //The primes
	  ZZ prime[7];
	  GenPrime(prime[0],10); //Generating prime numbers 10bits,18 bits...514 bits
	  GenPrime(prime[1],18);
	  GenPrime(prime[2],34);
	  GenPrime(prime[3],66);
	  GenPrime(prime[4],130);
	  GenPrime(prime[5],258);
	  GenPrime(prime[6],514);
	  //long sizearray[7]={8,16,32,64,128,256,512};
	  // User data
	  long bitsize;
	  std::cout <<"\nEnter the bitsize of the data being reconciled. Choose between 8/16/32/64/128/256/512: ";
	  std::cin >>bitsize;
	  long location=0;
	  long temp=8;
	  while((location<7)&&(temp<bitsize)) //To determine which prime field to use.
		{
		  temp*=2;
		  location++;
		}
	  ZZ tempZZ=prime[location];
	  ZZ_p::init(tempZZ);
	  std::cout << "\nAlright, I am using "<< prime[location] << " as the Finite field over which to do the math here.";
	  return(tempZZ);
}
        

/* TODO:
 * Don't think this is used. Could be deleted?
 */
inline bool elementOf(const ZZ_p item, const vec_ZZ_p vect) {
  for (int ii=0; ii < vect.length(); ii++)
    if (item == vect[ii])
      return true;
  return false;
}
