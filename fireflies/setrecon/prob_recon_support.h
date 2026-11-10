//====================================================================
// Filename:      prob_recon_support.h
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
// $Id: prob_recon_support.h,v 1.1.1.1 2006/01/20 12:41:27 haavardj Exp $
//                
//====================================================================


#ifndef PROB_RECON_SUPPORT
#define PROB_RECON_SUPPORT

// Include Files
#include <stdlib.h>
#include <time.h>
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
#include "constants.h"

NTL_USE_NNS

vec_ZZ_p compute_samplepoints(const long numberof, const ZZ_p fieldminus1);
// This function calculates Sample points and stores the result in a vector which is returned by the function.
// number_of - Number of desired sample points.
// fieldminus1 - for a field chosen to be over prime p, fieldminus1 = p-1.

vec_ZZ_p compute_validationpoints(const int mbar, const int numpoints, const ZZ start, const ZZ stop, ZZ seed = ZZ_zero);
/*
	R: the value of mbar and the number of validation points
	E: Validation points so they dont clash with the sample points
	M: 
	Date: 28th November 2002
*/

vec_ZZ_p calc_poly(vec_ZZ_p& set, vec_ZZ_p& samplepoints);
//  This function calculates the polynomial formed by the elements of "set" at the "sample points" and returns the vector containing the
// evaluated set polynomials at each sample point. Characteristic Polynomial evaluations.

// AUXILIARY PROCEDURES
long calc_diff_ma_mb(vec_ZZ_p& A, vec_ZZ_p& B);
//This function calculates "d" = |Sa|-|Sb|

long calc_diff_ma_mb_1(long& A,long& B);

long calc_mabar(long mbar,long d);
// This Function calculates ma_bar based on mbar and d
//It returns the floor value

long calc_mbbar(long mbar,long d);
// This Function calculates mb_bar based on mbar and d. Similar to the calc_mabar function.

mat_ZZ_p construct_vandermonde_matrix(const vec_ZZ_p& samplepoints,const vec_ZZ_p& RF, const vec_ZZ_p& bmatrix, const long mbar, const long d);
// This function constructs the Vandemonde Matrix.
//RF is the Rational function vector (all the fi s) bmatrix is the RHS Matrix of size m bar.

vec_ZZ_p construct_RHS_constant_vector(vec_ZZ_p& RF,vec_ZZ_p& samplepoints,long& rank,long& mbar, long& d);
//Constructs the rhs for the vandrmonde matrix - the bmatrix . RF is the Rational Function Matrix. Rank is the rank of the LHS Matrix

mat_ZZ_p makeA(mat_ZZ_p vmat,long rank,long mbar);
//Reducing the A matrix into rank*rank size. (This is done after Gauss elimination

vec_ZZ_p makeB(mat_ZZ_p& vmatrix,long& rank,long& mbar,long& d);
//Reducing the B matrix into rank*1 size

vec_ZZ_p backsubstitutesolve(mat_ZZ_p& mat, vec_ZZ_p& bvec, long rank,long totalcoeffs);
//Solve by back substitution - mat is the LHS rank*rank matrix. bvec is the RHS rank size matrix

int match_value(ZZ_pX& PX,ZZ_pX& QX,vec_ZZ_p& PCEVALS,vec_ZZ_p& EXTRASPS,vec_ZZ_p& EXTRAEVALS);
/* This function returns 0 if more Sample Points are needed, else returns a 1 if no more sample points are needed */

void reconstruct(vec_ZZ_p& B,long& mm,long& old_mm);
ZZ prime_to_use();

bool elementOf(const ZZ_p item, vec_ZZ_p vect);

#endif
