//====================================================================
// Filename:      prob_reconcile.h
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
// $Id: prob_reconcile.h,v 1.1.1.1 2006/01/20 12:41:27 haavardj Exp $
//                
//====================================================================

#ifndef PROB_RECON
#define PROB_RECON

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

NTL_USE_NNS

int reconcile(vec_ZZ_p& HASamplevalues, 
	      vec_ZZ_p& A_EVALS,
	      vec_ZZ_p& HBSamplevalues, 
	      vec_ZZ_p& B_EVALS,
	      vec_ZZ_p& samplepoints, 
	      vec_ZZ_p& validationpoints, 
	      long asize,
	      long bsize,
	      vec_ZZ_p& returnvalue);
/*
	Function to run the basic reconciliation algorithm.
	R: Requires the sample point evelations of the characteristic polynomials (H*Samplevalues), 
	   Extra evaluation points for testing the interpolated rational function (*_EVALS),
	   Sample points
	   Validation points 
	   Set sizes of set A and set B
	E:
	M: returnvalue - returns 0 if reconciliation is unsuccessful
*/

#endif
