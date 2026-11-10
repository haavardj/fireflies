//====================================================================
// Filename:      constants.cpp
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
// $Id: constants.h,v 1.1.1.1 2006/01/20 12:41:27 haavardj Exp $
//                
//====================================================================


#ifndef CONSTANTS
#define CONSTANTS
// Various constants used throughout the program
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
#include "assert.h"

NTL_USE_NNS

extern const ZZ ZZ_zero; // 0 in ZZ
extern const ZZ ZZ_one;  // 1 in ZZ
extern const ZZ ZZ_two;  // 2 in ZZ

#define NODE_TYPE_TERMINAL 1
#define NODE_TYPE_NON_TERMINAL 0

#endif
