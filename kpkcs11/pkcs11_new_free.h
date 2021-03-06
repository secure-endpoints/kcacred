/*
 * Copyright (c) 1999
 * The Trustees of Columbia University in the City of New York.
 * All rights reserved.
 * 
 * Permission is granted to you to use, copy, create derivative works,
 * and redistribute this software and such derivative works for any
 * purpose, so long as the name of Columbia University is not used in any
 * advertising, publicity, or for any other purpose pertaining to the use
 * or distribution of this software, other than for including the
 * copyright notice set forth herein, without specific, written prior
 * authorization.  Columbia University reserves the rights to use, copy,
 * and distribute any such derivative works for any purposes.  The above
 * copyright notice must be included in any copy of any portion of this
 * software and the disclaimer below must also be included.
 * 
 *   THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION FROM THE
 *   TRUSTEES OF COLUMBIA UNIVERSITY IN THE CITY OF NEW YORK AS TO ITS
 *   FITNESS FOR ANY PURPOSE, AND WITHOUT WARRANTY BY THE TRUSTEES OF
 *   COLUMBIA UNIVERSITY IN THE CITY OF NEW YORK OF ANY KIND, EITHER
 *   EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED
 *   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *   THE TRUSTEES OF COLUMBIA UNIVERSITY IN THE CITY OF NEW YORK SHALL
 *   NOT BE LIABLE FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT,
 *   INCIDENTAL, OR CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM
 *   ARISING OUT OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN IF
 *   IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF SUCH
 *   DAMAGES.  YOU SHALL INDEMNIFY AND HOLD HARMLESS THE TRUSTEES OF
 *   COLUMBIA UNIVERSITY IN THE CITY OF NEW YORK, ITS EMPLOYEES AND
 *   AGENTS FROM AND AGAINST ANY AND ALL CLAIMS, DEMANDS, LOSS, DAMAGE OR
 *   EXPENSE (INCLUDING ATTORNEYS' FEES) ARISING OUT OF YOUR USE OF THIS
 *   SOFTWARE. 
 * 
 * The Trustees of Columbia University in the City of New York reserves
 * the right to revoke this permission if any of the terms of use set
 * forth above are breached.
 */ 

/*
 * Copyright  �  2000
 * The Regents of the University of Michigan
 * ALL RIGHTS RESERVED
 *
 * permission is granted to use, copy, create derivative works 
 * and redistribute this software and such derivative works 
 * for any purpose, so long as the name of the university of 
 * michigan is not used in any advertising or publicity 
 * pertaining to the use or distribution of this software 
 * without specific, written prior authorization.  if the 
 * above copyright notice or any other identification of the 
 * university of michigan is included in any copy of any 
 * portion of this software, then the disclaimer below must 
 * also be included.
 *
 * this software is provided as is, without representation 
 * from the university of michigan as to its fitness for any 
 * purpose, and without warranty by the university of 
 * michigan of any kind, either express or implied, including 
 * without limitation the implied warranties of 
 * merchantability and fitness for a particular purpose. the 
 * regents of the university of michigan shall not be liable 
 * for any damages, including special, indirect, incidental, or 
 * consequential damages, with respect to any claim arising 
 * out of or in connection with the use of the software, even 
 * if it has been or is hereafter advised of the possibility of 
 * such damages.
 */

/*
 * Copyright  �  2006
 * Secure Endpoints Inc.
 * ALL RIGHTS RESERVED
 *
 */

#ifndef _PKCS11_NEW_FREE_H
#define _PKCS11_NEW_FREE_H

#ifdef _WIN32
#include "win32pre.h"
#endif

#include "cki_types.h"
#include "pkcs11_types.h"
#include "cki_new_free.h"

void PKCS11_FunctionInfo_Free(PKCS11_FUNCTION_INFO *FunctionInfoPtr);
PKCS11_FUNCTION_INFO *PKCS11_FunctionInfo_New();
void PKCS11_Functions_Free(PKCS11_FUNCTIONS *pFunctions);
PKCS11_FUNCTIONS *PKCS11_Functions_New();

void PKCS11_SignInfo_Free(PKCS11_SIGN_INFO *SignInfoPtr);
PKCS11_SIGN_INFO *PKCS11_SignInfo_New();

void PKCS11_Object_Free(PKCS11_OBJECT *pObject);
PKCS11_OBJECT *PKCS11_Object_New();

void PKCS11_Session_Free(PKCS11_SESSION *pSession);
PKCS11_SESSION *PKCS11_Session_New();

void PKCS11_Mechanism_Free(PKCS11_MECHANISM *pMechanism);
PKCS11_MECHANISM *PKCS11_Mechanism_New();

void PKCS11_Token_Free(PKCS11_TOKEN *pToken);
PKCS11_TOKEN *PKCS11_Token_New();
void PKCS11_Slot_Free(PKCS11_SLOT *pSlot);
PKCS11_SLOT * PKCS11_Slot_New();

void PKCS11_Module_Free(PKCS11_MODULE*pModule);
PKCS11_MODULE *PKCS11_Module_New();

#ifdef _WIN32
#include "win32post.h"
#endif

#endif /* _PKCS11_NEW_FREE_H */
