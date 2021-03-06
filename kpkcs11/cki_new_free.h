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

#ifndef _CKI_NEW_FREE_H
#define _CKI_NEW_FREE_H

#ifdef _WIN32
#include "win32pre.h"
#endif

#include "cki_types.h"
#include "pkcs11_types.h"

void CKI_Info_Free(CK_INFO_PTR pInfo) ;
CK_INFO_PTR CKI_Info_New();

void CKI_SlotInfo_Free(CK_SLOT_INFO_PTR pInfo);
CK_SLOT_INFO_PTR CKI_SlotInfo_New();
void CKI_TokenInfo_Free(CK_TOKEN_INFO_PTR pInfo);
CK_TOKEN_INFO_PTR CKI_TokenInfo_New();
void CKI_SessionInfo_Free(CK_SESSION_INFO_PTR pInfo);
CK_SESSION_INFO_PTR CKI_SessionInfo_New();

void CKI_Attribute_Free(CK_ATTRIBUTE_PTR pAttribute);
CK_ATTRIBUTE_PTR CKI_Attribute_New();

void CKI_Mechanism_Free(CK_MECHANISM_PTR pMechanism);
CK_MECHANISM_PTR CKI_Mechanism_New();
void CKI_MechanismInfo_Free(CK_MECHANISM_INFO_PTR pInfo);
CK_MECHANISM_INFO_PTR CKI_MechanismInfo_New();

void CKI_Pin_Free(CK_CHAR_PTR pPin);

void CKI_FunctionList_Free(CK_FUNCTION_LIST_PTR pFunctionList);
CK_FUNCTION_LIST_PTR CKI_FunctionList_New();

void CKI_AttributePtr_Free(CK_ATTRIBUTE_PTR pAttribute);

#ifdef _WIN32
#include "win32post.h"
#endif

#endif /* _CKI_NEW_FREE_H */
