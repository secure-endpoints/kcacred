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
 * Copyright  ©  2000
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
 * Copyright  ©  2006
 * Secure Endpoints Inc.
 * ALL RIGHTS RESERVED
 *
 */

#ifndef _PKCS11_FUNS_H_
#define _PKCS11_FUNS_H_

#ifdef _WIN32
#include "win32pre.h"
#endif

#include "cki_types.h"
#include "pkcs11_types.h"

CK_RV PKCS11_Init_Module(CK_C_INITIALIZE_ARGS_PTR pArgs, PKCS11_MODULE **ppModule);
CK_RV PKCS11_Init_Info(CK_INFO_PTR pInfo);
CK_RV PKCS11_Init_Function_List(CK_FUNCTION_LIST_PTR pFunctionList);
CK_RV PKCS11_Init_Slot(PKCS11_SLOT *pSlot, CK_SLOT_ID slotID, CK_FLAGS slotFlags);
CK_RV PKCS11_Init_Token(PKCS11_TOKEN *pToken, CK_CHAR_PTR serialNumber, CK_MECHANISM_TYPE_PTR pMechanismType);
CK_RV PKCS11_Init_Mechanism(PKCS11_MECHANISM *pMechanism,CK_MECHANISM_TYPE mechanismType);
CK_RV PKCS11_Init_Session(CK_SESSION_HANDLE ulSessionHandle, CK_SLOT_ID slotID, 
			  PKCS11_TOKEN_PTR pToken, CK_STATE state, CK_FLAGS flags,
			  CK_VOID_PTR pApplication, CK_NOTIFY NotifyFunc, PKCS11_SESSION *pSession);
CK_RV PKCS11_Init2_Session(PKCS11_SESSION *pSession);

/* from cki_objs.c */
CK_RV PKCS11_CreateDataObject(PKCS11_SESSION *pSession, CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pObject);
CK_RV PKCS11_CreateX509CertificateObject(PKCS11_SESSION *pSession,
  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pObject);
CK_RV PKCS11_CreateRSAPublicKeyObject(PKCS11_SESSION *pSession,
  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pObject);
CK_RV PKCS11_CreateRSAPrivateKeyObject(PKCS11_SESSION *pSession,
  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pObject);
CK_RV PKCS11_SetCommonObjectAttrs(CK_ATTRIBUTE_PTR pAttributes, 
  CK_OBJECT_CLASS objectClass, int *ctr);
CK_RV PKCS11_SetCommonKeyObjectAttrs(CK_ATTRIBUTE_PTR pAttributes, 
  CK_KEY_TYPE keyType, int *ctr);
CK_RV PKCS11_CreateSecretKeyObject(PKCS11_SESSION *pSession, 
  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pObject);
CK_RV PKCS11_CreateVendorDefinedObject(PKCS11_SESSION *pSession, 
  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pObject);
CK_RV PKCS11_SetCommonPrivateKeyObjectAttrs(CK_ATTRIBUTE_PTR pAttributes, 
  int *ctr);
CK_ULONG PKCS11_NextObjectHandle();
RSA *PKCS11_RsaPrivateKey_to_RSA(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);

CK_ATTRIBUTE_PTR PKCS11_FindAttribute_p(CK_ATTRIBUTE_PTR pAttributes,
  CK_ATTRIBUTE_TYPE Type);
CK_ATTRIBUTE_PTR PKCS11_GetAttribute(CK_ATTRIBUTE_PTR pAttributes,
  CK_ATTRIBUTE_TYPE Type);

void PKCS11_CheckTokenPresent(PKCS11_SLOT *pSlot);
PKCS11_SESSION *PKCS11_FindSession(CK_SESSION_HANDLE hSession);
PKCS11_SLOT *PKCS11_FindSlot(CK_SLOT_ID slotID);


#ifdef _WIN32
#include "win32post.h"
#endif

#endif /* _PKCS11_FUNS_H_ */
