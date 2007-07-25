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

#ifndef _CKI_FUNCS_H_
#define _CKI_FUNCS_H_

#include <stdio.h>

#ifdef _WIN32
# include "win32pre.h"
#endif

#include <openssl/x509.h>

#include "cki_types.h"
#include "pkcs11_types.h"

CK_RV CK_ENTRY CK_CALLCONV C_Initialize(CK_VOID_PTR pReserved);
CK_RV CK_ENTRY CK_CALLCONV C_Finalize(CK_VOID_PTR pReserved);

CK_RV CK_ENTRY CK_CALLCONV C_GetInfo(CK_INFO_PTR pInfo);
CK_RV CK_ENTRY CK_CALLCONV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
CK_RV CK_ENTRY CK_CALLCONV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
       CK_ULONG_PTR pulCount);
CK_RV CK_ENTRY CK_CALLCONV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
CK_RV CK_ENTRY CK_CALLCONV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);

CK_RV CK_ENTRY CK_CALLCONV C_GetMechanismList(CK_SLOT_ID slotID, 
    CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
CK_RV CK_ENTRY CK_CALLCONV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR pInfo);

CK_RV CK_ENTRY CK_CALLCONV C_InitToken(CK_SLOT_ID slotID, CK_CHAR_PTR pPin,
    CK_ULONG ulPinLen, CK_CHAR_PTR pLabel);

CK_RV CK_ENTRY CK_CALLCONV C_InitPIN(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin,
    CK_ULONG ulPinLen);
CK_RV CK_ENTRY CK_CALLCONV C_SetPIN(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pOldPin,
    CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen);

CK_RV CK_ENTRY CK_CALLCONV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
    CK_VOID_PTR pApplication, CK_NOTIFY Notify, 
    CK_SESSION_HANDLE_PTR phSession);
CK_RV CK_ENTRY CK_CALLCONV C_CloseSession(CK_SESSION_HANDLE hSession);
CK_RV CK_ENTRY CK_CALLCONV C_CloseAllSessions(CK_SLOT_ID slotID);
CK_RV CK_ENTRY CK_CALLCONV C_GetSessionInfo(CK_SESSION_HANDLE hSession, 
    CK_SESSION_INFO_PTR pInfo);

CK_RV CK_ENTRY CK_CALLCONV C_GetOperationState(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
CK_RV CK_ENTRY CK_CALLCONV C_SetOperationState(CK_SESSION_HANDLE hSession, 
    CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen,
    CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);

CK_RV CK_ENTRY CK_CALLCONV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
    CK_CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV CK_ENTRY CK_CALLCONV C_Logout(CK_SESSION_HANDLE hSession);

CK_RV CK_ENTRY CK_CALLCONV C_CreateObject(CK_SESSION_HANDLE hSession, 
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, 
    CK_OBJECT_HANDLE_PTR pObject);
CK_RV CK_ENTRY CK_CALLCONV C_CopyObject(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, 
    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pNewObject);
CK_RV CK_ENTRY CK_CALLCONV C_DestroyObject(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject);
CK_RV CK_ENTRY CK_CALLCONV C_GetObjectSize(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);

CK_RV CK_ENTRY CK_CALLCONV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, 
    CK_ULONG ulCount);
CK_RV CK_ENTRY CK_CALLCONV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, 
    CK_ULONG ulCount);

CK_RV CK_ENTRY CK_CALLCONV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV CK_ENTRY CK_CALLCONV C_FindObjects(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
    CK_ULONG_PTR pulObjectCount);
CK_RV CK_ENTRY CK_CALLCONV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);

CK_RV CK_ENTRY CK_CALLCONV C_EncryptInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV CK_ENTRY CK_CALLCONV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, 
    CK_ULONG_PTR pulEncryptedDataLen);
CK_RV CK_ENTRY CK_CALLCONV C_EncryptUpdate(CK_SESSION_HANDLE hSession, 
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen);
CK_RV CK_ENTRY CK_CALLCONV C_EncryptFinal(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncyptedPartLen);

CK_RV CK_ENTRY CK_CALLCONV C_DecryptInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV CK_ENTRY CK_CALLCONV C_Decrypt(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
    CK_ULONG_PTR pulDataLen);
CK_RV CK_ENTRY CK_CALLCONV C_DecryptUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
CK_RV CK_ENTRY CK_CALLCONV C_DecryptFinal(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);

CK_RV CK_ENTRY CK_CALLCONV C_DigestInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism);
CK_RV CK_ENTRY CK_CALLCONV C_Digest(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen);
CK_RV CK_ENTRY CK_CALLCONV C_DigestUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
CK_RV CK_ENTRY CK_CALLCONV C_DigestKey(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hKey);
CK_RV CK_ENTRY CK_CALLCONV C_DigestFinal(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);

CK_RV CK_ENTRY CK_CALLCONV C_SignInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV CK_ENTRY CK_CALLCONV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV CK_ENTRY CK_CALLCONV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
    CK_ULONG ulPartLen);
CK_RV CK_ENTRY CK_CALLCONV C_SignFinal(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

CK_RV CK_ENTRY CK_CALLCONV C_SignRecoverInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV CK_ENTRY CK_CALLCONV C_SignRecover(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignature);

CK_RV CK_ENTRY CK_CALLCONV C_VerifyInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV CK_ENTRY CK_CALLCONV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
CK_RV CK_ENTRY CK_CALLCONV C_VerifyUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
CK_RV CK_ENTRY CK_CALLCONV C_VerifyFinal(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

CK_RV CK_ENTRY CK_CALLCONV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV CK_ENTRY CK_CALLCONV C_VerifyRecover(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
    CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);

CK_RV CK_ENTRY CK_CALLCONV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen);
CK_RV CK_ENTRY CK_CALLCONV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pEncryptedPart, CK_ULONG pEncryptedPartLen,
    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
CK_RV CK_ENTRY CK_CALLCONV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen);
CK_RV CK_ENTRY CK_CALLCONV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);

CK_RV CK_ENTRY CK_CALLCONV C_GenerateKey(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
CK_RV CK_ENTRY CK_CALLCONV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
    CK_ULONG ulPublicKeyAttributeCount, 
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, 
    CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey,
    CK_OBJECT_HANDLE_PTR phPrivateKey);

CK_RV CK_ENTRY CK_CALLCONV C_WrapKey(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey,
    CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, 
    CK_ULONG_PTR pulWrappedKeyLen);
CK_RV CK_ENTRY CK_CALLCONV C_UnwrapKey(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
    CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE_PTR phKey);

CK_RV CK_ENTRY CK_CALLCONV C_DeriveKey(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE_PTR phKey);

CK_RV CK_ENTRY CK_CALLCONV C_SeedRandom(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
CK_RV CK_ENTRY CK_CALLCONV C_GenerateRandom(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);

CK_RV CK_ENTRY CK_CALLCONV C_GetFunctionStatus(CK_SESSION_HANDLE hSession);
CK_RV CK_ENTRY CK_CALLCONV C_CancelFunction(CK_SESSION_HANDLE hSession);

/* from cki_ssleay.c */
CK_RV PKCS11_RSA_to_RsaPrivateKey(CK_SESSION_HANDLE hSession, RSA *rsa, 
  char *username, char *subject, int subject_len, CK_CHAR_PTR pID);
CK_RV PKCS11_RSA_to_RsaPublicKey(CK_SESSION_HANDLE hSession, RSA *rsa, 
 char *username, char *subject, int subject_len, CK_CHAR_PTR pID);
CK_RV PKCS11_X509_to_X509Certificate(CK_SESSION_HANDLE hSession, 
  X509 *x, char *username, CK_CHAR_PTR * ppID);

/* from cki_objs.c */
CK_RV CKI_SetAttrValue(CK_ATTRIBUTE_PTR pAttribute,CK_VOID_PTR pValue);
CK_RV PKCS11_SetCommonPublicKeyObjectAttrs(CK_ATTRIBUTE_PTR pAttributes, 
  int *ctr);
void CKI_Date_Init(CK_DATE *Date);
CK_RV CKI_SetAttrValue_nf(CK_ATTRIBUTE_PTR pAttribute,CK_VOID_PTR pValue);

/* from cki_err.c */
void display_attribute(CK_ATTRIBUTE_PTR attr);
void display_object(PKCS11_OBJECT *object);

#ifdef _WIN32
# include "win32post.h"
#endif

#endif
