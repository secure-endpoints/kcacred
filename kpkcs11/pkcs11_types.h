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

#ifndef _PKCS11_TYPES_H_
#define _PKCS11_TYPES_H_

#ifdef _WIN32
#include "win32pre.h"
#endif

#include "cki_types.h"
#include <openssl/evp.h>

typedef struct PKCS11_FUNCTION_INFO {
  CK_MECHANISM_PTR pMechanism;
  CK_OBJECT_HANDLE hKey;
  EVP_CIPHER_CTX * pEvpCipherCtx;
  EVP_MD_CTX * pEvpMdCtx;
} PKCS11_FUNCTION_INFO;

typedef struct PKCS11_FINDOBJECTS_INFO {
  CK_ATTRIBUTE_PTR pTemplate;
  CK_ULONG ulAttrCount;
  CK_LONG TokenObjectsIndex;
  CK_BBOOL isactive;
} PKCS11_FINDOBJECTS_INFO;

typedef struct PKCS11_SIGN_INFO {
  CK_MECHANISM_PTR pMechanism;
  CK_OBJECT_HANDLE hKey; /* points to the key to use. */
  CK_BYTE_PTR pSignature; /* keep partial sig here */
  CK_BBOOL isactive;
  CK_ULONG_PTR pulSignatureLen; /* keep length of partial sig here */
} PKCS11_SIGN_INFO;

typedef struct PKCS11_FUNCTIONS {
  PKCS11_FINDOBJECTS_INFO * pFindObjects;
  PKCS11_FUNCTION_INFO * pEncrypt;
  PKCS11_FUNCTION_INFO * pDecrypt;
  PKCS11_FUNCTION_INFO * pDigest;
  PKCS11_SIGN_INFO * pSign;
  PKCS11_FUNCTION_INFO * pSignRecover;
  PKCS11_FUNCTION_INFO * pVerify;
  PKCS11_FUNCTION_INFO * pVerifyRecover;
} PKCS11_FUNCTIONS;

typedef struct PKCS11_OBJECT {
  CK_OBJECT_HANDLE ulObjectHandle;
  CK_OBJECT_CLASS ulObjectClass;
  CK_SESSION_HANDLE ulSessionHandle;
  CK_ATTRIBUTE_PTR pAttribute;
} PKCS11_OBJECT;

/* The relationship between tokens and sessions
 * is one token to many sessions. 
 */
typedef struct PKCS11_TOKEN * PKCS11_TOKEN_PTR;
typedef struct PKCS11_SESSION {
  CK_SESSION_HANDLE ulSessionHandle;
  CK_SESSION_INFO_PTR pInfo;
  PKCS11_TOKEN_PTR pToken; 
  PKCS11_FUNCTIONS *pCryptoFunctions;
  CK_VOID_PTR pApplication;
  CK_NOTIFY   NotifyFunc;
} PKCS11_SESSION;

typedef struct PKCS11_MECHANISM {
  CK_MECHANISM_INFO_PTR pInfo;
  CK_MECHANISM_PTR pMechanism;
} PKCS11_MECHANISM;

typedef struct PKCS11_TOKEN {
  CK_TOKEN_INFO_PTR pInfo;
  PKCS11_MECHANISM ** ppMechanism;
  CK_CHAR_PTR pPin;
  CK_ULONG ulPinLen;
  PKCS11_SESSION ** ppSession;
  PKCS11_OBJECT ** ppTokenObject;
} PKCS11_TOKEN;

typedef struct PKCS11_SLOT {
  CK_SLOT_ID slotID;
  CK_SLOT_INFO_PTR pInfo;
  PKCS11_TOKEN * pToken;
} PKCS11_SLOT;

typedef struct PKCS11_MODULE {
    CK_INFO_PTR pInfo;
    PKCS11_SLOT ** ppSlot;
    CK_C_INITIALIZE_ARGS applArgs;
} PKCS11_MODULE;

#ifdef _WIN32
#include "win32post.h"
#endif

#endif
