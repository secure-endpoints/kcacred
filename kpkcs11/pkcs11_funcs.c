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
 * Copyright  ©  2000,2002
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

#include <string.h>
#include <stdlib.h>

#include "cki_types.h"
#include "pkcs11_types.h"
#include "cki_funcs.h"
#include "pkcs11_funcs.h"
#include "cki_globals.h"
#include "pkcs11_globals.h"
#include "cki_new_free.h"
#include "pkcs11_new_free.h"
#include "doauth.h"
#include <openssl/err.h>
#include "debug.h"

#ifndef _WIN32
#define MANUFID "Kerberized Certificate Factory"
#define LIBDESCR "Kerberos derived X509"

#define TLABEL "Kerberized X509"
#define TMODEL "Size XXXL"
#else
#define MANUFID  "Secure Endpoints Inc."
#define LIBDESCR "Software PKCS#11"

#define TLABEL "Windows \"MY\" Certificate Store"
#define TMODEL "Software PKCS#11"
#endif

CK_RV PKCS11_Init_Module(CK_C_INITIALIZE_ARGS_PTR pArgs, PKCS11_MODULE **ppModule) {
    CK_SLOT_ID slotID;
    CK_FLAGS slotFlags;
    PKCS11_SLOT *pSlot=NULL;
    CK_RV res;
    PKCS11_MODULE * pModule;
    CK_MECHANISM_TYPE pMechanismType[2];
	
    log_printf("entering PKCS11_Init_Module\n");

    /* Verify that the arguments are correct */
    if (!(pArgs->CreateMutex && pArgs->DestroyMutex &&
	   pArgs->LockMutex && pArgs->UnlockMutex ||
	   !pArgs->CreateMutex && !pArgs->DestroyMutex &&
	   !pArgs->LockMutex && !pArgs->UnlockMutex))
	return(CKR_ARGUMENTS_BAD);
	
    PKCS11_ModuleInitDone++;

    *ppModule=PKCS11_Module_New();
    if (*ppModule==NULL) {
	return(CKR_HOST_MEMORY);
    }
    
    pModule=*ppModule;
    res=PKCS11_Init_Info(pModule->pInfo);
    if (res!=CKR_OK) 
	return(res);

    pSlot=PKCS11_Slot_New();
    if (pSlot==NULL) {
	return(CKR_HOST_MEMORY);
    }
    slotID=1L;
    slotFlags=CKF_TOKEN_PRESENT;
    res=PKCS11_Init_Slot(pSlot,slotID,slotFlags);
    if (res!=CKR_OK) 
	return(res);
    pMechanismType[0]=CKM_RSA_PKCS;
    pMechanismType[1]=0;
    res=PKCS11_Init_Token(pSlot->pToken,
#if defined(_WIN32)
			   (unsigned char *)TLABEL,
#elif defined(USE_KRB5)
			   (unsigned char *)"KRB5",
#else	
			   (unsigned char *)"Unknown",
#endif
			   pMechanismType);	  
    if (res!=CKR_OK) 
	return(res);
    pModule->ppSlot=(PKCS11_SLOT **)malloc(sizeof(PKCS11_SLOT *)*2);
    if (pModule->ppSlot==NULL) {
	return(CKR_HOST_MEMORY);
    }
    pModule->ppSlot[0]=pSlot;
    pModule->ppSlot[1]=NULL;

    if (pArgs) {
	pModule->applArgs.CreateMutex = pArgs->CreateMutex;
	pModule->applArgs.DestroyMutex = pArgs->DestroyMutex;
	pModule->applArgs.LockMutex = pArgs->LockMutex;
	pModule->applArgs.UnlockMutex = pArgs->UnlockMutex;
	pModule->applArgs.flags = pArgs->flags;
	pModule->applArgs.pReserved = pArgs->pReserved;
    } else {
	memset(&pModule->applArgs, 0, sizeof(CK_C_INITIALIZE_ARGS));
    }
    return(CKR_OK);
}

CK_RV PKCS11_Init_Info(CK_INFO_PTR pInfo) {
    log_printf("entering PKCS11_Init_Info\n");
    pInfo->cryptokiVersion.major=2;
    pInfo->cryptokiVersion.minor=0;
    memcpy(pInfo->manufacturerID,MANUFID,strlen(MANUFID));
    pInfo->flags=0L;
    memcpy(pInfo->libraryDescription,LIBDESCR,strlen(LIBDESCR));
    pInfo->libraryVersion.major=0;
    pInfo->libraryVersion.minor=1;
    return(CKR_OK);
}

CK_RV PKCS11_Init_Function_List(CK_FUNCTION_LIST_PTR pFunctionList) {
    log_printf("entering PKCS11_Init_Function_List\n");
    pFunctionList->version.major=0;
    pFunctionList->version.minor=1;
    pFunctionList->C_Initialize=C_Initialize;
    pFunctionList->C_Finalize=C_Finalize;
    pFunctionList->C_GetInfo=C_GetInfo;
    pFunctionList->C_GetFunctionList=C_GetFunctionList;

    pFunctionList->C_GetSlotList=C_GetSlotList;
    pFunctionList->C_GetSlotInfo=C_GetSlotInfo;
    pFunctionList->C_GetTokenInfo=C_GetTokenInfo;
    pFunctionList->C_GetMechanismList=C_GetMechanismList;

    pFunctionList->C_GetMechanismInfo=C_GetMechanismInfo;
    pFunctionList->C_InitToken=C_InitToken;
    pFunctionList->C_InitPIN=C_InitPIN;
    pFunctionList->C_SetPIN=C_SetPIN;
    pFunctionList->C_OpenSession=C_OpenSession;
    pFunctionList->C_CloseSession=C_CloseSession;
    pFunctionList->C_CloseAllSessions=C_CloseAllSessions;
    pFunctionList->C_GetSessionInfo=C_GetSessionInfo;
    pFunctionList->C_GetOperationState=C_GetOperationState;
    pFunctionList->C_SetOperationState=C_SetOperationState;
    pFunctionList->C_Login=C_Login;
    pFunctionList->C_Logout=C_Logout;
    pFunctionList->C_CreateObject=C_CreateObject;
    pFunctionList->C_CopyObject=C_CopyObject;
    pFunctionList->C_DestroyObject=C_DestroyObject;
    pFunctionList->C_GetObjectSize=C_GetObjectSize;
    pFunctionList->C_GetAttributeValue=C_GetAttributeValue;
    pFunctionList->C_SetAttributeValue=C_SetAttributeValue;
    pFunctionList->C_FindObjectsInit=C_FindObjectsInit;
    pFunctionList->C_FindObjects=C_FindObjects;
    pFunctionList->C_FindObjectsFinal=C_FindObjectsFinal;
    pFunctionList->C_EncryptInit=C_EncryptInit;
    pFunctionList->C_Encrypt=C_Encrypt;
    pFunctionList->C_EncryptUpdate=C_EncryptUpdate;
    pFunctionList->C_EncryptFinal=C_EncryptFinal;
    pFunctionList->C_DecryptInit=C_DecryptInit;
    pFunctionList->C_Decrypt=C_Decrypt;
    pFunctionList->C_DecryptUpdate=C_DecryptUpdate;
    pFunctionList->C_DecryptFinal=C_DecryptFinal;
    pFunctionList->C_DigestInit=C_DigestInit;
    pFunctionList->C_Digest=C_Digest;
    pFunctionList->C_DigestUpdate=C_DigestUpdate;
    pFunctionList->C_DigestKey=C_DigestKey;
    pFunctionList->C_DigestFinal=C_DigestFinal;
    pFunctionList->C_SignInit=C_SignInit;
    pFunctionList->C_Sign=C_Sign;
    pFunctionList->C_SignUpdate=C_SignUpdate;
    pFunctionList->C_SignFinal=C_SignFinal;
    pFunctionList->C_SignRecoverInit=C_SignRecoverInit;
    pFunctionList->C_SignRecover=C_SignRecover;
    pFunctionList->C_VerifyInit=C_VerifyInit;
    pFunctionList->C_Verify=C_Verify;
    pFunctionList->C_VerifyUpdate=C_VerifyUpdate;
    pFunctionList->C_VerifyFinal=C_VerifyFinal;
    pFunctionList->C_VerifyRecoverInit=C_VerifyRecoverInit;
    pFunctionList->C_VerifyRecover=C_VerifyRecover;
    pFunctionList->C_DigestEncryptUpdate=C_DigestEncryptUpdate;
    pFunctionList->C_DecryptDigestUpdate=C_DecryptDigestUpdate;
    pFunctionList->C_SignEncryptUpdate=C_SignEncryptUpdate;
    pFunctionList->C_DecryptVerifyUpdate=C_DecryptVerifyUpdate;
    pFunctionList->C_GenerateKey=C_GenerateKey;
    pFunctionList->C_GenerateKeyPair=C_GenerateKeyPair;
    pFunctionList->C_WrapKey=C_WrapKey;
    pFunctionList->C_UnwrapKey=C_UnwrapKey;
    pFunctionList->C_DeriveKey=C_DeriveKey;
    pFunctionList->C_SeedRandom=C_SeedRandom;
    pFunctionList->C_GenerateRandom=C_GenerateRandom;
    pFunctionList->C_GetFunctionStatus=C_GetFunctionStatus;
    pFunctionList->C_CancelFunction=C_CancelFunction;
    return(CKR_OK);
}	

#define SLOTDESC TLABEL
CK_RV PKCS11_Init_Slot(PKCS11_SLOT *pSlot, CK_SLOT_ID slotID, CK_FLAGS slotFlags) {
    size_t len;	

    log_printf("entering PKCS11_Init_Slot\n");
    pSlot->slotID=slotID;
    len = strlen(SLOTDESC);
    if (len > sizeof(pSlot->pInfo->slotDescription))
	len = sizeof(pSlot->pInfo->slotDescription);
    memcpy(pSlot->pInfo->slotDescription,SLOTDESC,len);
    len = strlen(MANUFID);
    if (len > sizeof(pSlot->pInfo->manufacturerID))
	len = sizeof(pSlot->pInfo->manufacturerID);
    memcpy(pSlot->pInfo->manufacturerID,MANUFID,len);
    pSlot->pInfo->flags=slotFlags;
    pSlot->pInfo->hardwareVersion.major=0;
    pSlot->pInfo->hardwareVersion.minor=1;
    pSlot->pInfo->firmwareVersion.major=0;
    pSlot->pInfo->firmwareVersion.minor=1;
    return(CKR_OK);
}

/* this should take a string of mech types so we can do this up right. later */
CK_RV PKCS11_Init_Token(PKCS11_TOKEN *pToken, CK_CHAR_PTR serialNumber, CK_MECHANISM_TYPE_PTR pMechanismType) {
    CK_CHAR_PTR pPin;
    PKCS11_MECHANISM *pMechanism;
    CK_TOKEN_INFO_PTR pInfo;
    CK_RV res;
    int i;
	
    log_printf("entering PKCS11_Init_Token\n");
    if (pToken->pInfo==NULL) {
	log_printf("in PKCS11_Init_Token, pToken->pInfo is NULL\n");
	return(CKR_FUNCTION_FAILED);
    }
    pInfo=pToken->pInfo;
	
    memcpy(pInfo->label,TLABEL,strlen(TLABEL));
    memcpy(pInfo->manufacturerID,MANUFID,strlen(MANUFID));
    memcpy(pInfo->model,TMODEL,strlen(TMODEL));
    memcpy(pInfo->serialNumber,serialNumber,strlen((const char *)serialNumber));
    pInfo->flags=CKF_WRITE_PROTECTED|CKF_USER_PIN_INITIALIZED|CKF_EXCLUSIVE_EXISTS; 
    pInfo->ulMaxSessionCount=1L;
    pInfo->ulSessionCount=0L;
    pInfo->ulMaxRwSessionCount=0L;
    pInfo->ulRwSessionCount=0L;
    pInfo->ulMaxPinLen=64L;
    pInfo->ulMinPinLen=1L;
    pInfo->ulTotalPublicMemory=131072L;
    pInfo->ulFreePublicMemory=131072L;
    pInfo->ulTotalPrivateMemory=131072L;
    pInfo->ulFreePrivateMemory=131072L;
    pInfo->hardwareVersion.major=0;
    pInfo->hardwareVersion.minor=1;
    pInfo->firmwareVersion.major=0;
    pInfo->firmwareVersion.minor=1;

    /* mechanism */
    for (i=0; pMechanismType[i]; i++) {
	pMechanism=PKCS11_Mechanism_New();
	if (pMechanism==NULL) {
	    return(CKR_HOST_MEMORY);
	}
	res=PKCS11_Init_Mechanism(pMechanism,pMechanismType[0]);
	if (res!=CKR_OK) return(res);

	pToken->ppMechanism=(PKCS11_MECHANISM **)malloc(sizeof(PKCS11_MECHANISM *)*2);
	if (pToken->ppMechanism==NULL){
	    return(CKR_HOST_MEMORY);
	}	
	pToken->ppMechanism[i]=pMechanism;
    }
    pToken->ppMechanism[i]=NULL;
	
    /* PIN */
    pPin=(CK_CHAR_PTR)malloc(sizeof(CK_CHAR)*(pInfo->ulMaxPinLen));
    if (pPin==NULL) {
	return(CKR_HOST_MEMORY);
    }
    memset(pPin,' ',pInfo->ulMaxPinLen);
    memcpy(pPin,"abcdefg",strlen("abcdefg")); /* bogus, will be fixed later */
    pToken->pPin=pPin;
    pToken->ulPinLen=(CK_ULONG)strlen("abcdefg");
    return(CKR_OK);
}

CK_RV PKCS11_Init_Mechanism(PKCS11_MECHANISM *pMechanism,CK_MECHANISM_TYPE mechanismType) {
    log_printf("entering PKCS11_Init_Mechanism\n");
    switch (mechanismType) {
    case CKM_RSA_PKCS:
	pMechanism->pMechanism->mechanism=mechanismType;
	pMechanism->pMechanism->pParameter=NULL;
	pMechanism->pMechanism->ulParameterLen=0L;
	pMechanism->pInfo->ulMinKeySize=512L;
	pMechanism->pInfo->ulMaxKeySize=4096L;
	pMechanism->pInfo->flags=CKF_SIGN;
	break;
    default:
	return(CKR_FUNCTION_FAILED);
    }
    return(CKR_OK);
}

CK_RV PKCS11_Init_Session( CK_SESSION_HANDLE ulSessionHandle,
			   CK_SLOT_ID slotID,
			   PKCS11_TOKEN_PTR pToken,
			   CK_STATE state,
			   CK_FLAGS flags,
			   CK_VOID_PTR pApplication,
			   CK_NOTIFY NotifyFunc,
			   PKCS11_SESSION *pSession
			   )
{
    log_printf("PKCS11_Init_Session: entered\n");
    if (pSession==NULL)
	return(CKR_FUNCTION_FAILED);

    pSession->ulSessionHandle=ulSessionHandle;	
    pSession->pInfo->slotID=slotID;
    pSession->pToken = pToken;
    pSession->pInfo->flags=flags; /* is this value sane? */

    /* set the state... */
    if (state==CKS_RO_PUBLIC_SESSION)
	pSession->pInfo->state=CKS_RO_USER_FUNCTIONS; 
    else 
	pSession->pInfo->state=CKS_RW_USER_FUNCTIONS; 

    pSession->pApplication = pApplication;
    pSession->NotifyFunc = NotifyFunc;

    log_printf("PKCS11_Init_Session: returning with successful login\n");
    return(CKR_OK);
}

CK_RV PKCS11_Init2_Session( PKCS11_SESSION *pSession )
{
    int res = CKR_OK;
    struct a_t **attrl = NULL;
    struct a_t **tattrl = NULL;
    char *user = NULL;
    char *cert_der = NULL;
    char *key_der = NULL;
    char *cert_enc = NULL;
    char *key_enc = NULL;
#if 0
    int cert_len;
    int key_len;
    int subject_len;
#endif
    RSA *rsa = NULL;
    X509 *x = NULL;
    char *subject_der = NULL;
    X509_NAME *subject = NULL;
    char *ptr = NULL;
    CK_CHAR_PTR pID = NULL;
    int i;
	
    log_printf("PKCS11_Init2_Session: entered\n");
    if (pSession==NULL) {
	res = CKR_FUNCTION_FAILED;
	goto error;
    }

    b64_init();
    ERR_load_crypto_strings();
       
#if 0
    /* Replaced by LoadTokensObjects() in C_FindObjectsInit() */
    res=doauth(&attrl,&tattrl);
    if (res)
    {
	log_printf("PKCS11_Init2_Session: doauth failed.  no certificate store?\n");
	/* jaltman - this error is wrong.  The fact that there are no objects stored
	 * in the token doesn't mean the token is not present.  Instead we should 
	 * mark the object list as empty and return success.
	 */
	res = CKR_OK;
	goto error;
    }

    /* create cert and key objects... */
    user=getelt(tattrl,"user");
    if (!user) {
	res = CKR_FUNCTION_FAILED;
	goto error;
    }
    cert_enc=getelt(attrl,"cert");
    if (!cert_enc) {
	res = CKR_FUNCTION_FAILED;
	goto error;
    }
    cert_der=(char *) malloc(strlen(cert_enc)*2);
    if (!cert_der) {
	res = CKR_HOST_MEMORY;
	goto error;
    }
    log_printf("PKCS11_Init2_Session: cert '%s'\n",cert_enc);
    cert_len=b64_decode(cert_enc,strlen(cert_enc),cert_der);

    log_printf("PKCS11_Init2_Session: cert_len %d\n",cert_len);
    key_enc=getelt(attrl,"key");
    if (!key_enc) {
	res = CKR_FUNCTION_FAILED;
	goto error;
    }
    key_der=(char *) malloc(strlen(key_enc)*2);
    if (!key_der) {
	res = CKR_HOST_MEMORY;
	goto error;
    }
    key_len=b64_decode(key_enc,strlen(key_enc),key_der);
    log_printf("PKCS11_Init2_Session: key_len %d\n",key_len);

    ptr=cert_der;
    x=NULL;
    d2i_X509(&x,(unsigned char **)&ptr, cert_len);
    if (x==NULL)
    {
	log_printf("PKCS11_Init2_Session: Login here with null x\n");
	res = CKR_FUNCTION_FAILED;
	goto error;
    }
   
    res = PKCS11_X509_to_X509Certificate(pSession->ulSessionHandle,x,user,&pID);
    if (res) {
	log_printf("PKCS11_X509_to_X509Certificate: Failed with 0x%0x\n", res);
	res = CKR_FUNCTION_FAILED;
	goto error;
    }
    subject=X509_get_subject_name(x);
    subject_len=i2d_X509_NAME(subject,NULL);
    subject_der=(char *)malloc(subject_len);
    if (!subject_der) {
	res = CKR_HOST_MEMORY;
	goto error;
    }
    ptr=subject_der;
    i2d_X509_NAME(subject,(unsigned char **)&ptr);

    ptr=key_der;
    d2i_RSAPrivateKey(&rsa,(unsigned char **)&ptr,key_len);   
    res=PKCS11_RSA_to_RsaPrivateKey(pSession->ulSessionHandle,rsa,user,subject_der,subject_len,pID);
    res=PKCS11_RSA_to_RsaPublicKey(pSession->ulSessionHandle,rsa,user,subject_der,subject_len,pID);
#endif

  error:
    if (attrl) {
	for (i=0;attrl[i];i++) {
	    if (attrl[i])
		free(attrl[i]);
	}
	free(attrl);
    }
    if (tattrl) {
	for (i=0;tattrl[i];i++) {
	    if (tattrl[i])
		free(tattrl[i]);
	}
	free(tattrl);
    }
    if (cert_der)
	free(cert_der);
    if (key_der)
	free(key_der);
    if (cert_enc)
	free(cert_enc);
    if (key_enc)
	free(key_enc);
    if (subject_der)
	free(subject_der);
    if (rsa)
	RSA_free(rsa);
    if (pID)
	free(pID);

    if (res == CKR_OK)
	log_printf("PKCS11_Init2_Session: returning with successful login\n");

    return(res);
}	

void PKCS11_CheckTokenPresent(PKCS11_SLOT *pSlot) {
    int validity;
    CK_MECHANISM_TYPE pMechanismType[2];
	
    log_printf("entering PKCS11_CheckTokenPresent\n");

    validity=checkTokenValidity();
	
    log_printf("PKCS11_CheckTokenPresent found %d\n", validity);
    if (validity == 0) {
	/* No cert doesn't mean the token is invalid. */
	;
    } else if (validity<0) {
	if (pSlot->pToken) {
	    /* The token list changed. */
	    log_printf("PKCS11_CheckTokenPresent: token list has changed\n");
	    /* This used to close the session.  What it should do
	     * is obtain the new token list.
	     */
	} else {
	    /* Build a new token description */
	    pSlot->pToken=PKCS11_Token_New();
	    pMechanismType[0]=CKM_RSA_PKCS;
	    pMechanismType[1]=0;
	    PKCS11_Init_Token(pSlot->pToken,
#if defined(_WIN32)
			       (unsigned char *)TLABEL,
#elif defined(USE_KRB5)
			       (unsigned char *)"KRB5",
#else
			       (unsigned char *)"Unknown",
#endif
			       pMechanismType);
	}
    }
}
		
PKCS11_SESSION *PKCS11_FindSession(CK_SESSION_HANDLE hSession) {
    unsigned int i, j;
	
    for (i=0; PKCS11_ModulePtr->ppSlot[i]; i++) {
	if (PKCS11_ModulePtr->ppSlot[i]->pToken &&
	     PKCS11_ModulePtr->ppSlot[i]->pToken->ppSession) {
	    for (j=0; PKCS11_ModulePtr->ppSlot[i]->pToken->ppSession[j]; j++) {
		if (PKCS11_ModulePtr->ppSlot[i]->pToken->ppSession[j]->ulSessionHandle == hSession) {
		    return (PKCS11_ModulePtr->ppSlot[i]->pToken->ppSession[j]);
		}
	    }
	}
    }

    log_printf("Session handle %d is invalid\n", hSession);

    return(NULL);
}
	
PKCS11_SLOT *PKCS11_FindSlot(CK_SLOT_ID slotID) {
    unsigned int i = 0;
	
    log_printf("entering PKCS11_FindSlot\n");

    for (i=0; PKCS11_ModulePtr->ppSlot[i]; i++) {
	if (slotID == PKCS11_ModulePtr->ppSlot[i]->slotID) {
#if 0
	    PKCS11_CheckTokenPresent(PKCS11_ModulePtr->ppSlot[i]);
#endif
	    return PKCS11_ModulePtr->ppSlot[i];
	}
    }
	
    log_printf("Slot id %d is invalid\n", slotID);
    return(NULL);
}
