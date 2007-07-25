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

/* was stubs for functions we don't support; now is becoming a library */
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#endif

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include "cki_types.h"
#include "pkcs11_types.h"
#include "cki_globals.h"
#include "pkcs11_globals.h"
#include "pkcs11_funcs.h"
#include "cki_new_free.h"
#include "pkcs11_new_free.h"
#include "cki_dup.h"
#include "doauth.h"
#include "debug.h"

/*
 * We have a couple of work-arounds to work
 * with Globus 1.1.1. (02/18/2000)
 */
#define GLOBUS_111

/*
 * PKCS11_ModulePtr->			// Global PKCS11_MODULE ptr
 *	ppSlot[0]->				    // only Slot's PKCS11_SLOT ptr
 *		pToken->			    // only Token's PKCS11_TOKEN ptr
 *			ppSession[]->		// Session's PKCS11_SESSION ptr
 *				pInfo->		    // Session's CK_SESSION_INFO_PTR
 *					slotId
 *					state
 *					flags
 *                      pTokenObject[]-> // Token's PKCS11_OBJECT ptr
 */

void hexdump(void *pin, char *label, int len)
{
    BYTE *p = (BYTE *)pin;
    int	i;
    
    log_printf("%s (%0d bytes):", label, len<<2);
    for (i=0; i<len*BN_BYTES; i++)
    {
	if ((i & 0x7) == 0)
	    log_printf("\n    ");
	log_printf("0x%02X, ", p[i]);
    }
    log_printf("\n\n");
}


#ifdef DEBUG
void dump_key(RSA *rsa)
{
    log_printf("Dumping private key values:\n");
    hexdump((char *)rsa->n->d,	  "pk->modulus",	  rsa->n->top);
    hexdump((char *)rsa->p->d,	  "pk->prime1",		  rsa->p->top);
    hexdump((char *)rsa->q->d,	  "pk->prime2",		  rsa->q->top);
    hexdump((char *)rsa->dmp1->d, "pk->exponent1",	  rsa->dmp1->top);
    hexdump((char *)rsa->dmq1->d, "pk->exponent2",	  rsa->dmq1->top);
    hexdump((char *)rsa->iqmp->d, "pk->coefficient",	  rsa->iqmp->top);
    hexdump((char *)rsa->d->d,	  "pk->privateExponent",  rsa->d->top);
}
#endif

static CK_VOID_PTR C_Mutex = NULL_PTR;

static CK_RV C_CreateMutex(void)
{
    CK_C_INITIALIZE_ARGS_PTR pArgs = &PKCS11_ModulePtr->applArgs;

    if (!(pArgs->flags & CKF_OS_LOCKING_OK) && pArgs->CreateMutex == NULL)
	return CKR_OK;		/* no threading in use */

    if (pArgs->CreateMutex)
	return pArgs->CreateMutex(&C_Mutex);

    C_Mutex = CreateMutex(NULL, FALSE, NULL);
    return CKR_OK;
}

static CK_RV C_DestroyMutex(void)
{
    CK_C_INITIALIZE_ARGS_PTR pArgs = &PKCS11_ModulePtr->applArgs;

    if (C_Mutex == NULL_PTR)
		return CKR_OK;

    if (pArgs->DestroyMutex) {
	CK_RV res = pArgs->DestroyMutex(C_Mutex);
	C_Mutex = NULL_PTR;
	return res;
    }

    CloseHandle(C_Mutex);
    C_Mutex = NULL_PTR;
    return CKR_OK;
}

static CK_RV C_LockMutex(void)
{
    CK_C_INITIALIZE_ARGS_PTR pArgs = &PKCS11_ModulePtr->applArgs;

    if (C_Mutex == NULL_PTR)
	return CKR_OK;

    if (pArgs->LockMutex)
	return pArgs->LockMutex(C_Mutex);
	
    WaitForSingleObject(C_Mutex, INFINITE);
	
	return CKR_OK;
}

static CK_RV C_UnlockMutex(void)
{
    CK_C_INITIALIZE_ARGS_PTR pArgs = &PKCS11_ModulePtr->applArgs;

    if (C_Mutex == NULL_PTR)
	return CKR_OK;
	
    if (pArgs->UnlockMutex)
	return pArgs->UnlockMutex(C_Mutex);
	
    ReleaseMutex(C_Mutex);

	return CKR_OK;
}

CK_RV CK_ENTRY C_Initialize(CK_VOID_PTR pReserved) {
    CK_C_INITIALIZE_ARGS_PTR pInitializeArgs = (CK_C_INITIALIZE_ARGS_PTR)pReserved;
    CK_RV res;

    log_printf("entering C_Initialize\n");

    if (PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_ALREADY_INITIALIZED);
    
    res = PKCS11_Init_Module(pInitializeArgs, &PKCS11_ModulePtr);
    if (res == CKR_OK)
	C_CreateMutex();
    return(res);
}

CK_RV CK_ENTRY C_Finalize(CK_VOID_PTR pReserved) {
    log_printf("entering C_Finalize\n");
    
    if (pReserved != NULL)
	return(CKR_ARGUMENTS_BAD);

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    C_DestroyMutex();

    PKCS11_ModuleInitDone = 0;
    PKCS11_Module_Free(PKCS11_ModulePtr);
    PKCS11_ModulePtr = NULL;
    
    return(CKR_OK);
}

CK_RV CK_ENTRY C_GetInfo(CK_INFO_PTR pInfo) {
    int res;
    log_printf("entering C_GetInfo\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    C_LockMutex();

    res = CKI_Info_Dup(pInfo,PKCS11_ModulePtr->pInfo);
    
    C_UnlockMutex();
    return(res);
}

/* C_GetFunctionList can be called before C_Initialize.  Therefore,
 * this function is not protected by the global mutex nor does it
 * check the initialization state.
 */
CK_RV CK_ENTRY C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    int res = CKR_OK;

    log_printf("entering C_GetFunctionList\n");

    if (PKCS11_FunctionListPtr == NULL) {
	PKCS11_FunctionListPtr = CKI_FunctionList_New();
	if (PKCS11_FunctionListPtr == NULL) {
	    return(CKR_HOST_MEMORY);
	}
	res = PKCS11_Init_Function_List(PKCS11_FunctionListPtr);
    }
    if (res == CKR_OK)
	*ppFunctionList = PKCS11_FunctionListPtr;
    
    return(res);
}

CK_RV CK_ENTRY C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
			     CK_ULONG_PTR pulCount) {
    unsigned int i,j;

    log_printf("entering C_GetSlotList\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);

    C_LockMutex();

    i = 0; j = 0;

    /* This gives total number of occupied slots in i,
       and total number of slots with valid tokens in j
    */

    while(PKCS11_ModulePtr->ppSlot[i]) {
#if 0
	PKCS11_CheckTokenPresent(PKCS11_ModulePtr->ppSlot[i]);
#endif
	if (PKCS11_ModulePtr->ppSlot[i]->pToken)
	    j++;
	i++;
    }

    if (tokenPresent) {
	while (PKCS11_ModulePtr->ppSlot[i++]);
	i=j;
    }

    if (pSlotList == NULL) {
	log_printf("C_GetSlotList: returning number of slots as %d\n",i);
	*pulCount = i;
	C_UnlockMutex();
	return(CKR_OK);
    }

    if (i>*pulCount) {
	*pulCount = i;
	C_UnlockMutex();
	return(CKR_BUFFER_TOO_SMALL);
    }

    i = 0; j = 0;
    while (PKCS11_ModulePtr->ppSlot[i]) {
	if (!tokenPresent || PKCS11_ModulePtr->ppSlot[i]->pToken) {
	    pSlotList[j] = PKCS11_ModulePtr->ppSlot[i]->slotID;
	    j++;
	}
	i++;
    }
    *pulCount = j;
    C_UnlockMutex();
    return(CKR_OK);
}	

CK_RV CK_ENTRY C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    int res;
    PKCS11_SLOT *pSlot;
	
    log_printf("entering C_GetSlotInfo\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    C_LockMutex();

    if ((pSlot=PKCS11_FindSlot(slotID))==NULL) {
	C_UnlockMutex();
	return(CKR_SLOT_ID_INVALID);
    }

    res = CKI_SlotInfo_Dup(pInfo,pSlot->pInfo);
    if (res != CKR_OK) {
	C_UnlockMutex();
	return(res);
    }

    if (pInfo->flags&CKF_REMOVABLE_DEVICE) {
	if (pSlot->pToken) {
	    pInfo->flags=pInfo->flags|CKF_TOKEN_PRESENT;
	} else {
	    pInfo->flags=pInfo->flags&~CKF_TOKEN_PRESENT;
	}
    } else {
	log_printf("Urk - not a removable device");
	pInfo->flags=pInfo->flags|CKF_TOKEN_PRESENT;
    }
    C_UnlockMutex();
    return(CKR_OK);
}

CK_RV CK_ENTRY C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    int res;
    PKCS11_SLOT *pSlot;
	
    log_printf("C_GetTokenInfo: entered\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    C_LockMutex();
    if ((pSlot=PKCS11_FindSlot(slotID))==NULL) {
	C_UnlockMutex();
	return(CKR_SLOT_ID_INVALID);
    }

    if (!pSlot->pToken) {
	C_UnlockMutex();
	return(CKR_TOKEN_NOT_PRESENT);
    }
    res = CKI_TokenInfo_Dup(pInfo,pSlot->pToken->pInfo);
    if (res != CKR_OK) {
	log_printf("C_GetTokenInfo: problems with TokenInfo_Dup\n");
	C_UnlockMutex();
	return(res);
    }

    C_UnlockMutex();
    return(CKR_OK);
}	

CK_RV CK_ENTRY C_GetMechanismList(CK_SLOT_ID slotID, 
				  CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
    int j;
    PKCS11_SLOT *pSlot;
	
    log_printf("C_GetMechanismList: entered\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);

    C_LockMutex();

    if ((pSlot=PKCS11_FindSlot(slotID))==NULL) {
	C_UnlockMutex();
	return(CKR_SLOT_ID_INVALID);
    }

    if (pSlot->pToken == NULL) {
	C_UnlockMutex();
	return(CKR_TOKEN_NOT_PRESENT);
    }

    j = 0;
    while (pSlot->pToken->ppMechanism[j++]) ;
    if (pMechanismList  == NULL) {
	*pulCount = (unsigned long)j;
	C_UnlockMutex();
	return(CKR_OK);
    }
    if (j>(int)*pulCount) {
	*pulCount = j;
	C_UnlockMutex();
	return(CKR_BUFFER_TOO_SMALL);
    }
    j = 0;
    while (pSlot->pToken->ppMechanism[j]) {
	pMechanismList[j] = pSlot->pToken->ppMechanism[j]->pMechanism->mechanism;
	j++;
    }
    *pulCount = j;
    C_UnlockMutex();
    return(CKR_OK);
}	

CK_RV CK_ENTRY C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
				  CK_MECHANISM_INFO_PTR pInfo) {
    log_printf("entering C_GetMechanismInfo\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_InitToken(CK_SLOT_ID slotID, CK_CHAR_PTR pPin,
			   CK_ULONG ulPinLen, CK_CHAR_PTR pLabel) {
    log_printf("entering C_InitToken\n");
    
    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_InitPIN(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin,
			 CK_ULONG ulPinLen) {
    log_printf("entering C_InitPIN\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_SetPIN(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pOldPin,
			CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen) {
    log_printf("entering C_SetPIN\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
			     CK_VOID_PTR pApplication, CK_NOTIFY Notify, 
			     CK_SESSION_HANDLE_PTR phSession) {
    PKCS11_SESSION *pSession, **ppSession;
    int res;
    CK_STATE state;
    PKCS11_SLOT *pSlot;
    static CK_SESSION_HANDLE nextSessionHandle = 1;
    CK_SESSION_HANDLE sessionHandle;
    int sessionCount;
	
    log_printf("C_OpenSession: entered\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);

    C_LockMutex();

#ifndef GLOBUS_111
    if (flags & CKF_RW_SESSION) {
	C_UnlockMutex();
	return(CKR_SESSION_READ_ONLY);
    }
#endif
    if (! flags&CKF_SERIAL_SESSION) {
	C_UnlockMutex();
	return(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
    }
    state = (flags&CKF_EXCLUSIVE_SESSION) ? CKS_RO_USER_FUNCTIONS : CKS_RO_PUBLIC_SESSION;

    if ((pSlot=PKCS11_FindSlot(slotID))==NULL) {
	C_UnlockMutex();
	return (CKR_SLOT_ID_INVALID);
    }

    if (pSlot->pToken == NULL) {
	C_UnlockMutex();
	return (CKR_TOKEN_NOT_PRESENT);
    }

    pSession = PKCS11_Session_New();
    if (pSession == NULL) {
	C_UnlockMutex();
	return(CKR_HOST_MEMORY);
    }

    /* Session 0 is reserved for token objects allocated 
     * outside of any specific session.  
     */
    if (nextSessionHandle == 0)
	nextSessionHandle = 1L;

    sessionHandle = nextSessionHandle++;
    res = PKCS11_Init_Session(sessionHandle,slotID,pSlot->pToken,state,flags,pApplication,Notify,pSession);
    if (res != CKR_OK) {
	PKCS11_Session_Free(pSession);
	C_UnlockMutex();
	return(res);
    }

    if (pSlot->pToken->ppSession == NULL) {
	sessionCount = 0;
	ppSession = (PKCS11_SESSION **)malloc(sizeof(PKCS11_SESSION *)*2);
	if (ppSession == NULL) {
	    PKCS11_Session_Free(pSession);
	    C_UnlockMutex();
	    return(CKR_HOST_MEMORY);
	}
	memset(ppSession, 0, sizeof(PKCS11_SESSION *)*2);
    } else {
	ppSession = pSlot->pToken->ppSession;
	for (sessionCount = 0; ppSession[sessionCount] ; sessionCount++ )
	    ;

	ppSession = (PKCS11_SESSION **)realloc(ppSession, sizeof(PKCS11_SESSION *)*(sessionCount+2));
	if (ppSession == NULL) {
	    PKCS11_Session_Free(pSession);
	    C_UnlockMutex();
	    return(CKR_HOST_MEMORY);
	}
    }
    pSlot->pToken->ppSession = ppSession;
    pSlot->pToken->ppSession[sessionCount] = pSession;
    pSlot->pToken->ppSession[sessionCount+1] = NULL_PTR;

    res = PKCS11_Init2_Session(pSession);
    if (res != CKR_OK) {
	C_CloseSession(sessionHandle);
	C_UnlockMutex();
	return(res);
    }

    log_printf("C_OpenSession: pSlot->pToken->ppSession[%d]->ulSessionHandle is 0x%08x\n",
		sessionCount, pSlot->pToken->ppSession[sessionCount]->ulSessionHandle);

    *phSession = sessionHandle;
    C_UnlockMutex();
    return(CKR_OK);
}

CK_RV CK_ENTRY C_CloseSession(CK_SESSION_HANDLE hSession) {
    PKCS11_SESSION **ppSession;
    int i, j;
    int bFound = FALSE;
	
	log_printf("entering C_CloseSession: session %d\n", hSession);

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);

    C_LockMutex();

    /* we should find the PKCS11_SESSION object in the ppSession
     * list and remove it.
     */
	
    for (i = 0; PKCS11_ModulePtr->ppSlot[i]; i++) {
	if (PKCS11_ModulePtr->ppSlot[i]->pToken &&
	    PKCS11_ModulePtr->ppSlot[i]->pToken->ppSession) {
	    ppSession = PKCS11_ModulePtr->ppSlot[i]->pToken->ppSession;

	    for (j = 0; ppSession[j]; j++) {
		if (ppSession[j]->ulSessionHandle == hSession) {
		    PKCS11_Session_Free(ppSession[j]);
		    ppSession[j] = NULL_PTR;
		    bFound = TRUE;
		    break;
		}
	    }

	    /* if found we must consolidate the session list. */
	    if (bFound) {
		for ( ; ppSession[j+1]; j++) {
		    ppSession[j] = ppSession[j+1];
		    ppSession[j+1] = NULL_PTR;
		}
		break;
	    }
	}
    }
    
    C_UnlockMutex();
    return(bFound ? CKR_OK : CKR_SESSION_HANDLE_INVALID);
}

CK_RV CK_ENTRY C_CloseAllSessions(CK_SLOT_ID slotID) {
    PKCS11_SLOT *pSlot;
    PKCS11_SESSION **ppSession;
    int i;
	
    log_printf("entering C_CloseAllSessions\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);

    C_LockMutex();

    if ((pSlot=PKCS11_FindSlot(slotID))==NULL) {
	C_UnlockMutex();
	return(CKR_SLOT_ID_INVALID);
    }
		
    if (pSlot->pToken == NULL) {
	C_UnlockMutex();
	return(CKR_TOKEN_NOT_PRESENT);
    }

    if (pSlot->pToken && pSlot->pToken->ppSession) {
	ppSession = pSlot->pToken->ppSession;

	/* Session 0 is a special session.  Do not free it. */
	for (i = 1; ppSession[i]; i++) {
	    PKCS11_Session_Free(ppSession[i]);
	    pSlot->pToken->ppSession[i] = NULL_PTR;
	}
	free(ppSession);
	pSlot->pToken->ppSession = NULL_PTR;
    }
    
    C_UnlockMutex();
    return(CKR_OK);
}

CK_RV CK_ENTRY C_GetSessionInfo(CK_SESSION_HANDLE hSession, 
				CK_SESSION_INFO_PTR pInfo) {
    int res;
    PKCS11_SESSION *pSession;
	
    log_printf("entering C_GetSessionInfo\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);

    C_LockMutex();

    /* find right session */
    if ((pSession=PKCS11_FindSession(hSession))==NULL) {
	C_UnlockMutex();
	return(CKR_SESSION_HANDLE_INVALID);
    }
		
    /* give them this info */
    res = CKI_SessionInfo_Dup(pInfo,pSession->pInfo);
    C_UnlockMutex();
    return(res);
}

CK_RV CK_ENTRY C_GetOperationState(CK_SESSION_HANDLE hSession,
				   CK_BYTE_PTR pOperationState, 
				   CK_ULONG_PTR pulOperationStateLen) {
    log_printf("entering C_GetOperationState\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_SetOperationState(CK_SESSION_HANDLE hSession, 
				   CK_BYTE_PTR pOperationState, 
				   CK_ULONG ulOperationStateLen,
				   CK_OBJECT_HANDLE hEncryptionKey, 
				   CK_OBJECT_HANDLE hAuthenticationKey) {
    log_printf("entering C_SetOperationState\n");
    
    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
		       CK_CHAR_PTR pPin, CK_ULONG ulPinLen) {
    PKCS11_SESSION *pSession;
	
    log_printf("entering C_Login\n");
	
    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);

    C_LockMutex();

    /* we mark the state of the session. I wonder if we need to specify
     * anything else here?  we need to keep user authentication info
     * because eventually this could be one of a huge crowd of users. */
	
    if (userType == CK_SO) {
	log_printf("C_Login: login attempted for invalid user type\n");
	C_UnlockMutex();
	return(CKR_USER_TYPE_INVALID);
    }
	
    /* first find the right session... */
    if ((pSession=PKCS11_FindSession(hSession))==NULL) {
	C_UnlockMutex();
	return(CKR_SESSION_HANDLE_INVALID);
    }

    /* log them into this one; anyone already logged in? */
    if ((pSession->pInfo->state == CKS_RO_USER_FUNCTIONS) ||
	 (pSession->pInfo->state == CKS_RW_USER_FUNCTIONS)) {
	log_printf("C_Login: login attempted when user already logged in\n");
#ifndef GLOBUS_111
	C_UnlockMutex();
	return(CKR_USER_ALREADY_LOGGED_IN);
#endif
    }
		
    /* set the state... */
    if (pSession->pInfo->state == CKS_RO_PUBLIC_SESSION) {
	pSession->pInfo->state = CKS_RO_USER_FUNCTIONS; 
    }
    else 
	pSession->pInfo->state = CKS_RW_USER_FUNCTIONS; 

    log_printf("C_Login: returning with successful login\n");
    C_UnlockMutex();
    return(CKR_OK);
}	

CK_RV CK_ENTRY C_Logout(CK_SESSION_HANDLE hSession) {
    PKCS11_SESSION *pSession;
	
    log_printf("entering C_Logout\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);

    C_LockMutex();

    /* first find the right session... */
    if ((pSession=PKCS11_FindSession(hSession))==NULL) {
	C_UnlockMutex();
	return(CKR_SESSION_HANDLE_INVALID);
    }
                    
    if (pSession->pInfo->state == CKS_RO_USER_FUNCTIONS) {
	pSession->pInfo->state = CKS_RO_PUBLIC_SESSION; 
    }
    else 
	pSession->pInfo->state = CKS_RW_PUBLIC_SESSION; 

    /* now we may have some objects around we want to get rid of... */
    C_UnlockMutex();
    return (CKR_OK);	/* Return now, don't throw away our stuff! KWC -- 20000218 */
}

CK_RV CK_ENTRY C_CopyObject(CK_SESSION_HANDLE hSession,
			    CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, 
			    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pNewObject) {
    log_printf("entering C_CopyObject\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_GetObjectSize(CK_SESSION_HANDLE hSession,
			       CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
    log_printf("entering C_GetObjectSize\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_GetAttributeValue(CK_SESSION_HANDLE hSession,
				   CK_OBJECT_HANDLE hObject, 
				   CK_ATTRIBUTE_PTR pTemplate,
				   CK_ULONG ulCount) {
    int i,j, ctr;
    CK_RV res;
    PKCS11_SESSION *pSession;
    CK_ATTRIBUTE_PTR attr;

    log_printf("entering C_GetAttributeValue\n");
	
    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    C_LockMutex();

    log_printf("C_GetAttributeValue: looking for the following attributes from object 0x%08x\n",hObject);
    for (i = 0; i<(int)ulCount; i++) {
	log_printf("\tattribute type 0x%08x\n",pTemplate[i].type);
    }
	
    /* find right session */
    log_printf("C_GetAttributeValue: object handle 0x%08x\n",hObject);
    if ((pSession=PKCS11_FindSession(hSession))==NULL) {
	C_UnlockMutex();
	return(CKR_SESSION_HANDLE_INVALID);
    }

    if (!pSession->pToken->ppTokenObject) {
	C_UnlockMutex();
	return(CKR_OBJECT_HANDLE_INVALID);
    }

    /*
    * Browsers like Netscape 6 look for special things in the token,
    * like additional root certificates.  If we're asked for those,
    * we just say that we don't have any.
    *
    * Check through all the attributes requested, if any are for
    * CKA_VENDOR_DEFINED types, then we won't have a match, so
    * just return now!
    */
    for (i = 0; i < (int)ulCount; i++) {
	if (pTemplate[i].type & CKA_VENDOR_DEFINED) {
	    log_printf("C_GetAttributeValue: caller requested a CKA_VENDOR_DEFINED type 0x%08x in the template, we're outta here!\n",
			pTemplate[ulCount-1].type);
	    C_UnlockMutex();
	    return(CKR_ATTRIBUTE_TYPE_INVALID);
	}
    }

    for (ctr = 0; pSession->pToken->ppTokenObject[ctr]; ctr++) {
	if (pSession->pToken->ppTokenObject[ctr]->ulObjectHandle == hObject) {
	    log_printf("C_GetAttributeValue: the object in question has these attributes and values:\n");
	    display_object(pSession->pToken->ppTokenObject[ctr]);
	    for (j = 0, res = CKR_OK; j<(int)ulCount; j++) {
		log_printf("C_GetAttributeValue: on attribute %02d\n",j);
		attr = PKCS11_FindAttribute_p(pSession->pToken->ppTokenObject[ctr]->pAttribute,pTemplate[j].type);
		if (!attr) {
		    log_printf("C_GetAttributeValue: attr not present\n");
		    pTemplate[j].ulValueLen = -1L;
		    res = CKR_ATTRIBUTE_TYPE_INVALID;
		}
		else if (pTemplate[j].value == NULL_PTR) {
		    log_printf("C_GetAttributeValue: just supposed to return the length\n");
		    pTemplate[j].ulValueLen = attr->ulValueLen;
		}
		else if (pTemplate[j].ulValueLen<attr->ulValueLen) {
		    log_printf("C_GetAttributeValue: length %ld less than %ld\n",pTemplate[j].ulValueLen,attr->ulValueLen);
		    pTemplate[j].ulValueLen = attr->ulValueLen;
		    res = CKR_BUFFER_TOO_SMALL;
		}
		else {
		    log_printf("C_GetAttributeValue: returning the attr value\n");
		    pTemplate[j].ulValueLen = attr->ulValueLen;
		    CKI_SetAttrValue_nf(&(pTemplate[j]),attr->value);			  
		}
	    }
	    log_printf("C_GetAttributeValue: returning res %ld\n",res);
	    C_UnlockMutex();
	    return(res);
	}
    }
    log_printf("C_GetAttributeValue: returning CKR_OBJECT_HANDLE_INVALID\n");
    C_UnlockMutex();
    return(CKR_OBJECT_HANDLE_INVALID);
}	

CK_RV CK_ENTRY C_SetAttributeValue(CK_SESSION_HANDLE hSession,
				   CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, 
				   CK_ULONG ulCount) {
    log_printf("entering C_SetAttributeValue\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_FindObjectsInit( CK_SESSION_HANDLE hSession,
				  CK_ATTRIBUTE_PTR pTemplate, 
				  CK_ULONG ulCount) {
    int i,j,res;
    PKCS11_FINDOBJECTS_INFO *pFunction;
    PKCS11_SESSION *pSession;
    static time_t last_update = 0;
    time_t now;
	
    log_printf("C_FindObjectsInit: sessionhandle is 0x%08x\n",hSession);

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);

    C_LockMutex();

    log_printf("C_FindObjectsInit: looking for all objects with the following %ld attr(s):\n", ulCount);
    for (i = 0; i<(int)ulCount; i++) {
	display_attribute(&(pTemplate[i]));
    }

    /*
     * Browsers like Netscape 6 look for special things in the token,
     * like additional root certificates.  If we're asked for those,
     * we just say that we don't have any.
     *
     * Check through all the attributes requested, if any are for
     * CKA_VENDOR_DEFINED types, then we won't have a match, so
     * just return now!
     */
    for (i = 0; i < (int)ulCount; i++) {
	if (pTemplate[i].type & CKA_VENDOR_DEFINED) {
	    log_printf("C_FindObjectsInit: caller requested a CKA_VENDOR_DEFINED type 0x%08x in the template, we're outta here!\n",
			pTemplate[ulCount-1].type);
	    C_UnlockMutex();
	    return(CKR_ATTRIBUTE_TYPE_INVALID);
	}
    }

    /* find right session */
    log_printf("C_FindObjectsInit: pTemplate[0].type is 0x%08x\n",pTemplate[0].type);
    if (pTemplate[0].type == CKA_CLASS)
	log_printf("C_FindObjectsInit: CKA_CLASS wanted is 0x%08x\n",*(CK_ULONG *)pTemplate[0].value);
    else if(pTemplate[0].type == CKA_ID) {
	log_printf("C_FindObjectsInit: CKA_ID wanted is '");
#if defined(macintosh) && defined(DEBUG)
	log_write((const char *)pTemplate[0].value, pTemplate[0].ulValueLen);
#else
	log_write((CK_BYTE_PTR)pTemplate[0].value, pTemplate[0].ulValueLen);
#endif
	log_printf("'\n");
    }
	
    if ((pSession=PKCS11_FindSession(hSession))==NULL) {
	C_UnlockMutex();
	return(CKR_SESSION_HANDLE_INVALID);
    }

    time(&now);
    if (now - last_update > 300) {
	LoadTokenObjects(pSession->pToken);
	/* loading tokens can take a while */
	time(&last_update);			
    }

    if (!pSession->pToken->ppTokenObject) 
	log_printf("C_FindObjectsInit: no objects!\n");

    pFunction = pSession->pCryptoFunctions->pFindObjects;
    if (pFunction->isactive == TRUE) {
	log_printf("C_FindObjectsInit: returning CKR_OPERATION_ACTIVE\n");
	C_UnlockMutex();
	return(CKR_OPERATION_ACTIVE);
    }
    pFunction->isactive = TRUE;
    pFunction->ulAttrCount = ulCount;
    pFunction->TokenObjectsIndex = 0L;
    pFunction->pTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE)*(ulCount+1));
    if (!pFunction->pTemplate) {
	C_UnlockMutex();
	return(CKR_HOST_MEMORY);
    }
    log_printf("C_FindObjectsInit: ulCount is %ld\n",ulCount);
    for (j = 0; j<(int)ulCount; j++) {
	if (pTemplate[j].type == CKA_CLASS)
	    log_printf("C_FindObjectsInit: (first) class wanted is 0x%08x\n",*(CK_ULONG *)pTemplate[j].value);
	pFunction->pTemplate[j].value = NULL_PTR;
	pFunction->pTemplate[j].ulValueLen = 0L;
	res = CKI_Attribute_Dup(&(pFunction->pTemplate[j]),&(pTemplate[j]));
	if (pTemplate[j].type == CKA_CLASS)
	    log_printf("C_FindObjectsInit: class wanted is 0x%08x\n",*(CK_ULONG *)pTemplate[j].value);
	if (res != CKR_OK) {
	    log_printf("C_FindObjectsInit: returning with bad result (0x%08x)\n", res);
	    CKI_AttributePtr_Free(pFunction->pTemplate);
	    pFunction->pTemplate = NULL;
	    C_UnlockMutex();
	    return(res);
	}
    }
    pFunction->pTemplate[j].value = NULL_PTR; /* marks end of attrs */
    pFunction->pTemplate[j].ulValueLen = 0L;
    log_printf("C_FindObjectsInit: exiting with CKR_OK\n");
    C_UnlockMutex();
    return(CKR_OK);    
}

CK_RV CK_ENTRY C_FindObjects( CK_SESSION_HANDLE hSession,
			      CK_OBJECT_HANDLE_PTR phObject, 
			      CK_ULONG ulMaxObjectCount,
			      CK_ULONG_PTR pulObjectCount) {
    int j;
    PKCS11_FINDOBJECTS_INFO *pFunction;
    PKCS11_SESSION *pSession;
    int ctr = 0;
    int objsret;
    CK_ATTRIBUTE_PTR attr;
	
    log_printf("C_FindObjects: entered\n");
	
    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);

    C_LockMutex();

    /* find right session */
    if ((pSession=PKCS11_FindSession(hSession))==NULL) {
	C_UnlockMutex();
	return(CKR_SESSION_HANDLE_INVALID);
    }

    pFunction = pSession->pCryptoFunctions->pFindObjects;

    if (pFunction->isactive == FALSE) {
	log_printf("C_FindObjects: returning with CKR_OPERATION_NOT_INITIALIZED\n");
	C_UnlockMutex();
	return(CKR_OPERATION_NOT_INITIALIZED);
    }
	
    *pulObjectCount = 0;
    ctr = pFunction->TokenObjectsIndex;
    objsret = 0;

    if (!pSession->pToken->ppTokenObject) {
	log_printf("C_FindObjects: no objects to look at!\n");
	C_UnlockMutex();
	return(CKR_OK);
    }
	
    log_printf("C_FindObjects: ctr is %d, pFunction->ulAttrCount is %ld\n",
		ctr, pFunction->ulAttrCount);

    while ((objsret<(int)ulMaxObjectCount) && (pSession->pToken->ppTokenObject[ctr])) {
	for (j = 0; j<(int)pFunction->ulAttrCount; j++) {
	    log_printf("C_FindObjects: pFunction->pTemplate[%d].type is 0x%08x\n",
			j, pFunction->pTemplate[j].type);
	    attr = PKCS11_FindAttribute_p(pSession->pToken->ppTokenObject[ctr]->pAttribute,pFunction->pTemplate[j].type);
	    if (!attr) { 
		log_printf("C_FindObjects: no such attribute present\n");
		ctr++; 
		break;
	    }

	    if (attr->ulValueLen != pFunction->pTemplate[j].ulValueLen) {
		log_printf("C_FindObjects: attr values (lengths) don't match [%d vs. %d]\n",
			    attr->ulValueLen, pFunction->pTemplate[j].ulValueLen);
		ctr++; 
		break;
	    }

	    if (memcmp(attr->value,pFunction->pTemplate[j].value,pFunction->pTemplate[j].ulValueLen)) {
		log_printf("C_FindObjects: attr values don't match [%s vs. %s\n",
			    attr->value, pFunction->pTemplate[j].value);
		ctr++;
		break;
	    }
	}

	if (j == (int)pFunction->ulAttrCount) {
	    phObject[*pulObjectCount] = pSession->pToken->ppTokenObject[ctr]->ulObjectHandle;
	    log_printf("FindObj 12, returning object handle 0x%08x\n",phObject[*pulObjectCount]);
	    display_object(pSession->pToken->ppTokenObject[ctr]); 	  
	    (*pulObjectCount)++;			
	    ctr++;
	    objsret++;
	}
    }	 
    log_printf("FindObj 13, objsret is %d\n",objsret);
    log_printf("FindObj 13, *pulObjectCount is %ld\n",*pulObjectCount);
    pFunction->TokenObjectsIndex=ctr;

    /* set index to done, etc... FIXME */
    log_printf("FindObj 14\n");
    C_UnlockMutex();
    return(CKR_OK); /* no more matching objects left */
}	


CK_RV CK_ENTRY C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    PKCS11_SESSION *pSession;
    PKCS11_FINDOBJECTS_INFO *pFunction;
	
    log_printf("entering C_FindObjectsFinal\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    C_LockMutex();

    /* find right session */
    if ((pSession=PKCS11_FindSession(hSession))==NULL) {
	C_UnlockMutex();
	return(CKR_SESSION_HANDLE_INVALID);
    }
                    	
    pFunction = pSession->pCryptoFunctions->pFindObjects;
    if (pFunction->isactive == FALSE) {
	log_printf("C_FindObjectsFinal: returning CKR_OPERATION_NOT_INITIALIZED\n");
	C_UnlockMutex();
	return(CKR_OPERATION_NOT_INITIALIZED);
    }

    CKI_AttributePtr_Free(pFunction->pTemplate);
    pFunction->pTemplate = NULL_PTR;
    pFunction->ulAttrCount = 0L;
    pFunction->TokenObjectsIndex = 0L;
    pFunction->isactive = FALSE;
    log_printf("C_FindObjectsFinal: returning CKR_OK\n");
    C_UnlockMutex();
    return(CKR_OK);
}	


CK_RV CK_ENTRY C_EncryptInit(CK_SESSION_HANDLE hSession,
			     CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    log_printf("entering C_EncryptInit\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
			 CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, 
			 CK_ULONG_PTR pulEncryptedDataLen) {
    log_printf("entering C_Encrypt\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_EncryptUpdate(CK_SESSION_HANDLE hSession, 
			       CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
			       CK_ULONG_PTR pulEncryptedPartLen) {
    log_printf("entering C_EncryptUpdate\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_EncryptFinal(CK_SESSION_HANDLE hSession,
			      CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncyptedPartLen) {
    log_printf("entering C_Initialize\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_DecryptInit(CK_SESSION_HANDLE hSession,
			     CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    log_printf("entering C_DecryptInit\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_Decrypt(CK_SESSION_HANDLE hSession,
			 CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
			 CK_ULONG_PTR pulDataLen) {
    log_printf("entering C_Decrypt\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_DecryptUpdate(CK_SESSION_HANDLE hSession,
			       CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
			       CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    log_printf("entering C_DecryptUpdate\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_DecryptFinal(CK_SESSION_HANDLE hSession,
			      CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
    log_printf("entering C_DecryptFinal\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_DigestInit(CK_SESSION_HANDLE hSession,
			    CK_MECHANISM_PTR pMechanism) {
    log_printf("entering C_DigestInit\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_DigestUpdate(CK_SESSION_HANDLE hSession,
			      CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    log_printf("entering C_DigestUpdate\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_DigestKey(CK_SESSION_HANDLE hSession,
			   CK_OBJECT_HANDLE hKey) {
    log_printf("entering C_DigestKey\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_Digest(CK_SESSION_HANDLE hSession,
			CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
			CK_ULONG_PTR pulDigestLen) {
    log_printf("entering C_Digest\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_DigestFinal(CK_SESSION_HANDLE hSession,
			     CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    log_printf("entering C_DigestFinal\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_SignInit(CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    CK_RV res;
    PKCS11_SESSION *pSession;
    PKCS11_SIGN_INFO *pFunction;
	
    log_printf("entering C_SignInit\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);

    C_LockMutex();

    /* find right session */
    if ((pSession=PKCS11_FindSession(hSession))==NULL) {
	C_UnlockMutex();
	return(CKR_SESSION_HANDLE_INVALID);
    }
                    
    pFunction = pSession->pCryptoFunctions->pSign;
    if (pFunction->isactive == TRUE) {
	log_printf("C_SignInit: returning CKR_OPERATION_ACTIVE\n");
	C_UnlockMutex();
	return(CKR_OPERATION_ACTIVE);
    }
    pFunction->isactive = TRUE;
    log_printf("C_SignInit: hKey = 0x%08x\n", hKey);
    if (!hKey) {
	C_UnlockMutex();
	return(CKR_KEY_HANDLE_INVALID);
    }
    pFunction->hKey = hKey; /* do we have to check its existence? */
    pFunction->pSignature = NULL_PTR;
    pFunction->pulSignatureLen = 0L;
    pFunction->pMechanism = CKI_Mechanism_New();
    if (!pFunction->pMechanism) {
	C_UnlockMutex();
	return(CKR_HOST_MEMORY);
    }
    res = CKI_Mechanism_Dup(pFunction->pMechanism,pMechanism);
    if (res != CKR_OK) {
	log_printf("C_SignInit: CKI_Mechanism_Dup failed (0x%08x)\n", res);	
	C_UnlockMutex();
	return(res);
    }
    log_printf("C_SignInit: returning CKR_OK\n");
    C_UnlockMutex();
    return(CKR_OK);
}

CK_RV CK_ENTRY C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		      CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    int j;
    PKCS11_SESSION *pSession;
    PKCS11_SIGN_INFO *pFunction = NULL;
    RSA *key;
	
    log_printf("entering C_Sign\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);

    C_LockMutex();

    /* find right session */
    if ((pSession=PKCS11_FindSession(hSession))==NULL) {
	C_UnlockMutex();
	return(CKR_SESSION_HANDLE_INVALID);
    }
                    
    pFunction = pSession->pCryptoFunctions->pSign;
    if (pFunction->isactive == FALSE) {
	log_printf("C_Sign: returning CKR_OPERATION_NOT_INITIALIZED\n");
	C_UnlockMutex();
	return(CKR_OPERATION_NOT_INITIALIZED);
    }
    /* convert the key to internal RSA, then sign */
    key = PKCS11_RsaPrivateKey_to_RSA(hSession,pFunction->hKey);
    if (key == NULL) {
	pFunction->isactive = FALSE;
	log_printf("C_Sign: failed to obtain RSA\n");
	C_UnlockMutex();
	return(CKR_FUNCTION_FAILED);
    }
#ifdef DEBUG
    /* Dump out the key we're about to use... */
    dump_key(key);
#endif

    /*	  j = RSA1_private_encrypt(ulDataLen,pData,pSignature,key,RSA_PKCS1_PADDING); */
    j = RSA_private_encrypt(ulDataLen,pData,pSignature,key,RSA_PKCS1_PADDING);
	
    RSA_free(key);
    if (j <= 0) {
	pFunction->isactive = FALSE;
	log_printf("C_Sign: failed to encrypt\n");
	C_UnlockMutex();
	return(CKR_FUNCTION_FAILED);
    }
    *pulSignatureLen = j;
    pFunction->isactive = FALSE;
    log_printf("C_Sign: returning CKR_OK\n");
    C_UnlockMutex();
    return(CKR_OK);
}	

CK_RV CK_ENTRY C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
			    CK_ULONG ulPartLen) {
    log_printf("entering C_SignUpdate\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_SignFinal(CK_SESSION_HANDLE hSession,
			   CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    PKCS11_SESSION *pSession;
    PKCS11_SIGN_INFO *pFunction;
	
    log_printf("entering C_SignFinal\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    /* find right session */
    if ((pSession=PKCS11_FindSession(hSession))==NULL) {
	C_UnlockMutex();
	return(CKR_SESSION_HANDLE_INVALID);
    }
                    
    pFunction = pSession->pCryptoFunctions->pSign;
    if (pFunction->isactive == FALSE) {
	log_printf("C_SignFinal: returning CKR_OPERATION_NOT_INITIALIZED\n");
	C_UnlockMutex();
	return(CKR_OPERATION_NOT_INITIALIZED);
    }
    pFunction->hKey = 0L; 
    pFunction->pSignature = NULL_PTR;
    pFunction->pulSignatureLen = 0L;
    if (pFunction->pMechanism)
	CKI_Mechanism_Free(pFunction->pMechanism);
    pFunction->pMechanism = NULL_PTR;
    pFunction->isactive = FALSE;
    log_printf("C_SignFinal: returning CKR_OK\n");
    C_UnlockMutex();
    return(CKR_OK);
}	

CK_RV CK_ENTRY C_SignRecoverInit(CK_SESSION_HANDLE hSession,
				 CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    log_printf("entering C_SignRecoverInit\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_SignRecover(CK_SESSION_HANDLE hSession,
			     CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
			     CK_ULONG_PTR pulSignature) {
    log_printf("entering C_SignRecover\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_VerifyInit(CK_SESSION_HANDLE hSession,
			    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    log_printf("entering C_VerifyInit\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
			CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    log_printf("entering C_Verify\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_VerifyUpdate(CK_SESSION_HANDLE hSession,
			      CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    log_printf("entering C_VerifyUpdate\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_VerifyFinal(CK_SESSION_HANDLE hSession,
			     CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    log_printf("entering C_VerifyFinal\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
				   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    log_printf("entering C_VerifyRecoverInit\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_VerifyRecover(CK_SESSION_HANDLE hSession,
			       CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
			       CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
    log_printf("entering C_VerifyRecover\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
				     CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
				     CK_ULONG_PTR pulEncryptedPartLen) {
    log_printf("entering C_DigestEncryptUpdate\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
				     CK_BYTE_PTR pEncryptedPart, CK_ULONG pEncryptedPartLen,
				     CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    log_printf("entering C_DecryptDigestUpdate\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
				   CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
				   CK_ULONG_PTR pulEncryptedPartLen) {
    log_printf("entering C_SignEncryptUpdate\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
				     CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
				     CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    log_printf("entering C_DecryptVerifyUpdate\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_GenerateKey(CK_SESSION_HANDLE hSession,
			     CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
			     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
    log_printf("entering C_GenerateKey\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
				 CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
				 CK_ULONG ulPublicKeyAttributeCount, 
				 CK_ATTRIBUTE_PTR pPrivateKeyTemplate, 
				 CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey,
				 CK_OBJECT_HANDLE_PTR phPrivateKey) {
    log_printf("entering C_GenerateKeyPair\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_WrapKey(CK_SESSION_HANDLE hSession,
			 CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey,
			 CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, 
			 CK_ULONG_PTR pulWrappedKeyLen) {
    log_printf("entering C_WrapKey\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_UnwrapKey(CK_SESSION_HANDLE hSession,
			   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
			   CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
			   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
			   CK_OBJECT_HANDLE_PTR phKey) {
    log_printf("entering C_UnwrapKey\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_DeriveKey(CK_SESSION_HANDLE hSession,
			   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
			   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
			   CK_OBJECT_HANDLE_PTR phKey) {
    log_printf("entering C_DeriveKey\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_SeedRandom(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
    log_printf("entering C_SeedRandom\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_GenerateRandom(CK_SESSION_HANDLE hSession,
				CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
    log_printf("entering C_GenerateRandom\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_GetFunctionStatus(CK_SESSION_HANDLE hSession) {
    log_printf("entering C_GetFunctionStatus\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV CK_ENTRY C_CancelFunction(CK_SESSION_HANDLE hSession) {
    log_printf("entering C_CancelFunction\n");

    if (!PKCS11_ModuleInitDone)
	return(CKR_CRYPTOKI_NOT_INITIALIZED);
    
    return(CKR_FUNCTION_NOT_SUPPORTED);
}
