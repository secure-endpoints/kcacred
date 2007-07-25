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

#include <stdlib.h>
#include <string.h>

#include "cki_types.h"
#include "pkcs11_types.h"
#include "cki_globals.h"
#include "pkcs11_globals.h"
#include "cki_new_free.h"
#include "pkcs11_funcs.h"
#include "pkcs11_new_free.h"
#include "pkcs11_evp_funcs.h"
#include "debug.h"

PKCS11_FUNCTION_INFO * PKCS11_FunctionInfo_New() {
    PKCS11_FUNCTION_INFO * FunctionInfoPtr;

    log_printf("entering PKCS11_FunctionInfo_New\n");
    FunctionInfoPtr=(PKCS11_FUNCTION_INFO *)malloc(sizeof(PKCS11_FUNCTION_INFO));
    if (FunctionInfoPtr==NULL) {
	return(NULL);
    }
    FunctionInfoPtr->pMechanism=NULL;
    FunctionInfoPtr->hKey=0L;
    FunctionInfoPtr->pEvpCipherCtx=NULL;
    FunctionInfoPtr->pEvpMdCtx=NULL;		/* Needed for all platforms! */

    FunctionInfoPtr->pMechanism=CKI_Mechanism_New();
    if (FunctionInfoPtr->pMechanism==NULL) {
	PKCS11_FunctionInfo_Free(FunctionInfoPtr);
	return(NULL);
    }
    FunctionInfoPtr->pEvpCipherCtx=PKCS11_EvpCipherCtx_New();
    if (FunctionInfoPtr->pEvpCipherCtx==NULL) {
	PKCS11_FunctionInfo_Free(FunctionInfoPtr);
	return(NULL);
    }
    return(FunctionInfoPtr);
}

PKCS11_FINDOBJECTS_INFO * PKCS11_FindObjectsInfo_New() {
    PKCS11_FINDOBJECTS_INFO * FindObjectsInfoPtr;

    log_printf("entering PKCS11_FindObjectsInfo_New\n");
    FindObjectsInfoPtr=(PKCS11_FINDOBJECTS_INFO *)malloc(sizeof(PKCS11_FINDOBJECTS_INFO));
    if (FindObjectsInfoPtr==NULL) {
	return(NULL);
    }
    FindObjectsInfoPtr->pTemplate=NULL;
    FindObjectsInfoPtr->ulAttrCount=0L;
    FindObjectsInfoPtr->TokenObjectsIndex=0L;
    FindObjectsInfoPtr->isactive=FALSE;

    return(FindObjectsInfoPtr);
}

PKCS11_SIGN_INFO * PKCS11_SignInfo_New() {
    PKCS11_SIGN_INFO * SignInfoPtr;

    log_printf("entering PKCS11_SignInfo_New\n");
    SignInfoPtr=(PKCS11_SIGN_INFO *)malloc(sizeof(PKCS11_SIGN_INFO));
    if (SignInfoPtr==NULL) {
	return(NULL);
    }
    SignInfoPtr->pMechanism=NULL;
    SignInfoPtr->hKey=0L;
    SignInfoPtr->pSignature=NULL;
    SignInfoPtr->isactive=FALSE;
    SignInfoPtr->pulSignatureLen=0L;

    return(SignInfoPtr);
}

PKCS11_FUNCTIONS *PKCS11_Functions_New() {
    PKCS11_FUNCTIONS *pFunctions;

    log_printf("entering PKCS11_Functions_New\n");
    pFunctions=(PKCS11_FUNCTIONS *)malloc(sizeof(PKCS11_FUNCTIONS));
    if (pFunctions==NULL) {
	return(NULL);
    }
    pFunctions->pFindObjects=NULL;
    pFunctions->pEncrypt=NULL;
    pFunctions->pDecrypt=NULL;
    pFunctions->pDigest=NULL;
    pFunctions->pSign=NULL;
    pFunctions->pSignRecover=NULL;
    pFunctions->pVerify=NULL;
    pFunctions->pVerifyRecover=NULL;
    /* now alloc new for each of these */
    pFunctions->pFindObjects=PKCS11_FindObjectsInfo_New();
    if (pFunctions->pFindObjects==NULL) {
	PKCS11_Functions_Free(pFunctions);
	return(NULL);
    }
    pFunctions->pEncrypt=PKCS11_FunctionInfo_New();
    if (pFunctions->pEncrypt==NULL) {
	PKCS11_Functions_Free(pFunctions);
	return(NULL);
    }
    pFunctions->pDecrypt=PKCS11_FunctionInfo_New();
    if (pFunctions->pDecrypt==NULL) {
	PKCS11_Functions_Free(pFunctions);
	return(NULL);
    }
    pFunctions->pDigest=PKCS11_FunctionInfo_New();
    if (pFunctions->pDigest==NULL) {
	PKCS11_Functions_Free(pFunctions);
	return(NULL);
    }
    pFunctions->pSign=PKCS11_SignInfo_New();
    if (pFunctions->pSign==NULL) {
	PKCS11_Functions_Free(pFunctions);
	return(NULL);
    }
    pFunctions->pSignRecover=PKCS11_FunctionInfo_New();
    if (pFunctions->pSignRecover==NULL) {
	PKCS11_Functions_Free(pFunctions);
	return(NULL);
    }
    pFunctions->pVerify=PKCS11_FunctionInfo_New();
    if (pFunctions->pVerify==NULL) {
	PKCS11_Functions_Free(pFunctions);
	return(NULL);
    }
    pFunctions->pVerifyRecover=PKCS11_FunctionInfo_New();
    if (pFunctions->pVerifyRecover==NULL) {
	PKCS11_Functions_Free(pFunctions);
	return(NULL);
    }
    return(pFunctions);
}

PKCS11_SESSION *PKCS11_Session_New() {
    PKCS11_SESSION *pSession;

    log_printf("entering PKCS11_Session_New\n");
    pSession=(PKCS11_SESSION *)malloc(sizeof(PKCS11_SESSION));
    if (pSession==NULL) {
	return(NULL);
    }
    pSession->ulSessionHandle=0L;
    pSession->pInfo=NULL;
    pSession->pCryptoFunctions=NULL;

    pSession->pInfo=CKI_SessionInfo_New();
    if (pSession->pInfo==NULL) {
	PKCS11_Session_Free(pSession);
	return(NULL);
    }
    pSession->pCryptoFunctions=PKCS11_Functions_New();
    if (pSession->pCryptoFunctions==NULL) {
	PKCS11_Session_Free(pSession);
	return(NULL);
    }
    return(pSession);
}

PKCS11_MECHANISM *PKCS11_Mechanism_New() {
    PKCS11_MECHANISM *pMechanism;

    log_printf("entering PKCS11_Mechanism_New\n");
    pMechanism=(PKCS11_MECHANISM *)malloc(sizeof(PKCS11_MECHANISM));
    if (pMechanism==NULL) {
	return(NULL);
    }
    pMechanism->pInfo=NULL;
    pMechanism->pMechanism=NULL;

    pMechanism->pInfo=CKI_MechanismInfo_New();
    if (pMechanism->pInfo==NULL) {
	PKCS11_Mechanism_Free(pMechanism);
	return(NULL);
    }	
    pMechanism->pMechanism=CKI_Mechanism_New();
    if (pMechanism->pMechanism==NULL) {
	PKCS11_Mechanism_Free(pMechanism);
	return(NULL);
    }
    return(pMechanism);
}

PKCS11_OBJECT *PKCS11_Object_New() {
    PKCS11_OBJECT *pObject;

    log_printf("entering PKCS11_Object_New\n");
    pObject=(PKCS11_OBJECT *)malloc(sizeof(PKCS11_OBJECT));
    if (pObject==NULL) {
	return(NULL);
    }
    pObject->ulObjectHandle=0L;
    pObject->ulObjectClass=0L;
    pObject->pAttribute=NULL; 
    return(pObject);
}

PKCS11_TOKEN *PKCS11_Token_New() {
    PKCS11_TOKEN *pToken;
  
    log_printf("entering PKCS11_Token_New\n");
    pToken=(PKCS11_TOKEN *)malloc(sizeof(PKCS11_TOKEN));
    if (pToken==NULL) {
	return(NULL);
    }
    pToken->pInfo=NULL;
    pToken->ppMechanism=NULL; /* don't know how many; leave it */
    pToken->pPin=NULL; /* don't know how long; leave it */
    pToken->ulPinLen=0L;
    pToken->ppSession=NULL; /* don't know how many.. */
    pToken->ppTokenObject=NULL; /* none yet */

    pToken->pInfo=CKI_TokenInfo_New();
    if (pToken->pInfo==NULL) {
	PKCS11_Token_Free(pToken);
	return(NULL);
    }
    return(pToken);
}

PKCS11_SLOT * PKCS11_Slot_New() {
    PKCS11_SLOT *pSlot;
 
    log_printf("entering PKCS11_Slot_New\n");
    pSlot=(PKCS11_SLOT *)malloc(sizeof(PKCS11_SLOT));
    if (pSlot==NULL) {
	return(NULL);
    }
    pSlot->slotID=0L;
    pSlot->pInfo=NULL;
    pSlot->pToken=NULL;

    pSlot->pInfo=CKI_SlotInfo_New();
    if (pSlot->pInfo==NULL) {
	PKCS11_Slot_Free(pSlot);
	return(NULL);
    }
    pSlot->pToken=PKCS11_Token_New();
    if (pSlot->pToken==NULL) {
	PKCS11_Slot_Free(pSlot);
	return(NULL);
    }

    pSlot->pToken->ppSession = (PKCS11_SESSION **)malloc(sizeof(PKCS11_SESSION *)*2);
    if (pSlot->pToken->ppSession == NULL) {
	PKCS11_Slot_Free(pSlot);
	return(NULL);
    }

    pSlot->pToken->ppSession[1] = NULL;
    pSlot->pToken->ppSession[0] = PKCS11_Session_New();
    if (pSlot->pToken->ppSession[0] == NULL) {
	PKCS11_Slot_Free(pSlot);
	return(NULL);
    }
    PKCS11_Init_Session(0L,0L,pSlot->pToken,CKS_RO_PUBLIC_SESSION,0L,
			NULL,NULL,pSlot->pToken->ppSession[0]);
    PKCS11_Init2_Session(pSlot->pToken->ppSession[0]);

    return(pSlot);
}

PKCS11_MODULE *PKCS11_Module_New() {
    PKCS11_MODULE *pModule;
  
    log_printf("entering PKCS11_Module_New\n");
    pModule=(PKCS11_MODULE *)malloc(sizeof(PKCS11_MODULE));
    if (pModule==NULL) {
	return(NULL);
    }
    pModule->pInfo=NULL;
    pModule->ppSlot=NULL; /* don't know how many, leave for now */

    pModule->pInfo=CKI_Info_New();
    if (pModule->pInfo==NULL) {
	PKCS11_Module_Free(pModule);
	return(NULL);
    }

    return(pModule);
}

void PKCS11_FunctionInfo_Free(PKCS11_FUNCTION_INFO *FunctionInfoPtr) {

    log_printf("entering PKCS11_FunctionInfo_Free\n");
    if (FunctionInfoPtr==NULL) 
	return;
    if (FunctionInfoPtr->pMechanism!=NULL) 
	CKI_Mechanism_Free(FunctionInfoPtr->pMechanism);
    if (FunctionInfoPtr->pEvpCipherCtx!=NULL) 
	PKCS11_EvpCipherCtx_Free(FunctionInfoPtr->pEvpCipherCtx);
    if (FunctionInfoPtr->pEvpMdCtx!=NULL) 
	PKCS11_EvpMdCtx_Free(FunctionInfoPtr->pEvpMdCtx);
    free(FunctionInfoPtr);
    return;
}

void PKCS11_FindObjectsInfo_Free(PKCS11_FINDOBJECTS_INFO *FindObjectsInfoPtr) {

    log_printf("entering PKCS11_FindObjectsInfo_Free\n");
    if (FindObjectsInfoPtr==NULL) 
	return;
    if (FindObjectsInfoPtr->pTemplate!=NULL) 
	CKI_Attribute_Free(FindObjectsInfoPtr->pTemplate);
    free(FindObjectsInfoPtr);
    return;
}

void PKCS11_SignInfo_Free(PKCS11_SIGN_INFO *SignInfoPtr) {

    log_printf("entering PKCS11_SignInfo_Free\n");
    if (SignInfoPtr==NULL) 
	return;
    if (SignInfoPtr->pMechanism!=NULL) 
	CKI_Mechanism_Free(SignInfoPtr->pMechanism);
    if (SignInfoPtr->pSignature!=NULL)
	free(SignInfoPtr->pSignature);
    free(SignInfoPtr);
    return;
}

void PKCS11_Functions_Free(PKCS11_FUNCTIONS *pFunctions) {

    log_printf("entering PKCS11_Functions_Free\n");
    if (pFunctions==NULL) return;
    if (pFunctions->pFindObjects!=NULL)
	PKCS11_FindObjectsInfo_Free(pFunctions->pFindObjects);
    if (pFunctions->pEncrypt!=NULL)
	PKCS11_FunctionInfo_Free(pFunctions->pEncrypt);
    if (pFunctions->pDecrypt!=NULL)
	PKCS11_FunctionInfo_Free(pFunctions->pDecrypt);
    if (pFunctions->pDigest!=NULL)
	PKCS11_FunctionInfo_Free(pFunctions->pDigest);
    if (pFunctions->pSign!=NULL)
	PKCS11_SignInfo_Free(pFunctions->pSign);
    if (pFunctions->pSignRecover!=NULL)
	PKCS11_FunctionInfo_Free(pFunctions->pSignRecover);
    if (pFunctions->pVerify!=NULL)
	PKCS11_FunctionInfo_Free(pFunctions->pVerify);
    if (pFunctions->pVerifyRecover!=NULL)
	PKCS11_FunctionInfo_Free(pFunctions->pVerifyRecover);
    free(pFunctions);
    return;
}

void PKCS11_Object_Free(PKCS11_OBJECT *pObject) {

    log_printf("entering PKCS11_Object_Free\n");
    if (pObject==NULL) 
	return;
    if (pObject->pAttribute!=NULL) {
	CKI_AttributePtr_Free(pObject->pAttribute);
    }
    free(pObject);
    return;
}

void PKCS11_Session_Free(PKCS11_SESSION *pSession) {
    int i,j;

    log_printf("entering PKCS11_Session_Free\n");
    if (pSession==NULL) 
	return;
    if (pSession->pInfo!=NULL)
	CKI_SessionInfo_Free(pSession->pInfo);
    if (pSession->pToken->ppTokenObject!=NULL) {
	for (i =0; pSession->pToken->ppTokenObject[i]; i++) {
	    if (pSession->pToken->ppTokenObject[i]->ulSessionHandle == pSession->ulSessionHandle) {
		PKCS11_Object_Free(pSession->pToken->ppTokenObject[i]);
		pSession->pToken->ppTokenObject[i] = NULL_PTR;

		for ( j=i; pSession->pToken->ppTokenObject[j+1]; j++ ) {
		    pSession->pToken->ppTokenObject[j] = pSession->pToken->ppTokenObject[j+1];
		    pSession->pToken->ppTokenObject[j+1] = NULL_PTR;
		}
		i--;
	    }
	}	
    }
    if (pSession->pCryptoFunctions!=NULL)
	PKCS11_Functions_Free(pSession->pCryptoFunctions);

    free(pSession);
    return;
}

void PKCS11_Mechanism_Free(PKCS11_MECHANISM *pMechanism) {

    log_printf("entering PKCS11_Mechanism_Free\n");
    if (pMechanism==NULL) return;
    if (pMechanism->pInfo!=NULL)
	CKI_MechanismInfo_Free(pMechanism->pInfo);
    if (pMechanism->pMechanism!=NULL) 
	CKI_Mechanism_Free(pMechanism->pMechanism);
    free(pMechanism);
    return;    
}

void PKCS11_Token_Free(PKCS11_TOKEN *pToken) {
    int i;

    log_printf("entering PKCS11_Token_Free\n");
    if (pToken==NULL) return;
    if (pToken->pInfo!=NULL)
	CKI_TokenInfo_Free(pToken->pInfo);
    if (pToken->ppMechanism!=NULL) {
	for (i=0; pToken->ppMechanism[i]; i++)
	    PKCS11_Mechanism_Free(pToken->ppMechanism[i]);
	free(pToken->ppMechanism);
    }
    if (pToken->pPin!=NULL)
	CKI_Pin_Free(pToken->pPin);
    if (pToken->ppSession!=NULL) {
	for (i=0; pToken->ppSession[i]; i++)
	    PKCS11_Session_Free(pToken->ppSession[i]);
	free(pToken->ppSession);
    }
    if (pToken->ppTokenObject!=NULL) {
	for (i=0; pToken->ppTokenObject[i]; i++)
	    PKCS11_Object_Free(pToken->ppTokenObject[i]);
	free(pToken->ppTokenObject);
    }
    free(pToken);
}

void PKCS11_Slot_Free(PKCS11_SLOT *pSlot) {

    log_printf("entering PKCS11_Slot_Free\n");
    if (pSlot==NULL) return;
    if (pSlot->pInfo!=NULL) 
	CKI_SlotInfo_Free(pSlot->pInfo);
    if (pSlot->pToken!=NULL)
	PKCS11_Token_Free(pSlot->pToken);
    free(pSlot);
    return;
}

void PKCS11_Module_Free(PKCS11_MODULE*pModule) {
    int i;

    log_printf("entering PKCS11_Module_Free\n");
    if (pModule==NULL) return;
    if (pModule->pInfo!=NULL)
	CKI_Info_Free(pModule->pInfo);
    if (pModule->ppSlot!=NULL) {
	for (i=0; pModule->ppSlot[i]; i++)
	    PKCS11_Slot_Free(pModule->ppSlot[i]);
	free(pModule->ppSlot);
    }
    free(pModule);
    return;
}


