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
#include "debug.h"

void CKI_Info_Free(CK_INFO_PTR pInfo) {
    log_printf("CKI_Info_Free: entered\n");
    if (pInfo==NULL)
	return;
    free(pInfo);
    return;
}

CK_INFO_PTR CKI_Info_New() {
    CK_INFO_PTR pInfo;
  
    log_printf("CKI_Info_New: entered\n");
    pInfo=(CK_INFO_PTR)malloc(sizeof(CK_INFO));
    if (pInfo==NULL) {
	return(NULL);
    }
    pInfo->cryptokiVersion.major=0;
    pInfo->cryptokiVersion.minor=0;
    memset(pInfo->manufacturerID,' ',sizeof(pInfo->manufacturerID));
    pInfo->flags=0L;
    memset(pInfo->libraryDescription,' ',sizeof(pInfo->libraryDescription));
    pInfo->libraryVersion.major=0;
    pInfo->libraryVersion.minor=0;
    return(pInfo);
}

void CKI_SlotInfo_Free(CK_SLOT_INFO_PTR pInfo) {
    log_printf("CKI_SlotInfo_Free: entered\n");
    if (pInfo==NULL) return;
    free(pInfo);
    return;
}

CK_SLOT_INFO_PTR CKI_SlotInfo_New() {
    CK_SLOT_INFO_PTR pSlotInfo;

    log_printf("CKI_SlotInfo_New: entered\n");
    pSlotInfo=(CK_SLOT_INFO_PTR)malloc(sizeof(CK_SLOT_INFO));
    if (pSlotInfo==NULL) {
	return(NULL);
    }	
    memset(pSlotInfo->slotDescription,' ',sizeof(pSlotInfo->slotDescription));
    memset(pSlotInfo->manufacturerID,' ',sizeof(pSlotInfo->manufacturerID));
    pSlotInfo->flags=(CK_FLAGS)CKF_REMOVABLE_DEVICE;
    log_printf("CKI_SlotInfo_New: pSlotInfo->flags = 0x%08lX\n",
		pSlotInfo->flags);
    pSlotInfo->hardwareVersion.major=0;
    pSlotInfo->hardwareVersion.minor=0;
    pSlotInfo->firmwareVersion.major=0;
    pSlotInfo->firmwareVersion.minor=0;
    return(pSlotInfo);
}

void CKI_TokenInfo_Free(CK_TOKEN_INFO_PTR pInfo) {
    log_printf("CKI_TokenInfo_Free: entered\n");
    if (pInfo==NULL) return;
    free(pInfo);
    return;  
}

CK_TOKEN_INFO_PTR CKI_TokenInfo_New() {
    CK_TOKEN_INFO_PTR pInfo;

    log_printf("CKI_TokenInfo_New: entered\n");
    pInfo=(CK_TOKEN_INFO_PTR)malloc(sizeof(CK_TOKEN_INFO));
    if (pInfo==NULL) {
	return(NULL);
    }
    memset(pInfo->label,' ',sizeof(pInfo->label));
    memset(pInfo->manufacturerID,' ',sizeof(pInfo->manufacturerID));
    memset(pInfo->model,' ',sizeof(pInfo->model));
    memset(pInfo->serialNumber,' ',sizeof(pInfo->serialNumber));
    pInfo->flags=0L;
    pInfo->flags=(CK_FLAGS)(CKF_PROTECTED_AUTHENTICATION_PATH
			     | CKF_USER_PIN_INITIALIZED) ;
    log_printf("CKI_TokenInfo_New: pInfo->flags = 0x%08lX (CKF_PROTECTED_AUTHENTICATION_PATH | CKF_USER_PIN_INITIALIZED)\n", (CK_FLAGS)pInfo->flags);
    pInfo->ulMaxSessionCount=0L;
    pInfo->ulSessionCount=0L;
    pInfo->ulMaxRwSessionCount=0L;
    pInfo->ulRwSessionCount=0L;
    pInfo->ulMaxPinLen=0L;
    pInfo->ulMinPinLen=0L;
    pInfo->ulTotalPublicMemory=0L;
    pInfo->ulFreePublicMemory=0L;
    pInfo->ulTotalPrivateMemory=0L;
    pInfo->ulFreePrivateMemory=0L;
    pInfo->hardwareVersion.major=0;
    pInfo->hardwareVersion.minor=0;
    pInfo->firmwareVersion.major=0;
    pInfo->firmwareVersion.minor=0;
    memset(pInfo->utcTime,' ',sizeof(pInfo->utcTime));
    return(pInfo);
}

void CKI_SessionInfo_Free(CK_SESSION_INFO_PTR pInfo) {
    log_printf("CKI_SessionInfo_Free: entered\n");
    if (pInfo==NULL) return;
    free(pInfo);
    return;
}

CK_SESSION_INFO_PTR CKI_SessionInfo_New() {
    CK_SESSION_INFO_PTR pInfo;

    log_printf("CKI_SessionInfo_New: entered\n");
    pInfo=(CK_SESSION_INFO_PTR)malloc(sizeof(CK_SESSION_INFO));
    if (pInfo==NULL) {
	return(NULL);
    }
    pInfo->slotID=0L;
    pInfo->state=0L;
    pInfo->flags=0L;
    pInfo->ulDeviceError=0L;
    return(pInfo);
}

void CKI_Attribute_Free(CK_ATTRIBUTE_PTR pAttribute) {
    log_printf("CKI_Attribute_Free: entered\n");
    if (pAttribute==NULL) return;
    if (pAttribute->value==NULL_PTR) 
	free(pAttribute->value); 
    free(pAttribute);
    return;
}

CK_ATTRIBUTE_PTR CKI_Attribute_New() {
    CK_ATTRIBUTE_PTR pAttribute;

    log_printf("CKI_Attribute_New: entered\n");
    pAttribute=(CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE));
    if (pAttribute==NULL) {
	return(NULL);
    }
    pAttribute->value=NULL_PTR;
    pAttribute->ulValueLen=0L;
    return(pAttribute);
}

void CKI_Mechanism_Free(CK_MECHANISM_PTR pMechanism) {
    log_printf("CKI_Mechanism_Free: entered\n");
    if (pMechanism==NULL) return;
    if (pMechanism->pParameter!=NULL)   
	free(pMechanism->pParameter); /* is this correct? */
    free(pMechanism);
    return;
}

CK_MECHANISM_PTR CKI_Mechanism_New() {
    CK_MECHANISM_PTR pMechanism;

    log_printf("CKI_Mechanism_New: entered\n");
    pMechanism=(CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
    if (pMechanism==NULL) {
	return(NULL);
    }
    pMechanism->mechanism=0L;
    pMechanism->pParameter=NULL;
    pMechanism->ulParameterLen=0L;
    return(pMechanism);
}

void CKI_MechanismInfo_Free(CK_MECHANISM_INFO_PTR pInfo) {
    log_printf("CKI_MechanismInfo_Free: entered\n");
    if (pInfo==NULL) return;
    free(pInfo);
    return;  
}

CK_MECHANISM_INFO_PTR CKI_MechanismInfo_New() {
    CK_MECHANISM_INFO_PTR pInfo;
  
    log_printf("CKI_MechanismInfo_New: entered\n");
    pInfo=(CK_MECHANISM_INFO_PTR)malloc(sizeof(CK_MECHANISM_INFO));
    if (pInfo==NULL) {
	return(NULL);
    }
    pInfo->ulMinKeySize=0L;
    pInfo->ulMaxKeySize=0L;
    pInfo->flags=0L;
    return(pInfo);
}

void CKI_Pin_Free(CK_CHAR_PTR pPin) {
    log_printf("CKI_Pin_Free: entered\n");
    if (pPin==NULL) return;
    free(pPin);
    return;
}

/* no New function for Pins yet. */

void CKI_FunctionList_Free(CK_FUNCTION_LIST_PTR pFunctionList) {
    log_printf("CKI_FunctionList_Free: entered\n");
    if (pFunctionList==NULL) return;
    free(pFunctionList);
    return;
}

CK_FUNCTION_LIST_PTR CKI_FunctionList_New() {
    CK_FUNCTION_LIST_PTR pFunctionList;

    log_printf("CKI_FunctionList_New: entered\n");
    pFunctionList=(CK_FUNCTION_LIST_PTR)malloc(sizeof(CK_FUNCTION_LIST));
    if (pFunctionList==NULL) {
	return(NULL);
    }
    pFunctionList->version.major=0;
    pFunctionList->version.minor=0;
    pFunctionList->C_Initialize=NULL;
    pFunctionList->C_Finalize=NULL;
    pFunctionList->C_GetInfo=NULL;
    pFunctionList->C_GetFunctionList=NULL;
    pFunctionList->C_GetSlotList=NULL;
    pFunctionList->C_GetSlotInfo=NULL;
    pFunctionList->C_GetTokenInfo=NULL;
    pFunctionList->C_GetMechanismList=NULL;
    pFunctionList->C_GetMechanismInfo=NULL;
    pFunctionList->C_InitToken=NULL;
    pFunctionList->C_InitPIN=NULL;
    pFunctionList->C_SetPIN=NULL;
    pFunctionList->C_OpenSession=NULL;
    pFunctionList->C_CloseSession=NULL;
    pFunctionList->C_CloseAllSessions=NULL;
    pFunctionList->C_GetSessionInfo=NULL;
    pFunctionList->C_GetOperationState=NULL;
    pFunctionList->C_SetOperationState=NULL;
    pFunctionList->C_Login=NULL;
    pFunctionList->C_Logout=NULL;
    pFunctionList->C_CreateObject=NULL;
    pFunctionList->C_CopyObject=NULL;
    pFunctionList->C_DestroyObject=NULL;
    pFunctionList->C_GetObjectSize=NULL;
    pFunctionList->C_GetAttributeValue=NULL;
    pFunctionList->C_SetAttributeValue=NULL;
    pFunctionList->C_FindObjectsInit=NULL;
    pFunctionList->C_FindObjects=NULL;
    pFunctionList->C_FindObjectsFinal=NULL;
    pFunctionList->C_EncryptInit=NULL;
    pFunctionList->C_Encrypt=NULL;
    pFunctionList->C_EncryptUpdate=NULL;
    pFunctionList->C_EncryptFinal=NULL;
    pFunctionList->C_DecryptInit=NULL;
    pFunctionList->C_Decrypt=NULL;
    pFunctionList->C_DecryptUpdate=NULL;
    pFunctionList->C_DecryptFinal=NULL;
    pFunctionList->C_DigestInit=NULL;
    pFunctionList->C_Digest=NULL;
    pFunctionList->C_DigestUpdate=NULL;
    pFunctionList->C_DigestKey=NULL;
    pFunctionList->C_DigestFinal=NULL;
    pFunctionList->C_SignInit=NULL;
    pFunctionList->C_Sign=NULL;
    pFunctionList->C_SignUpdate=NULL;
    pFunctionList->C_SignFinal=NULL;
    pFunctionList->C_SignRecoverInit=NULL;
    pFunctionList->C_SignRecover=NULL;
    pFunctionList->C_VerifyInit=NULL;
    pFunctionList->C_Verify=NULL;
    pFunctionList->C_VerifyUpdate=NULL;
    pFunctionList->C_VerifyFinal=NULL;
    pFunctionList->C_VerifyRecoverInit=NULL;
    pFunctionList->C_VerifyRecover=NULL;
    pFunctionList->C_DigestEncryptUpdate=NULL;
    pFunctionList->C_DecryptDigestUpdate=NULL;
    pFunctionList->C_SignEncryptUpdate=NULL;
    pFunctionList->C_DecryptVerifyUpdate=NULL;
    pFunctionList->C_GenerateKey=NULL;
    pFunctionList->C_GenerateKeyPair=NULL;
    pFunctionList->C_WrapKey=NULL;
    pFunctionList->C_UnwrapKey=NULL;
    pFunctionList->C_DeriveKey=NULL;
    pFunctionList->C_SeedRandom=NULL;
    pFunctionList->C_GenerateRandom=NULL;
    pFunctionList->C_GetFunctionStatus=NULL;
    pFunctionList->C_CancelFunction=NULL;
    return(pFunctionList);
}  

void CKI_AttributePtr_Free(CK_ATTRIBUTE_PTR pAttribute) {
    int i;

    if (!pAttribute) 
	return;
    for (i=0; pAttribute[i].value; i++) {
	free(pAttribute[i].value);
	pAttribute[i].value = NULL;
    }  
    free(pAttribute);
    return;
}
