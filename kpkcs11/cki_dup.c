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

#include "cki_types.h"
#include "pkcs11_types.h"
#include "cki_funcs.h"
#include "cki_globals.h"
#include "pkcs11_globals.h"
#include "debug.h"
#include <string.h>

CK_RV CKI_Info_Dup(CK_INFO_PTR pInfoOut, CK_INFO_PTR pInfoIn) {
    if (pInfoOut == NULL) {
	log_printf("CKI_Info_Dup: null pointer to copy into\n");
	return(CKR_FUNCTION_FAILED);
    }
    if (pInfoIn == NULL) {
	log_printf("CKI_Info_Dup: null pointer to copy from\n");
	return(CKR_FUNCTION_FAILED);
    }
    pInfoOut->cryptokiVersion.major = pInfoIn->cryptokiVersion.major;
    pInfoOut->cryptokiVersion.minor = pInfoIn->cryptokiVersion.minor;
    memcpy(pInfoOut->manufacturerID,pInfoIn->manufacturerID,sizeof(pInfoOut->manufacturerID));
    pInfoOut->flags = pInfoIn->flags;
    memcpy(pInfoOut->libraryDescription,pInfoIn->libraryDescription,sizeof(pInfoOut->libraryDescription));
    pInfoOut->libraryVersion.major = pInfoIn->libraryVersion.major;
    pInfoOut->libraryVersion.minor = pInfoIn->libraryVersion.minor;
	
    return(CKR_OK);
}

CK_RV CKI_TokenInfo_Dup(CK_TOKEN_INFO_PTR pInfoOut,CK_TOKEN_INFO_PTR pInfoIn) {
    if (pInfoOut  == NULL) {
	log_printf("CKI_TokenInfo_Dup: null pointer to copy from\n");
	return(CKR_FUNCTION_FAILED);
    }
    if (pInfoIn == NULL) {
	log_printf("CKI_TokenInfo_Dup: null pointer to copy into\n");
	return(CKR_FUNCTION_FAILED);
    }
    memcpy(pInfoOut->label,pInfoIn->label,sizeof(pInfoOut->label));
    memcpy(pInfoOut->manufacturerID,pInfoIn->manufacturerID,sizeof(pInfoOut->manufacturerID));
    memcpy(pInfoOut->model,pInfoIn->model,sizeof(pInfoOut->model));
    memcpy(pInfoOut->serialNumber,pInfoIn->serialNumber,sizeof(pInfoOut->serialNumber));
    pInfoOut->flags = pInfoIn->flags;
    pInfoOut->ulMaxSessionCount = pInfoIn->ulMaxSessionCount;
    pInfoOut->ulSessionCount = pInfoIn->ulSessionCount;
    pInfoOut->ulMaxRwSessionCount = pInfoIn->ulMaxRwSessionCount;
    pInfoOut->ulRwSessionCount = pInfoIn->ulRwSessionCount;
    pInfoOut->ulMaxPinLen = pInfoIn->ulMaxPinLen;
    pInfoOut->ulMinPinLen = pInfoIn->ulMinPinLen;
    pInfoOut->ulTotalPublicMemory = pInfoIn->ulTotalPublicMemory;
    pInfoOut->ulFreePublicMemory = pInfoIn->ulFreePublicMemory;
    pInfoOut->ulTotalPrivateMemory = pInfoIn->ulTotalPrivateMemory;
    pInfoOut->ulFreePrivateMemory = pInfoIn->ulFreePrivateMemory;
    pInfoOut->hardwareVersion.major = pInfoIn->hardwareVersion.major;
    pInfoOut->hardwareVersion.minor = pInfoIn->hardwareVersion.minor;
    pInfoOut->firmwareVersion.major = pInfoIn->firmwareVersion.major;
    pInfoOut->firmwareVersion.minor = pInfoIn->firmwareVersion.minor;
    memcpy(pInfoOut->utcTime,pInfoIn->utcTime,sizeof(pInfoOut->utcTime));
    return(CKR_OK);  
}

CK_RV CKI_SlotInfo_Dup(CK_SLOT_INFO_PTR pInfoOut, CK_SLOT_INFO_PTR pInfoIn) {
    if (pInfoOut == NULL) {
	log_printf("CKI_SlotInfo_Dup: null pointer to copy into\n");
	return(CKR_FUNCTION_FAILED);
    }
    if (pInfoIn == NULL) {
	log_printf("CKI_SlotInfo_Dup: null pointer to copy from\n");
	return(CKR_FUNCTION_FAILED);
    }
    memcpy(pInfoOut->slotDescription,pInfoIn->slotDescription,sizeof(pInfoOut->slotDescription));
    memcpy(pInfoOut->manufacturerID,pInfoIn->manufacturerID,sizeof(pInfoOut->manufacturerID));
    pInfoOut->flags = pInfoIn->flags;
    pInfoOut->hardwareVersion.major = pInfoIn->hardwareVersion.major;
    pInfoOut->hardwareVersion.minor = pInfoIn->hardwareVersion.minor;
    pInfoOut->firmwareVersion.major = pInfoIn->firmwareVersion.major;
    pInfoOut->firmwareVersion.minor = pInfoIn->firmwareVersion.minor;
    return(CKR_OK);
}	

CK_RV CKI_SessionInfo_Dup(CK_SESSION_INFO_PTR pInfoOut, CK_SESSION_INFO_PTR pInfoIn) {
    if (pInfoOut == NULL) {
	log_printf("CKI_SessionInfo_Dup: null pointer to copy into\n");
	return(CKR_FUNCTION_FAILED);
    }
    if (pInfoIn == NULL) {
	log_printf("CKI_SessionInfo_Dup: null pointer to copy from\n");
	return(CKR_FUNCTION_FAILED);
    }
    pInfoOut->slotID = pInfoIn->slotID;
    pInfoOut->state = pInfoIn->state;
    pInfoOut->flags = pInfoIn->flags;
    pInfoOut->ulDeviceError = pInfoIn->ulDeviceError;
    return(CKR_OK);
}

CK_RV CKI_Date_Dup (CK_DATE *pDateOut, 
		    CK_DATE *pDateIn) {
    if (pDateOut == NULL) {
	log_printf("CKI_Date_Dup: null pointer to copy into\n");
	return(CKR_FUNCTION_FAILED);
    }
    if (pDateIn == NULL) {
	log_printf("CKI_Date_Dup: null pointer to copy from\n");
	return(CKR_FUNCTION_FAILED);
    }
    memcpy(pDateOut->year,pDateIn->year,sizeof(pDateIn->year));
    memcpy(pDateOut->month,pDateIn->month,sizeof(pDateIn->month));
    memcpy(pDateOut->day,pDateIn->day,sizeof(pDateIn->day));
    return(CKR_OK);
}

CK_RV CKI_Attribute_Dup (CK_ATTRIBUTE_PTR pAttributeOut, 
			 CK_ATTRIBUTE_PTR pAttributeIn) {
    CK_RV res;
	
    if (pAttributeOut == NULL) {
	log_printf("CKI_Attribute_Dup: null pointer to copy into\n");
	return(CKR_FUNCTION_FAILED);
    }
    if (pAttributeIn == NULL) {
	log_printf("CKI_Attribute_Dup: null pointer to copy from\n");
	return(CKR_FUNCTION_FAILED);
    }
    log_printf("CKI_Attribute_Dup: type is 0x%08x\n",pAttributeIn->type);
    pAttributeOut->type = pAttributeIn->type;
    pAttributeOut->ulValueLen = pAttributeIn->ulValueLen;

    res = CKI_SetAttrValue(pAttributeOut,pAttributeIn->value);
    if (pAttributeIn->type == CKA_CLASS) {
	log_printf("CKI_Attribute_Dup: CKA_CLASS new value 0x%08x, old value 0x%08x\n",
		    *(CK_OBJECT_CLASS *)pAttributeOut->value, *(CK_OBJECT_CLASS *)pAttributeIn->value);
    }	
    if (res != CKR_OK)
    {
	log_printf("CKI_Attribute_Dup: returning error (0x%08x)\n", res);
	return(res);
    }

    log_printf("CKI_Attribute_Dup: returning CKR_OK\n");
    return(CKR_OK);
}	

CK_RV CKI_Mechanism_Dup(CK_MECHANISM_PTR pMechanismOut, CK_MECHANISM_PTR pMechanismIn) {
	
    if (pMechanismOut == NULL) {
	log_printf("CKI_Mechanism_Dup: null pointer to copy into\n");
	return(CKR_FUNCTION_FAILED);
    }
    if (pMechanismIn == NULL) {
	log_printf("CKI_Mechanism_Dup: null pointer to copy from\n");
	return(CKR_FUNCTION_FAILED);
    }
    pMechanismOut->mechanism = pMechanismIn->mechanism;
    pMechanismOut->ulParameterLen = pMechanismIn->ulParameterLen;
    if (pMechanismIn->pParameter == NULL_PTR) 
	pMechanismOut->pParameter = pMechanismIn->pParameter;
    else {
	log_printf("CKI_Mechanism_Dup: Unsupported parameter\n");
	return(CKR_FUNCTION_NOT_SUPPORTED);
    }
    /* to be added later...
    CKM_DH_PKCS_DERIVE: bigint (byte ptr)
    CKM_KEA_DERIVE: CK_KEA_DERIVE_PARAMS
    CKM_MAYFLY_DERIVE: CK_MAYFLY_DERIVE_PARAMS
    CKM_RC2_ECB: CK_RC2_PARAMS
    CKM_RC2_CBC: CK_RC2_CBC_PARAMS
    CKM_RC2_CBC_PAD: CK_RC2_CBC_PARAMS
    CKM_RC2_MAC_GENERAL: CK_MAC_GENERAL_PARAMS
    CKM_RC2_MAC: CK_RC2_PARAMS
    CKM_RC5_ECB: CK_RC5_PARAMS
    CKM_RC5_CBC: CK_RC5_CBC_PARAMS
    CKM_RC5_CBC_PAD: CK_RC5_CBC_PARAMS
    CKM_RC5_MAC_GENERAL: CK_RC5_MAC_GENERAL_PARAMS
    CKM_RC5_MAC: CK_RC5_PARAMS
    CKM_DES_ECB:
    CKM_DES3_ECB:
    CKM_CAST_ECB:
    CKM_CAST3_ECB:
    CKM_CAST5_ECB:
    CKM_IDEA_ECB:
    CKM_CDMF_ECB:
    CKM_DES_CBC:
    CKM_DES3_CBC:
    CKM_CAST_CBC:
    CKM_CAST3_CBC:
    CKM_CAST5_CBC:
    CKM_IDEA_CBC:
    CKM_CDMF_CBC:
    CKM_DES_MAC_GENERAL:
    CKM_DES3_MAC_GENERAL:
    CKM_CAST_MAC_GENERAL:
    CKM_CAST3_MAC_GENERAL:
    CKM_CAST5_MAC_GENERAL:
    CKM_IDEA_MAC_GENERAL:
    CKM_CDMF_MAC_GENERAL:
    CKM_DES_MAC:
    CKM_DES3_MAC:
    CKM_CAST_MAC:
    CKM_CAST3_MAC:
    CKM_CAST5_MAC:
    CKM_IDEA_MAC:
    CKM_CDMF_MAC:
    and more... */

    return(CKR_OK);
}	
