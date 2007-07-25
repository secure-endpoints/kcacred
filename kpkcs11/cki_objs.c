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

#include <stdlib.h>
#include <string.h>

#include "cki_types.h"
#include "pkcs11_types.h"
#include "cki_funcs.h"
#include "pkcs11_funcs.h"
#include "cki_globals.h"
#include "pkcs11_globals.h"
#include "cki_new_free.h"
#include "pkcs11_new_free.h"
#include "cki_dup.h"
#include "debug.h"
#ifdef DEBUG
#include <assert.h>
#endif

CK_RV CK_ENTRY C_CreateObject(CK_SESSION_HANDLE hSession, 
			      CK_ATTRIBUTE_PTR pTemplate, 
			      CK_ULONG ulCount,
			      CK_OBJECT_HANDLE_PTR pObject) {
    PKCS11_SESSION *pSession;
    CK_RV res;
    CK_ATTRIBUTE_PTR attr;
    CK_OBJECT_CLASS objV;
    CK_CERTIFICATE_TYPE certV;
    CK_KEY_TYPE keyV;
#ifdef DEBUG
	int i;
#endif
	
    log_printf("entering C_CreateObject\n");
	
    /* now we have to check the attributes for every object they might
     * create and that we know about. */
	
    /* first: is it a valid session handle? */
    if ((pSession=PKCS11_FindSession(hSession))==NULL)
	return(CKR_SESSION_HANDLE_INVALID);

#ifdef DEBUG
    /* debug only */
    for (i = 0; i < 20; i++) {
	if (pTemplate[i].ulValueLen == 0L) break;
	if (pTemplate[i].type == CKA_CLASS) {
	    log_printf("attr type is CKA_CLASS, value is 0x%08x\n",*(CK_OBJECT_CLASS *)pTemplate[i].value);
	    break;
	}
    }
    /* end debug */
#endif

    attr = PKCS11_GetAttribute(pTemplate,CKA_CLASS);
    if (!attr) {
	log_printf("C_CreateObject: could not locate CKA_CLASS attribute, returning with CKR_TEMPLATE_INCOMPLETE\n");
	return(CKR_TEMPLATE_INCOMPLETE);
    }

    objV = *(CK_OBJECT_CLASS *)attr->value;
    log_printf("C_CreateObject: CKA_CLASS object class value 0x%08x\n", objV);

    CKI_Attribute_Free(attr);
	attr = NULL;

    switch (objV) {
    case CKO_DATA:
	log_printf("C_CreateObject: processing class value CKO_DATA\n");
	res = PKCS11_CreateDataObject(pSession, pTemplate, ulCount, pObject);
	break;
    case CKO_CERTIFICATE:
	log_printf("C_CreateObject: processing class value CKO_CERTIFICATE\n");
	attr = PKCS11_GetAttribute(pTemplate,CKA_CERTIFICATE_TYPE);
	if (!attr) {
	    log_printf("C_CreateObject: could not get CKA_CERTIFICATE_TYPE attribute\n");
	    return(CKR_TEMPLATE_INCOMPLETE);
	}
	certV = *((CK_CERTIFICATE_TYPE *)(attr->value));
	CKI_Attribute_Free(attr);
	attr = NULL;
	switch (certV) {
	case CKC_X_509:
	    log_printf("C_CreateObject: processing CKC_X_509 certificate\n");
	    res = PKCS11_CreateX509CertificateObject(pSession, pTemplate, ulCount, pObject);
	    break;
	default:
	    log_printf("C_CreateObject: invalid certificate type encounted (0x%08x)\n", certV);
	    return(CKR_ATTRIBUTE_VALUE_INVALID);
	}
	break;
    case CKO_PUBLIC_KEY:
	log_printf("C_CreateObject: processing class value CKO_PUBLIC_KEY\n");
	attr = PKCS11_GetAttribute(pTemplate,CKA_KEY_TYPE);
	if (!attr) {
	    log_printf("C_CreateObject: could not get CKA_KEY_TYPE\n");
	    return(CKR_TEMPLATE_INCOMPLETE);
	}
	keyV = *((CK_KEY_TYPE *)(attr->value));
	CKI_Attribute_Free(attr);
	attr = NULL;
	switch (keyV) {
	case CKK_RSA:
	    res = PKCS11_CreateRSAPublicKeyObject(pSession, pTemplate, ulCount, pObject);
	    break;
	case CKK_DSA:
	case CKK_ECDSA:
	case CKK_DH:
	case CKK_KEA:
	case CKK_MAYFLY:
	    log_printf("C_CreateObject: returning CKR_FUNCTION_NOT_SUPPORTED\n");
	    return(CKR_FUNCTION_NOT_SUPPORTED);
	default:
	    log_printf("C_CreateObject: returning CKR_ATTRIBUTE_VALUE_INVALID\n");
	    return(CKR_ATTRIBUTE_VALUE_INVALID);
	}
	break;
    case CKO_PRIVATE_KEY:
	log_printf("C_CreateObject: processing class value CKO_PRIVATE_KEY\n");
	attr = PKCS11_GetAttribute(pTemplate,CKA_KEY_TYPE);
	if (!attr) {
	    log_printf("C_CreateObject: could not get CKA_KEY_TYPE\n");
	    return(CKR_TEMPLATE_INCOMPLETE);
	}
	keyV = *((CK_KEY_TYPE *)(attr->value));
	CKI_Attribute_Free(attr);
	attr = NULL;
	switch (keyV) {
	case CKK_RSA:
	    res = PKCS11_CreateRSAPrivateKeyObject(pSession, pTemplate, ulCount, pObject);
	    break;
	case CKK_DSA:
	case CKK_ECDSA:
	case CKK_DH:
	case CKK_KEA:
	case CKK_MAYFLY:
	    log_printf("C_CreateObject: returning CKR_FUNCTION_NOT_SUPPORTED\n");
	    return(CKR_FUNCTION_NOT_SUPPORTED);
	default:
	    log_printf("C_CreateObject: returning CKR_ATTRIBUTE_VALUE_INVALID\n");
	    return(CKR_ATTRIBUTE_VALUE_INVALID);
	}
	break;
    case CKO_SECRET_KEY:
	log_printf("C_CreateObject: processing class value CKO_SECRET_KEY\n");
	res = PKCS11_CreateSecretKeyObject(pSession, pTemplate, ulCount, pObject);
	break;
    case CKO_VENDOR_DEFINED:
	log_printf("C_CreateObject: processing class value CKO_VENDOR_DEFINED\n");
	res = PKCS11_CreateVendorDefinedObject(pSession, pTemplate, ulCount, pObject);
	break;
    default:
	log_printf("C_CreateObject: processing class value *UNKNOWN* (0x%08x)\n", objV);
	return(CKR_ATTRIBUTE_TYPE_INVALID);
    }
    log_printf("C_CreateObject: returning with result %d\n", res);
    return(res);
}	

CK_RV CK_ENTRY C_DestroyObject(CK_SESSION_HANDLE hSession,
			       CK_OBJECT_HANDLE hObject) {
    int j;
    PKCS11_SESSION *pSession;
    int ctr = 0;
	
    log_printf("entering C_DestroyObject\n");

    /* first: is it a valid session handle? */
    if ((pSession=PKCS11_FindSession(hSession))==NULL)
	return(CKR_SESSION_HANDLE_INVALID);

    for(ctr = 0; pSession->pToken->ppTokenObject[ctr]; ctr++) {
	if (pSession->pToken->ppTokenObject[ctr]->ulObjectHandle == hObject) {
	    break;
	}
    }
    if (!pSession->pToken->ppTokenObject[ctr])
	return(CKR_OBJECT_HANDLE_INVALID);

    log_printf("C_DestroyObject: found an object to free\n");    
    PKCS11_Object_Free(pSession->pToken->ppTokenObject[ctr]);
    pSession->pToken->ppTokenObject[ctr] = NULL_PTR;

    /* move 'em all up in the chain */
    j = ctr;
    while (pSession->pToken->ppTokenObject[j+1]) {
	pSession->pToken->ppTokenObject[j] = pSession->pToken->ppTokenObject[j+1];
	j++;
    }
    pSession->pToken->ppTokenObject[j] = NULL_PTR;
    return(CKR_OK);
}	


CK_ATTRIBUTE_PTR PKCS11_FindAttribute_p(CK_ATTRIBUTE_PTR pAttributes, 
					CK_ATTRIBUTE_TYPE Type) {
    int i;
	
    log_printf("PKCS11_FindAttribute_p: entered to find Type 0x%08x\n", Type);

    if (!pAttributes)
    {
	log_printf("PKCS11_FindAttribute_p: no CK_ATTRIBUTE_PTR given\n");
	return(NULL);
    }
	
    for (i=0; pAttributes[i].value; i++) {
#ifdef VERBBOSE_DEBUG
	log_printf("PKCS11_FindAttribute_p: checking index %02d (0x%08x vs. 0x%08x)\n",
		    i, pAttributes[i].type, Type);
#endif		
	if (pAttributes[i].type == Type) {
	    log_printf("PKCS11_FindAttribute_p: found a match at index %d\n", i);
	    return(&(pAttributes[i]));
	}
    }
    log_printf("PKCS11_FindAttribute_p: returning with no match\n");
    return(NULL);
}

CK_ATTRIBUTE_PTR PKCS11_GetAttribute(CK_ATTRIBUTE_PTR pAttributes, 
				     CK_ATTRIBUTE_TYPE Type) {
    CK_ATTRIBUTE_PTR attr_copy;
    CK_ATTRIBUTE_PTR attr_source;
    CK_RV res;
	int i = 0;
	
    log_printf("PKCS11_GetAttribute: looking for attribute type 0x%08x\n", Type);

    if (!pAttributes)
    {
	log_printf("PKCS11_GetAttribute: no CK_ATTRIBUTE_PTR given\n");
	return(NULL);
    }

    attr_source = PKCS11_FindAttribute_p(pAttributes, Type);
    if (!attr_source)
    {
	log_printf("PKCS11_GetAttribute: returning without finding a match\n");
	return(NULL);
    }

    attr_copy = CKI_Attribute_New();
    if (!attr_copy)
    {
	log_printf("PKCS11_GetAttribute: could not CKI_Attribute_New()\n");
	return(NULL);
    }
	
    res = CKI_Attribute_Dup(attr_copy, attr_source);
    if (res != CKR_OK)
    {
	log_printf("PKCS11_GetAttribute: failed to duplicate the attribute!\n");
	CKI_Attribute_Free(attr_copy);
	return(NULL);
    }
    log_printf("PKCS11_GetAttribute: returning attribute at location 0x%08x\n", attr_copy);
    return(attr_copy);
}	

CK_ULONG PKCS11_NextObjectHandle() {
    PKCS11_ObjectHandleCounter++;  
    return(PKCS11_ObjectHandleCounter);
}

#define NUM_ATTRS 8
CK_RV PKCS11_CreateDataObject(PKCS11_SESSION *pSession, CK_ATTRIBUTE_PTR pTemplate,
			      CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pObject) {
    int i;
    CK_ATTRIBUTE_PTR pAttributes, pTemp, attr;
    PKCS11_OBJECT ** ppTokenObject, *object;
    CK_RV res;
    CK_BYTE empty = '\0';

    log_printf("entering PKCS11_CreateDataObject\n");

    pAttributes = malloc(sizeof(CK_ATTRIBUTE)*NUM_ATTRS);
    if (!pAttributes)
    {
	log_printf("PKCS11_CreateDataObject: unable to allocate space for attributes\n");
	return(CKR_HOST_MEMORY);
    }

    /* set default values first */
    memset(pAttributes,0,sizeof(sizeof(CK_ATTRIBUTE)*NUM_ATTRS));
    
    i = 0;
    res = PKCS11_SetCommonObjectAttrs(pAttributes, CKO_DATA, &i);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateDataObject: failed to PKCS11_SetCommonObjectAttrs (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
	
    pAttributes[i].type = CKA_APPLICATION;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateDataObject: failed to set attribute CKA_APPLICATION (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;
	
    pAttributes[i].type = CKA_VALUE;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateDataObject: failed to set attribute CKA_VALUE (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
#ifdef DEBUG
    assert(i < NUM_ATTRS);
#endif

    for (i = 0; (char *)pTemplate[i].value; i++) {
	attr = &(pTemplate[i]);
	switch (attr->type) {
	case CKA_CLASS:
	    break;
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_LABEL:
	case CKA_APPLICATION:
	case CKA_VALUE:
	case CKA_MODIFIABLE:
	    pTemp = PKCS11_FindAttribute_p(pAttributes, attr->type);
	    res = CKI_Attribute_Dup(pTemp, attr);
	    if (res != CKR_OK) {
		log_printf("PKCS11_CreateDataObject: failed to dup attribute type 0x%08x (result 0x%08x)\n",
			    attr->type, res);
		CKI_AttributePtr_Free(pAttributes);
		return(CKR_FUNCTION_FAILED);
	    }
	    break;
	default:
	    log_printf("PKCS11_CreateDataObject: returning CKR_ATTRIBUTE_TYPE_INVALID\n");
	    CKI_AttributePtr_Free(pAttributes);
	    return(CKR_ATTRIBUTE_TYPE_INVALID);
	}
    }

    /* now put them somewhere... */
    if (!pSession->pToken->ppTokenObject) {
	pSession->pToken->ppTokenObject = (PKCS11_OBJECT **)malloc(sizeof(PKCS11_OBJECT *));
	pSession->pToken->ppTokenObject[0] = NULL;
    }
    ppTokenObject = pSession->pToken->ppTokenObject;
    for (i = 0; ppTokenObject[i]; i++)
	;
    ppTokenObject = (PKCS11_OBJECT **)realloc(ppTokenObject,sizeof(PKCS11_OBJECT *)*(i+2));
    if (!ppTokenObject)
    {
	log_printf("PKCS11_CreateDataObject: failed to realloc space for object\n");
	CKI_AttributePtr_Free(pAttributes);
	return(CKR_HOST_MEMORY);
    }
    pSession->pToken->ppTokenObject = ppTokenObject;
    ppTokenObject[i+1] = NULL;
    ppTokenObject[i] = PKCS11_Object_New();
    if (!ppTokenObject[i])
    {
	log_printf("PKCS11_CreateDataObject: failed to allocate new object\n");
	CKI_AttributePtr_Free(pAttributes);
	return(CKR_HOST_MEMORY);
    }

    object = ppTokenObject[i];
    object->ulObjectHandle = PKCS11_NextObjectHandle();
    *pObject = object->ulObjectHandle;
    object->ulObjectClass = CKO_DATA;
    object->pAttribute = pAttributes;
    log_printf("PKCS11_CreateDataObject: returning CKR_OK\n");
    return(CKR_OK);
}
#undef NUM_ATTRS

#define NUM_ATTRS 12
CK_RV PKCS11_CreateX509CertificateObject(PKCS11_SESSION *pSession, CK_ATTRIBUTE_PTR pTemplate,
					 CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pObject) {
	
    int i;
    CK_ATTRIBUTE_PTR pAttributes, pTemp, attr;
    PKCS11_OBJECT ** ppTokenObject, *object;
    CK_CERTIFICATE_TYPE certValue = CKC_X_509;
    CK_BYTE empty = '\0';
    CK_RV res;
	
    log_printf("entering PKCS11_CreateX509CertificateObject\n");
	
    pAttributes = malloc(sizeof(CK_ATTRIBUTE)*NUM_ATTRS);
    if (!pAttributes)
    {
	log_printf("PKCS11_CreateX509CertificateObject: could not get memory for attributes\n");
	return(CKR_HOST_MEMORY);
    }
	
    /* set default values first */
    memset(pAttributes, 0, sizeof(CK_ATTRIBUTE)*NUM_ATTRS);

    i = 0;
    res = PKCS11_SetCommonObjectAttrs(pAttributes, CKO_CERTIFICATE, &i);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateX509CertificateObject: error from PKCS11_SetCommonObjectAttrs (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }

    pAttributes[i].type = CKA_CERTIFICATE_TYPE;
    pAttributes[i].ulValueLen = sizeof(CK_CERTIFICATE_TYPE);
    res = CKI_SetAttrValue(&(pAttributes[i]),&certValue);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateX509CertificateObject: error while setting CKA_CERTIFICATE_TYPE (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;

    pAttributes[i].type = CKA_SUBJECT;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateX509CertificateObject: error while setting CKA_SUBJECT (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;
	
    pAttributes[i].type = CKA_ID;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateX509CertificateObject: error while setting CKA_ID (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;

    pAttributes[i].type = CKA_ISSUER;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateX509CertificateObject: error while setting CKA_ISSUER (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;

    pAttributes[i].type = CKA_SERIAL_NUMBER;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateX509CertificateObject: error while setting CKA_SERIAL_NUMBER (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;

    pAttributes[i].type = CKA_VALUE;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateX509CertificateObject: error while setting CKA_VALUE (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
#ifdef DEBUG
    assert(i < NUM_ATTRS);
#endif

    for (i = 0; pTemplate[i].value; i++) {
	attr = &(pTemplate[i]);
	log_printf("PKCS11_CreateX509CertificateObject: attr->type is 0x%08x\n",attr->type);
	switch (attr->type) {
	case CKA_CLASS:
	case CKA_CERTIFICATE_TYPE:
	    log_printf("PKCS11_CreateX509CertificateObject: ignoring CKA_CLASS or CKA_CERTIFICATE_TYPE\n");
	    break;
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
	case CKA_LABEL:
	case CKA_VALUE:
	case CKA_SUBJECT:
	case CKA_ID:
	case CKA_ISSUER:
	case CKA_SERIAL_NUMBER:
	    log_printf("PKCS11_CreateX509CertificateObject: processing attribute\n");
	    pTemp = PKCS11_FindAttribute_p(pAttributes,attr->type);
	    if (attr->type == CKA_VALUE) 
		log_printf("PKCS11_CreateX509CertificateObject: attr value length for CKA_VALUE is %ld\n",attr->ulValueLen);
	    if (attr->type == CKA_VALUE) 
		log_printf("PKCS11_CreateX509CertificateObject: pTemp->type is 0x%08x\n",pTemp->type);
	    res = CKI_Attribute_Dup(pTemp,attr);
	    if (res != CKR_OK) {
		log_printf("PKCS11_CreateX509CertificateObject: unable to dup attribute (0x%08x)\n", res);
		CKI_AttributePtr_Free(pAttributes);
		return(CKR_FUNCTION_FAILED);
	    }
	    break;
	default:
	    log_printf("PKCS11_CreateX509CertificateObject: returning CKR_ATTRIBUTE_TYPE_INVALID\n");
	    CKI_AttributePtr_Free(pAttributes);
	    return(CKR_ATTRIBUTE_TYPE_INVALID);
	}
    }

    /* now put them somewhere... */
    log_printf("PKCS11_CreateX509CertificateObject: now creating object...\n");
    if (!pSession->pToken->ppTokenObject) {
	log_printf("PKCS11_CreateX509CertificateObject: initial malloc of objects space\n");
	pSession->pToken->ppTokenObject = (PKCS11_OBJECT **)malloc(sizeof(PKCS11_OBJECT *));
	pSession->pToken->ppTokenObject[0] = NULL;
    }
    ppTokenObject = pSession->pToken->ppTokenObject;

    for (i = 0; ppTokenObject[i]; i++)
	;
    log_printf("PKCS11_CreateX509CertificateObject: create new object at index %d\n",i);
    ppTokenObject = (PKCS11_OBJECT **)realloc(ppTokenObject,sizeof(PKCS11_OBJECT *)*(i+2));

    if (!ppTokenObject)
    {
	log_printf("PKCS11_CreateX509CertificateObject: realloc failed for new object!\n");
	CKI_AttributePtr_Free(pAttributes);
	return(CKR_HOST_MEMORY);
    }

    pSession->pToken->ppTokenObject = ppTokenObject;
    ppTokenObject[i+1] = NULL;
    ppTokenObject[i] = PKCS11_Object_New();
    if (!ppTokenObject[i])
    {
	log_printf("PKCS11_CreateX509CertificateObject: PKCS11_Object_New failed!\n");
	CKI_AttributePtr_Free(pAttributes);
	return(CKR_HOST_MEMORY);
    }

    object = ppTokenObject[i];
    object->ulObjectHandle = PKCS11_NextObjectHandle();
    *pObject = object->ulObjectHandle;
    object->ulObjectClass = CKO_CERTIFICATE;
    object->pAttribute = pAttributes;
    log_printf("PKCS11_CreateX509CertificateObject: returning CKR_OK\n");
    return(CKR_OK);
}	
#undef NUM_ATTRS

#define NUM_ATTRS 21
CK_RV PKCS11_CreateRSAPublicKeyObject(PKCS11_SESSION *pSession, CK_ATTRIBUTE_PTR pTemplate,
				      CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pObject) {
    int i;
    CK_ATTRIBUTE_PTR pAttributes, pTemp, attr;
    PKCS11_OBJECT ** ppTokenObject, *object;
    CK_BYTE empty = '\0';
    CK_ULONG zero = 0;
    CK_RV res;
	
    log_printf("entering CreateRSAPublicKey\n");

    pAttributes = malloc(sizeof(CK_ATTRIBUTE)*NUM_ATTRS);
    if (!pAttributes) 
	return(CKR_HOST_MEMORY);

	/* set default values first */
    memset(pAttributes, 0, sizeof(CK_ATTRIBUTE)*NUM_ATTRS);

    i = 0;
    res = PKCS11_SetCommonObjectAttrs(pAttributes, CKO_PUBLIC_KEY, &i);
    if (res != CKR_OK) {
	log_printf("CreateRSAPublicKey: PKCS11_SetCommonObjectAttrs failed! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    res = PKCS11_SetCommonKeyObjectAttrs(pAttributes, CKK_RSA, &i);
    if (res != CKR_OK) {
	log_printf("CreateRSAPublicKey: PKCS11_SetCommonKeyObjectAttrs failed! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    res = PKCS11_SetCommonPublicKeyObjectAttrs(pAttributes, &i);
    if (res != CKR_OK) {
	log_printf("CreateRSAPublicKey: PKCS11_SetCommonPublicKeyObjectAttrs failed! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
	
    pAttributes[i].type = CKA_MODULUS;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("CreateRSAPublicKey: CKI_SetAttrValue failed for CKA_MODULUS! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;

    pAttributes[i].type = CKA_MODULUS_BITS;
    pAttributes[i].ulValueLen = sizeof(CK_ULONG);
    res = CKI_SetAttrValue(&(pAttributes[i]),&zero);
    if (res != CKR_OK) {
	log_printf("CreateRSAPublicKey: CKI_SetAttrValue failed for CKA_MODULUS_BITS! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;
	
    pAttributes[i].type = CKA_PUBLIC_EXPONENT;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("CreateRSAPublicKey: CKI_SetAttrValue failed for CKA_PUBLIC_EXPONENT! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;
#ifdef DEBUG
    assert(i < NUM_ATTRS);
#endif

    for (i = 0; pTemplate[i].value; i++) {
	attr = &(pTemplate[i]);
	switch (attr->type) {
	case CKA_CLASS:
	case CKA_KEY_TYPE:
	    break;
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
	case CKA_LABEL:
	case CKA_VALUE:
	case CKA_ID:
	case CKA_START_DATE:
	case CKA_END_DATE:
	case CKA_DERIVE:
	case CKA_LOCAL:
	case CKA_SUBJECT:
	case CKA_ENCRYPT:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_WRAP:
	case CKA_MODULUS:
	case CKA_MODULUS_BITS:
	case CKA_PUBLIC_EXPONENT:
	    pTemp = PKCS11_FindAttribute_p(pAttributes,attr->type);
	    res = CKI_Attribute_Dup(pTemp,attr);
	    if (res != CKR_OK) {
		log_printf("CreateRSAPublicKey: dup failed (0x%08x)\n", res);
		CKI_AttributePtr_Free(pAttributes);
		return(CKR_FUNCTION_FAILED);
	    }
	    break;
	default:
	    log_printf("CreateRSAPublicKey: invalid attr type 0x%08x\n", attr->type);
	    CKI_AttributePtr_Free(pAttributes);
	    return(CKR_ATTRIBUTE_TYPE_INVALID);
	}
    }
    /* now put them somewhere... */
    if (!pSession->pToken->ppTokenObject) {
	log_printf("CreateRSAPublicKey: initial malloc of objects space\n");
	pSession->pToken->ppTokenObject = (PKCS11_OBJECT **)malloc(sizeof(PKCS11_OBJECT *));
	pSession->pToken->ppTokenObject[0] = NULL;
    }
    ppTokenObject = pSession->pToken->ppTokenObject;

    for (i = 0; ppTokenObject[i]; i++)
	;
    log_printf("CreateRSAPublicKey: creating new object at index %d\n", i);

    ppTokenObject = (PKCS11_OBJECT **)realloc(ppTokenObject,sizeof(PKCS11_OBJECT *)*(i+2));
    if (!ppTokenObject)
    {
	log_printf("CreateRSAPublicKey: realloc failed for sessionobject\n");
	CKI_AttributePtr_Free(pAttributes);
	return(CKR_HOST_MEMORY);
    }
    pSession->pToken->ppTokenObject = ppTokenObject;
    ppTokenObject[i+1] = NULL;
    ppTokenObject[i] = PKCS11_Object_New();
    if (!ppTokenObject[i])
    {
	log_printf("CreateRSAPublicKey: PKCS11_Object_New failed!\n");
	CKI_AttributePtr_Free(pAttributes);
	return(CKR_HOST_MEMORY);
    }

    object = ppTokenObject[i];
    object->ulObjectHandle = PKCS11_NextObjectHandle();
    *pObject = object->ulObjectHandle;
    object->ulObjectClass = CKO_PUBLIC_KEY;
    object->pAttribute = pAttributes;
    log_printf("CreateRSAPublicKey: returning CKR_OK\n");
    return(CKR_OK);
}
#undef NUM_ATTRS


#define NUM_ATTRS 29
CK_RV PKCS11_CreateRSAPrivateKeyObject(PKCS11_SESSION *pSession, CK_ATTRIBUTE_PTR pTemplate,
				       CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pObject) {
    int i;
    CK_ATTRIBUTE_PTR pAttributes, pTemp, attr;
    PKCS11_OBJECT ** ppTokenObject, *object;
    CK_BYTE empty = '\0';
    CK_RV res;
	
    log_printf("entering PKCS11_CreateRSAPrivateKeyObject\n");
	
    pAttributes = malloc(sizeof(CK_ATTRIBUTE)*NUM_ATTRS);
    if (!pAttributes)
    {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: could not allocate memory for attributes\n");
	return(CKR_HOST_MEMORY);
    }
	
    /* set default values first */
    memset(pAttributes, 0, sizeof(CK_ATTRIBUTE)*NUM_ATTRS);

    i = 0;
    res = PKCS11_SetCommonObjectAttrs(pAttributes, CKO_PRIVATE_KEY, &i);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: PKCS11_SetCommonObjectAttrs failed! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    res = PKCS11_SetCommonKeyObjectAttrs(pAttributes, CKK_RSA, &i);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: PKCS11_SetCommonKeyObjectAttrs failed! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    res = PKCS11_SetCommonPrivateKeyObjectAttrs(pAttributes, &i);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: PKCS11_SetCommonPrivateKeyObjectAttrs failed! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
	
    pAttributes[i].type = CKA_MODULUS;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: CKI_SetAttrValue failed for CKA_MODULUS! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;

    pAttributes[i].type = CKA_PUBLIC_EXPONENT;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: CKI_SetAttrValue failed for CKA_PUBLIC_EXPONENT! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;

    pAttributes[i].type = CKA_PRIVATE_EXPONENT;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: CKI_SetAttrValue failed for CKA_PRIVATE_EXPONENT! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;

    pAttributes[i].type = CKA_PRIME_1;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: CKI_SetAttrValue failed for CKA_PRIME_1! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;

    pAttributes[i].type = CKA_PRIME_2;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: CKI_SetAttrValue failed for CKA_PRIME_2! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;

    pAttributes[i].type = CKA_EXPONENT_1;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: CKI_SetAttrValue failed for CKA_EXPONENT_1! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
    i++;

    pAttributes[i].type = CKA_EXPONENT_2;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: CKI_SetAttrValue failed for CKA_EXPONENT_2! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
		return(res);
    }
    i++;
	
    pAttributes[i].type = CKA_COEFFICIENT;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: CKI_SetAttrValue failed for CKA_COEFFICIENT! (0x%08x)\n", res);
	CKI_AttributePtr_Free(pAttributes);
	return(res);
    }
#ifdef DEBUG
    assert(i < NUM_ATTRS);
#endif

    for (i = 0; (char *)pTemplate[i].value; i++) {
	attr = &(pTemplate[i]);
	switch (attr->type) {
	case CKA_CLASS:
	case CKA_KEY_TYPE:
	    break;
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
	case CKA_LABEL:
	case CKA_SUBJECT:
	case CKA_ID:
	case CKA_START_DATE:
	case CKA_END_DATE:
	case CKA_DERIVE:
	case CKA_LOCAL:
	case CKA_SENSITIVE:
	case CKA_DECRYPT:
	case CKA_SIGN:
	case CKA_SIGN_RECOVER:
	case CKA_UNWRAP:
	case CKA_EXTRACTABLE:
	case CKA_ALWAYS_SENSITIVE:
	case CKA_NEVER_EXTRACTABLE:
	case CKA_MODULUS:
	case CKA_PUBLIC_EXPONENT:
	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
	    pTemp = PKCS11_FindAttribute_p(pAttributes,attr->type);
	    res = CKI_Attribute_Dup(pTemp,attr);
	    if (res != CKR_OK) {
		log_printf("PKCS11_CreateRSAPrivateKeyObject: CKI_AttrDup failed for type 0x%08x! (result 0x%08x)\n", attr->type, res);
		CKI_AttributePtr_Free(pAttributes);
		return(CKR_FUNCTION_FAILED);
	    }
	    break;
	default:
	    log_printf("PKCS11_CreateRSAPrivateKeyObject: invalid attr 0x%08x\n",attr->type);
	    CKI_AttributePtr_Free(pAttributes);
	    return(CKR_ATTRIBUTE_TYPE_INVALID);
	}
    }
    
    /* now put them somewhere... */
    if (!pSession->pToken->ppTokenObject) {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: initial malloc of objects space\n");
	pSession->pToken->ppTokenObject = (PKCS11_OBJECT **)malloc(sizeof(PKCS11_OBJECT *));
	pSession->pToken->ppTokenObject[0] = NULL;
    }
    ppTokenObject = pSession->pToken->ppTokenObject;
    for (i=0; ppTokenObject[i]; i++)
	;
    log_printf("PKCS11_CreateRSAPrivateKeyObject: inserting new objects starting at index %d \n",i);
    ppTokenObject = (PKCS11_OBJECT **)realloc(ppTokenObject,sizeof(PKCS11_OBJECT *)*(i+2));

    if (!ppTokenObject)
    {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: could not realloc space for session objects\n");
	CKI_AttributePtr_Free(pAttributes);
	return(CKR_HOST_MEMORY);
    }
    pSession->pToken->ppTokenObject = ppTokenObject;
    ppTokenObject[i+1] = NULL;
    ppTokenObject[i] = PKCS11_Object_New();
    if (!ppTokenObject[i])
    {
	log_printf("PKCS11_CreateRSAPrivateKeyObject: PKCS11_Object_New failed!\n");
	CKI_AttributePtr_Free(pAttributes);
	return(CKR_HOST_MEMORY);
    }

    object = ppTokenObject[i];
    object->ulObjectHandle = PKCS11_NextObjectHandle();
    object->ulSessionHandle = pSession->ulSessionHandle;
    *pObject = object->ulObjectHandle;
    object->ulObjectClass = CKO_PRIVATE_KEY;
    object->pAttribute = pAttributes;

    log_printf("PKCS11_CreateRSAPrivateKeyObject: returning CKR_OK\n");
    return(CKR_OK);
}
#undef NUM_ATTRS

CK_RV PKCS11_CreateSecretKeyObject(PKCS11_SESSION *pSession, CK_ATTRIBUTE_PTR pTemplate,
				   CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pObject) {
	
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV PKCS11_CreateVendorDefinedObject(PKCS11_SESSION *pSession, CK_ATTRIBUTE_PTR pTemplate,
				       CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pObject) {
	
    return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV PKCS11_SetCommonObjectAttrs(CK_ATTRIBUTE_PTR pAttributes, 
				  CK_OBJECT_CLASS objectClass, int *ctr) {
    int i;
    CK_RV res;
    CK_BBOOL false = FALSE;
    CK_BBOOL true = TRUE;
    CK_BYTE empty = '\0';

    log_printf("entering PKCS11_SetCommonObjectAttrs\n");

    i = *ctr;
    pAttributes[i].type = CKA_CLASS;
    pAttributes[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
    res = CKI_SetAttrValue(&(pAttributes[i]), &objectClass);
    if (res != CKR_OK)
    {
	log_printf("PKCS11_SetCommonObjectAttrs: error setting CKA_CLASS (0x%08x)\n", res);
	return(res);
    }
    i++;
	
    pAttributes[i].type = CKA_TOKEN;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK)
    {
	log_printf("PKCS11_SetCommonObjectAttrs: error setting CKA_TOKEN (0x%08x)\n", res);
	return(res);
    }
    i++;

    pAttributes[i].type = CKA_PRIVATE;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK)
    {
	log_printf("PKCS11_SetCommonObjectAttrs: error setting CKA_PRIVATE (0x%08x)\n", res);
	return(res);
    }
    i++;

    pAttributes[i].type = CKA_MODIFIABLE;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&true);
    if (res != CKR_OK)
    {
	log_printf("PKCS11_SetCommonObjectAttrs: error setting CKA_MODIFIABLE (0x%08x)\n", res);
	return(res);
    }
    i++;

    pAttributes[i].type = CKA_LABEL;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK)
    {
	log_printf("PKCS11_SetCommonObjectAttrs: error setting CKA_LABEL (0x%08x)\n", res);
	return(res);
    }
    i++;
    *ctr = i;

    log_printf("PKCS11_SetCommonObjectAttrs: returning CKR_OK\n", res);
    return(CKR_OK);
}	

void CKI_Date_Init(CK_DATE *Date) {
    log_printf("CKI_Date_Init: yr 0x%08x mo 0x%08x da 0x%08x\n",
		Date->year, Date->month, Date->day);
    memset(Date->year,' ',sizeof(Date->year));
    memset(Date->month,' ',sizeof(Date->month));
    memset(Date->day,' ',sizeof(Date->day));
    return;
}	

CK_RV PKCS11_SetCommonKeyObjectAttrs(CK_ATTRIBUTE_PTR pAttributes, CK_KEY_TYPE keyType, int *ctr) {
    int i;
    CK_RV res;
    CK_BBOOL false = FALSE;
    CK_BYTE empty = '\0';
    CK_DATE date;

    CKI_Date_Init(&date);

    i = *ctr;

    pAttributes[i].type = CKA_KEY_TYPE;
    pAttributes[i].ulValueLen = sizeof(CK_KEY_TYPE);
    res = CKI_SetAttrValue(&(pAttributes[i]), &keyType);
    if (res != CKR_OK) return(res);
    i++;

    pAttributes[i].type = CKA_ID;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) return(res);
    i++;
	
    pAttributes[i].type = CKA_START_DATE;
    pAttributes[i].ulValueLen = sizeof(CK_DATE);
    res = CKI_SetAttrValue(&(pAttributes[i]),&date);
    if (res != CKR_OK) return(res);
    i++;

    pAttributes[i].type = CKA_END_DATE;
    pAttributes[i].ulValueLen = sizeof(CK_DATE);
    res = CKI_SetAttrValue(&(pAttributes[i]),&date);
    if (res != CKR_OK) return(res);
    i++;
	
    pAttributes[i].type = CKA_DERIVE;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK) return(res);
    i++;

    pAttributes[i].type = CKA_LOCAL;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK) return(res);
    i++;
	
    *ctr = i;
    return(CKR_OK);
}	

CK_RV PKCS11_SetCommonPublicKeyObjectAttrs(CK_ATTRIBUTE_PTR pAttributes, int *ctr) {
    int i;
    CK_RV res;
    CK_BBOOL false = FALSE;
    CK_BYTE empty = '\0';
	
    i = *ctr;
    pAttributes[i].type = CKA_SUBJECT;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) return(res);
    i++;

    pAttributes[i].type = CKA_ENCRYPT;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK) return(res);
    i++;

    pAttributes[i].type = CKA_VERIFY;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK) return(res);
    i++;

    pAttributes[i].type = CKA_VERIFY_RECOVER;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK) return(res);
    i++;

    pAttributes[i].type = CKA_WRAP;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK) return(res);
    i++;

    *ctr = i;
    return(CKR_OK);
}	

CK_RV PKCS11_SetCommonPrivateKeyObjectAttrs(CK_ATTRIBUTE_PTR pAttributes, int *ctr) {
    int i;
    CK_RV res;
    CK_BBOOL false = FALSE;
    CK_BYTE empty = '\0';
	
    i = *ctr;
    pAttributes[i].type = CKA_SUBJECT;
    pAttributes[i].ulValueLen = 1L;
    res = CKI_SetAttrValue(&(pAttributes[i]),&empty);
    if (res != CKR_OK) return(res);
    i++;
	
    pAttributes[i].type = CKA_SENSITIVE;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK) return(res);
    i++;
	
    pAttributes[i].type = CKA_DECRYPT;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK) return(res);
    i++;
	
    pAttributes[i].type = CKA_SIGN;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK) return(res);
    i++;

    pAttributes[i].type = CKA_SIGN_RECOVER;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK) return(res);
    i++;

    pAttributes[i].type = CKA_UNWRAP;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK) return(res);
    i++;

    pAttributes[i].type = CKA_EXTRACTABLE;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK) return(res);
    i++;

    pAttributes[i].type = CKA_ALWAYS_SENSITIVE;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK) return(res);
    i++;

    pAttributes[i].type = CKA_NEVER_EXTRACTABLE;
    pAttributes[i].ulValueLen = sizeof(CK_BBOOL);
    res = CKI_SetAttrValue(&(pAttributes[i]),&false);
    if (res != CKR_OK) return(res);
    i++;

    *ctr = i;
    return(CKR_OK);
}	

/* expects pAttribute->type and pAttribute->ulValueLen to be set */
CK_RV CKI_SetAttrValue_nf(CK_ATTRIBUTE_PTR pAttribute,CK_VOID_PTR pValue) {
    CK_RV res;
	
    log_printf("entering CKI_SetAttrValue_nf with type 0x%08x, len %03ld\n",
		pAttribute->type, pAttribute->ulValueLen);
	
    switch (pAttribute->type) {
    case CKA_TOKEN:
    case CKA_PRIVATE:
    case CKA_MODIFIABLE:
    case CKA_DERIVE:
    case CKA_LOCAL:
    case CKA_ENCRYPT:
    case CKA_VERIFY:
    case CKA_VERIFY_RECOVER:
    case CKA_WRAP:
    case CKA_SENSITIVE:
    case CKA_DECRYPT:
    case CKA_SIGN:
    case CKA_SIGN_RECOVER:
    case CKA_UNWRAP:
    case CKA_EXTRACTABLE:
    case CKA_ALWAYS_SENSITIVE:
    case CKA_NEVER_EXTRACTABLE:
	*(CK_BBOOL *)pAttribute->value = *(CK_BBOOL *)pValue;
	break;
    case CKA_LABEL:
    case CKA_APPLICATION:
	memcpy(pAttribute->value,pValue,pAttribute->ulValueLen);
	break;
    case CKA_CERTIFICATE_TYPE:
	*(CK_CERTIFICATE_TYPE *)pAttribute->value = *(CK_CERTIFICATE_TYPE *)pValue;
	break;
    case CKA_VALUE: /* Bigint and BYTE_PTR are the same now; later, FIXME. */
    case CKA_SUBJECT:
    case CKA_ID:
    case CKA_ISSUER:
    case CKA_SERIAL_NUMBER:
	memcpy(pAttribute->value,pValue,pAttribute->ulValueLen);
	break;
    case CKA_KEY_TYPE:
	*(CK_KEY_TYPE *)pAttribute->value = *(CK_KEY_TYPE *)pValue;
	break;
    case CKA_MODULUS:
    case CKA_PUBLIC_EXPONENT:
    case CKA_PRIME:
    case CKA_SUBPRIME:
    case CKA_BASE:
    case CKA_PRIVATE_EXPONENT:
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_COEFFICIENT:
	/* these are 'bigints' */
	memcpy(pAttribute->value,pValue,pAttribute->ulValueLen);
	break;
    case CKA_CLASS:
    case CKA_MODULUS_BITS:
    case CKA_VALUE_BITS:
    case CKA_VALUE_LEN:
	*(CK_ULONG_PTR)pAttribute->value = *(CK_ULONG_PTR)pValue;
	break;
    case CKA_START_DATE:
    case CKA_END_DATE:
	res = CKI_Date_Dup(pAttribute->value,(CK_DATE *)pValue);
	if (res != CKR_OK)
	{
	    log_printf("CKI_SetAttrValue_nf: error processing START_DATE, END_DATE (0x%08x)\n", res);
	    return(res);
	}
	break;
    case CKA_VENDOR_DEFINED:
    default:
	return(CKR_FUNCTION_NOT_SUPPORTED);
    }
    display_attribute(pAttribute);
    return(CKR_OK);
}	


/* expects pAttribute->type and pAttribute->ulValueLen to be set;
if pAttribute->value is set, it is freed first */
CK_RV CKI_SetAttrValue(CK_ATTRIBUTE_PTR pAttribute,CK_VOID_PTR pValue) {
    CK_RV res;
	
    log_printf("entering CKI_SetAttrValue with type 0x%08x, len %03ld, value 0x%08x\n",
		pAttribute->type, pAttribute->ulValueLen, pAttribute->value);

    if (pAttribute->value) {
	free(pAttribute->value);
	pAttribute->value = NULL;
    }

    switch (pAttribute->type) {
    case CKA_TOKEN:
    case CKA_PRIVATE:
    case CKA_MODIFIABLE:
    case CKA_DERIVE:
    case CKA_LOCAL:
    case CKA_ENCRYPT:
    case CKA_VERIFY:
    case CKA_VERIFY_RECOVER:
    case CKA_WRAP:
    case CKA_SENSITIVE:
    case CKA_DECRYPT:
    case CKA_SIGN:
    case CKA_SIGN_RECOVER:
    case CKA_UNWRAP:
    case CKA_EXTRACTABLE:
    case CKA_ALWAYS_SENSITIVE:
    case CKA_NEVER_EXTRACTABLE:
	pAttribute->value = (CK_BBOOL *)malloc(pAttribute->ulValueLen);
	*(CK_BBOOL *)pAttribute->value = *(CK_BBOOL *)pValue;
	break;
    case CKA_LABEL:
    case CKA_APPLICATION:
	pAttribute->value = (CK_CHAR_PTR)malloc(pAttribute->ulValueLen);
	memcpy(pAttribute->value,pValue,pAttribute->ulValueLen);
	break;
    case CKA_CERTIFICATE_TYPE:
	pAttribute->value = (CK_CERTIFICATE_TYPE *)malloc(pAttribute->ulValueLen);
	memcpy(pAttribute->value,pValue,pAttribute->ulValueLen);
	break;
    case CKA_VALUE: /* Bigint and BYTE_PTR are the same now; later, FIXME. */
    case CKA_SUBJECT:
    case CKA_ID:
    case CKA_ISSUER:
    case CKA_SERIAL_NUMBER:
	pAttribute->value = (CK_BYTE_PTR)malloc(pAttribute->ulValueLen);
	memcpy(pAttribute->value,pValue,pAttribute->ulValueLen);
	break;
    case CKA_KEY_TYPE:
	pAttribute->value = (CK_KEY_TYPE *)malloc(pAttribute->ulValueLen);
	*(CK_KEY_TYPE *)pAttribute->value = *(CK_KEY_TYPE *)pValue;
	break;
    case CKA_MODULUS:
    case CKA_PUBLIC_EXPONENT:
    case CKA_PRIME:
    case CKA_SUBPRIME:
    case CKA_BASE:
    case CKA_PRIVATE_EXPONENT:
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_COEFFICIENT:
	/* these are 'bigints' */
	pAttribute->value = (CK_BYTE_PTR)malloc(pAttribute->ulValueLen);
	memcpy(pAttribute->value,pValue,pAttribute->ulValueLen);
	break;
    case CKA_CLASS:
    case CKA_MODULUS_BITS:
    case CKA_VALUE_BITS:
    case CKA_VALUE_LEN:
	pAttribute->value = (CK_ULONG_PTR)malloc(pAttribute->ulValueLen);
	*(CK_ULONG_PTR)pAttribute->value = *(CK_ULONG_PTR)pValue;
	break;
    case CKA_START_DATE:
    case CKA_END_DATE:
	pAttribute->value = (CK_DATE *)malloc(pAttribute->ulValueLen);
	res = CKI_Date_Dup(pAttribute->value,(CK_DATE *)pValue);
	if (res != CKR_OK) return(res);
	break;
    case CKA_VENDOR_DEFINED:
    default:
	return(CKR_FUNCTION_NOT_SUPPORTED);
    }
    return(CKR_OK);
}
