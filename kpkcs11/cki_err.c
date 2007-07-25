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

/* for debugging only */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#ifndef _WIN32
# include <unistd.h>
#else
  void log_write(char *data, int len);
#endif

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "cki_types.h"
#include "pkcs11_types.h"
#include "cki_globals.h"
#include "pkcs11_globals.h"
#include "pkcs11_funcs.h"
#include "cki_new_free.h"
#include "pkcs11_new_free.h"
#include "cki_dup.h"
#include "debug.h"



void display_attribute(CK_ATTRIBUTE_PTR attr) {
    unsigned int i, j;
    int totalLength = attr->ulValueLen;
    char temphex[64];
    char tempascii[32];
    unsigned char c;

    unsigned int remain;

    temphex[0] = '\0';
    tempascii[0] = '\0';

    log_printf("display_attribute: type: 0x%08x, length %03ld value:\n", attr->type, attr->ulValueLen);
    for (j = 0; j < attr->ulValueLen; j += 16) {
	remain = attr->ulValueLen - j;
	for (i = 0; i < 16 && i < remain;  i++) {
	    c = *((char *)(attr->value)+i+j);
	    sprintf(&(temphex[i*2]), "%02x", c);
	    sprintf(&(tempascii[i]), "%c", isprint(c) ? c : '.');
	}
	for (; i < 16; i++) {
	    strcat(temphex, "..");
	    strcat(tempascii, ".");
	}
	log_printf("%s  |%s|\n", temphex, tempascii);
    }
    return;
}

void display_object(PKCS11_OBJECT *object) {
    int i;

    if (!object) 
	return;
    log_printf("display_object: object handle 0x%08x class 0x%08x\n",
		object->ulObjectHandle, object->ulObjectClass);
    for (i=0; object->pAttribute[i].ulValueLen!=0; i++) {
	display_attribute(&(object->pAttribute[i]));
    }
    return;
}

