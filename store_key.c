/*
 * Copyright (c) 2006-2008 Secure Endpoints Inc.
 *  
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
 * Copyright  ©  2000, 2002
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

//
// OVERVIEW:
//
// store_key is called, provided with "p" -- a pointer to a
//     CryptoAPI PRIVKEYBLOB (see rsa_to_keyblob.cc)
//     and a parameter that specifies the name of the Key Container
//     to create for its storage.
//
// store_key's raison d'etre is to:
//
//   Import the provided PRIVKEYBLOB into the named Key Container,
//      creating this container if it doesn't already exist.
//
//------------------------------------------------------------------------------------

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include "debug.h" 

int store_key(BYTE *p, DWORD cbPk, wchar_t * container)
{
    HCRYPTPROV hCryptProv = 0;
    HCRYPTKEY  hKey = 0;
    DWORD      gle;
    LPVOID     gletext;
    int        rc = 1;

    //----------------------------------------
    // ACQUIRE CRYPT CONTEXT
    if(!CryptAcquireContext(&hCryptProv,       // Handle to the CSP
                            container,         // ContainerName
                            MS_DEF_PROV,       // Provider name
                            PROV_RSA_FULL,     // Provider type
                            0))                // Flag values (?? CRYPT_SILENT ??)
    {
        gle = GetLastError();
        if (gle != NTE_BAD_KEYSET) {
            gletext = GetLastErrorText();
            log_printf("initial CryptAcquireContext returned 0x%8X -- %s\n.", gle, gletext ? gletext : "");
            if (gletext)
                LocalFree(gletext);
            rc = 0;
        }   

        //--------------------------------------------------------------------
        // NO PRE-EXISTING CONTAINER.  Create a new default key container. 
        if(!CryptAcquireContext(&hCryptProv,
                                 container,     // ContainerName
                                 MS_DEF_PROV,   // Provider name 
                                 PROV_RSA_FULL, // Provider type
                                 CRYPT_NEWKEYSET))
        {       
            gle = GetLastError();
            gletext = GetLastErrorText();
            log_printf("second CryptAcquireContext returned 0x%8X -- %s\n.", gle, gletext ? gletext : "");
            if (gletext)
                LocalFree(gletext);
            HandleError("Cannot create Registry container for your private key.\n");
            rc = 0;
        }
    }
    
    if (hCryptProv) {
        // NOW IMPORT CALLER'S RSA KEY INTO THAT CONTAINER'S SIGNATURE KEY
        //   (the PRIVKEYBLOB specifies that it's a "SIGNATURE" key)

        log_printf("About to ImportKey of Blob length of %0d\n", cbPk);

        if(!CryptImportKey(hCryptProv, 
                            p,
                            cbPk,
                            0,
                            CRYPT_EXPORTABLE,
                            &hKey))
        {       
            gle = GetLastError();
            gletext = GetLastErrorText();
            log_printf("CryptImportKey failed GetLastError() returns 0x%08x -- %s\n", gle, gletext ? gletext : "");
            if (gletext)
                LocalFree(gletext);
            rc = 0;
        }

        if (!CryptReleaseContext(hCryptProv, 0))
        {
            gle = GetLastError();
            gletext = GetLastErrorText();
            log_printf("CryptReleaseContext failed with GetLastError() = 0x%08x -- %s\n", gle, gletext ? gletext : "");
            if (gletext)
                LocalFree(gletext);
            rc = 0;
        }
    }   
    return rc;
}
