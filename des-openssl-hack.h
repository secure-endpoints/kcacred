/*
 * Copyright (c) 2006-2007 Secure Endpoints Inc.
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

#ifndef DES_OPENSSL_HACK_H
#define DES_OPENSSL_HACK_H

/*
 * This is all a hack because of conflicts with the des include files from
 * MIT Kerberos and OpenSSL.  There are defines in the MIT des include file
 * that don't seem to belong there.  However they are needed by other MIT code.
 * So we cannot simply define DES_DEFS and avoid including the MIT des
 * include file.  Instead, we define DES_DEFS and then define all the
 * garbage that is in the MIT des.h that should be elsewhere (IMHO).
 *  KWC circa 4/2001
 */

#undef closesocket	/* undef what is to-be-defined by krb.h -- billdo 2000.1205 */
#undef ioctlsocket	/* undef what is to-be-defined by krb.h -- billdo 2000.1205 */

/*
 * The OpenSSL des header file defines HEADER_DES_H.  If that has already been
 * included, then we want to avoid conflicts with the MIT des header file.
 */

#if defined(HEADER_DES_H)               /* Has openssl des header been included? */
   
/*
 * This is all very, very, very, very ugly.
 * There MUST be a better way!  KWC 7/19/2000
 * (The kerberosIV/krb.h that comes with K5 depends on definitions from
 * kerberosIV/des.h, but some (most?) of those conflict with definitions
 * made in the openssl/des.h header.  If the openssl header has already
 * been included, HEADER_DES_H will be defined, so we define DES_DEFS
 * here so that kerberosIV/krb.h doesn't include kerberosIV/des.h, but
 * then we still need the following stuff that would have been defined
 * by kerberosIV/des.h.  In other words, it's a mess...
 */
 
#ifndef DES_DEFS
#define DES_DEFS 1
#endif

/* Windows declarations */
#ifndef KRB5_CALLCONV
#define KRB5_CALLCONV
#define KRB5_CALLCONV_C
#define KRB5_DLLIMP
#define GSS_DLLIMP 
#define KRB5_EXPORTVAR
#endif

#ifndef FAR
#define FAR
#define NEAR
#endif

#ifndef __alpha
#define KRB4_32 long
#else
#define KRB4_32 int
#endif

#ifndef PROTOTYPE
#if (defined(__STDC__) || defined(_WINDOWS)) && !defined(KRB5_NO_PROTOTYPES)
#define PROTOTYPE(x) x
#else
#define PROTOTYPE(x) ()
#endif
#endif

/* That was all very, very, very, very ugly.  There MUST be a better way!  KWC 7/19/2000 */
#endif /* HEADER_DES_H */

#endif /* DES_OPENSSL_HACK_H */
