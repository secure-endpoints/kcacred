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

#include <stdio.h>

#ifndef WIN32
# include <unistd.h>
#endif

#include <stdlib.h>

#ifndef macintosh
# include <sys/types.h>
#endif /* !macintosh */

#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#ifdef macintosh
# include <utime.h>
#else /* !macintosh */
# ifndef WIN32
#  include <sys/time.h>
# endif /* !WIN32 */
#endif /* macintosh */

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "doauth.h"

#define NAME_C 1
#define NAME_ST 2
#define NAME_L 3
#define NAME_O 4
#define NAME_OU 5
#define NAME_CN 6
#define OTHER_UNKNOWN 255

X509_NAME *makesubject(char *cn, char *ou, char *o, char *l, 
   char *sp, char *c);
int logcert(BIGNUM *serial, char *certout);
BIGNUM *getnextserial();
int add_nentry(X509_NAME *name,char *string,int nid,int i);
EVP_PKEY *parse_spkac(NETSCAPE_SPKI *spkac);

int setno(int nid) {
  int ret;

  switch(nid) {
  case NID_commonName:
    ret=5;
    break;
  case NID_organizationalUnitName:
    ret=4;
    break;
  case NID_organizationName:
    ret=3;
    break;
  case NID_localityName:
    ret=2;
    break;
  case NID_stateOrProvinceName:
    ret=1;
    break;
  case NID_countryName:
    ret=0;
    break;
  default:
    ret=-1;
    break;
  }
  return(ret);
}

int cmp_by_set(X509_NAME_ENTRY **a, X509_NAME_ENTRY **b) {
  return((*a)->set - (*b)->set);
}

#ifndef NOPROTO
# define FP_ICC  (int (*)(const void *,const void *))
#else
# define FP_ICC
#endif

#if !defined(linux) && !defined(SOLARIS) && !defined(HPUX) && !defined (DARWIN)

void sk_sort(STACK *st) {
   int (*comp_func)();

   comp_func=(int (*)())st->comp;
   qsort((char *)st->data,st->num,sizeof(char *),FP_ICC comp_func);
   st->sorted=1;
}
#endif

int name2num(char *name, char **newname) {

  *newname=name;
  if (!strcasecmp(name,"countryName")) {
    *newname=_strdup("countryName");
    return(NAME_C);
  }
  else if (!strcasecmp(name,"stateOrProvinceName")) {
    *newname=_strdup("stateOrProvinceName");
    return(NAME_ST);
  }
  else if (!strcasecmp(name,"localityName")) {
    *newname=_strdup("localityName");
    return(NAME_L);
  }
  else if (!strcasecmp(name,"organizationName")) {
    *newname=_strdup("organizationName");
    return(NAME_O);
  }
  else if (!strcasecmp(name,"organizationalUnitName")) { 
    *newname=_strdup("organizationalUnitName");
    return(NAME_OU);
  }
  else if (!strcasecmp(name,"commonName")) {
    *newname=_strdup("commonName");
    return(NAME_CN);
  }
  else return(OTHER_UNKNOWN);
}

int add2subject(X509_NAME *subject, char *name, char *value) {
   int num,nid;
   char *newname;

   num=name2num(name,&newname);
   switch(num) {
   case NAME_C:
   case NAME_ST:
   case NAME_L:
   case NAME_O:
   case NAME_OU:
   case NAME_CN:
      nid=OBJ_ln2nid(newname);
      if (nid==0) {
        log_printf("unknown DN subfield name, '%s'...\n",name);
	return(-1);
      }
      add_nentry(subject,value,nid,setno(nid));  
      break;
   case OTHER_UNKNOWN:
   default:
      log_printf("unknown DN subfield name, '%s'...\n",name);
      return(-1);
      break;
   }
   return(0);
}

X509 *gencert(NETSCAPE_SPKI *spkac, struct a_t **tattrl, char *keyfile, 
  char *certfile) {
   X509 *x, *my_cert;
   int days=30; /* FIXME... some lousy default. But this is a TEST module. */
   X509_NAME *subject;
   ASN1_INTEGER *sn;
   BIGNUM *serial;
   char *user;
   int res;
   FILE *fpcert;
   EVP_MD *digest=EVP_md5();
   EVP_PKEY *pkey, *user_pkey;
   FILE *fp;

  log_printf("entering gencert\n");

  x=X509_new();
  if (x==NULL) {
      log_printf("out of memory!\n");
      return(NULL);
  }
  serial=getnextserial(); 
  subject=X509_NAME_new();
  X509_set_version(x,1L); 

  log_printf("gencert 1\n");

  sn=ASN1_INTEGER_new();
  if (sn==NULL) {
     log_printf("out of memory");
     return(NULL);
  }
  if (!BN_to_ASN1_INTEGER(serial,sn)) {
     log_printf("error filling in cert fields (ASN1_INTEGER_set failed)");
     return(NULL);
  }
  X509_set_serialNumber(x,sn);

  log_printf("gencert 2\n");

  /* hope you like these defaults :) */
  user=getelt(tattrl,"user");
  if (!user) user=_strdup("anonymous"); /* uh huh. */
  if (add2subject(subject,"commonname",user)) 
      return(NULL);
  if (add2subject(subject,"organizationalunitname","TEST -- CITI Client CA v1")) 
      return(NULL);
  if (add2subject(subject,"organizationname","University of Michigan")) 
      return(NULL);
  if (add2subject(subject,"localityname","Ann Arbor")) 
      return(NULL);
  if (add2subject(subject,"stateorprovincename","Michigan")) 
      return(NULL);
  if (add2subject(subject,"countryname","US")) 
      return(NULL);

  log_printf("gencert 3\n");

  if (spkac) {
    user_pkey=parse_spkac(spkac);  
    if (!user_pkey) {
      log_printf("parse of spkac failed\n");
      return(NULL);
    }
  }
  else return(NULL);

  log_printf("gencert 4\n");

/* BILLDO 2001.0607 cast cmp_by_set to prevent warning message */
/*  sk_set_cmp_func((STACK *)subject->entries,cmp_by_set); */
  sk_set_cmp_func((STACK *)subject->entries,
		  (int (*)(const char * const *, const char * const *))
			cmp_by_set);

  sk_sort((STACK *)subject->entries);  
  res=X509_set_subject_name(x,subject);
  if (!res) {
    log_printf("error filling in cert fields (X509_set_subject_name failed)");
    return(NULL);
  }

  log_printf("gencert 5\n");

  if ((fpcert=fopen(certfile,"r")) == NULL) {
     log_printf("can't get certificate from '%s'\n",certfile);
     return(NULL);
  }
  my_cert=NULL;
  PEM_read_X509(fpcert,&my_cert,NULL,NULL);
  if (!my_cert) {
    log_printf("can't read my certificate from file '%s'\n",certfile);
    ERR_print_errors_fp(stderr);
    return(NULL);
  }

  log_printf("gencert 6\n");

  res=X509_set_issuer_name(x,X509_get_subject_name(my_cert));
  if (!res) {
    log_printf("error filling in cert fields (X509_set_issuer_name failed)");
    return(NULL);
  }
  res=X509_set_pubkey(x,user_pkey); 
  if (!res) {
     log_printf("error filling in cert fields (X509_set_pubkey failed)");
     return(NULL);
  }
  X509_gmtime_adj(X509_get_notBefore(x),0);
  X509_gmtime_adj(X509_get_notAfter(x),24*60*60*days);

  log_printf("gencert 7\n");

  if ((fp=fopen(keyfile,"r")) == NULL) {
    log_printf("can't get private key from '%s'\n",keyfile);
    return(NULL);
  }
  pkey=NULL;
  PEM_read_PrivateKey(fp,&pkey,NULL,NULL);
  if (!pkey) {
    log_printf("can't read private key\n");
    return(NULL);
  }

  log_printf("gencert 8\n");

  res=X509_sign(x,pkey,digest); 
  if (!res) {
    log_printf("couldn't sign cert\n");
    return(NULL);
  }

  log_printf("leaving gencert\n");

  return(x);
}

int add_nentry(X509_NAME *name,char *string,int nid,int i)
{
  X509_NAME_ENTRY *nentry;

  nentry=X509_NAME_ENTRY_new();
  nentry->object=OBJ_nid2obj(nid);
  nentry->set=i;
  nentry->value->type=ASN1_PRINTABLE_type((unsigned char *)string,strlen(string));
  nentry->value->length=strlen(string);
  nentry->value->data=(unsigned char *)_strdup(string);
  sk_push((STACK *)name->entries,(char *)nentry);  
  return(0);
}

BIGNUM *getnextserial()
{
  struct timeval t;
#ifdef macintosh
  int pid;
#else /* !macintosh */
  pid_t pid;
#endif /* macintosh */
  BIGNUM *serial;

  gettimeofday(&t,NULL);
  pid=getpid();
  serial=BN_new();
  BN_add_word(serial,(unsigned long)t.tv_sec);
  BN_lshift(serial,serial,sizeof(unsigned long));
  BN_add_word(serial,(unsigned long)pid);
  return(serial);
}

EVP_PKEY *parse_spkac(NETSCAPE_SPKI *spkac)
{
  EVP_PKEY *pubkey;
  int j;

  if ((pubkey=X509_PUBKEY_get(spkac->spkac->pubkey)) == NULL) {
    log_printf("pubkey field of spkac unavailable\n");
    return(NULL);
  }
  EVP_add_digest(EVP_md5());
  EVP_add_digest(EVP_sha());
  EVP_add_digest(EVP_sha1());
  EVP_add_digest(EVP_dss());
  EVP_add_digest(EVP_dss1());
  j=NETSCAPE_SPKI_verify(spkac,pubkey);
  if (j<=0) {
    log_printf("signature bad on spkac\n");
    return(NULL);
  }
  return(pubkey);
}

