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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

# define WSHELPER
# include <wshelper.h>

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# ifndef FD_SET
#  include <sys/select.h>
# endif
#endif

#include <memory.h>

# define __WINCRYPT_H__		// PREVENT windows.h from including wincrypt.h
				// since wincrypt.h and openssl namepsaces collide
				//  ex. X509_NAME is #define'd and typedef'd ...
# include <winsock.h>		// Must be included before <windows.h> !!!
# include <windows.h>
# include <netidmgr.h>
# include <openssl/pem.h>


#include <stdlib.h>
#include <openssl/x509v3.h>
# include <krb5.h>
# include <com_err.h>

#include "msg.h"
#include "udp_nb.h"
#include "kx509.h"
#include "doauth.h"
#include "debug.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>
#include "kx509_asn.h"
#include <openssl/rand.h>

#include<strsafe.h>

char version_2_0_string[4]={0,0,2,0};

#define	MAX_MSG_LEN	2048
#define RECV_TIMEOUT	5
#define SEND_TIMEOUT	5
#define MAX_KCA_HOSTS	16

#if 0
#if defined(WIN32) && !defined(USE_KRB5)
/* I don't know if WIN32 defines this or not, but if not, here it is... */
# ifndef MAX_KTXT_LEN
#  define MAX_KTXT_LEN 1250
# endif
# ifndef ANAME_SZ
#  define ANAME_SZ	40
# endif
# ifndef REALM_SZ
#  define REALM_SZ	40
# endif
# ifndef SNAME_SZ
#  define SNAME_SZ	40
# endif
# ifndef INST_SZ
#  define INST_SZ	40
# endif
# ifndef KSUCCESS
#  define KSUCCESS	0
# endif
#endif	/* WIN32 && !USE_KRB5 */
#endif

#if SSLEAY_VERSION_NUMBER > 0x0090601eL
# define ADD_ALL_ALGORITHMS		OpenSSL_add_all_algorithms
#else
# define ADD_ALL_ALGORITHMS		SSLeay_add_all_algorithms
#endif

#ifdef DEBUG
void print_response(KX509_RESPONSE *);
void print_request(KX509_REQUEST *);
#endif

extern int debugPrint;	/* XXX TEMPORARY TAKE THIS OUT */

void print_response(KX509_RESPONSE *client_response);
void fill_in_octet_string( ASN1_OCTET_STRING *osp, char *st, int len);

int get_krb5_realm(krb5_context k5_context, char *realm, size_t cch_realm, 
                   char *tkt_cache_name,char **err_msg);
int get_kca_list(char *base_realm, char ***dns_hostlist);

#define KCA_PORT     (u_short)9878
#define CA_SERVICE	"kca_service"

/* Make "buffer" static since it's sometimes used for returned error messages */
static int  init = 1;

static const char *
wsa_strerror(DWORD ecode)
{
    DWORD dwMsgLen;
    static char buff[1024];

    dwMsgLen = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM
                             |FORMAT_MESSAGE_IGNORE_INSERTS
                             |FORMAT_MESSAGE_MAX_WIDTH_MASK,
                              NULL,
                              ecode,
                              MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                              (LPSTR)buff,
                              sizeof(buff)-1,
                              NULL);

    return buff;
}


/*
 *=========================================================================*
 *
 * get_cert_authent_K5()
 *
 *=========================================================================*
 */
int
get_cert_authent_K5(krb5_context k5_context,
		    char *ca_hostname,
		    krb5_data *k5_authent,
		    char sess_key_result[],
		    int *sess_len_ptr,
		    char *realm,
		    char *tkt_cache_name,
		    char **err_ptr)
{
    /* TODO: sess_len_ptr should be a  (size_t *) */
    krb5_auth_context k5_auth_context = NULL;
    krb5_ccache cc = NULL;
    krb5_creds mcreds, *outcreds = NULL;
    krb5_error_code result;
    int retval = 0;

    /* Initialize data structures */
    memset(&mcreds, 0, sizeof(mcreds));
    memset(&outcreds, 0, sizeof(outcreds));

    /* DETERMINE USER'S PRINCIPAL NAME FROM TICKET FILE */

    if (tkt_cache_name) {
        if (result = krb5_cc_resolve(k5_context, tkt_cache_name, &cc)) {
            const char * result_text = error_message(result);

            _report_cs1(KHERR_DEBUG_1, L"get_cert_authent_K5: krb5_cc_resolve: %1!S!",
                        _cptr(result_text));
            _resolve();
            *err_ptr = "Unable to determine default credentials cache.";
            retval = KX509_STATUS_CLNT_FIX;
	    goto cleanup;
        }
    } else {
        if (result = krb5_cc_default(k5_context, &cc)) {
            const char * result_text = error_message(result);

            _report_cs1(KHERR_DEBUG_1, L"get_cert_authent_K5: krb5_cc_default: %1!S!",
                        _cptr(result_text));
            _resolve();
            *err_ptr = "Unable to determine default credentials cache.";
            retval = KX509_STATUS_CLNT_FIX;
	    goto cleanup;
        }
    }

    if (result = krb5_cc_get_principal(k5_context, cc, &mcreds.client)) {
        const char * result_text = error_message(result);

        _report_cs1(KHERR_DEBUG_1, L"get_cert_authent_K5: krb5_cc_get_principal: %1!S!",
                    _cptr(result_text));
        _resolve();
        *err_ptr = "Unable to determine principal from credentials cache.";
        retval = KX509_STATUS_CLNT_FIX;
	goto cleanup;
    }

    /* GENERATE KRB5 AUTHENTICATOR FOR CA SERVER */
    
    /* obtain ticket & session key */
    if (result = krb5_build_principal_ext(k5_context, &mcreds.server,
                                          strlen(realm),
                                          realm,
                                          strlen(CA_SERVICE), CA_SERVICE,
                                          strlen(ca_hostname), ca_hostname,
                                          0))
    {
        const char * result_text = error_message(result);

        _report_cs1(KHERR_DEBUG_1, L"get_cert_authent_K5: krb5_build_principal_ext: %1!S!",
                    _cptr(result_text));
        _resolve();
        *err_ptr = "Unable to build service principal.";
        retval = KX509_STATUS_CLNT_FIX;
	goto cleanup;
    }


  retry_retcred:
    if (retval = krb5_get_credentials(k5_context, 0,
					cc, &mcreds, &outcreds)) {
        const char * result_text = error_message(result);
        _report_cs1(KHERR_DEBUG_1, L"get_cert_authent_K5: krb5_cc_retrieve_cred: %1!S!",
                    _cptr(result_text));
        _resolve();
        *err_ptr = "Unable to find correct credentials to get session key.";
        retval = KX509_STATUS_CLNT_FIX;
        goto cleanup;
    }

    retval = krb5_mk_req_extended(k5_context, &k5_auth_context, 
				  AP_OPTS_MUTUAL_REQUIRED,
                                  NULL, outcreds, k5_authent);

    /* Check to make sure we received a valid ticket; if not remove it 
     * and try again.  Perhaps there are two service tickets for the
     * same service in the ccache. 
     */
    if (outcreds->times.endtime < time(NULL)) {
	krb5_cc_remove_cred(k5_context, cc, 0, outcreds);
	krb5_free_creds(k5_context, outcreds);
	outcreds = NULL;
	goto retry_retcred;
    }

    /* Verify caller can hold session key, and return it */
    if (*sess_len_ptr < (int) outcreds->keyblock.length) {
        *err_ptr = "get_cert_authent_K5: Internal error; not enough room to hold session key.";
        krb5_free_creds(k5_context, outcreds);
        retval = KX509_STATUS_CLNT_FIX;
	goto cleanup;
    }
    *sess_len_ptr = outcreds->keyblock.length;
    memcpy(sess_key_result, outcreds->keyblock.contents, outcreds->keyblock.length);

  cleanup:
    if (k5_auth_context)
        krb5_auth_con_free(k5_context, k5_auth_context);
    krb5_free_cred_contents(k5_context, &mcreds);
    if (outcreds)
	krb5_free_creds(k5_context, outcreds);
    if (cc)
	krb5_cc_close(k5_context, cc);
    return retval;
}

/*
 *=========================================================================*
 *
 * try_ca()
 *
 * Request a certificate from a particular KCA.
 * If we haven't already generated a key-pair, do that now.
 * If using K5, we need a different authenticator for each
 * CA we contact.  If using K4, then we can use the same one
 * for each CA.  We use the session key to seed the generation
 * of the key-pair.
 *
 *=========================================================================*
 */
int try_ca(krb5_context k5_context,
           SOCKET	socket,				/* IN Socket to be used to communicate with CA */
           char	*ca_hostname,		/* IN Host name of the the CA to try */
           char 	*realm,				/* IN Realm name */
           RSA		**rsa,				/* IN/OUT key-pair information */
           X509	**certp,			/* OUT certificate information */
           int (*verify_recvd_packet)(),/*IN routine to call to verify the CA response */
           void	*arg,				/* IN Arguments passed to verification routine */
           char	sess_key[],			/* IN/OUT session key holder */
           int		*sess_len_ptr,		/* IN/OUT length of session key */
           char    *tkt_cache_name,		/* IN credential cache file name */
           char	**emsg,				/* IN/OUT error string buffer */
           int		*err_num_ptr		/* OUT Error value recipient */
)
{
    int			keybits=DEFBITS;	/* Number of bits in the public key / private key */
    fd_set		readfds;
    struct hostent	*ca_hostent = NULL;
    struct sockaddr_in  ca_addr;
    struct timeval	timeout;
    DWORD		i;
    KX_MSG		pkt_to_send;
    KX_MSG		pkt_recvd;
    KX509_REQUEST	*request = NULL;
    char		*pubkey_ptr = NULL;
    unsigned char	*tmp_ptr = NULL;
    int			pubkey_len = 0;
    int		len;
    static int	triedAuthent = 0;
    int		rc = 0;

    krb5_data	k5_authent;
    char 	lbuffer[2048];
    char 	buffer[2048];

    *err_num_ptr = 0;
    memset(&k5_authent, 0, sizeof(k5_authent));
    memset(&pkt_to_send, 0, sizeof(pkt_to_send));
    memset(&pkt_recvd, 0, sizeof(pkt_recvd));
    memset(&ca_addr, 0, sizeof(ca_addr));
    memset(lbuffer, 0, sizeof(lbuffer));

    /* For K5, we always generate a new authenticator for the host we are contacting */
    if (rc = get_cert_authent_K5(k5_context, ca_hostname, &k5_authent, sess_key,
                                 sess_len_ptr, realm, tkt_cache_name, emsg)) {
        goto cleanup;
    }

    /*
     * If this is the first host we've tried
     * {
     *	generate the key-pair
     * }
     */

    if (NULL == *rsa) {
        *rsa=client_genkey(keybits); 
        if (*rsa == NULL) {		/* Verify that key generation succeeded.  If not, bail out now! */
            *emsg = "Error generating RSA key pair.";
            rc = (*err_num_ptr = KX509_STATUS_CLNT_BAD);
	    goto cleanup;
        }
	 
        log_printf("try_ca: sending authentication request (len %d) to KCA\n",
                   k5_authent.length);
        
    }

	
    /* CONVERT KEY-PAIR INFO AND AUTHENT TO REQUEST */

    pubkey_ptr = lbuffer;
    tmp_ptr = (unsigned char *)pubkey_ptr;
    pubkey_len = i2d_RSAPublicKey (*rsa, (unsigned char **)&tmp_ptr);

    log_printf("try_ca: sending pubkey_len=%d bytes of public key\n", pubkey_len);

    request = KX509_REQUEST_new();
    fill_in_octet_string(request->authenticator,
                         k5_authent.data, k5_authent.length);

    fill_in_octet_string(request->pkey, pubkey_ptr, pubkey_len);
    KX509_REQUEST_compute_checksum((unsigned char *)version_2_0_string, request,
                                   request->hash, sess_key, *sess_len_ptr);

    /* CONVERT REQUEST STRUCTURE TO WIRE-VERSION MSG */

    log_printf("try_ca: authent.length is %d, and pubkey_len is %d\n",
               k5_authent.length, pubkey_len);

    len = i2d_KX509_REQUEST(request, 0) + 4;
    log_printf("try_ca: Checking len %d against MAX_UDP_PAYLOAD_LEN %d\n",
               len, MAX_UDP_PAYLOAD_LEN);
    if (len > MAX_UDP_PAYLOAD_LEN) {
        log_printf("try_ca: len=%d MAX_UDP_PAYLOAD_LEN=%d\n",
                   len, MAX_UDP_PAYLOAD_LEN);
        *emsg = "Weird!  KX509 transmit packet is too large!";
        rc = (*err_num_ptr = KX509_STATUS_CLNT_BAD);
	goto cleanup;
    }

    if (MSG_ALLOC(&pkt_to_send, len)) {
        log_printf("try_ca: could not allocate %d bytes?\n", len);
        *emsg = "Try again.  (Hopefully) transient client-side malloc problem";
        rc = (*err_num_ptr = KX509_STATUS_CLNT_TMP);
	goto cleanup;
    }

    memcpy(pkt_to_send.m_data, version_2_0_string, 4);
    tmp_ptr = pkt_to_send.m_data+4;
    i2d_KX509_REQUEST(request, &tmp_ptr);
    pkt_to_send.m_curlen = tmp_ptr - pkt_to_send.m_data;

    /* XXX This won't work on macintosh */
    if (debugPrint) {
        PEM_write(stderr, "kx509 request", ca_hostname,
                  pkt_to_send.m_data+4, pkt_to_send.m_curlen-4);
    }


    /* DETERMINE IP ADDRESS OF KCA SERVER */

    if (!(ca_hostent = gethostbyname(ca_hostname))) {
		DWORD gle = WSAGetLastError();
        StringCbCopyA(buffer, sizeof(buffer), wsa_strerror(gle));
        log_printf("try_ca: gethostbyname of CA (%s) failed ('%s')\n",
                   ca_hostname, buffer);
        *emsg = "try_ca: gethostbyname failed";
        rc = (*err_num_ptr = KX509_STATUS_CLNT_TMP);
	goto cleanup;
    }

    memset(&ca_addr, 0, sizeof(ca_addr));
    ca_addr.sin_family	= AF_INET;
    ca_addr.sin_port	= htons(KCA_PORT);
    ca_addr.sin_addr.s_addr	= *(int *)(ca_hostent->h_addr_list[0]);

    /* "CONNECT" TO IT (ICMP RESPONSE INDICATES HOST ISN'T LISTENING ON THAT PORT) */

    log_printf("try_ca: About to connect to KCA at %s:%d\n",
               inet_ntoa(ca_addr.sin_addr), KCA_PORT);
    if (udp_nb_connect(socket, &ca_addr) == -1) {
		DWORD gle = WSAGetLastError();
        StringCbCopyA(buffer, sizeof(buffer), wsa_strerror(gle));
        log_printf("try_ca: udp_nb_connect failed with errno %d ('%s')\n",
                   errno, buffer);
        *emsg = "try_ca: udp_nb_connect failed";
        rc = (*err_num_ptr = KX509_STATUS_CLNT_TMP);
	goto cleanup;
    }

    /* SOMETHINGS LISTENING -- SEND PACKET */

    i = udp_nb_send(socket, &pkt_to_send);
    log_printf("try_ca: sent KX_CLNT_PKT of %0d bytes (rc = %d) \n",
               pkt_to_send.m_curlen, i);

    /* RECV WIRE-VERSION OF KX_SRVR_PKT FROM CA SERVER */

    if (MSG_ALLOC(&pkt_recvd, MAX_KSP_LEN)) {
        log_printf("try_ca: failed to allocate %d bytes for recv pkt?\n", MAX_KSP_LEN);
        *emsg = "Try again.  (Hopefully) transient client-side malloc problem";
        rc = (*err_num_ptr = KX509_STATUS_CLNT_TMP);
	goto cleanup;
    }

    /* WAIT UP TO "KX509_CLIENT_TIMEOUT" SECONDS FOR RESPONSE */

    FD_ZERO(&readfds);
    FD_SET((WORD)socket, &readfds);
    timeout.tv_sec = KX509_CLIENT_TIMEOUT;
    timeout.tv_usec = 0;
    i = udp_nb_select(&readfds, NULL, NULL, &timeout);
    if (i<0) {
		DWORD gle = WSAGetLastError();
        StringCbCopyA(buffer, sizeof(buffer), wsa_strerror(gle));
        log_printf("try_ca: udp_nb_select failed with code %d, errno %d ('%s')\n",
                   i, errno, buffer);
        *emsg = "Error return waiting for response.";
        rc = (*err_num_ptr = KX509_STATUS_CLNT_TMP);
	goto cleanup;
    } else if (i==0) {
        log_printf("try_ca: timeout during udp_nb_select\n");
        *emsg = "Timed out waiting for response from a Kerberized Certificate Authority";
        rc = (*err_num_ptr = KX509_STATUS_CLNT_TMP);
	goto cleanup;
    }

    if (udp_nb_recv(socket, &pkt_recvd) == -1) {
		DWORD gle = WSAGetLastError();
        StringCbCopyA(buffer, sizeof(buffer), wsa_strerror(gle));
        log_printf("try_ca: udp_nb_recv failed with errno %d ('%s')\n",
                   gle, buffer);

        if (gle == WSAECONNREFUSED) {
            *emsg = "Try again later.  None of the Kerberized Certificate Authorities are currently available.";
        } else {
            *emsg = "Strange.  Unexpected error on receive.";
        }
        rc = (*err_num_ptr = KX509_STATUS_CLNT_TMP);
	goto cleanup;
    }

    *emsg = NULL;
    rc = (*verify_recvd_packet)(&pkt_recvd, arg);

  cleanup:
    krb5_free_data_contents(k5_context, &k5_authent);

    if (pkt_to_send.m_data)
        MSG_FREE(&pkt_to_send);
    if (pkt_recvd.m_data)
        MSG_FREE(&pkt_recvd);

    KX509_REQUEST_free(request);
    return(rc);
}


void fill_in_octet_string(ASN1_OCTET_STRING *osp,
                          char *st,
                          int len)
{
    char *c;
    if (osp->data && osp->length)
        Free(osp->data);

    if (len <= 0)
        return;

    c = Malloc(len);
    memcpy(c, st, len);
    osp->data = (unsigned char *)c;
    osp->length = len;
}

struct verify_arg {
    KX509_RESPONSE	*response;
    char sess_key[32];
    int sess_len;
    char *emsg;
};


int
verify_recvd_packet(KX_MSG		*pkt_recvd,
                    void 		*arg)
{
    unsigned char *p;
    int length;
    ASN1_OCTET_STRING *hash = NULL;
    int result = 0;
    struct verify_arg *varg = (struct verify_arg *)arg;
    static char buffer[2048];	/* returned as error message - not thread safe */

    if (pkt_recvd->m_curlen < 4) {
        StringCbPrintfA(buffer, sizeof(buffer),
                        "verify_recvd_packet: received runt of length %d",
                        pkt_recvd->m_curlen);
        varg->emsg = buffer;
        result = KX509_STATUS_CLNT_BAD;
	goto cleanup;
    }
    if (2[(unsigned char *)pkt_recvd->m_data] != version_2_0_string[2]) {
        StringCbPrintfA(buffer, sizeof(buffer),
                        "verify_recvd_packet: rec'd version %d.%d does not match %d.*",
                        2[(unsigned char *)pkt_recvd->m_data],
                        3[(unsigned char *)pkt_recvd->m_data],
                        version_2_0_string[2]);
        varg->emsg = buffer;
        result = KX509_STATUS_CLNT_BAD;
	goto cleanup;
    }
    p = pkt_recvd->m_data+4;
    length = pkt_recvd->m_curlen-4;
    if (!(varg->response = d2i_KX509_RESPONSE(NULL, &p, length))) {
        varg->emsg = "verify_recvd_packet: d2i_X509_RESPONSE failed";
        result = KX509_STATUS_CLNT_BAD;
	goto cleanup;
    }
    if (!varg->response->hash) {
        if (varg->response->error_message) {
            int xlen = sizeof buffer-1;
            if (xlen > varg->response->error_message->length)
                xlen=varg->response->error_message->length;
            memcpy(buffer, varg->response->error_message->data, xlen);
            buffer[xlen] = 0;
            varg->emsg = buffer;
        }
        result = varg->response->status ?
            varg->response->status : KX509_STATUS_CLNT_BAD;
	goto cleanup;
    }
    if (!(hash = ASN1_OCTET_STRING_new())) {
        varg->emsg = "verify_recvd_packet: out of memory";
        result = KX509_STATUS_CLNT_BAD;
	goto cleanup;
    }
    KX509_RESPONSE_compute_checksum(pkt_recvd->m_data,
                                    varg->response,
                                    hash,
                                    varg->sess_key, varg->sess_len);
    if (hash->length != varg->response->hash->length
        || memcmp(hash->data, varg->response->hash->data, hash->length)) {
        varg->emsg = "verify_recvd_packet: generated hash did not compare";
        result = KX509_STATUS_CLNT_BAD;
    }

  cleanup:
    if (hash)
	ASN1_OCTET_STRING_free(hash);
    return result;
}

RSA *client_genkey(int keybits) 
{ 
    RSA *rsa=NULL; 
#ifdef drh
    char *inrand=NULL; 
    char *outfile=NULL; 
#endif /* drh */
    DWORD f4=RSA_F4; 
    BIO 	*bio_err	= NULL; 
 
#ifdef drh
    /* assign constants to needed filenames ... for now */ 
 
    inrand		= "/var/adm/messages"; 
    outfile		= "/tmp/t.key"; 
#endif /* drh */
 
    /* SET-UP HOUSE */ 
 
    if (init) {
	RAND_poll();
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON); 
	ADD_ALL_ALGORITHMS(); 

	if ((bio_err=BIO_new(BIO_s_file())) != NULL) 
	    BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);
	
	init = 0;
    }
 
#ifdef drh 
    gr_load_rand(inrand); 
#endif /* drh */
 
    /* GENERATE KEY-PAIR */ 
 
    rsa=RSA_generate_key(keybits,f4,NULL,NULL); 
		 
    return rsa; 
} 

void
clean_cert(RSA *rsa, X509 *certp)
{
    if (rsa)
	RSA_free(rsa);
    if (certp)
	X509_free(certp);
}

/*
 *=========================================================================*
 *
 * getcert()
 *
 * Attempt to obtain a certificate
 *
 *=========================================================================*
 */
int getcert(RSA	        **rsa,
            X509        **certp,
            char        *emsg,
            int	        elen,
            char        *realm,
            int         realmlen,
            char        *tkt_cache_name,
            char        *ext_hostlist) 
{
    krb5_error_code	k5_result;
    krb5_context	k5_context;
    char		**dns_hostlist = NULL;
    char		**kca_hostlist;
    char		ca_hostname_to_try[256];
    char		*base_realm = NULL;
    char		*env_host_list = NULL;
    int			rc;
    int			n, m;
    struct verify_arg 	arg[1]; 
    SOCKET		socket = INVALID_SOCKET;
    unsigned char	*tmp_ptr;

    WORD		wVersionRequested;
    WSADATA		wsaData;
    int			err;
    char 		buffer[2048];

    /* GET SOCKET */

    wVersionRequested = MAKEWORD( 2, 2 );
 
    err = WSAStartup( wVersionRequested, &wsaData );
    if ( err != 0 )
	return FALSE;

    /* Confirm that the WinSock DLL supports 2.2.*/
    /* Note that if the DLL supports versions greater    */
    /* than 2.2 in addition to 2.2, it will still return */
    /* 2.2 in wVersion since that is the version we      */
    /* requested.                                        */

    if ( LOBYTE( wsaData.wVersion ) != 2 ||
	 HIBYTE( wsaData.wVersion ) != 2 ) {
	/* Tell the user that we could not find a usable */
	/* WinSock DLL.                                  */
	WSACleanup( );
	return FALSE;
    }

    *certp = NULL;
    *emsg = '\0';
    memset((char*)arg, 0, sizeof *arg);
    arg->sess_len = sizeof(arg->sess_key);

    /* CREATE SOCKET TO BIND TO CA SERVER */

    if ((socket=udp_nb_socket(0)) == INVALID_SOCKET) {
#if _MSC_VER >= 1400
        strerror_s(buffer, sizeof(buffer), errno);
#else
        StringCbCopyA(buffer, sizeof(buffer), strerror(errno));
#endif
        log_printf("try_ca: udp_nb_socket failed to obtain a socket ('%s')\n",
                   buffer);
        arg->emsg = "Failed to create a socket.\n";
        rc = KX509_STATUS_CLNT_TMP;
        goto Failed;
    }

    if ((k5_result = krb5_init_context(&k5_context))) {
        const char * result_text = error_message(k5_result);

        _report_cs1(KHERR_DEBUG_1, L"getcert: unable to initialize Kerberos 5 context: %1!S!",
                    _cptr(result_text));
        _resolve();
        arg->emsg = "Verify KRB5 configuration. Failed to initialize Kerberos 5 context.\n";
        rc = KX509_STATUS_CLNT_BAD;
        goto Failed;
    }

    /* Determine the realm */

    /* we only get the the realm from the ccache if we haven't been
       given a realm. */
    if (realm[0] == '\0' &&
        (rc = get_krb5_realm(k5_context, realm, realmlen,
                             tkt_cache_name, &arg->emsg))) {
        /*		log_printf("getcert: failed to determine kerberos realm information (%d)\n", rc); */
        /*		arg->emsg = "Failed to determine kerberos realm information.\n"; */
        /*		rc = KX509_STATUS_CLNT_BAD; */
        goto Failed;
    }

    log_printf("getcert: for realm [%s]", realm);

    /*
     * We use one of three ways to determine the hostname(s) of the KCA server(s):
     *
     * 1.  if the ext_hostlist parameter is non-NULL and not empty, we
     *     use the list of hostnames specified there.
     *
     * 2.  if the KCA_HOST_LIST environment variable is defined,
     *	   we simply use the list of hostname(s) defined there
     *
     * 3.  otherwise, we *assume* that the KCA servers can be
     *	   reached by resolving the hostname(s) that Kerberos
     *	   expects the KDC to be at for a given base_realm as
     *	   specified in /etc/krb.conf
     *
     *		(note: for the "ENGIN.UMICH.EDU" realm,
     *		       "UMICH.EDU" is used for base_realm)
     */

    /* DNS SRV records should obviate need for ENGIN->UMICH mapping */
    base_realm = realm;

    env_host_list = NULL;

    if (ext_hostlist != NULL && ext_hostlist[0] == '\0')
        ext_hostlist = NULL;

#if 0
    if (ext_hostlist == NULL) {
#if defined(WIN32) && _MSC_VER >= 1400
        _dupenv_s(&env_host_list, NULL, "KCA_HOST_LIST");
#else
        env_host_list = getenv("KCA_HOST_LIST");
#endif
    }
#endif

    if (env_host_list != NULL || ext_hostlist != NULL) {
        char *host;
        int hostcount = 0;
        char *hostlist = NULL;
        char **hostarray = NULL;
        size_t len = 0;

        /* Make a copy of the environment string, if needed */
        if (ext_hostlist == NULL) {
            if (FAILED(StringCbLengthA(env_host_list, MAX_KCA_HOSTS * (256),
                                       &len))) {
                rc = KX509_STATUS_CLNT_FIX;
                arg->emsg = "Bad KCA_HOST_LIST environment value";
                goto Failed;
            }

#if defined(WIN32) && _MSC_VER >= 1400
            hostlist = env_host_list;
#else
            if (len) {
                len += sizeof(char);
                hostlist = malloc(len);
            } else {
                hostlist = NULL;
            }

            if (hostlist) {
                StringCbCopyA(hostlist, len, env_host_list);
            } else {
                rc = KX509_STATUS_CLNT_FIX;
                arg->emsg = "Empty KCA_HOST_LIST environment variable or malloc error";
                goto Failed;
            }
#endif
        } else {
            hostlist = ext_hostlist;
        }

        hostarray = calloc(MAX_KCA_HOSTS + 1, sizeof(char *));

        if (hostarray) {
#if defined(WIN32) && _MSC_VER >= 1400
            char * context = NULL;

            host = strtok_s(hostlist, " ", &context);
            while (host != NULL && *host != '\0') {
                hostarray[hostcount++] = host;
                host = strtok_s(NULL, " ", &context);
            }
#else  /* not using safe CRT functions */
            /* Separate the hosts in the list and keep an array of pointers */
            host = strtok(hostlist, " ");
            while (host != NULL && *host != '\0') {
                hostarray[hostcount++] = host;
                host = strtok(NULL, " ");
            }
#endif
        } else {
            rc = KX509_STATUS_CLNT_BAD;
            arg->emsg = "Error allocating array for KCA_HOST_LIST";
            goto Failed;
        }

#if !defined(WIN32) || _MSC_VER < 1400
        if (ext_hostlist == NULL) {
            free(hostlist);
            hostlist = NULL;
        }
#endif

        if (hostcount <= 0) {
            rc = KX509_STATUS_CLNT_IGN;
            arg->emsg = "Empty KCA_HOST_LIST environment variable or tokenize error";
            goto Failed;
        }

        kca_hostlist = hostarray;

    } else {
        if (get_kca_list(base_realm, &dns_hostlist)) {
            rc = KX509_STATUS_CLNT_IGN;
            arg->emsg = "DNS SRV lookup of KCA hostname(s) failed!";
            goto Failed;
        } else {
            kca_hostlist = dns_hostlist;
        }
    }

    if (kca_hostlist[0]) {
        rc = KX509_STATUS_CLNT_IGN;
        arg->emsg = "Error!  Unable to determine KCA hostname(s)!";
    }

    /* ITERATE THROUGH LIST OF KCA HOSTNAMES 
     * RETRYING A MINIMUM OF THREE TIMES 
     */
    for (m=0; m < 3;) {
	for (n=0; kca_hostlist[n]; n++, m++) {
	    int e;

	    log_printf("try_ca trying '%s' n=%d m=%d\n", kca_hostlist[n], n, m);
	    StringCbCopyA(ca_hostname_to_try,
			   sizeof(ca_hostname_to_try),
			   kca_hostlist[n]);

	    /* Exit the loop as soon as we get a good response */
	    if (!(rc = try_ca(k5_context, socket, ca_hostname_to_try,
			       realm, rsa, certp, verify_recvd_packet,
			       (void*)arg, arg->sess_key, &arg->sess_len,
			       tkt_cache_name,
			       &arg->emsg, &e))) 
	    {
			m = 3;
			break;
	    } else {
		log_printf("try_ca to '%s' returned rc %d, ecode %d, emsg '%s'\n",
			    ca_hostname_to_try, rc, e, arg->emsg);
	    }
	}
    }

    if (arg->emsg) {
        log_printf("%s\n", arg->emsg);
    }

  Failed:
    if (socket != INVALID_SOCKET)
	closesocket(socket);

    if (dns_hostlist != NULL) {
	Free(dns_hostlist);
    }

#if defined(WIN32) && _MSC_VER >= 1400
    if (env_host_list != NULL) {
            free(env_host_list);
    }
#endif

    if (rc) {
	if (!arg->emsg || !*arg->emsg)
	    arg->emsg = "Missing error message #1";
	StringCchCopyA(emsg, elen, arg->emsg);
    } else if (rc = arg->response->status) {
	if (arg->response->error_message) {
	    log_printf ("status %d; response had error message; contents were:\n", rc);
#ifdef DEBUG	
	    bin_dump((char *)arg->response->error_message->data, arg->response->error_message->length);
#endif
	} else {
	    log_printf ("status %d; response no longer has error message\n", rc);
	}
	if (!arg->response->error_message
	     || !arg->response->error_message->length) {
	    StringCchCopyA(emsg, elen, "Missing error message #2");
	     } else {
		 if (arg->response->error_message->length > (elen-1))
		     arg->response->error_message->length = elen-1;
		 memcpy(emsg,
			arg->response->error_message->data,
                        arg->response->error_message->length);
		 emsg[arg->response->error_message->length] = 0;
	     }
    } else if (arg->response->certificate) {
	tmp_ptr = arg->response->certificate->data;
	if (!(*certp = d2i_X509(NULL, &tmp_ptr,
				arg->response->certificate->length))) {
	    StringCchCopyA(emsg, elen, "getcert: d2i_X509 failed");
	    rc = KX509_STATUS_CLNT_BAD;
	}
    } else {
	StringCchCopyA(emsg, elen, "getcert: missing certificate");
	rc = KX509_STATUS_CLNT_BAD;
    }

    KX509_RESPONSE_free(arg->response);

    WSACleanup( );
    return rc;
}

#ifdef DEBUG

/*
 *=========================================================================*
 *
 * print_response()
 *
 *=========================================================================*
 */
void print_response(KX509_RESPONSE *client_response) {
    log_printf ("response status %d\n", client_response->status);
    if (client_response->certificate) {
        log_printf ("response certificate:\n");
        bin_dump((char *)client_response->certificate->data,
                 client_response->certificate->length);
    } else log_printf ("no response certificate\n");
    if (client_response->hash) {
        log_printf ("response hash:\n");
        bin_dump((char *)client_response->hash->data,
                 client_response->hash->length);
    } else log_printf ("no response hash\n");
    if (client_response->error_message) {
        log_printf ("response error_message:\n");
        bin_dump((char *)client_response->error_message->data,
                 client_response->error_message->length);
    } else log_printf ("no response error_message\n");
    return;
}

/*
 *=========================================================================*
 *
 * print_request()
 *
 *=========================================================================*
 */
void print_request(KX509_REQUEST *server_request)
{
    log_printf ("request Authenticator:\n");
    bin_dump((char *)server_request->authenticator->data,
             server_request->authenticator->length);
    log_printf ("request hash:\n");
    bin_dump((char *)server_request->hash->data,
             server_request->hash->length);
    log_printf ("request pkey:\n");
    bin_dump((char *)server_request->pkey->data,
             server_request->pkey->length);
}

/*
 *=========================================================================*
 *
 * bin_dump()
 *
 *=========================================================================*
 */
bin_dump(char *cp, int s)
{
    char *buffer;
    char c;
    int w;
    int i;
    long o;

    o = 0;
    buffer = cp;
    while (s > 0) {
        c = 16;
        if (c > s) c = s;
        log_printf ("%06lx:", o);
        w = 0;
        for (i = 0; i < c/2; ++i)
            w += 5, log_printf (" %4x", ((unsigned short *)buffer)[i]);
        if (c & 1)
            w += 3, log_printf (" %2x", buffer[c-1]);
        while (w < 41)
            ++w, log_printf(" ");
        for (i = 0; i < c; ++i)
            if (isprint(buffer[i]))
                log_printf("%c", buffer[i]);
            else
                log_printf(".");
        log_printf("\n");
        o += c;
        buffer += c;
        s -= c;
    }
    log_printf ("%06lx:\n", o);
    return 1;
}
#endif
