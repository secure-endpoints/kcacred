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

#include <time.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <string.h> 
#ifdef _WIN32
#include <winsock.h> 
#include <windows.h> 
#else /* WIN32 */ 
#include <netdb.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <sys/socketvar.h> 
#include <sys/fcntl.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
typedef int SOCKET;
#endif /* WIN32 */ 
#include <openssl/x509v3.h>
#include "debug.h" 
 
#define	BUF_LEN	2048 
#define	DEFBITS	1024 
 
typedef unsigned long DWORD; 
 
 
SOCKET
connect_x509(char *hostname, u_short port_no) 
{ 
    char *rn = "connect_x509"; 
 
    struct sockaddr_in peeraddr; 
    struct hostent *phostent; 
    int	optrc; 
    SOCKET	s; 

    struct  linger linger  =  {1, 1};          /* Linger Option set to 1 */ 
                                               /*   for 1 second         */ 

    phostent = gethostbyname (hostname);  
    if( phostent == NULL)  
    { 
	log_printf("%s: unknown host\n", rn); 
	return 0; 
    } 

    log_printf("%s: Host official name: %s\n", rn, phostent->h_name); 

    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)  
    { 
#ifdef _WIN32 
	log_printf("%s: Failed creating socket 0x%08x (%d)\n", 
		    rn, WSAGetLastError(), WSAGetLastError()); 
#else 
	log_printf("%s: Failed creating socket\n%s\n", 
		    rn, strerror(errno)); 
#endif 
	return 0; 
    } 
 
    log_printf("%s: Issuing connect to port %d\n", rn, port_no); 
    peeraddr.sin_family = AF_INET; 
    peeraddr.sin_port   = htons(port_no); 
    peeraddr.sin_addr.s_addr = ((struct in_addr *)(phostent->h_addr))->s_addr; 
    if (connect(s, (struct sockaddr *) &peeraddr, sizeof(struct sockaddr_in))  == -1)  
    { 
#ifdef _WIN32 
        log_printf("%s: Failed connecting socket 0x%08x (%d)\n", 
		    rn, WSAGetLastError(), WSAGetLastError()); 
#else 	
	log_printf("%s: Failed connecting socket\n%s\n", 
		    rn, strerror(errno));  
#endif 
  
	return 0; 
    } 
 
    /* 
    ** set the linger option.  This gives us a "Graceful" close 
    ** meaning we receive all the data before the socket closes. 
    */ 
    optrc = setsockopt (s, SOL_SOCKET, SO_LINGER,  
			 (char *) &linger, sizeof (struct linger)); 
    if (optrc == -1) 	
	log_printf("%s: Unable to set linger option on socket\n%s\n", 
		    rn, strerror(errno)); 
    return s; 
} 
 
 
/*
 * Convert an ASN.1 UTCTime structure into unix time format
 */
time_t utc2unix(ASN1_UTCTIME *utctime, time_t *unixtime)
{
    char *utcchars;
    int length, temp;
    time_t utime;
    char *current;
    struct tm tms;
#if defined(_WIN32)
    int  DayLight;
    long TimeZone;
#endif

    memset(&tms, '\0', sizeof(tms));

    utime = -1;				/* preset with error return */

    /*
     * XXX Here we are making the assumption that all times are (UTC/ZULU)
     * XXX and that all times include the seconds value.
     */
    length = utctime->length;
    if (length != 13)
	goto returntime;

    utcchars = (char*) utctime->data;
    if (utcchars[12] != 'Z')
	goto returntime;

    current = utcchars;
    temp = (current[0]-'0')*10 + (current[1]-'0');	/* get year value */
    if (temp < 50)		/* UTCTime runs from 1950 - 2049 */
	temp += 100;	/* Must use GeneralizedTime after 2049 */
    tms.tm_year = temp;

    current+=2;
    temp = (current[0]-'0')*10 + (current[1]-'0');	/* get month value */
    temp--;			/* make it zero based */
    tms.tm_mon = temp;

    current+=2;
    temp = (current[0]-'0')*10 + (current[1]-'0');	/* get day of the month value */
    tms.tm_mday = temp;

    current+=2;
    temp = (current[0]-'0')*10 + (current[1]-'0');	/* get hour value */
    tms.tm_hour = temp;

    current+=2;
    temp = (current[0]-'0')*10 + (current[1]-'0');	/* get minute value */
    tms.tm_min = temp;

    current+=2;
    temp = (current[0]-'0')*10 + (current[1]-'0');	/* get seconds value */
    tms.tm_sec = temp;

    tms.tm_isdst = -1;		/* Forces mktime to check DST */

#if defined(OPENBSD) || defined(_DARWIN)
    /*
     * mktime() doesn't seem to work the same on OpenBSD
     * as others (like linux and Solaris).  It would seem
     * that this should be a call to timelocal().
     * But hey, it works...
     */
    utime = timegm(&tms);
#elif defined(_WIN32)
    _tzset();						/* Make sure timezone & daylight are set */
    TimeZone = _timezone;
    DayLight = _daylight;
    utime = mktime(&tms);		/* get unix time (GMT) */
    if (utime != -1) {
	utime = utime - TimeZone + DayLight * 3600;
    }
#else
    tzset();						/* Make sure timezone & daylight are set */
    utime = mktime(&tms);		/* get unix time (GMT) */
    if (utime != -1) {
	utime = utime - timezone + daylight*3600;
    }
#endif

  returntime:
    if (unixtime)
	*unixtime = utime;
    return utime;
}
