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

#ifdef _WIN32
# include <windows.h>
#endif /* WIN32 */

#include "debug.h"

#ifndef ANSI
# ifdef macintosh
#   define DEBUG
#   include <stdarg.h>
# else /* macintosh */
#   include <varargs.h>
# endif /* macintosh */
#endif /* !ANSI */

/* Debug file for windows release version */
static FILE *dbgfile = NULL;
static int triedtoopen = 0;

#ifdef _WIN32
#define DEBUG_FILE_NAME "c:\\temp\\pkcs11dbg.txt"
#else
#define DEBUG_FILE_NAME "/tmp/pkcs11dbg.txt"
#endif



void log_dump(void *pin, char *label, int len)
{
    CK_BYTE *p = (CK_BYTE *)pin;
    int	i;

    log_printf("%s (%0d bytes):", label, len);
    for (i=0; i<len; i++)
    {
	if ((i & 0x7) == 0)
	    log_printf("\n    ");
	log_printf("0x%02X, ", p[i]);
    }
    log_printf("\n");
}


void try_open()
{
    triedtoopen = 1;
    /*
     * Try to open file for read.  If the file exists,
     * then re-open it for writing. 
     * Truncating any existing data
     */
    if ((dbgfile = fopen(DEBUG_FILE_NAME, "r")) != NULL) {
	fclose(dbgfile);
	dbgfile = fopen(DEBUG_FILE_NAME, "w");
    }
}

#ifdef _WIN32
void log_write(char *data, int len)
{
    char buffer[2048];
    int i;
	
    for (i = 0; i < len; i++)
	sprintf(&buffer[i], "%c", data[i]);

    buffer[len] = '\0';
#ifdef DEBUG
    OutputDebugString(buffer);
#else
    if (dbgfile == NULL && triedtoopen == 0)
    {
	try_open();
    }
    if (dbgfile != NULL)
    {
	fprintf(dbgfile, "%s", buffer);
	fflush(dbgfile);
    }
#endif
}


void log_printf(char *fmt, ...)
{
#ifdef DEBUG
    char buffer[2048];
#endif
	
    va_list vargs;

    va_start(vargs,fmt);
	
#ifdef DEBUG
    vsprintf(buffer, fmt, vargs);
    OutputDebugString(buffer);
#else
    if (dbgfile == NULL && triedtoopen == 0)
    {
	try_open();
    }
    if (dbgfile != NULL)
    {
	vfprintf(dbgfile, fmt, vargs);
	fflush(dbgfile);
    }
#endif	
	
    va_end(vargs);
}


#else /* UNIX compatible versions */

 
void log_write(char *data, int len)
{
#ifdef DEBUG
    char buffer[2048];
    int i;
	
    if (dbgfile == NULL && triedtoopen == 0)
    {
	try_open();
    }
    if (dbgfile != NULL)
    {
	for (i = 0; i < len; i++)
	    sprintf(&buffer[i], "%c", data[i]);

	buffer[len] = '\0';
	fprintf(dbgfile, "%s", buffer);
	fflush(dbgfile);
    }
#endif /* DEBUG */
}

void log_printf(va_alist)
#ifdef macintosh
int va_alist;
#else /* !macintosh */
va_dcl
#endif /* macintosh */
{
    va_list	ap;
    char	*fmt;
	

#ifdef macintosh
    va_start(ap, va_alist);
#else /* !macintosh */	
    va_start(ap);
#endif /* macintosh */
	
    fmt = va_arg(ap, char *);

    if (dbgfile == NULL && triedtoopen == 0)
    {
	try_open();
    }
    if (dbgfile != NULL)
    {
	vfprintf(dbgfile, fmt, ap);
	fflush(dbgfile);
    }
#ifdef DEBUG
    else 
    {
	vfprintf(stderr, fmt, ap);
    }
#endif /* DEBUG */
	
    va_end(ap);
}
#endif /* WIN32 */
