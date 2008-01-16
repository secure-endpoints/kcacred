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

/* b64.c -- base-64 encoding/decoding, for pem files */

int b64_decode();
void b64_do_decode();
void b64_dodecode_padding();
void _b64_init();
int b64_encode();
void b64_do_encode();
void b64_doencode_padding();


static char b64_encoding[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char b64_decoding[256];
int b64_init_done=0;

/* these routines all expect to be called with a preallocated 'out' where the
   results get put. */
int b64_decode(char *string, int len, char *out)
{
    int i;
    char bitstring[4];
    int pad;
    int b64_cnt=0;

    for (i=0;i<len-4;) {
	bitstring[0]=string[i++];
	bitstring[1]=string[i++];
	bitstring[2]=string[i++];    
	bitstring[3]=string[i++];
	b64_do_decode(bitstring,out,&b64_cnt);
    }
    bitstring[0]=string[i++];
    bitstring[1]='\0';
    bitstring[2]='\0';
    bitstring[3]='\0';
    pad=0;
    if (string[i]!='=') {
	bitstring[1]=string[i++];
	if (string[i]!='=') {
	    bitstring[2]=string[i++];
	    if (string[i]!='=') bitstring[3]=string[i++];
	    else { bitstring[3]='\0'; pad=1; }
	}
	else { bitstring[2]='\0'; pad=2; }
    }
    else { bitstring[1]='\0'; pad=3; }
    b64_dodecode_padding(bitstring,pad,out,&b64_cnt);
    out[b64_cnt]='\0';
    return(b64_cnt);
}

void b64_do_decode(char *bitstring, char *out, int *b64_cnt)
{
    int i;

    for (i=0; i<4; i++)
    {
#if 0
	log_printf("bitstring[i]=0x%02X, b64_decoding[(int)bitstring[i]]=0x%02X\n",
		    bitstring[i],
		    b64_decoding[(int)bitstring[i]] );
#endif
	bitstring[i]=b64_decoding[(int)bitstring[i]]; 
    }
    bitstring[0]=(bitstring[0]<<2) | (bitstring[1]>>4);
    bitstring[1]=(bitstring[1]<<4) | (bitstring[2]>>2);
    bitstring[2]=(bitstring[2]<<6) | bitstring[3];
    bitstring[3]='\0';
    out[(*b64_cnt)++]=bitstring[0];
    out[(*b64_cnt)++]=bitstring[1];
    out[(*b64_cnt)++]=bitstring[2];
    return;
}

void b64_dodecode_padding(char *bitstring, int pad, char *out, int *b64_cnt)
{
    int i;

    for (i=0; i<4; i++)
	bitstring[i]=b64_decoding[(int)bitstring[i]];
    bitstring[0]=(bitstring[0]<<2) | (bitstring[1]>>4);
    bitstring[1]=(bitstring[1]<<4) | (bitstring[2]>>2);
    bitstring[2]=(bitstring[2]<<6) | bitstring[3];
    bitstring[3]='\0';
    out[(*b64_cnt)++]=bitstring[0];
    if (pad<2)
	out[(*b64_cnt)++]=bitstring[1];
    if (pad<1)
	out[(*b64_cnt)++]=bitstring[2];
    return;
}

void _b64_init(void)
{
    unsigned char i;

    for (i=0; i<256; i++)
	b64_decoding[i]='\0';

    for (i=0; i<64; i++)
	b64_decoding[b64_encoding[i]]=i;

    b64_init_done++;
    return;
}


int b64_encode(char *string, int len, char *out)
{
    int i;
    char bitstring[4];
    int pad;
    int b64_cnt=0;

    for (i=0;i<len-3;) {
	bitstring[0]=string[i++];
	bitstring[1]=string[i++];
	bitstring[2]=string[i++];    
	bitstring[3]='\0';
	b64_do_encode(bitstring,out,&b64_cnt);
    }
    bitstring[0]=string[i++];
    pad=0;
    if (i<=len-1) {
	bitstring[1]=string[i++];
	if (i<=len-1) bitstring[2]=string[i++];
	else { bitstring[2]='\0'; pad=1; }
    }
    else { bitstring[1]='\0'; pad=2; }
    b64_doencode_padding(bitstring,pad,out,&b64_cnt);
    out[b64_cnt]='\0';
    return(b64_cnt);
}	


void 
b64_doencode_padding(char *bitstring, int pad, char *out, int *b64_cnt)
{
    out[(*b64_cnt)++]=b64_encoding[(bitstring[0]&0374) >> 2];
    out[(*b64_cnt)++]=b64_encoding[((bitstring[0]&0003) << 4) + ((bitstring[1]&0360) >> 4)];
    if (pad==2) {
	out[(*b64_cnt)++]='=';
	out[(*b64_cnt)++]='=';
	return;
    }
    out[(*b64_cnt)++]=b64_encoding[((bitstring[1]&0017) << 2) + ((bitstring[2]&0300) >> 6)];
    if (pad==1) {
	out[(*b64_cnt)++]='=';
	return;
    }
    out[(*b64_cnt)++]=b64_encoding[(bitstring[2]&0077)];
    return;
}

void
b64_do_encode(char *bitstring, char *out, int *b64_cnt)
{
    out[(*b64_cnt)++]=b64_encoding[(bitstring[0]&0374) >> 2];
    out[(*b64_cnt)++]=b64_encoding[((bitstring[0]&0003) << 4) + ((bitstring[1]&0360) >> 4)];
    out[(*b64_cnt)++]=b64_encoding[((bitstring[1]&0017) << 2) + ((bitstring[2]&0300) >> 6)];
    out[(*b64_cnt)++]=b64_encoding[(bitstring[2]&0077)];
    return;
}

