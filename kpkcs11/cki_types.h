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

#ifndef _CKI_TYPES_H_
#define _CKI_TYPES_H_

#ifdef _WIN32
# include "win32pre.h"
#endif

#ifndef NULL
# ifdef __cplusplus
#  define NULL 0
# else
#  define NULL (void*)0
# endif /* __cplusplus */
#endif /* NULL */

#ifndef FALSE
# define FALSE 0
#endif /* FALSE */
#ifndef TRUE
# define TRUE (!FALSE)
#endif /* TRUE */

typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_CHAR;
typedef CK_BYTE CK_BBOOL;
typedef unsigned short int CK_USHORT;
typedef short int CK_SHORT;
typedef unsigned long int CK_ULONG;
typedef long int CK_LONG;
typedef CK_ULONG CK_FLAGS;

typedef CK_BYTE * CK_BYTE_PTR;
typedef CK_CHAR * CK_CHAR_PTR;
typedef CK_USHORT * CK_USHORT_PTR;
typedef CK_SHORT * CK_SHORT_PTR;
typedef CK_ULONG * CK_ULONG_PTR;
typedef CK_LONG * CK_LONG_PTR;
typedef void *    CK_VOID_PTR;
typedef void **   CK_VOID_PTR_PTR;

#ifndef _WIN32
# define CK_ENTRY 
# define CK_CALLCONV 
#else
# define CK_ENTRY __declspec( dllexport ) 
# define CK_CALLCONV __cdecl
#endif

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
        returnType __declspec(dllexport) name

#define CK_DECLARE_FUNCTION(returnType, name) \
        returnType __declspec(dllimport) name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
        returnType __declspec(dllimport) (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
        returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR NULL
#endif

typedef CK_ULONG CK_RV;

typedef CK_CALLBACK_FUNCTION(CK_RV, CK_CREATEMUTEX) (
    CK_VOID_PTR_PTR ppMutex
);

typedef CK_CALLBACK_FUNCTION(CK_RV, CK_DESTROYMUTEX) (
    CK_VOID_PTR pMutex
);

typedef CK_CALLBACK_FUNCTION(CK_RV, CK_LOCKMUTEX) (
    CK_VOID_PTR pMutex
);

typedef CK_CALLBACK_FUNCTION(CK_RV, CK_UNLOCKMUTEX) (
    CK_VOID_PTR pMutex
);

typedef struct CK_C_INITIALIZE_ARGS {
    CK_CREATEMUTEX	CreateMutex;
    CK_DESTROYMUTEX	DestroyMutex;
    CK_LOCKMUTEX	LockMutex;
    CK_UNLOCKMUTEX	UnlockMutex;
    CK_FLAGS		flags;
    CK_VOID_PTR		pReserved;
} CK_C_INITIALIZE_ARGS;

typedef CK_C_INITIALIZE_ARGS * CK_C_INITIALIZE_ARGS_PTR;

typedef struct CK_VERSION {
  CK_BYTE major;
  CK_BYTE minor;
} CK_VERSION;

typedef struct CK_INFO {
  CK_VERSION cryptokiVersion;
  CK_CHAR manufacturerID[32];
  CK_FLAGS flags;
  CK_CHAR libraryDescription[32];
  CK_VERSION libraryVersion;
} CK_INFO;

typedef CK_INFO * CK_INFO_PTR;

typedef CK_ULONG CK_NOTIFICATION;

#define CKN_SURRENDER        0
#define CKN_COMPLETE         1
#define CKN_DEVICE_REMOVED   2
#define CKN_TOKEN_INSERTION  3

typedef CK_ULONG CK_SLOT_ID;
typedef CK_SLOT_ID * CK_SLOT_ID_PTR;

typedef struct CK_SLOT_INFO {
  CK_CHAR slotDescription[64];
  CK_CHAR manufacturerID[32];
  CK_FLAGS flags;
  CK_VERSION hardwareVersion;
  CK_VERSION firmwareVersion;
} CK_SLOT_INFO;
typedef CK_SLOT_INFO * CK_SLOT_INFO_PTR;

typedef struct CK_TOKEN_INFO {
  CK_CHAR label[32];
  CK_CHAR manufacturerID[32];
  CK_CHAR model[16];
  CK_CHAR serialNumber[16];
  CK_FLAGS flags;
  CK_ULONG ulMaxSessionCount;
  CK_ULONG ulSessionCount;
  CK_ULONG ulMaxRwSessionCount;
  CK_ULONG ulRwSessionCount;
  CK_ULONG ulMaxPinLen;
  CK_ULONG ulMinPinLen;
  CK_ULONG ulTotalPublicMemory;
  CK_ULONG ulFreePublicMemory;
  CK_ULONG ulTotalPrivateMemory;
  CK_ULONG ulFreePrivateMemory;
  CK_VERSION hardwareVersion;
  CK_VERSION firmwareVersion;
  CK_CHAR utcTime[16];
} CK_TOKEN_INFO;
typedef CK_TOKEN_INFO * CK_TOKEN_INFO_PTR;

typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_SESSION_HANDLE * CK_SESSION_HANDLE_PTR;

typedef CK_ULONG CK_USER_TYPE;

#define CK_SO     0
#define CK_USER    1

typedef CK_ULONG CK_STATE;

#define CKS_RO_PUBLIC_SESSION   0
#define CKS_RO_USER_FUNCTIONS   1
#define CKS_RW_PUBLIC_SESSION   2
#define CKS_RW_USER_FUNCTIONS   3
#define CKS_RWSO_FUNCTIONS      4

typedef struct CK_SESSION_INFO {
  CK_SLOT_ID slotID;
  CK_STATE state;
  CK_FLAGS flags;
  CK_ULONG ulDeviceError;
} CK_SESSION_INFO;
typedef CK_SESSION_INFO * CK_SESSION_INFO_PTR;

typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_OBJECT_HANDLE * CK_OBJECT_HANDLE_PTR;

typedef CK_ULONG CK_OBJECT_CLASS;

#define CKO_DATA             0x00000000
#define CKO_CERTIFICATE      0x00000001
#define CKO_PUBLIC_KEY       0x00000002
#define CKO_PRIVATE_KEY      0x00000003
#define CKO_SECRET_KEY       0x00000004
#define CKO_VENDOR_DEFINED   0x80000000

typedef CK_OBJECT_CLASS * CK_OBJECT_CLASS_PTR;

typedef CK_ULONG CK_KEY_TYPE;

#define CKK_RSA              0x00000000
#define CKK_DSA              0x00000001
#define CKK_DH               0x00000002
#define CKK_ECDSA            0x00000003
#define CKK_MAYFLY           0x00000004
#define CKK_KEA              0x00000005
#define CKK_GENERIC_SECRET   0x00000010
#define CKK_RC2              0x00000011
#define CKK_RC4              0x00000012
#define CKK_DES              0x00000013
#define CKK_DES2             0x00000014
#define CKK_DES3             0x00000015
#define CKK_CAST             0x00000016
#define CKK_CAST3            0x00000017
#define CKK_CAST5            0x00000018
#define CKK_RC5              0x00000019
#define CKK_IDEA             0x0000001A
#define CKK_SKIPJACK         0x0000001B
#define CKK_BATON            0x0000001C
#define CKK_JUNIPER          0x0000001D
#define CKK_CDMF             0x0000001E
#define CKK_VENDOR_DEFINED   0x80000000

typedef CK_ULONG CK_CERTIFICATE_TYPE;

#define CKC_X_509            0x00000000
#define CKC_VENDOR_DEFINED   0x80000000

typedef CK_ULONG CK_ATTRIBUTE_TYPE;

#define CKA_CLASS              0x00000000
#define CKA_TOKEN              0x00000001
#define CKA_PRIVATE            0x00000002
#define CKA_LABEL              0x00000003
#define CKA_APPLICATION        0x00000010
#define CKA_VALUE              0x00000011
#define CKA_CERTIFICATE_TYPE   0x00000080
#define CKA_ISSUER             0x00000081
#define CKA_SERIAL_NUMBER      0x00000082
#define CKA_KEY_TYPE           0x00000100
#define CKA_SUBJECT            0x00000101
#define CKA_ID                 0x00000102
#define CKA_SENSITIVE          0x00000103
#define CKA_ENCRYPT            0x00000104
#define CKA_DECRYPT            0x00000105
#define CKA_WRAP               0x00000106
#define CKA_UNWRAP             0x00000107
#define CKA_SIGN               0x00000108
#define CKA_SIGN_RECOVER       0x00000109
#define CKA_VERIFY             0x0000010A
#define CKA_VERIFY_RECOVER     0x0000010B
#define CKA_DERIVE             0x0000010C
#define CKA_START_DATE         0x00000110
#define CKA_END_DATE           0x00000111
#define CKA_MODULUS            0x00000120
#define CKA_MODULUS_BITS       0x00000121
#define CKA_PUBLIC_EXPONENT    0x00000122
#define CKA_PRIVATE_EXPONENT   0x00000123
#define CKA_PRIME_1            0x00000124
#define CKA_PRIME_2            0x00000125
#define CKA_EXPONENT_1         0x00000126
#define CKA_EXPONENT_2         0x00000127
#define CKA_COEFFICIENT        0x00000128
#define CKA_PRIME              0x00000130
#define CKA_SUBPRIME           0x00000131
#define CKA_BASE               0x00000132
#define CKA_VALUE_BITS         0x00000160
#define CKA_VALUE_LEN          0x00000161
#define CKA_EXTRACTABLE        0x00000162
#define CKA_LOCAL              0x00000163
#define CKA_NEVER_EXTRACTABLE  0x00000164
#define CKA_ALWAYS_SENSITIVE   0x00000165
#define CKA_MODIFIABLE         0x00000170
#define CKA_VENDOR_DEFINED     0x80000000

typedef struct CK_ATTRIBUTE {
  CK_ATTRIBUTE_TYPE type;
  CK_VOID_PTR value;
  CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef CK_ATTRIBUTE * CK_ATTRIBUTE_PTR;

typedef struct CK_DATE {
  CK_CHAR year[4];
  CK_CHAR month[12];
  CK_CHAR day[2];
} CK_DATE;

typedef CK_USHORT CK_MECHANISM_TYPE;

#define CKM_RSA_PKCS_KEY_PAIR_GEN   0x00000000
#define CKM_RSA_PKCS                0x00000001
#define CKM_RSA_9796                0x00000002
#define CKM_RSA_X_509               0x00000003
#define CKM_MD2_RSA_PKCS            0x00000004
#define CKM_MD5_RSA_PKCS            0x00000005
#define CKM_SHA1_RSA_PKCS           0x00000006
#define CKM_DSA_KEY_PAIR_GEN        0x00000010
#define CKM_DSA                     0x00000011
#define CKM_DSA_SHA1                0x00000012
#define CKM_DH_PKCS_KEY_PAIR_GEN    0x00000020
#define CKM_DH_PKCS_DERVIVE         0x00000021
#define CKM_RC2_KEY_GEN             0x00000100
#define CKM_RC2_ECB                 0x00000101
#define CKM_RC2_CBC                 0x00000102
#define CKM_RC2_MAC                 0x00000103
#define CKM_RC2_MAC_GENERAL         0x00000104
#define CKM_RC2_CBC_PAD             0x00000105
#define CKM_RC4_KEY_GEN             0x00000110
#define CKM_RC4                     0x00000111
#define CKM_DES_KEY_GEN             0x00000120
#define CKM_DES_ECB                 0x00000121
#define CKM_DES_CBC                 0x00000122
#define CKM_DES_MAC                 0x00000123
#define CKM_DES_MAC_GENERAL         0x00000124
#define CKM_DES_CBC_PAD             0x00000125
#define CKM_DES2_KEY_GEN            0x00000130
#define CKM_DES3_KEY_GEN            0x00000131
#define CKM_DES3_ECB                0x00000132
#define CKM_DES3_CBC                0x00000133
#define CKM_DES3_MAC                0x00000134
#define CKM_DES3_MAC_GENERAL        0x00000135
#define CKM_DES3_CBC_PAD            0x00000136
#define CKM_CDMF_KEY_GEN            0x00000140
#define CKM_CDMF_ECB                0x00000141
#define CKM_CDMF_CBC                0x00000142
#define CKM_CDMF_MAC                0x00000143
#define CKM_CDMF_MAC_GENERAL        0x00000144
#define CKM_CDMF_CBC_PAD            0x00000145
#define CKM_MD2                     0x00000200
#define CKM_MD2_HMAC                0x00000201
#define CKM_MD2_HMAC_GENERAL        0x00000202
#define CKM_MD5                     0x00000210
#define CKM_MD5_HMAC                0x00000211
#define CKM_MD5_HMAC_GENERAL        0x00000212
#define CKM_SHA_1                   0x00000220
#define CKM_SHA_1_HMAC              0x00000221
#define CKM_SHA_1_HMAC_GENERAL      0x00000222
#define CKM_CAST_KEY_GEN            0x00000300
#define CKM_CAST_ECB                0x00000301
#define CKM_CAST_CBC                0x00000302
#define CKM_CAST_MAC                0x00000303
#define CKM_CAST_MAC_GENERAL        0x00000304
#define CKM_CAST_CBC_PAD            0x00000305
#define CKM_CAST3_KEY_GEN           0x00000310
#define CKM_CAST3_ECB               0x00000311
#define CKM_CAST3_CBC               0x00000312
#define CKM_CAST3_MAC               0x00000313
#define CKM_CAST3_MAC_GENERAL       0x00000314
#define CKM_CAST3_CBC_PAD           0x00000315
#define CKM_CAST5_KEY_GEN           0x00000320
#define CKM_CAST5_ECB               0x00000321
#define CKM_CAST5_CBC               0x00000322
#define CKM_CAST5_MAC               0x00000323
#define CKM_CAST5_MAC_GENERAL       0x00000324
#define CKM_CAST5_CBC_PAD           0x00000325
#define CKM_RC5_KEY_GEN             0x00000330
#define CKM_RC5_ECB                 0x00000331
#define CKM_RC5_CBC                 0x00000332
#define CKM_RC5_MAC                 0x00000333
#define CKM_RC5_MAC_GENERAL         0x00000334
#define CKM_RC5_CBC_PAD             0x00000335
#define CKM_IDEA_KEY_GEN            0x00000340
#define CKM_IDEA_ECB                0x00000341
#define CKM_IDEA_CBC                0x00000342
#define CKM_IDEA_MAC                0x00000343
#define CKM_IDEA_MAC_GENERAL        0x00000344
#define CKM_IDEA_CBC_PAD            0x00000345
#define CKM_GENERIC_SECRET_KEY_GEN  0x00000350
#define CKM_CONCATENATE_BASE_AND_KEY  0x00000360
#define CKM_CONCATENATE_BASE_AND_DATA 0x00000362
#define CKM_CONCATENATE_DATA_AND_BASE 0x00000363
#define CKM_XOR_BASE_AND_DATA       0x00000364
#define CKM_EXTRACT_KEY_FROM_KEY    0x00000365
#define CKM_SSL3_PRE_MASTER_KEY_GEN 0x00000370
#define CKM_SSL3_MASTER_KEY_DERIVE  0x00000371
#define CKM_SSL3_KEY_AND_MAC_DERIVE 0x00000372
#define CKM_SSL3_MD5_MAC            0x00000380
#define CKM_SSL3_SHA1_MAC           0x00000381
#define CKM_MD5_KEY_DERIVATION      0x00000390
#define CKM_MD2_KEY_DERIVATION      0x00000391
#define CKM_SHA1_KEY_DERIVATION     0x00000392
#define CKM_PBE_MD2_DES_CBC         0x000003A0
#define CKM_PBE_MD5_DES_CBC         0x000003A1
#define CKM_PBE_MD5_CAST_CBC        0x000003A2
#define CKM_PBE_MD5_CAST3_CBC       0x000003A3
#define CKM_PBE_MD5_CAST5_CBC       0x000003A4
#define CKM_KEY_WRAP_LYNKS          0x00000400
#define CKM_KEY_WRAP_SET_OAEP       0x00000401
#define CKM_SKIPJACK_KEY_GEN        0x00001000
#define CKM_SKIPJACK_ECB64          0x00001001
#define CKM_SKIPJACK_CBC64          0x00001002
#define CKM_SKIPJACK_OFB64          0x00001003
#define CKM_SKIPJACK_CFB64          0x00001004
#define CKM_SKIPJACK_CFB32          0x00001005
#define CKM_SKIPJACK_CFB16          0x00001006
#define CKM_SKIPJACK_CFB8           0x00001007
#define CKM_SKIPJACK_WRAP           0x00001008
#define CKM_SKIPJACK_PRIVATE_WRAP   0x00001009
#define CKM_SKIPJACK_RELAYX         0x0000100A
#define CKM_KEA_KEY_PAIR_GEN        0x00001010
#define CKM_KEA_KEY_DERIVE          0x00001011
#define CKM_FORTEZZA_TIMESTAMP      0x00001020
#define CKM_BATON_KEY_GEN           0x00001030
#define CKM_BATON_ECB128            0x00001031
#define CKM_BATON_ECB96             0x00001032
#define CKM_BATON_CBC128            0x00001033
#define CKM_BATON_COUNTER           0x00001034
#define CKM_BATON_SHUFFLE           0x00001035
#define CKM_BATON_WRAP              0x00001036
#define CKM_ECDSA_KEY_PAR_GEN       0x00001040
#define CKM_ECDSA                   0x00001041
#define CKM_ECDSA_SHA1              0x00001042
#define CKM_MAYFLY_KEY_PAIR_GEN     0x00001050
#define CKM_MAYFLY_KEY_DERIVE       0x00001051
#define CKM_JUNIPER_KEY_GEN         0x00001060
#define CKM_JUNIPER_ECB128          0x00001061
#define CKM_JUNIPER_CBC128          0x00001062
#define CKM_JUNIPER_COUNTER         0x00001063
#define CKM_JUNIPER_SHUFFLE         0x00001064
#define CKM_JUNIPER_WRAP            0x00001065
#define CKM_FASTHASH                0x00001070
#define CKM_VENDOR_DEFINED          0x80000000

typedef CK_MECHANISM_TYPE * CK_MECHANISM_TYPE_PTR;

typedef struct CK_MECHANISM {
  CK_MECHANISM_TYPE mechanism;
  CK_VOID_PTR pParameter;
  CK_ULONG ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM * CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO {
  CK_ULONG ulMinKeySize;
  CK_ULONG ulMaxKeySize;
  CK_FLAGS flags;
} CK_MECHANISM_INFO;
typedef CK_MECHANISM_INFO * CK_MECHANISM_INFO_PTR;

#define CKR_OK                                0x00000000
#define CKR_CANCEL                            0x00000001
#define CKR_HOST_MEMORY                       0x00000002
#define CKR_SLOT_ID_INVALID                   0x00000003

/* CKR_FLAGS_INVALID was removed for v2.0 */
/* CKR_GENERAL_ERROR and CKR_FUNCTION_FAILED are new for v2.0 */
#define CKR_GENERAL_ERROR                     0x00000005
#define CKR_FUNCTION_FAILED                   0x00000006

/* CKR_ARGUMENTS_BAD, CKR_NO_EVENT, CKR_NEED_TO_CREATE_THREADS,
 * and CKR_CANT_LOCK are new for v2.01 */
#define CKR_ARGUMENTS_BAD                     0x00000007
#define CKR_NO_EVENT                          0x00000008
#define CKR_NEED_TO_CREATE_THREADS            0x00000009
#define CKR_CANT_LOCK                         0x0000000A

#define CKR_ATTRIBUTE_READ_ONLY               0x00000010
#define CKR_ATTRIBUTE_SENSITIVE               0x00000011
#define CKR_ATTRIBUTE_TYPE_INVALID            0x00000012
#define CKR_ATTRIBUTE_VALUE_INVALID           0x00000013
#define CKR_DATA_INVALID                      0x00000020
#define CKR_DATA_LEN_RANGE                    0x00000021
#define CKR_DEVICE_ERROR                      0x00000030
#define CKR_DEVICE_MEMORY                     0x00000031
#define CKR_DEVICE_REMOVED                    0x00000032
#define CKR_ENCRYPTED_DATA_INVALID            0x00000040
#define CKR_ENCRYPTED_DATA_LEN_RANGE          0x00000041
#define CKR_FUNCTION_CANCELED                 0x00000050
#define CKR_FUNCTION_NOT_PARALLEL             0x00000051

/* CKR_FUNCTION_NOT_SUPPORTED is new for v2.0 */
#define CKR_FUNCTION_NOT_SUPPORTED            0x00000054

#define CKR_KEY_HANDLE_INVALID                0x00000060

/* CKR_KEY_SENSITIVE was removed for v2.0 */

#define CKR_KEY_SIZE_RANGE                    0x00000062
#define CKR_KEY_TYPE_INCONSISTENT             0x00000063

/* CKR_KEY_NOT_NEEDED, CKR_KEY_CHANGED, CKR_KEY_NEEDED,
 * CKR_KEY_INDIGESTIBLE, CKR_KEY_FUNCTION_NOT_PERMITTED,
 * CKR_KEY_NOT_WRAPPABLE, and CKR_KEY_UNEXTRACTABLE are new for
 * v2.0 */
#define CKR_KEY_NOT_NEEDED                    0x00000064
#define CKR_KEY_CHANGED                       0x00000065
#define CKR_KEY_NEEDED                        0x00000066
#define CKR_KEY_INDIGESTIBLE                  0x00000067
#define CKR_KEY_FUNCTION_NOT_PERMITTED        0x00000068
#define CKR_KEY_NOT_WRAPPABLE                 0x00000069
#define CKR_KEY_UNEXTRACTABLE                 0x0000006A

#define CKR_MECHANISM_INVALID                 0x00000070
#define CKR_MECHANISM_PARAM_INVALID           0x00000071

/* CKR_OBJECT_CLASS_INCONSISTENT and CKR_OBJECT_CLASS_INVALID
 * were removed for v2.0 */
#define CKR_OBJECT_HANDLE_INVALID             0x00000082
#define CKR_OPERATION_ACTIVE                  0x00000090
#define CKR_OPERATION_NOT_INITIALIZED         0x00000091
#define CKR_PIN_INCORRECT                     0x000000A0
#define CKR_PIN_INVALID                       0x000000A1
#define CKR_PIN_LEN_RANGE                     0x000000A2

/* CKR_PIN_EXPIRED and CKR_PIN_LOCKED are new for v2.0 */
#define CKR_PIN_EXPIRED                       0x000000A3
#define CKR_PIN_LOCKED                        0x000000A4

#define CKR_SESSION_CLOSED                    0x000000B0
#define CKR_SESSION_COUNT                     0x000000B1
#define CKR_SESSION_HANDLE_INVALID            0x000000B3
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED    0x000000B4
#define CKR_SESSION_READ_ONLY                 0x000000B5
#define CKR_SESSION_EXISTS                    0x000000B6

/* CKR_SESSION_READ_ONLY_EXISTS and
 * CKR_SESSION_READ_WRITE_SO_EXISTS are new for v2.0 */
#define CKR_SESSION_READ_ONLY_EXISTS          0x000000B7
#define CKR_SESSION_READ_WRITE_SO_EXISTS      0x000000B8

#define CKR_SIGNATURE_INVALID                 0x000000C0
#define CKR_SIGNATURE_LEN_RANGE               0x000000C1
#define CKR_TEMPLATE_INCOMPLETE               0x000000D0
#define CKR_TEMPLATE_INCONSISTENT             0x000000D1
#define CKR_TOKEN_NOT_PRESENT                 0x000000E0
#define CKR_TOKEN_NOT_RECOGNIZED              0x000000E1
#define CKR_TOKEN_WRITE_PROTECTED             0x000000E2
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID     0x000000F0
#define CKR_UNWRAPPING_KEY_SIZE_RANGE         0x000000F1
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  0x000000F2
#define CKR_USER_ALREADY_LOGGED_IN            0x00000100
#define CKR_USER_NOT_LOGGED_IN                0x00000101
#define CKR_USER_PIN_NOT_INITIALIZED          0x00000102
#define CKR_USER_TYPE_INVALID                 0x00000103

/* CKR_USER_ANOTHER_ALREADY_LOGGED_IN and CKR_USER_TOO_MANY_TYPES
 * are new to v2.01 */
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN    0x00000104
#define CKR_USER_TOO_MANY_TYPES               0x00000105

#define CKR_WRAPPED_KEY_INVALID               0x00000110
#define CKR_WRAPPED_KEY_LEN_RANGE             0x00000112
#define CKR_WRAPPING_KEY_HANDLE_INVALID       0x00000113
#define CKR_WRAPPING_KEY_SIZE_RANGE           0x00000114
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT    0x00000115
#define CKR_RANDOM_SEED_NOT_SUPPORTED         0x00000120

/* These are new to v2.0 */
#define CKR_RANDOM_NO_RNG                     0x00000121
#define CKR_BUFFER_TOO_SMALL                  0x00000150
#define CKR_SAVED_STATE_INVALID               0x00000160
#define CKR_INFORMATION_SENSITIVE             0x00000170
#define CKR_STATE_UNSAVEABLE                  0x00000180

/* These are new to v2.01 */
#define CKR_CRYPTOKI_NOT_INITIALIZED          0x00000190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED      0x00000191
#define CKR_MUTEX_BAD                         0x000001A0
#define CKR_MUTEX_NOT_LOCKED                  0x000001A1

#define CKR_VENDOR_DEFINED                    0x80000000



/*
  typedef CK_RV (CK_ENTRY CK_PTR CK_NOTIFY) {
  CK_SESSION_HANDLE hSession,
  CK_NOTIFICATION event,
  CK_VOID_PTR pApplication
};
*/

typedef CK_RV CK_ENTRY CK_PTR CK_NOTIFY;

/*
  CK_C_Initialize;
  CK_C_Finalize;
  CK_C_GetInfo;
  CK_C_GetFunctionList;
  CK_C_GetSlotList;
  CK_C_GetSlotInfo;
  CK_C_GetTokenInfo;
  CK_C_GetMechanismList;
  CK_C_GetMechanismInfo;
  CK_C_InitToken;
  CK_C_InitPIN;
  CK_C_SetPIN;
  CK_C_OpenSession;
  CK_C_CloseSession;
  CK_C_CloseAllSessions;
  CK_C_GetSessionInfo;
  CK_C_GetOperationState;
  CK_C_SetOperationState;
  CK_C_Login;
  CK_C_Logout;
  CK_C_CreateObject;
  CK_C_CopyObject;
  CK_C_DestroyObject;
  CK_C_GetObjectSize;
  CK_C_GetAttributeValue;
  CK_C_SetAttributeValue;
  CK_C_FindObjectsInit;
  CK_C_FindObjects;
  CK_C_FindObjectsFinal;
  CK_C_EncryptInit;
  CK_C_Encrypt;
  CK_C_EncryptUpdate;
  CK_C_EncryptFinal;
  CK_C_DecryptInit;
  CK_C_Decrypt;
  CK_C_DecryptUpdate;
  CK_C_DecryptFinal;
  CK_C_DigestInit;
  CK_C_Digest;
  CK_C_DigestUpdate;
  CK_C_DigestKey;
  CK_C_DigestFinal;
  CK_C_SignInit;
  CK_C_Sign;
  CK_C_SignUpdate;
  CK_C_SignFinal;
  CK_C_SignRecoverInit;
  CK_C_SignRecover;
  CK_C_VerifyInit;
  CK_C_Verify;
  CK_C_VerifyUpdate;
  CK_C_VerifyFinal;
  CK_C_VerifyRecoverInit;
  CK_C_VerifyRecover;
  CK_C_DigestEncryptUpdate;
  CK_C_DecryptDigestUpdate;
  CK_C_SignEncryptUpdate;
  CK_C_DecryptVerifyUpdate;
  CK_C_GenerateKey;
  CK_C_GenerateKeyPair;
  CK_C_WrapKey;
  CK_C_UnwrapKey;
  CK_C_DeriveKey;
  CK_C_SeedRandom;
  CK_C_GenerateRandom;
  CK_C_GetFunctionStatus;
  CK_C_CancelFunction;
*/

/*
  typedef struct CK_FUNCTION_LIST {
  CK_VERSION version;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_GetSlotList C_GetSlotList;
  CK_C_GetSlotInfo C_GetSlotInfo;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_SetPIN C_SetPIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_SetOperationState C_SetOperationState;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_GetObjectSize C_GetObjectSize;
  CK_C_GetAttributeValue C_GetAttributeValue;
  CK_C_SetAttributeValue C_SetAttributeValue;
  CK_C_FindObjectsInit C_FindObjectsInit;
  CK_C_FindObjects C_FindObjects;
  CK_C_FindObjectsFinal C_FindObjectsFinal;
  CK_C_EncryptInit C_EncryptInit;
  CK_C_Encrypt C_Encrypt;
  CK_C_EncryptUpdate C_EncryptUpdate;
  CK_C_EncryptFinal C_EncryptFinal;
  CK_C_DecryptInit C_DecryptInit;
  CK_C_Decrypt C_Decrypt;
  CK_C_DecryptUpdate C_DecryptUpdate;
  CK_C_DecryptFinal C_DecryptFinal;
  CK_C_DigestInit C_DigestInit;
  CK_C_Digest C_Digest;
  CK_C_DigestUpdate C_DigestUpdate;
  CK_C_DigestKey C_DigestKey;
  CK_C_DigestFinal C_DigestFinal;
  CK_C_SignInit C_SignInit;
  CK_C_Sign C_Sign;
  CK_C_SignUpdate C_SignUpdate;
  CK_C_SignFinal C_SignFinal;
  CK_C_SignRecoverInit C_SignRecoverInit;
  CK_C_SignRecover C_SignRecover;
  CK_C_VerifyInit C_VerifyInit;
  CK_C_Verify C_Verify;
  CK_C_VerifyUpdate C_VerifyUpdate;
  CK_C_VerifyFinal C_VerifyFinal;
  CK_C_VerifyRecoverInit C_VerifyRecoverInit;
  CK_C_VerifyRecover C_VerifyRecover;
  CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
  CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
  CK_C_SignEncryptUpdate C_SignEncryptUpdate;
  CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
  CK_C_GenerateKey C_GenerateKey;
  CK_C_GenerateKeyPair C_GenerateKeyPair;
  CK_C_WrapKey C_WrapKey;
  CK_C_UnwrapKey C_UnwrapKey;
  CK_C_DeriveKey C_DeriveKey;
  CK_C_SeedRandom C_SeedRandom;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_GetFunctionStatus C_GetFunctionStatus;
  CK_C_CancelFunction C_CancelFunction;
} CK_FUNCTION_LIST;
*/

typedef struct CK_FUNCTION_LIST * CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR * CK_FUNCTION_LIST_PTR_PTR;

typedef CK_RV (CK_CALLCONV *f_C_Initialize)(CK_VOID_PTR pReserved);
typedef CK_RV (CK_CALLCONV *f_C_Finalize)(CK_VOID_PTR pReserved);
typedef CK_RV (CK_CALLCONV *f_C_GetInfo)(CK_INFO_PTR pInfo);
typedef CK_RV (CK_CALLCONV *f_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef CK_RV (CK_CALLCONV *f_C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
				    CK_ULONG_PTR pulCount);
typedef CK_RV (CK_CALLCONV *f_C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef CK_RV (CK_CALLCONV *f_C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV (CK_CALLCONV *f_C_GetMechanismList)(CK_SLOT_ID slotID, 
					 CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
typedef CK_RV (CK_CALLCONV *f_C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
					 CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV (CK_CALLCONV *f_C_InitToken)(CK_SLOT_ID slotID, CK_CHAR_PTR pPin,
				  CK_ULONG ulPinLen, CK_CHAR_PTR pLabel);
typedef CK_RV (CK_CALLCONV *f_C_InitPIN)(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin,
				CK_ULONG ulPinLen);
typedef CK_RV (CK_CALLCONV *f_C_SetPIN)(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pOldPin,
			       CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen);
typedef CK_RV (CK_CALLCONV *f_C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags,
				    CK_VOID_PTR pApplication, CK_NOTIFY Notify, 
				    CK_SESSION_HANDLE_PTR phSession);
typedef CK_RV (CK_CALLCONV *f_C_CloseSession)(CK_SESSION_HANDLE hSession);
typedef CK_RV (CK_CALLCONV *f_C_CloseAllSessions)(CK_SLOT_ID slotID);
typedef CK_RV (CK_CALLCONV *f_C_GetSessionInfo)(CK_SESSION_HANDLE hSession, 
				       CK_SESSION_INFO_PTR pInfo);
typedef CK_RV (CK_CALLCONV *f_C_GetOperationState)(CK_SESSION_HANDLE hSession,
					  CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
typedef CK_RV (CK_CALLCONV *f_C_SetOperationState)(CK_SESSION_HANDLE hSession, 
					  CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen,
					  CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_RV (CK_CALLCONV *f_C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
			      CK_CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef CK_RV (CK_CALLCONV *f_C_Logout)(CK_SESSION_HANDLE hSession);
typedef CK_RV (CK_CALLCONV *f_C_CreateObject)(CK_SESSION_HANDLE hSession, 
				     CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, 
				     CK_OBJECT_HANDLE_PTR pObject);
typedef CK_RV (CK_CALLCONV *f_C_CopyObject)(CK_SESSION_HANDLE hSession,
				   CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, 
				   CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pNewObject);
typedef CK_RV (CK_CALLCONV *f_C_DestroyObject)(CK_SESSION_HANDLE hSession,
				      CK_OBJECT_HANDLE hObject);
typedef CK_RV (CK_CALLCONV *f_C_GetObjectSize)(CK_SESSION_HANDLE hSession,
				      CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
typedef CK_RV (CK_CALLCONV *f_C_GetAttributeValue)(CK_SESSION_HANDLE hSession,
					  CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, 
					  CK_ULONG ulCount);
typedef CK_RV (CK_CALLCONV *f_C_SetAttributeValue)(CK_SESSION_HANDLE hSession,
					  CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, 
					  CK_ULONG ulCount);
typedef CK_RV (CK_CALLCONV *f_C_FindObjectsInit)(CK_SESSION_HANDLE hSession,
					CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (CK_CALLCONV *f_C_FindObjects)(CK_SESSION_HANDLE hSession,
				    CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
				    CK_ULONG_PTR pulObjectCount);
typedef CK_RV (CK_CALLCONV *f_C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
typedef CK_RV (CK_CALLCONV *f_C_EncryptInit)(CK_SESSION_HANDLE hSession,
				    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_CALLCONV *f_C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
				CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, 
				CK_ULONG_PTR pulEncryptedDataLen);
typedef CK_RV (CK_CALLCONV *f_C_EncryptUpdate)(CK_SESSION_HANDLE hSession, 
				      CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
				      CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (CK_CALLCONV *f_C_EncryptFinal)(CK_SESSION_HANDLE hSession,
				     CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncyptedPartLen);
typedef CK_RV (CK_CALLCONV *f_C_DecryptInit)(CK_SESSION_HANDLE hSession,
				    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_CALLCONV *f_C_Decrypt)(CK_SESSION_HANDLE hSession,
				CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
				CK_ULONG_PTR pulDataLen);
typedef CK_RV (CK_CALLCONV *f_C_DecryptUpdate)(CK_SESSION_HANDLE hSession,
				      CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
				      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (CK_CALLCONV *f_C_DecryptFinal)(CK_SESSION_HANDLE hSession,
				     CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
typedef CK_RV (CK_CALLCONV *f_C_DigestInit)(CK_SESSION_HANDLE hSession,
				   CK_MECHANISM_PTR pMechanism);
typedef CK_RV (CK_CALLCONV *f_C_Digest)(CK_SESSION_HANDLE hSession,
			       CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
			       CK_ULONG_PTR pulDigestLen);
typedef CK_RV (CK_CALLCONV *f_C_DigestUpdate)(CK_SESSION_HANDLE hSession,
				     CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (CK_CALLCONV *f_C_DigestKey)(CK_SESSION_HANDLE hSession,
				  CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_CALLCONV *f_C_DigestFinal)(CK_SESSION_HANDLE hSession,
				    CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
typedef CK_RV (CK_CALLCONV *f_C_SignInit)(CK_SESSION_HANDLE hSession,
				 CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_CALLCONV *f_C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
			     CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (CK_CALLCONV *f_C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
				   CK_ULONG ulPartLen);
typedef CK_RV (CK_CALLCONV *f_C_SignFinal)(CK_SESSION_HANDLE hSession,
				  CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (CK_CALLCONV *f_C_SignRecoverInit)(CK_SESSION_HANDLE hSession,
					CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_CALLCONV *f_C_SignRecover)(CK_SESSION_HANDLE hSession,
				    CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
				    CK_ULONG_PTR pulSignature);
typedef CK_RV (CK_CALLCONV *f_C_VerifyInit)(CK_SESSION_HANDLE hSession,
				   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_CALLCONV *f_C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
			       CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_RV (CK_CALLCONV *f_C_VerifyUpdate)(CK_SESSION_HANDLE hSession,
				     CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (CK_CALLCONV *f_C_VerifyFinal)(CK_SESSION_HANDLE hSession,
				    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_RV (CK_CALLCONV *f_C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession,
					  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_CALLCONV *f_C_VerifyRecover)(CK_SESSION_HANDLE hSession,
				      CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
				      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef CK_RV (CK_CALLCONV *f_C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession,
					    CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
					    CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (CK_CALLCONV *f_C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession,
					    CK_BYTE_PTR pEncryptedPart, CK_ULONG pEncryptedPartLen,
					    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (CK_CALLCONV *f_C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession,
					  CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
					  CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (CK_CALLCONV *f_C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession,
					    CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
					    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (CK_CALLCONV *f_C_GenerateKey)(CK_SESSION_HANDLE hSession,
				    CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
				    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (CK_CALLCONV *f_C_GenerateKeyPair)(CK_SESSION_HANDLE hSession,
					CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
					CK_ULONG ulPublicKeyAttributeCount, 
					CK_ATTRIBUTE_PTR pPrivateKeyTemplate, 
					CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey,
					CK_OBJECT_HANDLE_PTR phPrivateKey);
typedef CK_RV (CK_CALLCONV *f_C_WrapKey)(CK_SESSION_HANDLE hSession,
				CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey,
				CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, 
				CK_ULONG_PTR pulWrappedKeyLen);
typedef CK_RV (CK_CALLCONV *f_C_UnwrapKey)(CK_SESSION_HANDLE hSession,
				  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
				  CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
				  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
				  CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (CK_CALLCONV *f_C_DeriveKey)(CK_SESSION_HANDLE hSession,
				  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
				  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
				  CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (CK_CALLCONV *f_C_SeedRandom)(CK_SESSION_HANDLE hSession,
				   CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
typedef CK_RV (CK_CALLCONV *f_C_GenerateRandom)(CK_SESSION_HANDLE hSession,
				       CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);
typedef CK_RV (CK_CALLCONV *f_C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
typedef CK_RV (CK_CALLCONV *f_C_CancelFunction)(CK_SESSION_HANDLE hSession);

typedef struct CK_FUNCTION_LIST {
  CK_VERSION version;
  f_C_Initialize             C_Initialize;
  f_C_Finalize               C_Finalize;
  f_C_GetInfo                C_GetInfo;
  f_C_GetFunctionList        C_GetFunctionList;
  f_C_GetSlotList            C_GetSlotList;
  f_C_GetSlotInfo            C_GetSlotInfo;
  f_C_GetTokenInfo           C_GetTokenInfo;
  f_C_GetMechanismList       C_GetMechanismList;
  f_C_GetMechanismInfo       C_GetMechanismInfo;
  f_C_InitToken              C_InitToken;
  f_C_InitPIN                C_InitPIN;
  f_C_SetPIN                 C_SetPIN;
  f_C_OpenSession            C_OpenSession;
  f_C_CloseSession           C_CloseSession;
  f_C_CloseAllSessions       C_CloseAllSessions;
  f_C_GetSessionInfo         C_GetSessionInfo;
  f_C_GetOperationState      C_GetOperationState;
  f_C_SetOperationState      C_SetOperationState;
  f_C_Login                  C_Login;
  f_C_Logout                 C_Logout;
  f_C_CreateObject           C_CreateObject;
  f_C_CopyObject             C_CopyObject;
  f_C_DestroyObject          C_DestroyObject;
  f_C_GetObjectSize          C_GetObjectSize;
  f_C_GetAttributeValue      C_GetAttributeValue;
  f_C_SetAttributeValue      C_SetAttributeValue;
  f_C_FindObjectsInit        C_FindObjectsInit;
  f_C_FindObjects            C_FindObjects;
  f_C_FindObjectsFinal       C_FindObjectsFinal;
  f_C_EncryptInit            C_EncryptInit;
  f_C_Encrypt                C_Encrypt;
  f_C_EncryptUpdate          C_EncryptUpdate;
  f_C_EncryptFinal           C_EncryptFinal;
  f_C_DecryptInit            C_DecryptInit;
  f_C_Decrypt                C_Decrypt;
  f_C_DecryptUpdate          C_DecryptUpdate;
  f_C_DecryptFinal           C_DecryptFinal;
  f_C_DigestInit             C_DigestInit;
  f_C_Digest                 C_Digest;
  f_C_DigestUpdate           C_DigestUpdate;
  f_C_DigestKey              C_DigestKey;
  f_C_DigestFinal            C_DigestFinal;
  f_C_SignInit               C_SignInit;
  f_C_Sign                   C_Sign;
  f_C_SignUpdate             C_SignUpdate;
  f_C_SignFinal              C_SignFinal;
  f_C_SignRecoverInit        C_SignRecoverInit;
  f_C_SignRecover            C_SignRecover;
  f_C_VerifyInit             C_VerifyInit;
  f_C_Verify                 C_Verify;
  f_C_VerifyUpdate           C_VerifyUpdate;
  f_C_VerifyFinal            C_VerifyFinal;
  f_C_VerifyRecoverInit      C_VerifyRecoverInit;
  f_C_VerifyRecover          C_VerifyRecover;
  f_C_DigestEncryptUpdate    C_DigestEncryptUpdate;
  f_C_DecryptDigestUpdate    C_DecryptDigestUpdate;
  f_C_SignEncryptUpdate      C_SignEncryptUpdate;
  f_C_DecryptVerifyUpdate    C_DecryptVerifyUpdate;
  f_C_GenerateKey            C_GenerateKey;
  f_C_GenerateKeyPair        C_GenerateKeyPair;
  f_C_WrapKey                C_WrapKey;
  f_C_UnwrapKey              C_UnwrapKey;
  f_C_DeriveKey              C_DeriveKey;
  f_C_SeedRandom             C_SeedRandom;
  f_C_GenerateRandom         C_GenerateRandom;
  f_C_GetFunctionStatus      C_GetFunctionStatus;
  f_C_CancelFunction         C_CancelFunction;
} CK_FUNCTION_LIST;

#define CKF_TOKEN_PRESENT                  0x00000001
#define CKF_REMOVABLE_DEVICE               0x00000002
#define CKF_HW_SLOT                        0x00000004

#define CKF_RNG                            0x00000001
#define CKF_WRITE_PROTECTED                0x00000002
#define CKF_LOGIN_REQUIRED                 0x00000004
#define CKF_USER_PIN_INITIALIZED           0x00000008
#define CKF_EXCLUSIVE_EXISTS               0x00000010
#define CKF_RESTORE_KEY_NOT_NEEDED         0x00000020
#define CKF_CLOCK_ON_TOKEN                 0x00000040
#define CKF_SUPPORTS_PARALLEL              0x00000080
#define CKF_PROTECTED_AUTHENTICATION_PATH  0x00000100
#define CKF_DUAL_CRYPTO_OPERATIONS         0x00000200

#define CKF_EXCLUSIVE_SESSION              0x00000001
#define CKF_RW_SESSION                     0x00000002
#define CKF_SERIAL_SESSION                 0x00000004
#define CKF_INSERTION_CALLBACK             0x00000008

#define CKF_HW                             0x00000001
#define CKF_ENCRYPT                        0x00000100
#define CKF_DECRYPT                        0x00000200
#define CKF_DIGEST                         0x00000400
#define CKF_SIGN                           0x00000800
#define CKF_SIGN_RECOVER                   0x00001000
#define CKF_VERIFY                         0x00002000
#define CKF_VERIFY_RECOVER                 0x00004000
#define CKF_GENERATE                       0x00008000
#define CKF_GENERATE_KEY_PAIR              0x00010000
#define CKF_WRAP                           0x00020000
#define CKF_UNWRAP                         0x00040000
#define CKF_DERIVE                         0x00080000
#define CKF_EXTENSION                      0x80000000

#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001
#define CKF_OS_LOCKING_OK		   0x00000002

#ifdef _WIN32
# include "win32post.h"
#endif

#endif
