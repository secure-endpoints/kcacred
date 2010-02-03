#
# Copyright (c) 2006-2010 Secure Endpoints Inc.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Environment variables
# ---------------------
#
# (paths should not end in a backslash)
#
# KFWSDKDIR : Path to the Kerberos for Windows SDK (version 3.1 or later)
#
# OPENSSLDIR: Path to installation of OpenSSL
#
# HHCFULLPATH: Full path to the HTML Help Compiler (hhc.exe)
#
# AUXCFLAGS : Auxilliary C flags to pass to the command line of CC
#

# Configuration settings
# ----------------------

# Declare a few things about our plug-in.

# TODO: Change the plug-in name
PLUGINNAME=KCACred

# TODO: Change the module name
MODULENAME=KCAMod

# TODO: Change the credtype name
CREDTYPENAME=KCACred

# TODO: Change this as appropriate
DLLBASENAME=kcacred

# Version info

VERMAJOR=2
VERMINOR=3
VERAUX  =0
VERPATCH=0

# Target NetIDMgr version (string) only for display purposes
NIDMVERSTR=1.1

# Leave these as-is
VERLIST=$(VERMAJOR).$(VERMINOR).$(VERAUX).$(VERPATCH)
VERLISTC=$(VERMAJOR),$(VERMINOR),$(VERAUX),$(VERPATCH)
VERLISTD=$(VERMAJOR)-$(VERMINOR)-$(VERAUX)-$(VERPATCH)

# Various checks

!ifndef KFWSDKDIR
! error KFWSDKDIR environment variable not set.
!endif

!ifndef OPENSSLDIR
! error OPENSSLDIR environemnt variable not set.
!endif

!ifndef HHCFULLPATH
! error HHCFULLPATH environment variable not set.
!endif

# Directories

BUILDROOT=.

!ifdef NODEBUG
BUILDTYPE=release
!else
BUILDTYPE=debug
! ifndef DEBUG
DEBUG=1
! endif
!endif


!if !defined(CPU)
!if "$(PROCESSOR_ARCHITECTURE)" == "x86"
CPU = i386
!endif
!if "$(PROCESSOR_ARCHITECTURE)" == "AMD64"
CPU = AMD64
!endif
!endif

!ifndef CPU
!error Environment variable 'CPU' is not defined.
!endif

DEST=$(BUILDROOT)\dest\$(CPU)_$(BUILDTYPE)
OBJ=$(BUILDROOT)\obj\$(CPU)_$(BUILDTYPE)

KPKCS11DEST=$(BUILDROOT)\kpkcs11\dest\$(CPU)_$(BUILDTYPE)

KFWINCDIR=$(KFWSDKDIR)\inc
KFWLIBDIR=$(KFWSDKDIR)\lib\$(CPU)

!ifndef NIDMSDKDIR
NIDMINCDIR=$(KFWINCDIR)\netidmgr
NIDMLIBDIR=$(KFWLIBDIR)
!else
NIDMINCDIR=$(NIDMSDKDIR)\inc
NIDMLIBDIR=$(NIDMSDKDIR)
!endif

!if "$(CPU)" == "AMD64"
!if exist($(OPENSSLDIR)\out64)
OPENSSLLIBDIR=$(OPENSSLDIR)\out64
!else
OPENSSLLIBDIR=$(OPENSSLDIR)\out64dll
!endif
!endif
!if "$(CPU)" == "i386"
!if exist($(OPENSSLDIR)\out32)
OPENSSLLIBDIR=$(OPENSSLDIR)\out32
!else
OPENSSLLIBDIR=$(OPENSSLDIR)\out32dll
!endif
!endif

!if !defined(OPENSSLLIBDIR)
!error 'OPENSSLLIBDIR' cannot be determined.
!endif

!IF "$(SIGNTOOL)" == ""
SIGNTOOL=signtool.exe
!ENDIF

!IF DEFINED(CODESIGN_DESC) && DEFINED(CODESIGN_URL) && DEFINED(CODESIGN_TIMESTAMP)
CODESIGN_USERLAND= "$(SIGNTOOL)" sign /a /d "$(CODESIGN_DESC)" /du $(CODESIGN_URL) /t $(CODESIGN_TIMESTAMP) /v $@
!ELSE
CODESIGN_USERLAND=
!ENDIF

!IF DEFINED(SYMSTORE_EXE) && DEFINED(SYMSTORE_ROOT)
!IF "$(SYMSTORE_COMMENT)" != ""
SYMSTORE_COMMENT = |$(SYMSTORE_COMMENT)
!ENDIF
SYMSTORE_IMPORT= \
$(SYMSTORE_EXE) add /s $(SYMSTORE_ROOT) /t "KCA Provider for Network Identity Manager" /v "$(VERLISTD)" /c "$(@F)$(SYMSTORE_COMMENT)" /f $*.*
!ELSE
SYMSTORE_IMPORT=
!ENDIF

# Win32.mak

!include <Win32.Mak>

# Program macros

CD=cd
RM=del /q
MKDIR=md
RMDIR=rd
ECHO=echo
CP=copy /y
LINK=link
MC=mc
HHC=-$(HHCFULLPATH)

# Lots more macros

incflags = -I"$(NIDMINCDIR)" -I"$(KFWINCDIR)\krb5" -I"$(KFWINCDIR)\wshelper" -I"$(OPENSSLDIR)\include" -I"$(KFWINCDIR)" -I"$(OBJ)" -I.
rincflags = /i "$(NIDMINCDIR)" /i "$(OBJ)" /i .

ldebug = $(ldebug) /DEBUG
cdebug = $(cdebug) -Os -Zi

cdefines = $(cdefines) -DUNICODE -D_UNICODE

cdefines = $(cdefines) -DUSE_KRB5

!ifndef NO_WX
cwarn=/WX
!else
cwarn=
!endif

C2OBJ=$(CC) $(cvarsmt) $(cdebug) $(cflags) $(cwarn) $(incflags) $(cdefines) $(AUXCFLAGS) /Fo"$@" /c $**

!ifdef DEBUG
#DLLGUILINK=$(LINK) /NOLOGO $(ldebug) $(dlllflags) $(guilibsmt) /OUT:"$@" /NODEFAULTLIB:LIBCMTD /IMPLIB:$(DEST)\$(@B).lib $**
DLLGUILINK=$(LINK) /NOLOGO $(ldebug) $(dlllflags) $(guilibsmt) /OUT:"$@" /IMPLIB:$(DEST)\$(@B).lib $**
!else
#DLLGUILINK=$(LINK) /NOLOGO $(ldebug) $(dlllflags) $(guilibsmt) /OUT:"$@" /NODEFAULTLIB:LIBCMT /IMPLIB:$(DEST)\$(@B).lib $**
DLLGUILINK=$(LINK) /NOLOGO $(ldebug) $(dlllflags) $(guilibsmt) /OUT:"$@" /IMPLIB:$(DEST)\$(@B).lib $**
!endif

DLLRESLINK=$(LINK) /NOLOGO /DLL /NOENTRY /MACHINE:$(PROCESSOR_ARCHITECTURE) /OUT:"$@" $**

EXECONLINK=$(LINK) /NOLOGO $(ldebug) $(conlflags) $(lndeflibflag) $(conlibsmt) /OUT:$@ $**

RC2RES=$(RC) $(RFLAGS) $(rincflags) /fo "$@" $**

MC2RC=$(MC) $(MCFLAGS) -h "$(OBJ)\" -m 1024 -r "$(OBJ)\" -x "$(OBJ)\" $**

#"

{}.c{$(OBJ)}.obj:
	$(C2OBJ)

{$(OBJ)}.c{$(OBJ)}.obj:
	$(C2OBJ)

{}.rc{$(OBJ)}.res:
	$(RC2RES)

mkdirs::
!if !exist($(DEST))
	$(MKDIR) "$(DEST)"
!endif
!if !exist($(OBJ))
	$(MKDIR) "$(OBJ)"
!endif

clean::
	-$(RM) "$(OBJ)\*.*"
	-$(RM) "$(DEST)\*.*"
        -$(RM) "*.pdb"

.SUFFIXES: .h

#
# Manifest handling
#
# Starting with Visual Studio 8, the C compiler and the linker
# generate manifests so that the applications will link with the
# correct side-by-side DLLs at run-time.  These are required for
# correct operation under Windows XP.  We also have custom manifests
# which need to be merged with the manifests that VS creates.
#
# The syntax for invoking the _VC_MANIFEST_EMBED_foo macro is:
# $(_VC_MANIFEST_EMBED_???) <any additional manifests that need to be merged in>
#

!ifndef MT
MT=mt.exe -nologo
!endif

_VC_MANIFEST_EMBED_EXE= \
if exist "$@.manifest" $(MT) -outputresource:"$@";1 -manifest "$@.manifest"

_VC_MANIFEST_EMBED_DLL= \
if exist "$@.manifest" $(MT) -outputresource:"$@";2 -manifest "$@.manifest"

# Note that if you are merging manifests, then the VS generated
# manifest should be cleaned up after calling _VC_MANIFEST_EMBED_???.
# This ensures that even if the DLL or EXE is executed in-place, the
# embedded manifest will be used.  Otherwise the $@.manifest file will
# be used.
_VC_MANIFEST_CLEAN= \
if exist "$@.manifest" $(RM) "$@.manifest"

# End of manifest handling


# Now for the actual build stuff

DLL=$(DEST)\$(DLLBASENAME).dll

!if "$(CPU)" == "i386"
KFWLIBS = \
	"$(KFWLIBDIR)\krb5_32.lib" 		\
	"$(KFWLIBDIR)\comerr32.lib"		\
	"$(NIDMLIBDIR)\nidmgr32.lib"		
!else 
KFWLIBS = \
	"$(KFWLIBDIR)\krb5_64.lib" 		\
	"$(KFWLIBDIR)\comerr64.lib"		\
	"$(NIDMLIBDIR)\nidmgr64.lib"
!endif

LIBFILES= 					\
	dnsapi.lib 				\
	secur32.lib				\
	crypt32.lib				\
	cryptui.lib				\
	shlwapi.lib				\
	htmlhelp.lib				\
	comctl32.lib				\
	shell32.lib				\
	"$(OPENSSLLIBDIR)\libeay32.lib"	\
	"$(OPENSSLLIBDIR)\ssleay32.lib"        \
        $(KFWLIBS)

OBJFILES= \
	$(OBJ)\credacq.obj	\
	$(OBJ)\credtype.obj	\
	$(OBJ)\main.obj		\
	$(OBJ)\plugin.obj	\
	$(OBJ)\proppage.obj	\
	$(OBJ)\config_main.obj	\
	$(OBJ)\config_id.obj	\
	$(OBJ)\config_ids.obj	\
	$(OBJ)\pluginconfig.obj \
	$(OBJ)\kpkcs11inst.obj  \
	$(OBJ)\kcaexports.obj	\
	$(OBJ)\kcaicon.obj	\
# kx509 stuff
	$(OBJ)\b64.obj		\
	$(OBJ)\debug.obj	\
	$(OBJ)\get_kca_list.obj	\
	$(OBJ)\get_realm.obj	\
	$(OBJ)\getcert.obj	\
	$(OBJ)\kx509_asn.obj	\
	$(OBJ)\kx509_ck.obj	\
	$(OBJ)\msg.obj		\
	$(OBJ)\rsa_to_keyblob.obj	\
	$(OBJ)\store_cert.obj	\
	$(OBJ)\list_cert.obj	\
	$(OBJ)\del_cert.obj	\
	$(OBJ)\store_key.obj	\
	$(OBJ)\udp_nb_bind.obj	\
	$(OBJ)\udp_nb_connect.obj	\
	$(OBJ)\udp_nb_recv.obj	\
	$(OBJ)\udp_nb_send.obj	\
	$(OBJ)\udp_nb_socket.obj	\
	$(OBJ)\udp_nb_select.obj

DLLRESFILE=$(OBJ)\version.res

CONFIGHEADER=$(OBJ)\credacq_config.h

HELPFILE=$(DEST)\kcaplugin.chm

$(HELPFILE): help\kcaplugin.chm
	$(CP) $** $@

help\kcaplugin.chm: help\kcaplugin.hhp
	$(HHC) help\kcaplugin.hhp

clean::
        -$(RM) $(HELPFILE)
        -$(RM) help\kcaplugin.chm

# This is built from the Makefile in the kpkcs11 directory
KPKCS11DLL=$(KPKCS11DEST)\kpkcs11.dll

$(KPKCS11DLL):
	$(CD) kpkcs11
	$(MAKE) /f NTMakefile all VERMAJOR=$(VERMAJOR) VERMINOR=$(VERMINOR) VERAUX=$(VERAUX) VERPATCH=$(VERPATCH)
	$(CD) ..

clean::
	$(CD) kpkcs11
	$(MAKE) /f NTMakefile clean
	$(CD) ..

fini:
	@echo --- done ---

bins: mkdirs $(CONFIGHEADER) $(DLL) $(KPKCS11DLL) $(HELPFILE) lang test fini

all: mkdirs $(CONFIGHEADER) $(DLL) $(KPKCS11DLL) $(HELPFILE) lang test msi fini

$(CONFIGHEADER): Makefile
	$(CP) << "$@"
/* This is a generated file.  Do not modify directly. */

#pragma once

#define MYPLUGIN_DLLBASE "$(DLLBASENAME)"

#define MYPLUGIN_NAME "$(PLUGINNAME)"

#define MYMODULE_NAME "$(MODULENAME)"

#define MYCREDTYPE_NAME "$(CREDTYPENAME)"

#define VERSION_MAJOR $(VERMAJOR)
#define VERSION_MINOR $(VERMINOR)
#define VERSION_AUX   $(VERAUX)
#define VERSION_PATCH $(VERPATCH)

#define VERSION_LIST  $(VERLIST)
#define VERSION_LISTC $(VERLISTC)
#define VERSION_STRING "$(VERLIST)"

<<

clean::
	-$(RM) $(CONFIGHEADER)

$(DLL): $(OBJFILES) $(DLLRESFILE)
	$(DLLGUILINK) $(LIBFILES)
	$(_VC_MANIFEST_EMBED_DLL)
	$(_VC_MANIFEST_CLEAN)
        $(CODESIGN_USERLAND)

clean::
	-$(RM) $(DLL)

# Language specific resources

# (repeat the following block as needed, redefining LANG for each
# supported language)

# English-US
LANG=en_us

LANGDLL=$(DEST)\$(DLLBASENAME)_$(LANG).dll

lang:: $(LANGDLL)

$(LANGDLL): $(OBJ)\langres_$(LANG).res $(OBJ)\version_$(LANG).res
	$(DLLRESLINK)
	$(_VC_MANIFEST_EMBED_DLL)
	$(_VC_MANIFEST_CLEAN)
        $(CODESIGN_USERLAND)

clean::
	-$(RM) $(LANGDLL)

$(OBJ)\version_$(LANG).res: version.rc
	$(RC) $(RFLAGS) $(rincflags) /d LANGRES /d LANG_$(LANG) /fo $@ $**

clean::
	-$(RM) $(OBJ)\version_$(LANG).res

$(OBJ)\langres_$(LANG).res: lang\$(LANG)\langres.rc
	$(RC2RES)

clean::
	-$(RM) $(OBJ)\langres_$(LANG).res

# /English-US


# Installer

!ifdef DEBUG
VERDEBUG=-debug
!else
VERDEBUG=
!endif

MSIFILE=$(DEST)\kcaplugin-$(VERMAJOR)_$(VERMINOR)_$(VERAUX)_$(VERPATCH)-$(CPU)$(VERDEBUG).msi

msi: $(MSIFILE)

$(MSIFILE): $(OBJ)\kcaplugin.wixobj $(OBJ)\kcaplugin-core.wixobj
	light -nologo -out $@ $**
        $(CODESIGN_USERLAND)

$(OBJ)\kcaplugin.wixobj: installer\kcaplugin.wxs $(DLL) $(HELPFILE)
	candle -nologo \
	-dKCAPluginVersion="$(VERLIST)" \
	-dNetIDMgrVersion="$(NIDMVERSTR)" \
	-dBinDir="$(DEST)" \
	-dKPKCS11BinDir="$(KPKCS11DEST)" \
	-out $@ installer\kcaplugin.wxs

$(OBJ)\kcaplugin-core.wixobj: installer\kcaplugin-core.wxs $(DLL) $(HELPFILE)
	candle -nolog \
	-dKCAPluginVersion="$(VERLIST)" \
	-dNetIDMgrVersion="$(NIDMVERSTR)" \
	-dBinDir="$(DEST)" \
	-dKPKCS11BinDir="$(KPKCS11DEST)" \
	-out $@ installer\kcaplugin-core.wxs

clean::
	-$(RM) $(MSIFILE)

# Tests

{test}.c{$(OBJ)}.obj:
	$(C2OBJ)

TESTEXEOBJS=$(OBJ)\testmain.obj

TESTSDKLIBS= \
        gdi32.lib       \
        user32.lib      \
	$(KFWLIBS) 	\
	"$(OPENSSLLIBDIR)\libeay32.lib"	\
	$(DEST)\kcacred.lib

TESTEXE=$(DEST)\kcatest.exe

$(TESTEXE): $(TESTEXEOBJS)
	$(EXECONLINK) $(TESTSDKLIBS)

test: $(TESTEXE)
