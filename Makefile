#
# Copyright (c) 2006-2011 Secure Endpoints Inc.
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


!if exist( ..\..\config\Makefile.w32 )
MODULE=plugins\kcacred
!include <..\..\config\Makefile.w32>
!else
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

!IF "$(SIGNTOOL)" == ""
SIGNTOOL=signtool.exe
!ENDIF

!IF DEFINED(CODESIGN_DESC) && DEFINED(CODESIGN_URL) && DEFINED(CODESIGN_TIMESTAMP)
CODESIGN= "$(SIGNTOOL)" sign /a /d "$(CODESIGN_DESC)" /du $(CODESIGN_URL) /t $(CODESIGN_TIMESTAMP) /v $@
!ELSE
CODESIGN=
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

!ifdef DEBUG
DLLGUILINK=$(LINK) /NOLOGO $(ldebug) $(dlllflags) $(guilibsmt) $(AUXLINKFLAGS) /OUT:"$@" /IMPLIB:$(DEST)\lib\$(@B).lib $**
!else
DLLGUILINK=$(LINK) /NOLOGO $(ldebug) $(dlllflags) $(guilibsmt) $(AUXLINKFLAGS) /OUT:"$@" /IMPLIB:$(DEST)\lib\$(@B).lib $**
!endif

DLLRESLINK=$(LINK) /NOLOGO /DLL /NOENTRY /MACHINE:$(PROCESSOR_ARCHITECTURE) /OUT:"$@" $**

EXECONLINK=$(LINK) /NOLOGO $(ldebug) $(conlflags) $(lndeflibflag) $(conlibsmt) $(AUXLINKFLAGS) /OUT:$@ $**

RC2RES=$(RC) $(RFLAGS) $(rincflags) /fo "$@" $**

MC2RC=$(MC) $(MCFLAGS) -h "$(OBJ)\" -m 1024 -r "$(OBJ)\" -x "$(OBJ)\" $**

#"

{}.c{$(OBJ)}.obj:
	$(C2OBJ)

{$(OBJ)}.c{$(OBJ)}.obj:
	$(C2OBJ)

{$(KERBEROSCOMPATSDKROOT)\src}.c{$(OBJ)}.obj:
	$(C2OBJ)

{}.rc{$(OBJ)}.res:
	$(RC2RES)

.SUFFIXES: .h
!endif

mkdirs::
!if !exist($(DEST))
	$(MKDIR) "$(DEST)"
!endif
!if !exist($(DEST)\bin)
	-$(MKDIR) "$(DEST)\bin"
!endif
!if !exist($(DEST)\lib)
	-$(MKDIR) "$(DEST)\lib"
!endif
!if !exist($(OBJ))
	$(MKDIR) "$(OBJ)"
!endif

clean::
	-$(RM) "$(OBJ)\*.*"
	-$(RM) "$(DEST)\*.*"
	-$(RM) "$(DEST)\bin\*.*"
	-$(RM) "$(DEST)\lib\*.*"
	-$(RM) "*.pdb"

# Environment variables
# ---------------------
#
# (paths should not end in a backslash)
#
# KERBEROSCOMPATSDKROOT : Path to the Kerberos Compatibility SDK 1.0
#
# HEIMDALSDKROOT : Path to the native Heimdal SDK (takes precedence
#                  over KERBEROSCOMPATSDKROOT
#
# OPENSSLDIR: Path to installation of OpenSSL
#
# HHCFULLPATH: Full path to the HTML Help Compiler (hhc.exe)
#
# AUXCFLAGS : Auxilliary C flags to pass to the command line of CC
#
# AUXLINKFLAGS : Auxiliary flags to pass to the linker
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

# TODO: Change the version numbers
VERMAJOR=2
VERMINOR=5
VERAUX  =5
VERPATCH=0

# Target NetIDMgr version (string) only for display purposes
NIDMVERSTR=1.1

# Leave these as-is
VERLIST=$(VERMAJOR).$(VERMINOR).$(VERAUX).$(VERPATCH)
VERLISTC=$(VERMAJOR),$(VERMINOR),$(VERAUX),$(VERPATCH)
VERLISTD=$(VERMAJOR)-$(VERMINOR)-$(VERAUX)-$(VERPATCH)

# Various checks

!ifndef HEIMDALSDKROOT
!ifndef KERBEROSCOMPATSDKROOT
! error Neither HEIMDALSDKROOT nor KERBEROSCOMPATSDKROOT environment variable not set.
!endif
!endif

!ifndef OPENSSLDIR
! error OPENSSLDIR environment variable not set.
!endif

!ifndef HHCFULLPATH
!ifdef KH_HHCFULLPATH
HHCFULLPATH=$(KH_HHCFULLPATH)
!else
! error HHCFULLPATH environment variable not set.
!endif
!endif

!ifndef NIDMRAWDIRS
!ifndef NIDMSDKDIR
! error NIDMSDKDIR environment variable not set.
!endif
!endif

# Directories

BUILDROOT=$(MAKEDIR)

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

!ifndef DEST
DEST=$(BUILDROOT)\dest\$(CPU)_$(BUILDTYPE)
!endif
!ifndef OBJ
OBJ=$(BUILDROOT)\obj\$(CPU)_$(BUILDTYPE)
!endif

KPKCS11BIN=$(DEST)\bin\kpkcs11
KPKCS11LIB=$(DEST)\lib
KPKCS11OBJ=$(OBJ)\kpkcs11

!ifdef HEIMDALSDKROOT
KERBEROSINCDIR=$(HEIMDALSDKROOT)\inc
KERBEROSLIBDIR=$(HEIMDALSDKROOT)\lib\$(CPU)
!else
KERBEROSINCDIR=$(KERBEROSCOMPATSDKROOT)\inc
KERBEROSLIBDIR=$(KERBEROSCOMPATSDKROOT)\lib\$(CPU)
!  ifndef BUILD_KRBCOMPAT
BUILD_KRBCOMPAT=1
!  endif
!endif

# If you are building against the NetIDMgr build tree, you can define
# the environment variable NIDMRAWDIRS.

!ifdef NIDMRAWDIRS
NIDMINCDIR=$(DEST)\inc
NIDMLIBDIR=$(DEST)\lib
!else
!  if exist("$(NIDMSDKDIR)\inc\netidmgr")
NIDMINCDIR=$(NIDMSDKDIR)\inc\netidmgr
NIDMLIBDIR=$(NIDMSDKDIR)\lib\$(CPU)
!  else
NIDMINCDIR=$(NIDMSDKDIR)\inc
NIDMLIBDIR=$(NIDMSDKDIR)\lib
!  endif
!endif


!if "$(CPU)" == "AMD64"
!if exist($(OPENSSLDIR)\out64)
OPENSSLLIBDIR=$(OPENSSLDIR)\out64
!else
#OPENSSLLIBDIR=$(OPENSSLDIR)\out64dll
!endif
!endif
!if "$(CPU)" == "i386"
!if exist($(OPENSSLDIR)\out32)
OPENSSLLIBDIR=$(OPENSSLDIR)\out32
!else
#OPENSSLLIBDIR=$(OPENSSLDIR)\out32dll
!endif
!endif

!if !defined(OPENSSLLIBDIR)
!error 'OPENSSLLIBDIR' cannot be determined.
!endif

# Lots more macros

incflags = -I"$(NIDMINCDIR)" -I"$(KERBEROSINCDIR)\krb5" -I"$(OPENSSLDIR)\inc32" -I"$(KERBEROSINCDIR)" -I"$(OBJ)" -I.
rincflags = /i "$(NIDMINCDIR)" /i "$(OBJ)" /i .

ldebug = $(ldebug) /MANIFEST
cdebug = $(cdebug) -Os -Zi

cdefines = $(cdefines) -DUNICODE -D_UNICODE -DUSE_KRB5

cwarn=/wd4996

C2OBJ=$(CC) $(cvarsmt) $(cdebug) $(cflags) $(cwarn) $(incflags) $(cdefines) $(AUXCFLAGS) /Fo"$@" /c $**

# Now for the actual build stuff

DLL=$(DEST)\bin\$(DLLBASENAME).dll

LIBFILES = \
!if "$(CPU)" == "i386"
	"$(NIDMLIBDIR)\nidmgr32.lib"	\
!else 
	"$(NIDMLIBDIR)\nidmgr64.lib"	\
!endif
	"$(KERBEROSLIBDIR)\heimdal.lib" \
	"$(OPENSSLLIBDIR)\libeay32.lib"	\
	"$(OPENSSLLIBDIR)\ssleay32.lib"

SDKLIBFILES= 					\
	dnsapi.lib 				\
	secur32.lib				\
	crypt32.lib				\
	cryptui.lib				\
	shlwapi.lib				\
	htmlhelp.lib				\
	comctl32.lib				\
	shell32.lib

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
	$(OBJ)\udp_nb_select.obj	\
!ifdef BUILD_KRBCOMPAT
	$(OBJ)\krbcompat_delayload.obj
!endif

DLLRESFILE=$(OBJ)\version.res

CONFIGHEADER=$(OBJ)\credacq_config.h

HELPFILE=$(DEST)\doc\kcaplugin.chm

$(HELPFILE): help\kcaplugin.chm
	$(CP) $** $@

help\kcaplugin.chm: help\kcaplugin.hhp
	$(HHC) help\kcaplugin.hhp

clean::
        -$(RM) $(HELPFILE)
        -$(RM) help\kcaplugin.chm

# This is built from the Makefile in the kpkcs11 directory
KPKCS11DLL=$(KPKCS11BIN)\kpkcs11.dll

$(KPKCS11DLL):
	$(CD) kpkcs11
	$(MAKE) /f NTMakefile all VERMAJOR=$(VERMAJOR) VERMINOR=$(VERMINOR) VERAUX=$(VERAUX) VERPATCH=$(VERPATCH) KPKCS11BIN=$(KPKCS11BIN) KPKCS11LIB=$(KPKCS11LIB) KPKCS11OBJ=$(KPKCS11OBJ)
	$(CD) ..

clean::
	$(CD) kpkcs11
	$(MAKE) /f NTMakefile clean KPKCS11BIN=$(KPKCS11BIN) KPKCS11LIB=$(KPKCS11LIB) KPKCS11OBJ=$(KPKCS11OBJ)
	$(CD) ..

fini:
	@echo --- done ---

bins: mkdirs $(CONFIGHEADER) $(DLL) $(KPKCS11DLL) $(HELPFILE) lang test fini

all: mkdirs $(CONFIGHEADER) $(DLL) $(KPKCS11DLL) $(HELPFILE) lang test msi wixlib fini

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

!ifdef BUILD_KRBCOMPAT
DELAYLOAD=/DELAYLOAD:heimdal.dll
!endif

$(DLL): $(OBJFILES) $(DLLRESFILE) $(LIBFILES)
	$(DLLGUILINK) $(SDKLIBFILES) $(DELAYLOAD)
	$(_MERGE_HEIMDAL_MANIFEST)
	$(__MERGE_COMMON_CONTROLS_MANIFEST)
	$(_VC_MANIFEST_EMBED_DLL)
	if exist $@.manifest type $@.manifest
	$(_VC_MANIFEST_CLEAN)
	$(CODESIGN)
	$(SYMTORE_IMPORT)

clean::
	-$(RM) $(DLL)

# Language specific resources

# (repeat the following block as needed, redefining LANG for each
# supported language)

# English-US
LANG=en_us

LANGDLL=$(DEST)\bin\$(DLLBASENAME)_$(LANG).dll

lang:: $(LANGDLL)

$(LANGDLL): $(OBJ)\langres_$(LANG).res $(OBJ)\version_$(LANG).res
	$(DLLRESLINK)
	$(_VC_MANIFEST_EMBED_DLL)
	$(_VC_MANIFEST_CLEAN)
	$(CODESIGN)
	$(SYMSTORE_IMPORT)

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
	light -nologo -sval -out $@ $**
	$(CODESIGN)

$(OBJ)\kcaplugin.wixobj: installer\kcaplugin.wxs $(DLL) $(HELPFILE)
	candle -nologo \
	-dKCAPluginVersion="$(VERLIST)" \
	-dNetIDMgrVersion="$(NIDMVERSTR)" \
	-dBinDir="$(DEST)\bin" \
	-dDocDir="$(DEST)\doc" \
	-dKPKCS11BinDir="$(KPKCS11BIN)" \
	-out $@ installer\kcaplugin.wxs

$(OBJ)\kcaplugin-core.wixobj: installer\kcaplugin-core.wxs $(DLL) $(HELPFILE)
	candle -nologo \
	-dKCAPluginVersion="$(VERLIST)" \
	-dNetIDMgrVersion="$(NIDMVERSTR)" \
	-dBinDir="$(DEST)\bin" \
	-dDocDir="$(DEST)\doc" \
	-dKPKCS11BinDir="$(KPKCS11BIN)" \
!ifndef NIDMRAWDIRS
!ifdef BUILD_KRBCOMPAT
	-dKerberosRedistDir="$(KERBEROSCOMPATSDKROOT)\redist\$(CPU)" \
!else
	-dKerberosRedistDir="$(HEIMDALSDKROOT)\redist\$(CPU)" \
!endif
!endif
	-out $@ installer\kcaplugin-core.wxs

WIXLIB=$(DEST)\kcaplugin-$(VERMAJOR)_$(VERMINOR)_$(VERAUX)_$(VERPATCH)-$(CPU)$(VERDEBUG).wixlib

wixlib: $(WIXLIB)

$(WIXLIB): $(OBJ)\kcaplugin-wl.wixobj
	lit -nologo -bf -out $@ $**

$(OBJ)\kcaplugin-wl.wixobj: installer\kcaplugin-core.wxs $(DLL) $(HELPFILE)
	candle -nologo \
	-dKCAPluginVersion="$(VERLIST)" \
	-dNetIDMgrVersion="$(NIDMVERSTR)" \
	-dBinDir="$(DEST)\bin" \
	-dDocDir="$(DEST)\doc" \
	-dKPKCS11BinDir="$(KPKCS11BIN)" \
	-dMainFeature=Feature.KCACred \
	-out $@ installer\kcaplugin-core.wxs

clean::
	-$(RM) $(MSIFILE)

# install-local:
#
# This target performs a minimal registration of the plug-in binary on
# the local system.  An install of Network Identity Manager should
# then be able to pick up the plug-in from the build location.
#
# The registration is done in HKCU.

HIVE=HKCU

REGPATH=$(HIVE)\Software\MIT\NetIDMgr\PluginManager\Modules\KCACred

install-local: all
	REG ADD "$(REGPATH)" /f
	REG ADD "$(REGPATH)" /v ImagePath /t REG_SZ /d "$(DLL)" /f
	REG ADD "$(REGPATH)" /v PluginList /t REG_SZ /d "KCACred" /f

clean-local:
	REG DELETE "$(REGPATH)"

# Tests

{test}.c{$(OBJ)}.obj:
	$(C2OBJ)

TESTEXEOBJS=$(OBJ)\testmain.obj

TESTSDKLIBS= \
        gdi32.lib       \
	user32.lib

TESTEXE=$(DEST)\bin\kcatest.exe

$(TESTEXE): $(TESTEXEOBJS) $(LIBFILES) $(NIDMLIBDIR)\kcacred.lib
	$(EXECONLINK) $(TESTSDKLIBS)

test:: $(TESTEXE)
