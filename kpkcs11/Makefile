# Generated automatically from Makefile.in by configure.
##### Top-level Makefile for KPKCS11 #####
##### $Id: Makefile.in,v 1.5 2002/03/11 16:04:33 kwc Exp $

SHELL		= /bin/sh


srcdir		= .

SHELL		= /bin/sh

CC		= gcc
LD		= gcc

INSTALL		= /usr/bin/install -c
INSTALL_PROGRAM	= ${INSTALL}
INSTALL_DATA	= ${INSTALL} -m 644

AR		= /usr/bin/ar
RANLIB		= ranlib
RM		= /bin/rm -f

DEFS		= -DHAVE_CONFIG_H

prefix		= /usr/local
bindir		= ${exec_prefix}/bin
exec_prefix	= ${prefix}
includedir	= ${prefix}/include
libdir		= ${exec_prefix}/lib
manprefix	= ${prefix}/man
man1dir		= ${manprefix}/man1
man3dir		= ${manprefix}/man3
man8dir		= ${manprefix}/man8

# The following need to be defined in order to locate
# the Kerberos and OpenSSL libraries and include files

KRB_BASE	= /usr/kerberos
OPENSSL_BASE	= /usr

KRB_LIBS	= -Wl,-rpath /usr/kerberos/lib -L/usr/kerberos/lib -lkrb5 -lk5crypto -lcom_err
OPENSSL_LIBS	= -Wl,-rpath /usr -L$(OPENSSL_BASE)/lib -lcrypto
EX_LIBS         = -lresolv -lnsl

KRB_INCDIR	= $(KRB_BASE)/include
KRB_INCS	= -I/usr/kerberos/include
OPENSSL_INC	= -I$(OPENSSL_BASE)/include

##### End of system configuration section #####

##### Targets #####

DEFINE		= -fPIC -DLINUX $(DEFS)

INCLUDE		= $(OPENSSL_INC) $(KRB_INCS) -I$(srcdir) -I$(srcdir)/..

CFLAGS		= -g -O2 -DUSE_KRB5 $(CCOPT) $(DEFINE) $(INCLUDE) $(DBG)

LDFLAGS 	= -shared

LIBS		= $(OPENSSL_LIBS) $(KRB_LIBS) $(EX_LIBS)

# nothing below this point should need to be touched

LIBOBJS		= cki_funcs.o cki_globals.o cki_new_free.o pkcs11_funcs.o \
			pkcs11_globals.o pkcs11_new_free.o pkcs11_evp_funcs.o \
			cki_dup.o cki_objs.o cki_ssleay.o cki_err.o debug.o \
			b64.o concat.o test_gencert.o borrowed.o  doauth.o \
			cu_util.o

MAJOR           = 0
MINOR           = 1
BASELIB		= libpkcs11.so
LIBRARY		= $(BASELIB).$(MAJOR)

all:	$(LIBRARY) 

.c.o:
	rm -f $@; $(CC) -c $(CFLAGS) $<

Makefile: Makefile.in ../config.status
	(cd ..; ./config.status)

../config.status: ../configure
	(cd ..; ./config.status --recheck)

$(LIBRARY):	$(LIBOBJS)
	$(LD) $(LDFLAGS) -o $(LIBRARY).$(MINOR) $(LIBOBJS) $(LIBS)
	-rm -f $(BASELIB); ln -s $(LIBRARY).$(MINOR) $(BASELIB)
	-rm -f $(LIBRARY); ln -s $(LIBRARY).$(MINOR) $(LIBRARY)

clean:	
	-rm -rf *.o lib $(BASELIB) $(LIBRARY) $(LIBRARY).$(MINOR) pkcs11.tar.gz

install: $(LIBRARY)
	-rm -f $(libdir)/$(LIBRARY).$(MINOR); $(INSTALL) $(LIBRARY).$(MINOR) $(libdir)
	-rm -f $(libdir)/$(LIBRARY); ln -s $(libdir)/$(LIBRARY).$(MINOR) $(libdir)/$(LIBRARY)
	-rm -f $(libdir)/$(BASELIB); ln -s $(libdir)/$(LIBRARY).$(MINOR) $(libdir)/$(BASELIB)
