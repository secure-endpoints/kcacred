
  KCA Plug-in for Network Identity Manager
  Version 2.3.0.0

------------------------------------------------------------------

        CONTENTS

        1.  INTRODUCTION
        2.  COPYRIGHT AND LICENSE
        3.  ROADMAP OF THE SOURCE TREE
        4.  BUILD REQUIREMENTS
        5.  BUILDING
        6.  RUNNING THE PLUG-IN
        7.  REGISTRY SETTINGS
        8.  DEPLOYING THE PLUG-IN
        9.  KNOWN ISSUES
        10. SUPPORT / BUG REPORTS

------------------------------------------------------------------

1.      INTRODUCTION

    This version of the KCA plug-in adheres to the following version
    constraints:

        Network Identity Manager API version : 6

    (This API version corresponds to the MIT Kerberos for Windows
    version 3.1).

    The source files in this template can be used to build the plug-in
    DLL, the US English resource DLL for the plug-in, the PKCS #1
    plug-in for Mozilla products exposing the Windows "My" Certificate
    Store, and the installer.

------------------------------------------------------------------

2.      COPYRIGHT AND LICENSE

    Copyright (c) 2006-2010 Secure Endpoints Inc.

    Permission is hereby granted, free of charge, to any person
    obtaining a copy of this software and associated documentation
    files (the "Software"), to deal in the Software without
    restriction, including without limitation the rights to use, copy,
    modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.


    Portions Copyright (c) 2000
    The Regents of the University of Michigan
    ALL RIGHTS RESERVED
   
    permission is granted to use, copy, create derivative works
    and redistribute this software and such derivative works
    for any purpose, so long as the name of the university of
    michigan is not used in any advertising or publicity
    pertaining to the use or distribution of this software
    without specific, written prior authorization.  if the
    above copyright notice or any other identification of the
    university of michigan is included in any copy of any
    portion of this software, then the disclaimer below must
    also be included.
   
    this software is provided as is, without representation
    from the university of michigan as to its fitness for any
    purpose, and without warranty by the university of
    michigan of any kind, either express or implied, including
    without limitation the implied warranties of
    merchantability and fitness for a particular purpose. the
    regents of the university of michigan shall not be liable
    for any damages, including special, indirect, incidental, or
    consequential damages, with respect to any claim arising
    out of or in connection with the use of the software, even
    if it has been or is hereafter advised of the possibility of
   
------------------------------------------------------------------

3.      ROADMAP OF THE SOURCE TREE

    The template consists of the following files and directories:

    .\README.TXT

        This file.

    .\Makefile

        The primary Makefile used by 'nmake' to build the plug-in.  In
        addition to providing build directives, it also contains a set
        of macros which defines the names and version information that
        is used throughout the plug-in code.

    .\credprov.h

        The main header file for all the C source files in the
        plug-in.

    .\main.c

        Provides the entry points for the module.

    .\plugin.c

        Provides the message processing functions and support routines
        for implementing the plug-in.  Note that some of the message
        processing routines have been moved to other sources files
        based on their use.

    .\credtype.c

        Functions for handling our credentials type.

    .\credacq.c

        Handlers for the credentials acquisition messages including
        handling the user interface for the new credentials dialogs.

    .\proppage.c

        Dialog procedures and support code for displaying property
        sheets for credentials that belong to our credentials type.

    .\config_main.c

        Dialog procedures and support code for providing the general
        configuration panel for this plug-in.

    .\config_id.c

        Dialog procedures and support code for providing per-identity
        configuration for this plug-in.

    .\config_ids.c

        Dialog procedures and support code for providing configuration
        for defaults across all identities.

    .\version.rc

        Version information for the plug-in as well as all the
        language resource DLLs.

    .\langres.h

        Declarations for the language resources (see below).  In its
        current form, it was generated via Visual Studio while editing
        the language resouces file.

    .\lang\en_us\langres.rc

        US-English language resources.  This will be used to create
        the language resource DLL.

    .\help\* and .\help\images\*

        Source files for building the compiled HTML documentation for
        the plug-in.

    .\installer\kcaplugin.wxs

        WiX source file for building the MSI installer.

    .\installer\nss

        MODUTIL.EXE and dependencies.  Used for optionally installing
        MODUTIL.  (see :
        http://www.mozilla.org/projects/security/pki/nss/tools/modutil.html)

    .\kpkcs11\*

        Source for building the PKCS #1 Windows "My" certificate store
        provider.

------------------------------------------------------------------

4.      BUILD REQUIREMENTS

    Microsoft(R) Platform SDK (Windows Server 2003 or later)

        (http://www.microsoft.com/msdownload/platformsdk/sdkupdate/)

    Microsoft(R) Visual C++ (Visual Studio 2003 or later)

        Although not tested, the template should build using the
        Microsoft Visual C++ toolkit.

    MIT Kerberos for Windows (version 3.1 or later) SDK

    OpenSSL (version 0.9.8d or later) SDK

    WiX version 2

        This is required for building the installer.  The WiX
        executables candle.exe and light.exe are expected to be on the
        execution path.

        (http://wix.sourceforge.net/)

------------------------------------------------------------------

5.      BUILDING

    The build process is fairly starightforward.  The source is set up
    to build using 'nmake', a build tool distributed with the Platform
    SDK as well as with Visual Studio.

    1.  Open a command prompt with a suitable build environment.

        From a plain command prompt, you can set up a debug build
        environment targetting Windows XP (32-bit) with:

        > "%PROGRAMFILES%\Microsoft Platform SDK\SetEnv.Cmd" /XP32 /DEBUG

    2.  Set the environment variable KFWSDKDIR to point to the root of
        the Kerberos for Windows 3.1 SDK.  (i.e. %KFWSDKDIR%\inc
        should be the include directory of the SDK)

        > SET KFWSDKDIR=%PROGRAMFILES%\MIT\Kerberos

    3.  Set the environment variable OPENSSLDIR to point to the root
        of the OpenSSL SDK.  (i.e. %OPENSSLDIR%\include should be the
        include directory of the SDK).

        > SET OPENSSLDIR=%PROGRAMFILES%\OpenSSL

    4.  Set the environment variable HHCFULLPATH to point to the
        hhc.exe binary of the Microsoft HTML Help Workshop.  This is
        used for building the compiled HTML help file for the plugin.

        > SET HHCFULLPATH=%PROGRAMFILES%\HTML Help Workshop\hhc.exe

    5.  Add the WiX binary path to the execution path.  Executables
        from here will be used to build the installer.

        > SET PATH=%PATH%;%PROGRAMFILES%\WiX2

    6.  Start the build:

        > NMAKE all

        The build target 'all' builds the plug-in and the language
        resources.  There is an additional build target 'clean' which
        removes the temporary files and the binaries generated during
        the build.

        Assuming everything goes well, the plug-in binaries should be
        created under a subdirectory under 'dest'.  The name of the
        subdirectory reflects the target architecture and the build
        type ('debug' or 'release').

        The PKCS #11 plug-in will build under the kpkcs11 directory
        and the relevant binaries will be under a subdirectory under
        'kpkcs11\dest'.

------------------------------------------------------------------

6.      RUNNING THE PLUG-IN

    Once the binaries for the plug-in have been built, you can
    register the plug-in with NetIDMgr by adding a registry value as
    follows:

    [HKEY_CURRENT_USER\Software\MIT\NetIDMgr\PluginManager\Modules\KCAMod]
       "ImagePath"="<path>"

    The <path> should be the full path to the plug-in DLL.

    Once this is done, you need to restart NetIDMgr so that it will
    pick up the new plug-in.

    Alternatively, you can build the installer and install the
    plug-in.

------------------------------------------------------------------

7.      REGISTRY SETTINGS

    Following the conventions used by Network Identity Manager, the
    settings for the KCA plug-in are maintained in the user and
    machine registry hives.  The layout of the settings is identical
    in both the user and machine hives.  User settings override
    machine settings.

    When obtaining credentials for an identity, the settings are
    looked-up from the following locations (in order):

    - Per-identity settings (see section 7.3)

    - Per-realm settings (see section 7.2)

    - Defaults for all identities (see section 7.3)

    For example, if credentials are being obtained for the Kerberos
    principal user@EXAMPLE.COM, locations that settings will be
    searched for are :

    - Per identity settings for user@EXAMPLE.COM

    (HKCU,HKLM\Software\MIT\NetIDMgr\KCDB\Identity\user@EXAMPLE.COM\KCACred)

    - Per-realm settings for EXAMPLE.COM

    (HKCU, HKLM\SOFTWARE\MIT\NetIDMgr\PluginManager\Plugins\KCACred\Parameters\Realms\EXAMPLE.COM)

    - Global defaults

    (HKCU, HKLM\SOFTWARE\MIT\NetIDMgr\PluginManager\Plugins\KCACred\Parameters)


    7.1 Plug-in global settings
    --------------------------------------------------------------

    Location :
      (user)    HKCU\SOFTWARE\MIT\NetIDMgr\PluginManager\Plugins\KCACred\Parameters
      (machine) HKLM\SOFTWARE\MIT\NetIDMgr\PluginManager\Plugins\KCACred\Parameters

    This location contains the settings that control the overall
    behavior of the plug-in.  Relevant settings are described in 7.3
    (Identity settings) below.

    7.2 Per-realm settings
    --------------------------------------------------------------

    Per-realm settings are chosen based on the realm of the identity
    principal.

    Location:
      (user)    HKCU\SOFTWARE\MIT\NetIDMgr\PluginManager\Plugins\KCACred\Parameters\Realms\<realm>
      (machine) HKLM\SOFTWARE\MIT\NetIDMgr\PluginManager\Plugins\KCACred\Parameters\Realms\<realm>

      Values
      ------------------------------------------------------------

      KCAEnabled (DWORD)

        Boolean value.  If non-zero, obtains credentials for this realm.

      KCAHostMethod (DWORD)

        Method for determining KCA hosts. Currently, the following
        values are supported:

        0 - Determine hosts automatically based on the identity realm
            (in which case 'KCAHosts' value is ignored).

        1 - Use the 'KCAHosts' value, and enables specifying host list
            manually.

        2 - Determine hosts automatically based on the realm specified
            in the KCARealm value.

      KCAHosts (STRING)

        Space separated list of KCA hosts to use if KCAHostMethod is
        1.

      KCARealm (STRING)

        Specifies the realm to use if KCAHostMethod is 2.

    7.3 Per-identity settings
    --------------------------------------------------------------

    Location: (identity-specific)
      (user) HKCU\Software\MIT\NetIDMgr\KCDB\Identity\<identity name>\KCACert

    Location: (defaults for all identities)
      (user)    HKCU\SOFTWARE\MIT\NetIDMgr\PluginManager\Plugins\KCACred\Parameters
      (machine) HKLM\SOFTWARE\MIT\NetIDMgr\PluginManager\Plugins\KCACred\Parameters

      Values
      ------------------------------------------------------------

      KCAEnabled (DWORD)

        Boolean value.  If non-zero, obtains credentials for this
        identity.

      KCAHostMethod (DWORD)

        Method for determining KCA hosts. Currently, the following
        values are supported:

        0 - Determine hosts automatically based on the identity realm
            (in which case 'KCAHosts' value is ignored).

        1 - Use the 'KCAHosts' value, and enables specifying host list
            manually.

        2 - Determine hosts automatically based on the realm specified
            in the KCARealm value.

      KCAHosts (STRING)

        Space separated list of KCA hosts to use if KCAHostMethod is
        1.

      KCARealm (STRING)

        Specifies the realm to use if KCAHostMethod is 2.

------------------------------------------------------------------

8.      DEPLOYING THE PLUG-IN

    This section provides information for organizations that wish to
    deploy the KCA plug-in MSI via group policy.

    A thorough overview of the procedure involved in deploying an MSI
    is beyond the scope of this document.  The information below only
    provides details that are specific to the KCA plug-in MSI.

    Currently, the MSI only provides a per-machine installation.
    Therefore, the ALLUSERS property must be set to 1.  This is done
    by the MSI by default, and should not be changed.

    8.1   Realm mappings
    --------------------------------------------------------------

    The MSI provides two public properties for organizations that wish
    to have all principals of a specific realm obtain KCA certs for
    another realm.  These properties are undefined by default, but
    when enabled, will add the necessary registry settings to perform
    the mapping.

      8.1.1 Public Properties
      ------------------------------------------------------------

      KCAREALMMAPFROM

         The realm of the identity (the realm of the Kerberos
         principal).

      KCAREALMMAPTO

         The realm from which KCA certs should be obtained by all
         principals of the realm specified by KCAREALMMAPFROM.

      All the principals that belong to the realm identified by the
      KCAREALMMAPFROM property will default to obtaining KCA certs for
      the realm identified by the KCAREALMMAPTO property.

      When both these properties are set, the installer adds the
      following registry keys:

      [HKEY_LOCAL_MACHINE\SOFTWARE\MIT\NetIDMgr\PluginManager\Plugins\KCACred\Realms\[KCAREALMMAPFROM]]
      "KCAEnabled"=dword:00000001
      "KCAHostMethod"=dword:00000002
      "KCARealm"="[KCAREALMMAPTO]"

      The [KCAREALMMAPFROM] and [KCAREALMMAPTO] will be replaced by
      the actual value to which the properties will be set to.

      E.g.:

        The following will result in all principals from realm
        REALM1.EXAMPLE.COM to obtain KCA certs for realm EXAMPLE.COM.

        KCAREALMMAPFROM = REALM1.EXAMPLE.COM
        KCAREALMMAPTO   = EXAMPLE.COM

      Note that this facility only exists to provide a default
      mapping.  Inidividual users may override the provided default
      with their own settings.

      Also note that setting the public properties only add one set of
      mappings.  If you need to configure multiple sets of mappings or
      different per-realm settings, then you need to create an MSI
      transform.

      8.1.2 Specifying public properties
      ------------------------------------------------------------

      Public properties may be specified at install time via arguments
      to the 'msiexec.exe' command line, or via a transform which will
      be applied to the MSI during deployment.

      E.g.: (command line)

      c:\> msiexec.exe /i kcaplugin.msi KCAREALMMAPFROM=REALM1.EXAMPLE.COM KCAREALMMAPTO=EXAMPLE.COM

------------------------------------------------------------------

9.      KNOWN ISSUES

    1. The kpkcs11.dll must be manually loaded into each
       application. For Mozilla Firefox and Thunderbird this is via
       the Tools->Options dialog. Firefox
       (Advanced->Encryption->Security Devices) Thunderbird
       (Privacy->Security->Security Devices)

    2. The KCA plug-in only permits a single certificate to be
       obtained for any given Kerberos 5 Identity. A future
       enhancement would be to obtain certificates from KCA servers in
       multiple Kerberos realms.

------------------------------------------------------------------

10.      SUPPORT / BUG REPORTS

    Problems should be sent to kca@secure-endpoints.com

------------------------------------------------------------------
