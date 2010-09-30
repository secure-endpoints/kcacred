@echo off

echo Setting up environment
call "c:\Program Files\Microsoft SDKs\Windows\v7.0\Bin\SetEnv" %1 %2 %3 %4

set NIDMSDKDIR=C:\src\kerberos\kfw-3.2.2
set HEIMDALSDKDIR=c:\src\heimdal\out\sdk
set OPENSSLDIR=c:\src\openssl-1.0.0a
set HHCFULLPATH="C:\Program Files (x86)\HTML Help Workshop\hhc.exe"
for %%i in (candle.exe) do (
        if "%%~$PATH:i"=="" goto nowix
        echo candle.exe found at : %%~$PATH:i
)
goto headout1
:nowix
set PATH=%PATH%;c:\tools\WiX3
:headout1
for %%i in (gtags.exe) do (
        if "%%~$PATH:i"=="" goto nogtags
        echo gtags.exe found at : %%~$PATH:i
)
goto headout2
:nogtags
rem set PATH=%PATH%;c:\work\global\bin
:headout2
for %%i in (runemacs.exe) do (
        if "%%~$PATH:i"=="" goto noemacs
        echo runemacs.exe found at : %%~$PATH:i
)
goto headout3
:noemacs
rem set PATH=%PATH%;c:\emacs-22.1\bin\
:headout3
title KCA Build
exit /b
