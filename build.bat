@echo off
set CompilerFlags= /nologo /Z7 /EHsc /wd4003 /MT /diagnostics:classic -Wno-unused-result  -fdiagnostics-absolute-paths  /clang:-std=c11
set LinkerFlags=-subsystem:console
set bits=x64
set AssetsLocation=..\assets\dist\
set LibraryLocation=..\deps\libs\%bits%\
set LinkLibraries=mbedcrypto.lib mbedtls.lib libpq.lib mbedx509.lib json-c.lib libsodium.lib nghttp2.lib uv.lib pdfium.dll.lib libc++.dll.lib zlib.dll.lib advapi32.lib winmm.lib user32.lib kernel32.lib 
mkdir build > NUL 2> NUL

IF NOT DEFINED vcvars_called (
      pushd %cd%
	  set vcvars_called=1
	  call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" %bits% > NUL 2>NUL 
	  popd )

cd build
del *.pdb > NUL 2> NUL
ctime -begin webapp.ctm
clang-cl %CompilerFlags% /c  /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_WARNINGS ..\code\picohttpparser.c ..\code\log.c ..\code\mustach.c ..\code\mustach-json-c.c /I..\deps\include
clang-cl %CompilerFlags% ..\code\server.c   /I..\deps\include /link mustach.obj log.obj mustach-json-c.obj picohttpparser.obj -incremental:no /LIBPATH:%LibraryLocation%  %LinkLibraries% %LinkerFlags% -out:server.exe
REM clang-cl %CompilerFlags% ..\code\client.c   /I..\deps\include /link mustach.obj mustach-json-c.obj picohttpparser.obj -incremental:no /LIBPATH:%LibraryLocation%  %LinkLibraries% %LinkerFlags% -out:client.exe
ctime -end webapp.ctm
REM "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe" /p /enable server.exe /full
REM "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe" /p /disable server.exe
robocopy %LibraryLocation% . *.dll > NUL 2> NUL
robocopy %AssetsLocation% . *.html > NUL 2> NUL
robocopy %AssetsLocation% . *.css > NUL 2> NUL
robocopy %AssetsLocation% . *.js > NUL 2> NUL
robocopy %AssetsLocation% . *.png > NUL 2> NUL
robocopy %AssetsLocation% . *.ico > NUL 2> NUL
cd ..
