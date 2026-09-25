@echo off
setlocal
cd /d "%~dp0"
if not exist ..\output mkdir ..\output
cl /std:c++17 /EHsc /W4 /MT tools\guardctl.cpp /Fe:..\output\guardctl.exe /Fo:..\output\guardctl.obj
if errorlevel 1 exit /b 1
msbuild SentinelGuard.vcxproj /p:Configuration=Release /p:Platform=x64
exit /b %errorlevel%
