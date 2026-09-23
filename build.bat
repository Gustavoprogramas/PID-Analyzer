@echo off
setlocal
cd /d "%~dp0"
where cl >nul 2>nul
if errorlevel 1 (
    echo Abra o Developer Command Prompt x64 do Visual Studio e execute este arquivo.
    exit /b 1
)
cl /std:c++17 /EHsc /O2 /MT pid.cpp /link iphlpapi.lib ws2_32.lib wintrust.lib crypt32.lib /OUT:pid.exe
exit /b %errorlevel%
