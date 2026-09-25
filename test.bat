@echo off
setlocal
cd /d "%~dp0"
where cl >nul 2>nul
if errorlevel 1 (
    echo Abra o Developer Command Prompt x64 do Visual Studio e execute este arquivo.
    exit /b 1
)
if not exist output mkdir output
cl /std:c++17 /EHsc /O2 /MT /W4 pid_tests.cpp /Fe:output\pid_tests.exe /Fo:output\pid_tests.obj
if errorlevel 1 exit /b 1
output\pid_tests.exe
if errorlevel 1 exit /b 1
cl /std:c++17 /EHsc /O2 /MT /W4 pid_monitor_tests.cpp /Fe:output\pid_monitor_tests.exe /Fo:output\pid_monitor_tests.obj
if errorlevel 1 exit /b 1
output\pid_monitor_tests.exe
if errorlevel 1 exit /b 1
cl /std:c++17 /EHsc /O2 /MT /W4 pid_shield_tests.cpp /Fe:output\pid_shield_tests.exe /Fo:output\pid_shield_tests.obj
if errorlevel 1 exit /b 1
output\pid_shield_tests.exe
exit /b %errorlevel%
