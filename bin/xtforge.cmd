@echo off
setlocal enabledelayedexpansion
rem portable xt-forge launcher for Windows — native-first dispatch, Python fallback.
rem Set XT_FORCE_PYTHON=1 to force pure-Python execution.

set "BIN_DIR=%~dp0"
for %%I in ("%BIN_DIR%..") do set "ROOT=%%~fI"

if "%XT_HOME%"=="" set "XT_HOME=%USERPROFILE%\.xt-forge"
if "%PYTHONPATH%"=="" (
    set "PYTHONPATH=%ROOT%"
) else (
    set "PYTHONPATH=%ROOT%;%PYTHONPATH%"
)

set "NATIVE=%ROOT%\native\xtforge-rs\target\release\xtforge-native.exe"
if not "%XT_FORCE_PYTHON%"=="1" if exist "%NATIVE%" (
    "%NATIVE%" %*
    exit /b %ERRORLEVEL%
)

if not "%XT_PYTHON%"=="" (
    pushd "%ROOT%" >nul
    "%XT_PYTHON%" -m xtforge.cli %*
    set "RC=%ERRORLEVEL%"
    popd >nul
    exit /b %RC%
)

where python >nul 2>nul
if %ERRORLEVEL%==0 (
    pushd "%ROOT%" >nul
    python -m xtforge.cli %*
    set "RC=%ERRORLEVEL%"
    popd >nul
    exit /b %RC%
)

where py >nul 2>nul
if %ERRORLEVEL%==0 (
    pushd "%ROOT%" >nul
    py -3 -m xtforge.cli %*
    set "RC=%ERRORLEVEL%"
    popd >nul
    exit /b %RC%
)

pushd "%ROOT%" >nul
python3 -m xtforge.cli %*
set "RC=%ERRORLEVEL%"
popd >nul
exit /b %RC%
