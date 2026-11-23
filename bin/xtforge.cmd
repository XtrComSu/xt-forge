@echo off
setlocal enabledelayedexpansion
rem portable xt-forge launcher for Windows — native-first dispatch, Python fallback.
rem Set XT_FORCE_PYTHON=1 to force pure-Python execution.
rem The caller's directory is never changed: %ROOT% is already on PYTHONPATH,
rem so relative arguments still resolve against the caller's directory.
rem No endlocal tricks either — the status is carried out through a capture/exit pair.
rem
rem Candidate order: %%XT_PYTHON%%, python, py -3, python3.

set "BIN_DIR=%~dp0"
for %%I in ("%BIN_DIR%..") do set "ROOT=%%~fI"

if "%XT_HOME%"=="" set "XT_HOME=%USERPROFILE%\.xt-forge"
if "%PYTHONPATH%"=="" (
    set "PYTHONPATH=%ROOT%"
) else (
    set "PYTHONPATH=%ROOT%;%PYTHONPATH%"
)

call :dispatch %*
set "RC=%ERRORLEVEL%"
exit /b %RC%

:dispatch
set "NATIVE=%ROOT%\native\xtforge-rs\target\release\xtforge-native.exe"
if "%XT_FORCE_PYTHON%"=="1" goto :py_xt_python
if exist "%NATIVE%" goto :run_native
goto :py_xt_python

:run_native
"%NATIVE%" %*
set "RC=%ERRORLEVEL%"
exit /b %RC%

rem ---- Python fallback: pick the first interpreter that is at least 3.11 ----

:py_xt_python
if "%XT_PYTHON%"=="" goto :py_default_python
set "PYCMD="%XT_PYTHON%""
set "STAGE=xt_python"
goto :py_check

:py_default_python
set "PYCMD=python"
set "STAGE=python"
goto :py_check

:py_launcher
set "PYCMD=py -3"
set "STAGE=py_launcher"
goto :py_check

:py_python3
set "PYCMD=python3"
set "STAGE=python3"
goto :py_check

:py_check
rem Version check runs before dispatch; failure means too old or not installed.
%PYCMD% -c "import sys; sys.exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>nul
if errorlevel 1 goto :py_next
%PYCMD% -m xtforge.cli %*
set "RC=%ERRORLEVEL%"
exit /b %RC%

:py_next
if "%STAGE%"=="xt_python" goto :py_default_python
if "%STAGE%"=="python" goto :py_launcher
if "%STAGE%"=="py_launcher" goto :py_python3

:no_interpreter
echo xt-forge: no suitable Python interpreter found. 1>&2
echo xt-forge: Python 3.11 or newer is required; set XT_PYTHON to a 3.11+ interpreter or install one. 1>&2
exit /b 2
