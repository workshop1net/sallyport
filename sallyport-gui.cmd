@echo off
rem Starts the Sallyport control panel (a local web page on 127.0.0.1).
rem Needs Python 3 with the packages in requirements.txt:  pip install -r requirements.txt
setlocal
cd /d "%~dp0"

set PY=
where py >nul 2>&1 && set PY=py -3
if not defined PY (
  where python >nul 2>&1 && set PY=python
)
if not defined PY (
  echo error: Python 3 was not found. Install it from python.org and tick "Add python.exe to PATH".
  pause
  exit /b 1
)

%PY% -I -c "import yaml, cryptography" >nul 2>&1
if errorlevel 1 (
  echo Installing the required Python packages...
  %PY% -m pip install -r requirements.txt
  if errorlevel 1 (
    echo error: pip could not install the packages.
    pause
    exit /b 1
  )
)

%PY% -I sallyport_gui.py %*
if errorlevel 1 pause
