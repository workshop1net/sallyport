@echo off
rem Runs the Sallyport helper inside Docker, so Python is not needed on the host.
rem Usage: sallyport.cmd init | load-targets [--dry-run] | check [--insecure] [--url URL]
setlocal
cd /d "%~dp0"

if "%~1"=="" (
  echo usage: sallyport.cmd init ^| load-targets ^| check
  exit /b 2
)

docker version >nul 2>&1
if errorlevel 1 (
  echo error: Docker is not running. Start Docker Desktop and try again.
  exit /b 1
)

docker build -q -t sallyport-tools tools >nul
if errorlevel 1 (
  echo error: could not build the helper image
  exit /b 1
)

if "%~1"=="init" (
  if not exist generated\initdb mkdir generated\initdb
  if not exist generated\initdb\001-schema.sql (
    echo generating Guacamole database schema...
    docker run --rm -v "%cd%\generated\initdb:/out" --entrypoint sh guacamole/guacamole:latest -c "/opt/guacamole/bin/initdb.sh --postgresql > /out/001-schema.sql"
    if errorlevel 1 (
      echo error: could not generate the schema
      exit /b 1
    )
  )
)

rem load-targets needs the stack's internal network, so the stack must be running.
set NET=
if "%~1"=="load-targets" set NET=--network sallyport_internal

docker run --rm %NET% -v "%cd%:/work" sallyport-tools %*
exit /b %errorlevel%
