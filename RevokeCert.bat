@echo off
pushd %~dp0

:do
if "%~1"=="" goto :done
RevokeCert.exe r %1
shift
goto :do

:done
pause
popd
exit /b
