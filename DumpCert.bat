@echo off
pushd %~dp0

:do
if "%~1"=="" goto :done
echo %1
RevokeCert.exe d %1
move %1.*.der "%cd%"
shift
goto :do

:done
pause
popd
exit /b
