@echo off
cd %~dp0
setlocal enabledelayedexpansion

if not exist php\php.exe (
	echo PHP wasn't detected; we'll download and install it for you.
	PowerShell -ExecutionPolicy Unrestricted -File "downloadphp.ps1"
)

if not exist php\php.exe (
	echo Failed to setup php, try doing it manually
	pause
	exit
)

echo The script can be terminated at any time by pressing Ctrl-C

php\php.exe -f steam.php
pause
