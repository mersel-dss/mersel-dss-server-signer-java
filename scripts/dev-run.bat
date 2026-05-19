@echo off
REM =====================================================================
REM  dev-run.bat — Mersel DSS Signer'i IDE'siz calistirmak icin Windows scripti.
REM =====================================================================
REM  Kullanim:
REM    scripts\dev-run.bat                  ^> default (KURUM01 RSA PFX)
REM    scripts\dev-run.bat kurum02-ec384    ^> KURUM02 EC-P384 PFX
REM    scripts\dev-run.bat mali-muhur-akis  ^> Mali Muhur AKIS (Windows)
REM    scripts\dev-run.bat list             ^> mevcut profilleri listele
REM
REM  Mali Muhur senaryolarinda CERTIFICATE_PIN env'i zorunlu:
REM    set CERTIFICATE_PIN=1234
REM    scripts\dev-run.bat mali-muhur-akis
REM =====================================================================

setlocal enabledelayedexpansion

set "SCENARIO=%~1"
if "%SCENARIO%"=="" set "SCENARIO=default"

REM ----- list mode
if /I "%SCENARIO%"=="list" (
    echo Mevcut senaryolar:
    echo   default ^| kurum01-rsa2048   -^> testkurum01 RSA-2048 ^(PIN=614573^) [default]
    echo   kurum02-rsa2048              -^> testkurum02 RSA-2048 sm.gov.tr ^(PIN=059025^)
    echo   kurum02-ec384                -^> testkurum02 EC-P384       ^(PIN=825095^)
    echo   kurum03-rsa2048              -^> testkurum03 RSA-2048      ^(PIN=181193^)
    echo   kurum03-ec384                -^> testkurum03 EC-P384       ^(PIN=540425^)
    echo   mali-muhur-akis ^| mali-muhur -^> Mali Muhur AKIS ^(Windows^)
    exit /b 0
)

REM ----- scenario -> profile mapping
if /I "%SCENARIO%"=="default"          set "PROFILES=local,pfx-kurum01-rsa2048"
if /I "%SCENARIO%"=="kurum01-rsa2048"  set "PROFILES=local,pfx-kurum01-rsa2048"
if /I "%SCENARIO%"=="kurum02-rsa2048"  set "PROFILES=local,pfx-kurum02-rsa2048"
if /I "%SCENARIO%"=="kurum02-ec384"    set "PROFILES=local,pfx-kurum02-ec384"
if /I "%SCENARIO%"=="kurum03-rsa2048"  set "PROFILES=local,pfx-kurum03-rsa2048"
if /I "%SCENARIO%"=="kurum03-ec384"    set "PROFILES=local,pfx-kurum03-ec384"
if /I "%SCENARIO%"=="mali-muhur-akis"  set "PROFILES=local,mali-muhur-akis-windows"
if /I "%SCENARIO%"=="mali-muhur"       set "PROFILES=local,mali-muhur-akis-windows"

if not defined PROFILES (
    echo [HATA] Bilinmeyen senaryo: %SCENARIO%
    echo Liste icin: scripts\dev-run.bat list
    exit /b 1
)

echo ^> OS         : windows
echo ^> Senaryo    : %SCENARIO%
echo ^> Profiles   : %PROFILES%

REM ----- Java check
where java >nul 2>&1
if errorlevel 1 (
    echo [HATA] java bulunamadi - JDK 8+ kurulu olmali.
    exit /b 1
)
for /f "tokens=*" %%v in ('java -version 2^>^&1 ^| findstr /R "version"') do (
    echo ^> Java       : %%v
    goto :java_ok
)
:java_ok

REM ----- Mali Muhur senaryosunda PIN fail-fast
echo %PROFILES% | findstr /C:"mali-muhur-akis" >nul
if not errorlevel 1 (
    if "%CERTIFICATE_PIN%"=="" (
        echo [HATA] Mali Muhur senaryosu icin CERTIFICATE_PIN env'i gerekli.
        echo        Ornek: set CERTIFICATE_PIN=1234 ^&^& scripts\dev-run.bat mali-muhur-akis
        exit /b 1
    )
)

REM ----- Maven runner
set "MVN_CMD=mvn"
if exist ".\mvnw.cmd" set "MVN_CMD=.\mvnw.cmd"

where %MVN_CMD% >nul 2>&1
if errorlevel 1 (
    if not exist ".\mvnw.cmd" (
        echo [HATA] mvn ^(veya .\mvnw.cmd^) bulunamadi - Maven 3.6+ kurulu olmali.
        exit /b 1
    )
)
echo ^> Maven      : %MVN_CMD%
echo [OK] Baslatiliyor...

%MVN_CMD% spring-boot:run -Dspring-boot.run.profiles=%PROFILES%

endlocal
