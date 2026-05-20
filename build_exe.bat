@echo off
title Coffee Shop - Generando ejecutable...
color 0B
cls

echo.
echo  ================================================
echo    COFFEE SHOP - Generador de Ejecutable (.exe)
echo  ================================================
echo.

cd /d "%~dp0"

:: Verificar Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python no encontrado. Instala Python desde python.org
    pause & exit /b 1
)

:: Activar entorno virtual
if exist "venv\Scripts\activate.bat" (
    echo  [1/5] Activando entorno virtual...
    call venv\Scripts\activate.bat
) else if exist ".venv\Scripts\activate.bat" (
    echo  [1/5] Activando entorno virtual...
    call .venv\Scripts\activate.bat
) else (
    echo  [1/5] Sin entorno virtual, usando Python del sistema...
)

:: Instalar PyInstaller si no esta instalado
echo  [2/5] Verificando PyInstaller...
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo        Instalando PyInstaller...
    pip install pyinstaller -q
)
pip install -r requirements.txt -q

:: Generar archivos estaticos
echo  [3/5] Generando archivos estaticos...
python manage.py collectstatic --noinput -v 0
if errorlevel 1 (
    echo  [ERROR] Fallo collectstatic. Revisa la configuracion.
    pause & exit /b 1
)

:: Copiar imagenes de productos a staticfiles/media
if exist "media" (
    echo        Copiando imagenes de productos...
    if not exist "staticfiles\media" mkdir "staticfiles\media"
    xcopy /E /I /Y "media" "staticfiles\media" >nul
)

:: Limpiar build anterior
echo  [4/5] Limpiando build anterior...
if exist "dist\CoffeeShop" rmdir /S /Q "dist\CoffeeShop"
if exist "build\CoffeeShop" rmdir /S /Q "build\CoffeeShop"

:: Construir el ejecutable
echo  [5/5] Construyendo ejecutable (esto tarda 2-5 minutos)...
echo.
pyinstaller coffee_shop.spec --noconfirm

if errorlevel 1 (
    echo.
    echo  [ERROR] La construccion fallo. Revisa los mensajes de arriba.
    pause & exit /b 1
)

echo.
echo  ================================================
echo   Ejecutable generado exitosamente!
echo.
echo   Ubicacion: dist\CoffeeShop\CoffeeShop.exe
echo.
echo   Para entregar al profesor:
echo   Comprime la carpeta  dist\CoffeeShop  en un ZIP
echo   y entregasela. Solo necesita hacer doble clic
echo   en CoffeeShop.exe
echo  ================================================
echo.
pause
