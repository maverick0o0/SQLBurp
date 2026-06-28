@echo off
title SQLMap REST API Server
color 0A

echo ====================================================
echo      Starting SQLMap REST API for SQLBurp...
echo ====================================================
echo.

:: Check if sqlmapapi.py exists in the current directory
if exist "sqlmapapi.py" (
    echo [INFO] Found sqlmapapi.py in current directory.
    echo [INFO] Starting server on 127.0.0.1:8775 with admin:admin credentials...
    echo.
    python sqlmapapi.py -s -H 127.0.0.1 -p 8775 --username admin --password admin
    
    echo.
    echo [ERROR] The server stopped unexpectedly!
    pause
    exit
)

:: If not found, tell the user to put it in the sqlmap directory
echo [ERROR] sqlmapapi.py not found!
echo.
echo Please move this .bat file directly inside your sqlmap folder
echo (the folder that contains sqlmap.py and sqlmapapi.py) and run it again.
echo.
pause
