@echo off
chcp 65001 >nul
pip install pyinstaller
pyinstaller --onefile --uac-admin --name RKNShield rknshield.py
echo.
echo Готово! Файл: dist\RKNShield.exe
pause
