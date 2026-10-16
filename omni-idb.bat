@echo off
cd /d "%~dp0"
where pythonw >nul 2>nul && (start "" pythonw -m omni_idb %*) || python -m omni_idb %*
