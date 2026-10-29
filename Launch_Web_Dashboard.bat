@echo off
title VeriBlue AI - Web Dashboard
echo ========================================================
echo Starting VeriBlue AI Streamlit Web Dashboard...
echo ========================================================
cd /d "%~dp0"
python -m streamlit run web_app.py
pause
