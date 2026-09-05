@echo off
REM ===========================================================================
REM  Mission 2 - the stage sequence, in order.
REM  MMS 2026 Midway Edition - Empowering SOC Teams
REM
REM  Three runs. Each makes a different point. See README.md.
REM ===========================================================================

setlocal
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8

echo.
echo ============================================================
echo   PRE-FLIGHT - do the guardrails actually hold?
echo ============================================================
python soc_triage_agent.py --self-test
if errorlevel 1 (
    echo.
    echo   Guardrail self-test FAILED. Do not demo this. Stop.
    exit /b 1
)
pause

echo.
echo ============================================================
echo   RUN 1 - the easy one. Agent closes a benign incident.
echo ============================================================
python soc_triage_agent.py --auto-approve --fast
pause

echo.
echo ============================================================
echo   RUN 2 - the real one. You are the approval gate.
echo           Press 'a' to approve when prompted.
echo ============================================================
python soc_triage_agent.py --incident 48213
pause

echo.
echo ============================================================
echo   RUN 3 - reject it on purpose. Watch the agent re-plan.
echo ============================================================
python soc_triage_agent.py --incident 48201 --reject
pause

echo.
echo ============================================================
echo   BONUS - prompt injection in the incident description
echo ============================================================
python soc_triage_agent.py --incident 48176 --auto-approve --fast

echo.
echo   Run records are in .\runs\
echo.
endlocal
