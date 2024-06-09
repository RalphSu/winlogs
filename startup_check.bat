@echo off
set /a failCount=0
set "taskName=checklogin"
set "lastRunStatus=0"

 REM 检查特定任务的最后一次运行状态
SCHTASKS /QUERY /TN "%taskName%" | FINDSTR /C:"Last Run Result" /C:"Failed" > nul
if "%ERRORLEVEL%"=="0" (
    set /a failCount+=1
    echo Failure count: %failCount%
) else (
    set failCount=0
)

REM 检查失败次数是否达到5
if %failCount% gtr 4 (
    echo Restarting the machine due to consecutive failures...
    shutdown /r /f
) else (
    echo Failure count: %failCount%
    echo Rescheduling the task...
    SCHTASKS /CHANGE /TN "%taskName%" /ENABLE
)


REM 记录最后一次运行状态
setx lastRunStatus %ERRORLEVEL%