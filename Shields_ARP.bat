@echo off
setlocal

set TASK_NAME=ECMcameraStartup
set EXE_FILE=ECMcamera_ARP_v0.6.9

REM 创建计划任务
schtasks /create /tn "%TASK_NAME%" /sc ONSTART /rl HIGHEST /tr "%EXE_FILE%" /ru "NT AUTHORITY\SYSTEM" /f

echo 完成！
pause
