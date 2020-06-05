@echo off
cd build
start WinDbgX -T Server -c "bu server!main;g;p;" server.exe 