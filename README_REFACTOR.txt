Project Restructuring Note (2025-12-01)
=========================================

The project has been refactored to clean up the workspace.

Active Project Folder:
----------------------
e:\学习编程\4399mc\mc_bot_project\

Contents:
- main.py       : Entry point (Run this!)
- manager.py    : Async Bot Manager
- client.py     : Async Bot Client
- auth.py       : Authentication Logic
- config.py     : Configuration
- utils.py      : Utilities
- netease_auth_server/ : Core dependency (Moved here)
- device.json   : Device config (Moved here)
- tools/        : Debug scripts (check_server.py, debug_login.py, etc.)

Obsolete Files (Safe to Delete):
--------------------------------
e:\学习编程\4399mc\bot_system\ (Directory)
e:\学习编程\4399mc\multi_bot_client.py
e:\学习编程\4399mc\run_bot_system.py
e:\学习编程\4399mc\连接插件服务器.py

How to Run:
-----------
cd e:\学习编程\4399mc
& .venv\Scripts\python.exe mc_bot_project\main.py
