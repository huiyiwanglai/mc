# 如何在安卓上运行此程序

由于这是一个 Python 程序，要在安卓上运行，你有两种主要选择：

## 方法一：使用 Pydroid 3 (最简单，推荐)

这是一个安卓上的 Python IDE，可以直接运行 Python 代码。

1.  **下载安装**: 在手机应用商店搜索并安装 "Pydroid 3"。
2.  **传输文件**: 将电脑上的 `mc_bot_project` 文件夹整个复制到手机存储中（例如 `/storage/emulated/0/mc_bot_project`）。
3.  **安装依赖**:
    *   打开 Pydroid 3。
    *   点击左上角菜单 -> Pip。
    *   输入 `cryptography` 并点击 INSTALL。
    *   输入 `kivy` 并点击 INSTALL。
4.  **运行**:
    *   在 Pydroid 3 中点击文件夹图标 -> Open。
    *   找到你复制进去的 `mc_bot_project` 文件夹。
    *   选择 `gui.py` (注意是 gui.py，不是 main.py，因为我们需要图形界面)。
    *   点击黄色的播放按钮运行。

## 方法二：打包成 APK (需要 Linux 环境)

如果你想把它做成一个独立的 APP 安装包 (.apk)，你需要使用 `buildozer` 工具进行编译。这通常需要在 Linux 系统（如 Ubuntu）或 Windows 的 WSL 子系统中进行。

1.  **准备环境**: 安装 WSL (Ubuntu) 或使用 Linux 虚拟机。
2.  **安装 Buildozer**:
    ```bash
    sudo apt update
    sudo apt install -y git zip unzip openjdk-17-jdk python3-pip autoconf libtool pkg-config zlib1g-dev libncurses5-dev libncursesw5-dev libtinfo5 cmake libffi-dev libssl-dev
    pip3 install --user --upgrade buildozer Cython virtualenv
    ```
3.  **编译**:
    *   将项目文件复制到 Linux 环境中。
    *   在项目目录下运行：
        ```bash
        buildozer android debug
        ```
    *   编译过程非常漫长（首次可能需要 30 分钟以上），且需要科学上网下载 Android SDK/NDK。
4.  **安装**: 编译成功后，在 `bin` 目录下会生成 `.apk` 文件，传输到手机安装即可。

## 注意事项

*   **保持后台运行**: 安卓系统对后台进程杀得很严。如果切换到后台，机器人可能会断开连接。建议在 Pydroid 3 设置中开启 "Stay awake" (保持唤醒)，或者在打包 APK 时申请 `WAKE_LOCK` 权限（已在配置文件中添加）。
*   **网络**: 确保手机网络能连接到游戏服务器。
