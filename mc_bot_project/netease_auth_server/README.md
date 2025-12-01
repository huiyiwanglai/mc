# 网易认证服务器最小Python实现（骨架）

> 注意：本目录只是根据 `Codexus.OpenSDK` 协议结构搭建的**教学/实验用骨架**，方便你理解协议和调试流程，尚不具备正式生产可用的安全性与完整性。

## 结构

- `net.py`：读写 `[uint16_be length][payload]` 的辅助函数。
- `chacha_packer.py`：模仿 C# `ChaChaPacker` 和 `YggdrasilExtensions.PackMessage/UnpackMessage` 的打包逻辑（目前使用 PyCryptodome 的 ChaCha20，轮数与 .NET ChaCha8 存在差异，后续可替换更精确实现）。
- `protocol.py`：实现与 `StandardYggdrasil.JoinServerAsync` 对话的最小服务器逻辑（初始化阶段 + JoinServer 阶段），目前所有校验逻辑极度简化。
- `server.py`：阻塞式 TCP 服务器入口，负责监听端口并为每个连接调用 `handle_client`。

## 安装依赖

建议使用虚拟环境（可选）：

```powershell
cd "E:\学习编程\4399mc"
python -m venv .venv
.venv\Scripts\activate
pip install pycryptodome
```

## 启动认证服务器

```powershell
cd "E:\学习编程\4399mc"
.venv\Scripts\activate
python -m netease_auth_server.server
```

如果你没有把当前目录添加为包，可以改为：

```powershell
cd "E:\学习编程\4399mc\netease_auth_server"
python server.py
```

服务器默认监听 `0.0.0.0:30000`。

## 在 C# 端如何指向这个服务器

在 `Codexus.ExampleConsole/Program.cs` 中，将 `StandardYggdrasil` 构造改为：

```csharp
var yggdrasil = new StandardYggdrasil(new YggdrasilData
{
    LauncherVersion = x19.GameVersion,
    Channel = "netease",
    CrcSalt = "22AC4B0143EFFC80F2905B267D4D84D3"
}, "127.0.0.1:30000");
```

确保你的 Python 认证服务器已经在本机 30000 端口监听。

> 当前版本的 Python 服务器并不知道真实的 `userToken`，因此无法真正解密 JoinServer 请求，只是构造了一个固定“成功”响应，目的是先验证整体链路（连接 → 初始化 → JoinServer 调用）能否跑通。

## 下一步可以做什么

1. **接入真实 userToken**：
   - 在 Python 侧保存每个用户的 `userId` 和 `userToken`，并根据 `loginSeed` 构造与 C# 一致的 ChaCha 密钥。
   - 真正调用 `unpack_message` 解开 JoinServer 请求，读取 `GameId`、`serverId` 等信息。

2. **补全 InitializeMessage 的校验**：
   - 按 `YggdrasilGenerator.GenerateInitializeMessage` 还原出 `id`、`seed`、版本号、`TcpSalt`、`McVersionSalt` 等字段；
   - 检查 AES 加密后的 `seed` 与原始 `loginSeed` 的对应关系，以及签名是否正确。

3. **对接你的租赁服逻辑**：
   - 将 JoinServer 请求中解析到的 `userId`、`serverId` 与自己的数据库/白名单进行比对；
   - 按照你的业务规则决定是否返回 0x00（成功）或其他错误码。

这样，你就可以逐步从“能跑通”演进到“完全兼容官方协议并融合你自己的验证逻辑”。
