# pwndbg-mcp

一个赋予 AI agent 调试 ELF 能力的 MCP 工具。其被设计用于常规的 CTF 题目，尤其是 pwn 题。

![Python version](https://img.shields.io/badge/Python-3.10%2B-blue)
![GitHub License](https://img.shields.io/github/license/RocketMaDev/pwndbg-mcp)

## 快速入门

由于当前仓库还没推送到 PyPI，所以请用以下指令 clone 仓库。

```bash
$ git clone https://github.com/RocketMaDev/pwndbg-mcp.git
```

然后使用 uv（没有的话就装一下）来拉取依赖并构建虚拟环境，或将其作为工具安装。

```bash
# 在 clone 的目录中运行 pwndbg-mcp
$ uv sync
$ uv run pwndbg-mcp
# 或者按传统方式运行
$ source .venv/bin/activate
$ python pwndbg_mcp/main.py
# 或者作为工具安装到本地，以在任意地方执行
$ uv tool install .
$ cd /what/ever/path/you/want && pwndbg-mcp
```

> [!CAUTION]
> **如果你没有做隔离，千万不要将你的 MCP 服务暴露出去！**
> 工具 `load_executable`、`execute_command`（GDB 命令）以及 `eval_to_send_to_process`
> 可能会导致任意代码执行。

默认情况下，不带参数启动 pwndbg-mcp 将在 `localhost:8780` 启动一个 MCP 服务器，`gdb`
是默认的 pwndbg 二进制文件，`/mcp` 是 MCP 连接端点，`HTTP streamable` 是默认的传输方式。
以下是一些帮助信息：

```
usage: main.py [-h] [--transport {stdio,http,sse}] [--host HOST] [--port PORT] [--pwndbg BIN] [--d2dname NAME] [--d2dhost HOST] [--d2dport PORT]

pwndbg-mcp: An MCP tool endows AI agent with the capability to debug ELF

options:
  -h, --help            show this help message and exit
  --transport {stdio,http,sse}, -t {stdio,http,sse}
                        Transport mode: stdio, http (streamable HTTP, default), or sse
  --host HOST, -H HOST  Host for HTTP/SSE modes (default: localhost)
  --port PORT, -p PORT  Port for HTTP/SSE modes (default: 8780)
  --pwndbg BIN, -b BIN  pwndbg binary to launch (default: gdb)
  --d2dname NAME, -d NAME
                        Decomp2dbg section display name. Set this to enable decomp2dbg support
  --d2dhost HOST, -D HOST
                        Decomp2dbg connection host
  --d2dport PORT, -P PORT
                        Decomp2dbg connection port
```

由于一些 agent，如 *Claude Code*，会尝试在其工作目录下运行二进制，因此推荐使用 `bwrap`
等最小化容器将 pwndbg-mcp 做些许隔离。如果将 pwndbg-mcp 放到容器中运行会导致二进制文件路径改变。

以下一行命令只读挂在你的根目录，将你的家目录映射为临时的可写目录
（任何写入操作不会影响磁盘上真正的家目录），然后绑定常规的文件系统，启用一个新的 PID
命名空间并最后启动一个 bash 进程。

```bash
$ bwrap --ro-bind / / --overlay-src ~ --tmp-overlay ~ --dev-bind /dev /dev --proc /proc --tmpfs /tmp --unshare-pid bash
```

## 屏幕截图

<img width="2560" height="1100" alt="claude code with pwndbg-mcp" src="https://github.com/user-attachments/assets/4ea1508c-9a56-4541-ad93-28c4301dcc62" />

## 工具一览

- GDB 相关
    1. `load_executable`
    2. `execute_command`
    3. `pwndbg_status` （可能不准确）
    4. `debug_control`
    5. `connect_decomp2dbg`
    6. `pwndbg_hard_reset`
- 与进程通信
    1. `send_to_process`
    2. `eval_to_send_to_process` （能够访问 pwntools）
    3. `read_from_process`
    4. `interrupt_process` （和按下 Ctrl-C 一样）
- pwndbg 别名
    1. `telescope`
    2. `context`
    3. `heap`
    4. `bins`
    5. `backtrace`
    6. `vmmap`
    7. `xinfo`

使用 TOON 作为返回格式因为它既是人类可读的，又比较省 token。

## 优点与缺点

这个项目从 [pwno-mcp](https://github.com/pwno-io/pwno-mcp) 汲取了一些灵感，
并有一些优势和劣势。

### 优点

1. pwndbg-mcp 利用了 GDB/MI 来与 GDB 直接通信，不需要 `echo` 来标记结束
2. 直接通过 tty 发送中断，和在键盘上按 Ctrl-C 一样，不需要记录 PID
3. `eval_to_send_to_process` 向 AI 提供了发送任意二进制数据的能力

### 缺点

1. 所有通信都被封装起来了，用户无法观察 GDB 的状态
2. 这个项目目标为本地调试，因此一个实例只负责一个 GDB 会话
3. 专注于调试，需要其他 MCP 协同工作，例如 IDA Pro MCP

## 未来路线图

请点击 **:star: STAR** 以及开 Issue（但是不要发送垃圾信息）来推动我开发这些新功能！

- [x] 整合 [decomp2dbg](https://github.com/mahaloz/decomp2dbg)
- [ ] 整合 pwntools (`gdb.debug`/`gdb.attach`)
- [ ] 连接本地进程调试（未测试）
- [ ] 连接远程 gdbserver（未测试）

## 感谢

[pwno-mcp](https://github.com/pwno-io/pwno-mcp): 为 pwndbg-mcp 提供了极好的起步框架

## 贡献

欢迎贡献！但是不要 vibe coding（指发送完全由 AI 生成的内容）和垃圾信息。

## LICENSE

Copyright (C) 2025-present, RocketDev, 基于 MIT 协议分发。
