# DEPRECATED — merged into [MoMoRedAll](https://github.com/pen-pig/MoMoRedAll) v2.4+

**PLT Hook 代码已移植到 MoMoRedAll LSPosed 模块的 native 库中。本仓库不再维护。**

---

# MomoRedAll-Magisk v3.0 — 爆红版

Zygisk + PLT Interposition 模块：**主动注入脏数据**，让所有 Root 检测器确认"此环境已被修改"（爆红）。

**哲学反转**：v2.x 是隐藏 Root 痕迹（伪装干净环境），v3.0 是主动制造 Root 证据（证明环境是脏的）。设计目标：所有检测器全部报红。

## 覆盖检测器（12+）

| 检测器 | 包名 | 爆红向量 |
|---|---|---|
| **Momo** | `io.github.vvb2060.mahoshojo` | /proc/maps 注入 + 脏属性 + 假 Shell |
| **MagiskDetector** | `io.github.vvb2060.magiskdetector` | /proc/status(TracerPid) + dirty props |
| **NativeTest** | `icu.nullptr.nativetest` | 假文件 + 脏属性 + /proc/mounts |
| **Ruru** | `com.byxiaorun.detector` | 假属性 + 假 Shell + LD_PRELOAD |
| **Hunter** | `com.zhenxi.hunter` | ptrace 拦截 + 假 Shell + /proc/maps |
| **Oprek Detector** | `com.godevelopers.OprekCek` | /proc/net/tcp + 假 Shell |
| **SafeCheck** | `com.ysh.hookapkverify` | /proc/maps + dirty props |
| **DetectZ** | `com.test.detectz` | ptrace 拦截 + /proc/maps |
| **Key Attestation** | `io.github.vvb2060.keyattestation` | dirty props (fingerprint etc) |
| **DuckDetector** | `duckduckgo.mobile.android` | 全量 /proc 注入 + Shell |
| **DirtySepolicy** | `org.lsposed.dirtysepolicy` | /sys/fs/selinux/enforce=0 |
| **DetectMagisk** | `com.darvin.security` | 假 Shell + dirty props |

## v3.0 重大变更

### 1. 删除文件路径拦截
v2.x 拦截 fopen/open/stat/access 对 Root 路径返回 ENOENT/nullptr。**v3.0 完全删除**，所有文件访问透传到真实系统调用。

### 2. /proc/self/* 内容注入（新增）
通过 `memfd_create` 对关键 /proc 文件注入伪造内容：

| 路径 | 策略 | 注入内容 |
|------|------|----------|
| `/proc/self/maps` | 真实+追加 | magisk32/64、zygisk、lsposed、frida、XposedBridge.jar 映射条目 |
| `/proc/self/status` | 完全替换 | Name=magisk.bin, TracerPid=9999, Uid=0 |
| `/proc/self/mounts` | 完全替换 | magisk tmpfs 挂载点 |
| `/proc/self/wchan` | 完全替换 | SyS_epoll_wait |
| `/proc/self/attr/current` | 完全替换 | u:r:magisk:s0 |
| `/proc/net/tcp` | 完全替换 | frida-server 端口 27042/27043 |
| `/proc/net/tcp6` | 完全替换 | 同上 IPv6 |
| `/sys/fs/selinux/enforce` | 完全替换 | "0" |

### 3. 系统属性：返回脏值（而非空串）
40 个系统属性全部返回明确脏值（ro.debuggable=1, ro.secure=0, ro.magisk.version=27000 等）。

### 4. Shell 命令注入
popen() 对 15 种命令模式返回伪造输出：ps（含 magiskd/frida/zygisk 进程）、getprop（全脏属性）、mount（magisk 挂载）、ls /data/adb、whoami（root）、id（uid=0）、getenforce（Permissive）、pgrep magisk（1234）等。

### 5. 保留项
- ptrace 拦截（返回 EPERM，阻止检测器追踪 Zygisk 进程）
- getenv 注入（LD_PRELOAD = libriruloader.so）
- readlink 重定向（/proc/self/exe → app_process64）

## 技术原理

PLT interposition：Zygisk 注入 .so 后通过导出同名函数覆盖 libc 的 PLT 表项。在目标进程内运行，无法被 ptrace 检测。

## Hook 清单

| 函数 | v3.0 行为 |
|---|---|
| `fopen` / `open` / `open64` / `__open_2` | /proc/* 路径注入 memfd；其他路径透传 |
| `stat` / `lstat` / `fstatat` / `__lxstat` / `__xstat` | 完全透传（v2.x 曾拦截） |
| `access` / `faccessat` | 完全透传（v2.x 曾拦截） |
| `opendir` / `fdopendir` | 完全透传（v2.x 曾拦截） |
| `popen` | Shell 命令返回伪造输出 |
| `system` | 透传 |
| `__system_property_get` | 返回脏值 |
| `readlink` / `readlinkat` | /proc/self/exe 重定向 |
| `ptrace` | 返回 EPERM |
| `getenv` / `secure_getenv` | LD_PRELOAD 注入 |

## 安全机制

1. **进程名校验**：构造函数中读 `/proc/self/cmdline`，仅目标进程启用 hook
2. **零开销转发**：非目标进程 PLT wrapper 首行直接调 orig_xxx，无分支、无 dlsym
3. **Magisk 安全模式**：开机按音量减键禁用模块

## 构建

GitHub Actions 自动编译四架构（arm64-v8a / armeabi-v7a / x86_64 / x86）。

## 安装

1. 刷入 Magisk/KernelSU
2. 安装 Zygisk Next 模块
3. 刷入本模块，重启
4. 验证：打开 Momo，应**全部爆红**（证明环境已被修改）

---

> 本项目由 AI 辅助生成。仅供教育用途。
