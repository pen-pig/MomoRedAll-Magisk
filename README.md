# MomoRedAll-Magisk v2.0

Zygisk + PLT Interposition 模块：Native 层全量劫持系统调用，覆盖 12+ 主流 Root/Magisk 检测器。

## 覆盖检测器

基于 [apkunpacker/MagiskDetection](https://github.com/apkunpacker/MagiskDetection) 汇总的公开 PoC 应用：

| 检测器 | 包名 | 原始检测向量 |
|---|---|---|
| **Momo** | `io.github.vvb2060.mahoshojo` | Frida/Magisk/Zygisk/模块/调试/开发者/BL/SELinux |
| **MagiskDetector** | `io.github.vvb2060.magiskdetector` | haveSu/haveMagiskHide/haveMagicMount |
| **NativeTest** | `icu.nullptr.nativetest` | Magisk/MagiskHide（全量 native） |
| **MinotaurPoc** | `icu.nullptr.nativetest` | Magisk/Zygisk |
| **Ruru** | `com.byxiaorun.detector` | Xposed Hook/Magisk Binary/Zygisk/Riru/Prop |
| **Hunter** | `com.zhenxi.hunter` | 签名/内存/GOT表/反调试/ISO强检测 |
| **Oprek Detector** | `com.godevelopers.OprekCek` | Root Apps/Magisk/模块/SU/SELinux/Xposed |
| **SafeCheck** | `com.ysh.hookapkverify` | 签名/SU/Syscall Hook/MagiskHide/Zygisk/Riru |
| **DetectZ** | `com.test.detectz` | Zygisk fork(ptrace)/ReZygisk/ZygiskNext/NeoZygisk |
| **DuckDetector/DirtySepolicy** | `org.lsposed.dirtysepolicy` | Magisk/KSU/LSPosed |
| **NativeRootDetector** | *reveny* | Magisk/SU/Zygisk/KSU/APatch/LSPosed/自定义ROM/Keybox/BL |
| **DetectMagisk** | `com.darvin.security` | Magisk/MagiskHide |

## 技术原理

PLT interposition：Zygisk 注入 .so 后，通过导出同名函数覆盖 libc 的 PLT 表项。非 Xposed（不能 hook native），非 ptrace（会被检测）。

## Hook 清单（17 个入口函数）

| 函数 | 拦截目标 | 覆盖检测类型 |
|---|---|---|
| `fopen` | 文件打开 | Magisk binary、模块目录、/data/adb、frida-server、Xposed、KSU、APatch、LSPosed 等 |
| `open` / `open64` / `__open_2` | 文件打开（含 mode） | 同上 + 全部 /proc/self/* |
| `stat` / `lstat` / `fstatat` | 文件属性查询 | 文件存在性检测 |
| `__lxstat` / `__xstat` | glibc 内部 stat | 绕过自定义的 stat 调用 |
| `access` / `faccessat` | 文件可访问性 | SU/Magisk 可执行检测 |
| `opendir` | 目录遍历 | 模块目录 `/data/adb/modules/*` |
| `popen` / `system` | shell 命令 | magisk/su/ps/mount/getprop/id/frida/kernel等命令 |
| `__system_property_get` | 系统属性 | ro.debuggable/ro.secure/ro.boot.verifiedbootstate/init.svc.adbd 等 50+ 属性 |
| `readlink` / `readlinkat` | 符号链接 | /proc/self/exe → 伪造为 `/system/bin/app_process64` |
| `ptrace` | 进程追踪 | DetectZ 的 Zygisk fork 检测、Hunter 的反调试 |
| `getenv` / `secure_getenv` | 环境变量 | LD_PRELOAD/MAGISK/ZYGISK/XPOSED/FRIDA |

## 拦截数据量

- **文件路径关键词**：80+（magisk/su/frida/xposed/kernelsu/apatch/lsposed/riru/shamiko/zygisk/playintegrityfix/trickystore...）
- **Shell 命令关键词**：30+（magisk/su/ps/mount/getprop/frida/find/cat /data/adb...）
- **系统属性**：50+（ro.debuggable/ro.secure/ro.build.type/ro.boot.verifiedbootstate/init.svc.adbd...）
- **/proc/self/* 路径**：25+（status/mounts/maps/fd/exe/cmdline/attr/wchan/sched/limits/cgroup/stat/seccomp...）

## 安全机制

1. **进程名校验**：构造函数中读 `/proc/self/cmdline`，仅目标进程启用 hook
2. **零开销转发**：非目标进程 `PLT wrapper` 首行直接调 `orig_xxx`，无分支、无 dlsym
3. **Magisk 安全模式**：开机按音量减键禁用模块，防止变砖

## 构建

GitHub Actions 自动编译四架构（arm64-v8a / armeabi-v7a / x86_64 / x86），产物：

<https://cdn.jsdelivr.net/gh/pen-pig/MomoRedAll-Magisk@main/module/MomoRedAll-Magisk-v2.0.zip>

## 安装

1. 刷入 Magisk/KernelSU
2. 安装 Zygisk Next 模块（推荐，小米 HyperOS 兼容性好于内置 Zygisk）
3. 刷入本模块，重启
4. 验证：打开 Momo，应全部正常（无红色告警）

---

> 本项目由 AI 辅助生成。仅供教育用途。
