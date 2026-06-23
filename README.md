# MomoRedAll-Magisk

Zygisk Native Hook 模块：在 Native 层全量伪造系统调用，让 Momo 检测显示全面红色告警。

## 原理

Xposed 只能 Hook Java 层，而 Momo 大部分检测走 Native 层（fopen/popen/stat）。本模块通过 Zygisk 注入 native hook，在 libc 层面拦截所有检测入口。

## Hook 覆盖

| 被Hook函数 | 目标 |
|---|---|
| `fopen` | /proc/self/* 全部返回伪造文件 |
| `popen` | shell命令全部返回伪造输出 |
| `stat`/`lstat`/`fstatat` | su/magisk/frida 路径伪造存在 |
| `access`/`facessat` | 同上 |
| `__system_property_get` | 返回伪造系统属性 |
| `opendir`/`readdir` | 目录列表注入假文件 |
| `fork` | 拦截子进程创建 |

## 安装

1. 在 Magisk/KernelSU 中刷入模块
2. 确保 Zygisk 已启用
3. 重启设备

## 构建

需要 Android NDK r27+。

```bash
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=module/zygisk/Android.mk
```

或使用 GitHub Actions 自动构建。

## 注：本项目由AI辅助生成
