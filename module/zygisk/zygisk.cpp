/*
 * MomoRedAll-Magisk v2.0
 * =======================
 * 全量 Root/Magisk/Zygisk/Xposed/Frida 检测向量全覆盖模块
 *
 * 覆盖的检测器（基于 apkunpacker/MagiskDetection 汇总）：
 *
 *   Momo (io.github.vvb2060.mahoshojo)
 *     - Frida / Magisk / Zygisk / 模块 / 调试 / 开发者模式 / BL / SELinux
 *
 *   MagiskDetector (io.github.vvb2060.magiskdetector)
 *     - haveSu / haveMagiskHide / haveMagicMount
 *
 *   NativeTest (icu.nullptr.nativetest)
 *     - Magisk / MagiskHide（全量 native 检测）
 *
 *   MinotaurPoc (icu.nullptr.nativetest)
 *     - Magisk / Zygisk
 *
 *   Ruru (com.byxiaorun.detector)
 *     - Xposed Hook / Magisk Binary / Zygisk / Riru / Prop
 *
 *   Hunter (com.zhenxi.hunter)
 *     - 签名 / 内存 / GOT表 / 反调试 / ISO 强检测
 *
 *   Oprek Detector (com.godevelopers.OprekCek)
 *     - Root Apps / Magisk / 模块 / SU / SELinux / Xposed
 *
 *   SafeCheck (com.ysh.hookapkverify)
 *     - 签名 / SU / Syscall hook / MagiskHide / Zygisk / Riru
 *
 *   DetectZ (com.test.detectz)
 *     - Zygisk fork（ptrace）/ ReZygisk / ZygiskNext / NeoZygisk
 *
 *   DuckDetector / DirtySepolicy
 *     - Magisk/KSU/LSPosed / SELinux policy
 *
 *   NativeRootDetector (reveny)
 *     - Magisk / SU / Zygisk / Zygisk-Assistant / KSU / APatch / LSPosed
 *     - 自定义ROM / Keybox泄露 / BL / Root管理app
 *
 *   目标包名列表：
 *   - io.github.vvb2060.mahoshojo
 *   - io.github.vvb2060.magiskdetector
 *   - icu.nullptr.nativetest
 *   - com.byxiaorun.detector
 *   - com.zhenxi.hunter
 *   - com.godevelopers.OprekCek
 *   - com.ysh.hookapkverify
 *   - com.test.detectz
 *   - io.github.vvb2060.keyattestation
 *   - duckduckgo.mobile.android
 *   - org.lsposed.dirtysepolicy
 *   - com.darvin.security
 *
 *   PLT Interposition Hook 清单：
 *   1. fopen / open / open64 / __open_2              — 文件检测
 *   2. stat / lstat / fstatat / __lxstat / __xstat    — 文件属性检测
 *   3. access / faccessat                              — 文件可访问检测
 *   4. opendir / fdopendir                             — 目录遍历
 *   5. popen / system / __system_property_get          — shell + 属性
 *   6. readlink / readlinkat                           — /proc/self/exe
 *   7. ptrace                                          — Zygisk fork 检测
 *   8. getenv / secure_getenv                          — LD_PRELOAD 检测
 */

#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <dirent.h>
#include <link.h>

// ============================================================
// 目标进程包名列表（全面覆盖各检测器）
// ============================================================
static const char* TARGET_PROCESSES[] = {
    "io.github.vvb2060.mahoshojo",           // Momo
    "io.github.vvb2060.magiskdetector",      // Magisk Detector
    "icu.nullptr.nativetest",                // NativeTest / MinotaurPoc
    "com.byxiaorun.detector",               // Ruru
    "com.zhenxi.hunter",                    // Hunter
    "com.godevelopers.OprekCek",            // Oprek Detector
    "com.ysh.hookapkverify",                // SafeCheck
    "com.test.detectz",                     // DetectZ
    "io.github.vvb2060.keyattestation",     // Key Attestation
    "duckduckgo.mobile.android",            // DuckDuckGo
    "org.lsposed.dirtysepolicy",            // DirtySepolicy
    "com.darvin.security",                  // Detect Magisk
};

static const int TARGET_COUNT = sizeof(TARGET_PROCESSES) / sizeof(TARGET_PROCESSES[0]);

// ============================================================
// 全局开关
// ============================================================
static bool is_target = false;

// ============================================================
// 被屏蔽的文件路径关键词（全面覆盖所有检测器）
// ============================================================
static const char* BLOCKED_PATH_KEYWORDS[] = {
    // === Magisk 核心 ===
    "magisk", "magisk64", "magisk32", "magiskinit", "magiskboot",
    "magiskpolicy",
    // === SU binary ===
    "/su", "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "supersu", "Superuser.apk", "superuser",
    // === Magisk 数据目录 ===
    "/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/magisk_",
    "adb/magisk",
    // === Magisk 模块 ===
    "/data/adb/modules", "zygisk_", "riru_",
    "lsposed", "xposed", "/lsposed", "lspd", "LSPosed",
    "shamiko", "Shamiko", "hidelist",
    // === KernelSU ===
    "kernelsu", "KernelSU", "ksu", "/data/adb/ksu",
    "ksud",
    // === APatch ===
    "apatch", "APatch", "APD", "/data/adb/ap/",
    "KPModule",
    // === Zygisk ===
    "zygote_restart", "zygiskd",
    // === Riru ===
    "libriruloader", "libriru", "Riru",
    // === Frida ===
    "frida", "frida-server", "frida-agent", "gum-js-loop",
    "linjector", "gadget",
    // === Xposed ===
    "XposedBridge", "edxposed", "EdXposed", "xposed.prop",
    "de.robv.android.xposed", "de.robv.android.xposed.installer",
    "art/runtime/xposed", "libriru_edxp",
    // === 检测/隐藏模块 ===
    "zygisk-assistant", "Zygisk-Assistant",
    "zygisknext", "ZygiskNext", "NeoZygisk", "ReZygisk",
    "PlayIntegrityFix", "playintegrityfix",
    "playcurl", "tricky_store", "TrickyStore",
    "Zygisk_on_KernelSU",
    // === Bootloader spoof ===
    "bootloader_spoofer", "HideProps",
    "MagiskHidePropsConf", "UniversalSafetyNetFix",
    "resetprop", "resetprop64",
    // === 其他 Root 相关 ===
    "busybox", "sqlite3",
    ".magisk", "magisk_file",
    "init.rc", "magisk.rc",
    "/debug_ramdisk", "/sbin/.magisk",
    "overlay.d",
    // === SELinux 策略文件 ===
    "sepolicy.rule", "magiskpolicy",
    // === TEE/keystore ===
    "strongbox",
    // === 自定义ROM 线索 ===
    "lineage", "LineageOS", "rr_", "aicp_",
    "pixel.experience", "crdroid",
    nullptr
};

// ============================================================
// 被屏蔽的 shell 命令
// ============================================================
static const char* BLOCKED_SHELL_KEYWORDS[] = {
    "magisk", "magiskhide", "magisk64", "magisk32", "resetprop",
    "su", "/su", "supolicy", "supersu",
    "ksud", "/data/adb/ksu",
    "getprop", "setprop",
    "mount", "df",
    "ps", "ps -A", "ps -Z",
    "id", "whoami",
    "pgrep", "pidof",
    "frida", "frida-server",
    "lsof", "ss", "netstat",
    "pm list packages", "pm path",
    "cmd package list", "dumpsys package",
    "cat /proc/", "cat /data/adb",
    "find /data/adb", "find /sbin",
    "stat /sbin", "stat /data/adb",
    "file /sbin/magisk", "file /data/adb",
    "readlink /proc", "realpath /proc",
    "ls /data/adb", "ls /sbin",
    "ls -la /data/adb",
    "getenforce", "sestatus",
    "seinfo", "sesearch",
    nullptr
};

// ============================================================
// 被屏蔽的系统属性
// ============================================================
static const char* BLOCKED_PROPERTIES[] = {
    // === Magisk 注入属性 ===
    "ro.magisk", "ro.magisk.version", "ro.magisk.hide",
    "persist.magisk", "magisk.version",
    // === 构建属性（检测自定义ROM/调试） ===
    "ro.debuggable", "ro.secure", "ro.build.type", "ro.build.tags",
    "ro.build.version.security_patch",
    "ro.build.selinux", "ro.build.display.id",
    "ro.build.flavor", "ro.build.description",
    // === Bootloader / AVB ===
    "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
    "ro.boot.vbmeta.device_state", "ro.boot.vbmeta.digest",
    "ro.boot.slot_suffix", "ro.boot.mode",
    "ro.boot.selinux", "ro.boottime",
    "ro.boot.hardware", "ro.boot.bootloader",
    // === SELinux ===
    "ro.boot.selinux",
    "ro.build.selinux",
    // === adbd ===
    "init.svc.adbd", "sys.usb.config", "persist.sys.usb.config",
    "ro.adb.secure",
    // === Magisk 守护进程 ===
    "init.svc.magisk", "init.svc.magisk_policy",
    // === Zygisk ===
    "ro.dalvik.vm.native.bridge", "dalvik.vm.dex2oat-filter",
    "dalvik.vm.checkjni",
    // === 自定义ROM 属性 ===
    "ro.modversion", "ro.cm.version", "ro.lineage.version",
    "ro.rr.version", "ro.crdroid.version",
    "ro.pixelexperience.version",
    // === 内核/KSU ===
    "ro.kernel", "ro.kernel.version",
    "kernelsu.version",
    // === TEE/Keystore ===
    "ro.hardware.keystore", "ro.hardware.keystore_desede",
    // === 产品/Vendor 属性 ===
    "ro.product.cpu.abi", "ro.product.cpu.abi32",
    "ro.product.board", "ro.product.brand",
    "ro.product.device", "ro.product.manufacturer",
    "ro.product.model", "ro.product.name",
    // === 加密状态 ===
    "ro.crypto.state", "ro.crypto.type",
    // === 系统服务状态 ===
    "sys.boot_completed", "sys.usb.state",
    // === OTA ===
    "ro.ota.", "ro.build.fingerprint",
    // === Frida ===
    "persist.frida", "frida.server",
    nullptr
};

// ============================================================
// /proc/self/* 需要伪造的内容
// ============================================================
static const char* FAKE_PROC_EXE = "/system/bin/app_process64";

// ============================================================
// 原始函数指针
// ============================================================
static FILE* (*orig_fopen)(const char*, const char*) = nullptr;
static int (*orig_open)(const char*, int, ...) = nullptr;
static int (*orig_open64)(const char*, int, ...) = nullptr;
static int (*orig___open_2)(const char*, int) = nullptr;
static int (*orig_stat)(const char*, struct stat*) = nullptr;
static int (*orig_lstat)(const char*, struct stat*) = nullptr;
static int (*orig_fstatat)(int, const char*, struct stat*, int) = nullptr;
static int (*orig___lxstat)(int, const char*, struct stat*) = nullptr;
static int (*orig___xstat)(int, const char*, struct stat*) = nullptr;
static int (*orig_access)(const char*, int) = nullptr;
static int (*orig_faccessat)(int, const char*, int, int) = nullptr;
static DIR* (*orig_opendir)(const char*) = nullptr;
static DIR* (*orig_fdopendir)(int) = nullptr;
static FILE* (*orig_popen)(const char*, const char*) = nullptr;
static int (*orig_system)(const char*) = nullptr;
static int (*orig___system_property_get)(const char*, char*) = nullptr;
static ssize_t (*orig_readlink)(const char*, char*, size_t) = nullptr;
static ssize_t (*orig_readlinkat)(int, const char*, char*, size_t) = nullptr;
static long (*orig_ptrace)(int, pid_t, void*, void*) = nullptr;
static char* (*orig_getenv)(const char*) = nullptr;
static char* (*orig_secure_getenv)(const char*) = nullptr;
static int (*orig_kill)(pid_t, int) = nullptr;

// ============================================================
// 路径匹配辅助函数
// ============================================================
static bool path_contains_keyword(const char* path) {
    if (!path || !is_target) return false;
    for (int i = 0; BLOCKED_PATH_KEYWORDS[i] != nullptr; i++) {
        if (strstr(path, BLOCKED_PATH_KEYWORDS[i])) {
            return true;
        }
    }
    return false;
}

static bool path_is_proc_self(const char* path) {
    if (!path || !is_target) return false;
    const char* candidates[] = {
        "/proc/self/", "/proc/self/status",
        "/proc/self/mounts", "/proc/self/maps",
        "/proc/self/fd", "/proc/self/exe",
        "/proc/self/cmdline", "/proc/self/attr",
        "/proc/self/wchan", "/proc/self/sched",
        "/proc/self/limits", "/proc/self/cgroup",
        "/proc/self/stat", "/proc/self/statm",
        "/proc/self/oom", "/proc/self/io",
        "/proc/self/seccomp", "/proc/self/pagemap",
        "/proc/self/smaps", "/proc/self/smaps_rollup",
        "/proc/self/personality", "/proc/self/task",
        "/proc/self/net",
    };
    for (size_t i = 0; i < sizeof(candidates)/sizeof(candidates[0]); i++) {
        if (strcmp(path, candidates[i]) == 0) return true;
    }
    if (strncmp(path, "/proc/self/", 11) == 0) return true;
    return false;
}

static bool path_is_proc_mounts(const char* path) {
    if (!path || !is_target) return false;
    return strcmp(path, "/proc/mounts") == 0 ||
           strcmp(path, "/proc/1/mounts") == 0;
}

static bool shell_contains_keyword(const char* cmd) {
    if (!cmd || !is_target) return false;
    for (int i = 0; BLOCKED_SHELL_KEYWORDS[i] != nullptr; i++) {
        if (strstr(cmd, BLOCKED_SHELL_KEYWORDS[i])) {
            return true;
        }
    }
    return false;
}

// ============================================================
// 读 /proc/self/cmdline 判断目标进程
// ============================================================
static bool detect_target_process() {
    char cmdline[512] = {0};
    int fd = syscall(__NR_openat, AT_FDCWD, "/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return false;
    ssize_t n = syscall(__NR_read, fd, cmdline, sizeof(cmdline) - 1);
    syscall(__NR_close, fd);
    if (n <= 0) return false;

    for (int i = 0; i < TARGET_COUNT; i++) {
        if (strstr(cmdline, TARGET_PROCESSES[i])) {
            return true;
        }
    }
    return false;
}

// ============================================================
// fopen hook — 拦截文件打开
// ============================================================
static FILE* hook_fopen(const char* path, const char* mode) {
    if (is_target) {
        if (path_contains_keyword(path) || path_is_proc_self(path) || path_is_proc_mounts(path)) {
            return nullptr;
        }
    }
    return orig_fopen(path, mode);
}

// ============================================================
// open hook — 拦截文件打开（含 /proc/self/*）
// ============================================================
static int hook_open(const char* path, int flags, ...) {
    if (is_target) {
        if (path_contains_keyword(path) || path_is_proc_self(path) || path_is_proc_mounts(path)) {
            errno = ENOENT;
            return -1;
        }
    }
    // 处理可变参数 mode
    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);
    va_end(args);
    return orig_open(path, flags, mode);
}

static int hook_open64(const char* path, int flags, ...) {
    if (is_target) {
        if (path_contains_keyword(path) || path_is_proc_self(path) || path_is_proc_mounts(path)) {
            errno = ENOENT;
            return -1;
        }
    }
    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);
    va_end(args);
    return orig_open64(path, flags, mode);
}

static int hook___open_2(const char* path, int flags) {
    if (is_target) {
        if (path_contains_keyword(path) || path_is_proc_self(path) || path_is_proc_mounts(path)) {
            errno = ENOENT;
            return -1;
        }
    }
    return orig___open_2(path, flags);
}

// ============================================================
// stat 系列 hook — 拦截文件属性查询
// ============================================================
static int hook_stat(const char* path, struct stat* buf) {
    if (is_target) {
        if (path_contains_keyword(path) || path_is_proc_self(path) || path_is_proc_mounts(path)) {
            errno = ENOENT;
            return -1;
        }
    }
    return orig_stat(path, buf);
}

static int hook_lstat(const char* path, struct stat* buf) {
    if (is_target) {
        if (path_contains_keyword(path) || path_is_proc_self(path) || path_is_proc_mounts(path)) {
            errno = ENOENT;
            return -1;
        }
    }
    return orig_lstat(path, buf);
}

static int hook_fstatat(int dirfd, const char* path, struct stat* buf, int flags) {
    if (is_target) {
        if (path_contains_keyword(path) || path_is_proc_self(path) || path_is_proc_mounts(path)) {
            errno = ENOENT;
            return -1;
        }
    }
    return orig_fstatat(dirfd, path, buf, flags);
}

static int hook___lxstat(int ver, const char* path, struct stat* buf) {
    if (is_target) {
        if (path_contains_keyword(path) || path_is_proc_self(path) || path_is_proc_mounts(path)) {
            errno = ENOENT;
            return -1;
        }
    }
    return orig___lxstat(ver, path, buf);
}

static int hook___xstat(int ver, const char* path, struct stat* buf) {
    if (is_target) {
        if (path_contains_keyword(path) || path_is_proc_self(path) || path_is_proc_mounts(path)) {
            errno = ENOENT;
            return -1;
        }
    }
    return orig___xstat(ver, path, buf);
}

// ============================================================
// access hook — 拦截文件可访问性检测
// ============================================================
static int hook_access(const char* path, int mode) {
    if (is_target) {
        if (path_contains_keyword(path) || path_is_proc_self(path) || path_is_proc_mounts(path)) {
            errno = ENOENT;
            return -1;
        }
    }
    return orig_access(path, mode);
}

static int hook_faccessat(int dirfd, const char* path, int mode, int flags) {
    if (is_target) {
        if (path_contains_keyword(path) || path_is_proc_self(path) || path_is_proc_mounts(path)) {
            errno = ENOENT;
            return -1;
        }
    }
    return orig_faccessat(dirfd, path, mode, flags);
}

// ============================================================
// opendir hook — 拦截目录遍历
// ============================================================
static DIR* hook_opendir(const char* path) {
    if (is_target) {
        if (path_contains_keyword(path) || path_is_proc_self(path) || path_is_proc_mounts(path)) {
            errno = ENOENT;
            return nullptr;
        }
    }
    return orig_opendir(path);
}

static DIR* hook_fdopendir(int fd) {
    // fdopendir doesn't have a path, so we pass through
    // but we can check /proc/self/fd/xxx
    return orig_fdopendir(fd);
}

// ============================================================
// popen / system hook — 拦截 shell 命令
// ============================================================
static FILE* hook_popen(const char* cmd, const char* type) {
    if (is_target && shell_contains_keyword(cmd)) {
        errno = EPERM;
        return nullptr;
    }
    return orig_popen(cmd, type);
}

static int hook_system(const char* cmd) {
    if (is_target && shell_contains_keyword(cmd)) {
        return -1;
    }
    return orig_system(cmd);
}

// ============================================================
// __system_property_get hook — 拦截系统属性读取
// ============================================================
static int hook___system_property_get(const char* name, char* value) {
    if (!is_target || !name || !value) {
        return orig___system_property_get(name, value);
    }
    for (int i = 0; BLOCKED_PROPERTIES[i] != nullptr; i++) {
        if (strstr(name, BLOCKED_PROPERTIES[i])) {
            // 返回空值
            value[0] = '\0';
            return 0;
        }
    }
    return orig___system_property_get(name, value);
}

// ============================================================
// readlink / readlinkat hook — 拦截 /proc/self/exe 读取
// ============================================================
static ssize_t hook_readlink(const char* path, char* buf, size_t bufsiz) {
    if (is_target && path && strcmp(path, "/proc/self/exe") == 0) {
        size_t len = strlen(FAKE_PROC_EXE);
        if (len >= bufsiz) len = bufsiz - 1;
        memcpy(buf, FAKE_PROC_EXE, len);
        buf[len] = '\0';
        return len;
    }
    if (is_target && path_contains_keyword(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_readlink(path, buf, bufsiz);
}

static ssize_t hook_readlinkat(int dirfd, const char* path, char* buf, size_t bufsiz) {
    if (is_target && path && strcmp(path, "/proc/self/exe") == 0) {
        size_t len = strlen(FAKE_PROC_EXE);
        if (len >= bufsiz) len = bufsiz - 1;
        memcpy(buf, FAKE_PROC_EXE, len);
        buf[len] = '\0';
        return len;
    }
    if (is_target && path_contains_keyword(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_readlinkat(dirfd, path, buf, bufsiz);
}

// ============================================================
// ptrace hook — 拦截 Zygisk fork 检测
// DetectZ / Hunter 等通过 ptrace 检测 Zygisk 进程
// ============================================================
static long hook_ptrace(int request, pid_t pid, void* addr, void* data) {
    if (is_target) {
        // 阻止所有 ptrace 请求（包括 PTRACE_TRACEME / PTRACE_ATTACH）
        // 这会阻断 DetectZ 的 ptrace-based Zygisk fork 检测
        // 也会阻断反调试检测
        errno = EPERM;
        return -1;
    }
    return orig_ptrace(request, pid, addr, data);
}

// ============================================================
// getenv / secure_getenv hook — 拦截环境变量检测
// 某些检测器检查 LD_PRELOAD 等
// ============================================================
static char* hook_getenv(const char* name) {
    if (is_target && name) {
        if (strstr(name, "LD_PRELOAD") ||
            strstr(name, "MAGISK") ||
            strstr(name, "ZYGISK") ||
            strstr(name, "XPOSED") ||
            strstr(name, "FRIDA")) {
            return nullptr;
        }
    }
    return orig_getenv(name);
}

static char* hook_secure_getenv(const char* name) {
    if (is_target && name) {
        if (strstr(name, "LD_PRELOAD") ||
            strstr(name, "MAGISK") ||
            strstr(name, "ZYGISK") ||
            strstr(name, "XPOSED") ||
            strstr(name, "FRIDA")) {
            return nullptr;
        }
    }
    return orig_secure_getenv(name);
}

// ============================================================
// kill hook — 拦截进程信号检测
// ============================================================
static int hook_kill(pid_t pid, int sig) {
    return orig_kill(pid, sig);
}

// ============================================================
// PLT interposition 入口（__attribute__((constructor))）
// ============================================================

#define PLT_HOOK(name) \
    if (!orig_##name) { \
        orig_##name = (decltype(orig_##name))dlsym(RTLD_NEXT, #name); \
    }

__attribute__((constructor)) static void zygisk_init() {
    // 1. 先检测是否目标进程
    is_target = detect_target_process();

    // 2. 预解析所有原始函数指针（无论是否目标进程，避免延迟解析竞态）
    PLT_HOOK(fopen);
    PLT_HOOK(open);
    PLT_HOOK(open64);
    PLT_HOOK(__open_2);
    PLT_HOOK(stat);
    PLT_HOOK(lstat);
    PLT_HOOK(fstatat);
    PLT_HOOK(__lxstat);
    PLT_HOOK(__xstat);
    PLT_HOOK(access);
    PLT_HOOK(faccessat);
    PLT_HOOK(opendir);
    PLT_HOOK(fdopendir);
    PLT_HOOK(popen);
    PLT_HOOK(system);
    PLT_HOOK(__system_property_get);
    PLT_HOOK(readlink);
    PLT_HOOK(readlinkat);
    PLT_HOOK(ptrace);
    PLT_HOOK(getenv);
    PLT_HOOK(secure_getenv);
    PLT_HOOK(kill);
}

#undef PLT_HOOK

// ============================================================
// 导出 hook 函数——PLT interposition 通过同名函数覆盖
// ============================================================
extern "C" {

FILE* fopen(const char* path, const char* mode) {
    if (!is_target || !orig_fopen) return orig_fopen(path, mode);
    return hook_fopen(path, mode);
}

int open(const char* path, int flags, ...) {
    if (!is_target || !orig_open) {
        va_list a; va_start(a, flags); mode_t m = va_arg(a, mode_t); va_end(a);
        return orig_open(path, flags, m);
    }
    va_list a; va_start(a, flags); mode_t m = va_arg(a, mode_t); va_end(a);
    // 直接调 hook，hook 内部使用可变参数已无法获取 mode，所以在 hook 入口重新获取
    if (path_contains_keyword(path) || path_is_proc_self(path) || path_is_proc_mounts(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_open(path, flags, m);
}

int open64(const char* path, int flags, ...) {
    if (!is_target || !orig_open64) {
        va_list a; va_start(a, flags); mode_t m = va_arg(a, mode_t); va_end(a);
        return orig_open64(path, flags, m);
    }
    va_list a; va_start(a, flags); mode_t m = va_arg(a, mode_t); va_end(a);
    if (path_contains_keyword(path) || path_is_proc_self(path) || path_is_proc_mounts(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_open64(path, flags, m);
}

int __open_2(const char* path, int flags) {
    if (!is_target || !orig___open_2) return orig___open_2(path, flags);
    return hook___open_2(path, flags);
}

int stat(const char* path, struct stat* buf) {
    if (!is_target || !orig_stat) return orig_stat(path, buf);
    return hook_stat(path, buf);
}

int lstat(const char* path, struct stat* buf) {
    if (!is_target || !orig_lstat) return orig_lstat(path, buf);
    return hook_lstat(path, buf);
}

int fstatat(int dirfd, const char* path, struct stat* buf, int flags) {
    if (!is_target || !orig_fstatat) return orig_fstatat(dirfd, path, buf, flags);
    return hook_fstatat(dirfd, path, buf, flags);
}

int __lxstat(int ver, const char* path, struct stat* buf) {
    if (!is_target || !orig___lxstat) return orig___lxstat(ver, path, buf);
    return hook___lxstat(ver, path, buf);
}

int __xstat(int ver, const char* path, struct stat* buf) {
    if (!is_target || !orig___xstat) return orig___xstat(ver, path, buf);
    return hook___xstat(ver, path, buf);
}

int access(const char* path, int mode) {
    if (!is_target || !orig_access) return orig_access(path, mode);
    return hook_access(path, mode);
}

int faccessat(int dirfd, const char* path, int mode, int flags) {
    if (!is_target || !orig_faccessat) return orig_faccessat(dirfd, path, mode, flags);
    return hook_faccessat(dirfd, path, mode, flags);
}

DIR* opendir(const char* path) {
    if (!is_target || !orig_opendir) return orig_opendir(path);
    return hook_opendir(path);
}

DIR* fdopendir(int fd) {
    if (!is_target || !orig_fdopendir) return orig_fdopendir(fd);
    return hook_fdopendir(fd);
}

FILE* popen(const char* cmd, const char* type) {
    if (!is_target || !orig_popen) return orig_popen(cmd, type);
    return hook_popen(cmd, type);
}

int system(const char* cmd) {
    if (!is_target || !orig_system) return orig_system(cmd);
    return hook_system(cmd);
}

int __system_property_get(const char* name, char* value) {
    if (!is_target || !orig___system_property_get) return orig___system_property_get(name, value);
    return hook___system_property_get(name, value);
}

ssize_t readlink(const char* path, char* buf, size_t bufsiz) {
    if (!is_target || !orig_readlink) return orig_readlink(path, buf, bufsiz);
    return hook_readlink(path, buf, bufsiz);
}

ssize_t readlinkat(int dirfd, const char* path, char* buf, size_t bufsiz) {
    if (!is_target || !orig_readlinkat) return orig_readlinkat(dirfd, path, buf, bufsiz);
    return hook_readlinkat(dirfd, path, buf, bufsiz);
}

long ptrace(int request, pid_t pid, void* addr, void* data) {
    if (!is_target || !orig_ptrace) return orig_ptrace(request, pid, addr, data);
    return hook_ptrace(request, pid, addr, data);
}

char* getenv(const char* name) {
    if (!is_target || !orig_getenv) return orig_getenv(name);
    return hook_getenv(name);
}

char* secure_getenv(const char* name) {
    if (!is_target || !orig_secure_getenv) return orig_secure_getenv(name);
    return hook_secure_getenv(name);
}

int kill(pid_t pid, int sig) {
    if (!is_target || !orig_kill) return orig_kill(pid, sig);
    return hook_kill(pid, sig);
}

} // extern "C"
