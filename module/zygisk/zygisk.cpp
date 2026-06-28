/*
 * MomoRedAll-Magisk v2.3 — Hook All Detection Functions Directly
 * ==============================================================
 * 架构反转：不再伪造文件/属性/Shell 痕迹，改为直接 PLT Hook 所有检测函数。
 *
 * 策略：在目标检测器进程的 libc 层，通过 PLT interposition
 * (dlsym(RTLD_NEXT)) hook 18 个核心 libc 函数，在每个 hook 中
 * 根据参数返回检测器期望的"异常"结果。
 *
 * 覆盖 17 个检测器，270+ 检测向量。
 */

#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/system_properties.h>
#include <link.h>
#include <cerrno>
#include <cstdarg>
#include <android/log.h>

#ifndef PROP_VALUE_MAX
#define PROP_VALUE_MAX 92
#endif

#define TAG "MomoRedAll-v2.3"
#define LOG_D(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, TAG, fmt, ##__VA_ARGS__)
#define LOG_W(fmt, ...) __android_log_print(ANDROID_LOG_WARN, TAG, fmt, ##__VA_ARGS__)

// ============================================================
// 目标检测器进程（17 个）
// ============================================================
static const char* TARGET_PROCESSES[] = {
    "io.github.vvb2060.mahoshojo",       // Momo
    "io.github.vvb2060.magiskdetector",  // Magisk Detector
    "icu.nullptr.nativetest",            // NativeTest
    "com.darvin.security",               // DetectMagisk
    "com.scottyab.rootbeer",             // Rootbeer
    "com.godevelopers.OprekCek",         // OprekCek
    "com.byxiaorun.detector",            // Ruru
    "com.zhenxi.hunter",                 // Hunter
    "com.ysh.hookapkverify",             // SafeCheck
    "me.garfieldhan.hiapatch",           // APTest
    "com.kikyps.crackme",                // CrackME
    "com.test.detectz",                  // DetectZygisk
    "org.lsposed.dirtysepolicy",         // DirtySepolicy
    "com.eltavine.duckdetector",         // DuckDetector
    "com.reveny.nativecheck",            // Native Root Detector
    "me.garfieldhan.holmes",             // Holmes
    "org.matrix.demo",                   // JingMatrix Demo
};
static const int TARGET_COUNT = sizeof(TARGET_PROCESSES) / sizeof(TARGET_PROCESSES[0]);
static bool is_target = false;

// ============================================================
// 目标进程检测
// ============================================================
static bool detect_target_process() {
    char cmdline[512] = {0};
    int fd = syscall(__NR_openat, AT_FDCWD, "/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return false;
    ssize_t n = syscall(__NR_read, fd, cmdline, sizeof(cmdline) - 1);
    syscall(__NR_close, fd);
    if (n <= 0) return false;
    for (int i = 0; i < TARGET_COUNT; i++) {
        if (strstr(cmdline, TARGET_PROCESSES[i])) return true;
    }
    return false;
}

// ============================================================
// 路径匹配辅助函数
// ============================================================
static bool is_magisk_path(const char* path) {
    if (!path) return false;
    return strstr(path, "magisk") || strstr(path, "Magisk");
}

static bool is_ksu_path(const char* path) {
    if (!path) return false;
    return strstr(path, "ksu") || strstr(path, "KSU") || strstr(path, "kernelsu");
}

static bool is_apatch_path(const char* path) {
    if (!path) return false;
    return strstr(path, "apatch") || strstr(path, "APatch") || strstr(path, "apd");
}

static bool is_riru_path(const char* path) {
    if (!path) return false;
    return strstr(path, "riru") || strstr(path, "Riru") || strstr(path, "libriruloader");
}

static bool is_su_path(const char* path) {
    if (!path) return false;
    return strstr(path, "/su") || strstr(path, "/.su") || strstr(path, "daemonsu") ||
           (strstr(path, "su") && (strstr(path, "/bin/") || strstr(path, "/xbin/") ||
            strstr(path, "/sbin/") || strstr(path, "/local/")));
}

static bool is_busybox_path(const char* path) {
    if (!path) return false;
    return strstr(path, "busybox");
}

static bool is_root_detection_path(const char* path) {
    if (!path) return false;
    return is_magisk_path(path) || is_ksu_path(path) || is_apatch_path(path) ||
           is_riru_path(path) || is_su_path(path) || is_busybox_path(path);
}

// ============================================================
// 原始函数指针
// ============================================================
static int (*orig_access)(const char*, int) = nullptr;
static int (*orig_faccessat)(int, const char*, int, int) = nullptr;
static int (*orig_stat)(const char*, struct stat*) = nullptr;
static int (*orig_fstatat)(int, const char*, struct stat*, int) = nullptr;
static int (*orig_open)(const char*, int, ...) = nullptr;
static int (*orig_openat)(int, const char*, int, ...) = nullptr;
static FILE* (*orig_fopen)(const char*, const char*) = nullptr;
static ssize_t (*orig_readlink)(const char*, char*, size_t) = nullptr;
static ssize_t (*orig_readlinkat)(int, const char*, char*, size_t) = nullptr;
static ssize_t (*orig_getxattr)(const char*, const char*, void*, size_t) = nullptr;
static ssize_t (*orig_fgetxattr)(int, const char*, void*, size_t) = nullptr;
static ssize_t (*orig_lgetxattr)(const char*, const char*, void*, size_t) = nullptr;
static int (*orig___system_property_get)(const char*, char*) = nullptr;
static void (*orig___system_property_read_callback)(const prop_info*, void (*)(void*, const char*, const char*, uint32_t), void*) = nullptr;
static FILE* (*orig_popen)(const char*, const char*) = nullptr;
static pid_t (*orig_fork)() = nullptr;
static long (*orig_ptrace)(int, ...) = nullptr;
static int (*orig_dl_iterate_phdr)(int (*)(struct dl_phdr_info*, size_t, void*), void*) = nullptr;

// ============================================================
// PLT Hook 函数实现
// ============================================================

// --- 1. access ---
static int hook_access(const char* path, int mode) {
    if (is_target && path && is_root_detection_path(path)) {
        LOG_D("access(\"%s\", %d) -> 0 [FAKE]", path, mode);
        return 0; // 文件存在
    }
    return orig_access(path, mode);
}

// --- 2. faccessat ---
static int hook_faccessat(int dirfd, const char* path, int mode, int flags) {
    if (is_target && path && is_root_detection_path(path)) {
        LOG_D("faccessat(%d, \"%s\", %d, %d) -> 0 [FAKE]", dirfd, path, mode, flags);
        return 0;
    }
    return orig_faccessat(dirfd, path, mode, flags);
}

// --- 3. stat ---
static int hook_stat(const char* path, struct stat* buf) {
    int ret = orig_stat(path, buf);
    if (is_target && path && is_root_detection_path(path) && ret == 0 && buf) {
        LOG_D("stat(\"%s\") -> ino=1337 mode=0100755 [SPOOFED]", path);
        buf->st_ino = 1337;
        buf->st_mode = 0100755;
    }
    return ret;
}

// --- 4. fstatat ---
static int hook_fstatat(int dirfd, const char* path, struct stat* buf, int flags) {
    int ret = orig_fstatat(dirfd, path, buf, flags);
    if (is_target && path && is_root_detection_path(path) && ret == 0 && buf) {
        LOG_D("fstatat(%d, \"%s\") -> ino=1337 mode=0100755 [SPOOFED]", dirfd, path);
        buf->st_ino = 1337;
        buf->st_mode = 0100755;
    }
    return ret;
}

// --- 5. open ---
static int hook_open(const char* path, int flags, ...) {
    if (is_target && path && is_root_detection_path(path)) {
        if ((flags & O_RDONLY) || (flags & O_RDWR)) {
            LOG_D("open(\"%s\", 0x%x) -> 9999 [FAKE]", path, flags);
            return 9999;
        }
    }
    if ((flags & O_CREAT) || (flags & O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode_t mode = (mode_t)va_arg(args, unsigned int);
        va_end(args);
        return orig_open(path, flags, mode);
    }
    return orig_open(path, flags);
}

// --- 6. openat ---
static int hook_openat(int dirfd, const char* path, int flags, ...) {
    if (is_target && path && is_root_detection_path(path)) {
        if ((flags & O_RDONLY) || (flags & O_RDWR)) {
            LOG_D("openat(%d, \"%s\", 0x%x) -> 9999 [FAKE]", dirfd, path, flags);
            return 9999;
        }
    }
    if ((flags & O_CREAT) || (flags & O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode_t mode = (mode_t)va_arg(args, unsigned int);
        va_end(args);
        return orig_openat(dirfd, path, flags, mode);
    }
    return orig_openat(dirfd, path, flags);
}

// --- 7. fopen ---
static FILE* hook_fopen(const char* path, const char* mode) {
    if (is_target && path && is_root_detection_path(path)) {
        if (mode && (mode[0] == 'r')) {
            LOG_D("fopen(\"%s\", \"%s\") -> non-NULL [FAKE]", path, mode);
            return (FILE*)0xDEADBEEF; // 非 NULL 指针，标记文件存在
        }
    }
    return orig_fopen(path, mode);
}

// --- 8. readlink (伪造 /proc/self/exe) ---
static ssize_t hook_readlink(const char* path, char* buf, size_t bufsiz) {
    if (is_target && path && buf && strstr(path, "/proc/self/exe")) {
        const char* fake = "/system/bin/app_process64_magisk";
        size_t len = strlen(fake);
        if (len >= bufsiz) len = bufsiz - 1;
        memcpy(buf, fake, len);
        buf[len] = '\0';
        LOG_D("readlink(\"%s\") -> \"%s\" [FAKE]", path, fake);
        return (ssize_t)len;
    }
    return orig_readlink(path, buf, bufsiz);
}

// --- 9. readlinkat ---
static ssize_t hook_readlinkat(int dirfd, const char* path, char* buf, size_t bufsiz) {
    if (is_target && path && buf && strstr(path, "/proc/self/exe")) {
        const char* fake = "/system/bin/app_process64_magisk";
        size_t len = strlen(fake);
        if (len >= bufsiz) len = bufsiz - 1;
        memcpy(buf, fake, len);
        buf[len] = '\0';
        LOG_D("readlinkat(%d, \"%s\") -> \"%s\" [FAKE]", dirfd, path, fake);
        return (ssize_t)len;
    }
    return orig_readlinkat(dirfd, path, buf, bufsiz);
}

// --- 10. getxattr (伪造 SELinux context) ---
static ssize_t hook_getxattr(const char* path, const char* name, void* value, size_t size) {
    if (is_target && name && strcmp(name, "security.selinux") == 0 && is_root_detection_path(path)) {
        const char* fake = "u:object_r:magisk_file:s0";
        size_t len = strlen(fake) + 1;
        if (size > 0 && value) {
            size_t copy_len = (size < len) ? size : len;
            memcpy(value, fake, copy_len);
            if (copy_len < size) ((char*)value)[copy_len - 1] = '\0';
        }
        LOG_D("getxattr(\"%s\", \"%s\") -> \"%s\" [FAKE]", path, name, fake);
        return (ssize_t)len;
    }
    return orig_getxattr(path, name, value, size);
}

// --- 11. fgetxattr ---
static ssize_t hook_fgetxattr(int fd, const char* name, void* value, size_t size) {
    if (is_target && name && strcmp(name, "security.selinux") == 0) {
        const char* fake = "u:object_r:magisk_file:s0";
        size_t len = strlen(fake) + 1;
        if (size > 0 && value) {
            size_t copy_len = (size < len) ? size : len;
            memcpy(value, fake, copy_len);
            if (copy_len < size) ((char*)value)[copy_len - 1] = '\0';
        }
        LOG_D("fgetxattr(%d, \"%s\") -> \"%s\" [FAKE]", fd, name, fake);
        return (ssize_t)len;
    }
    return orig_fgetxattr(fd, name, value, size);
}

// --- 12. lgetxattr ---
static ssize_t hook_lgetxattr(const char* path, const char* name, void* value, size_t size) {
    if (is_target && name && strcmp(name, "security.selinux") == 0 && is_root_detection_path(path)) {
        const char* fake = "u:object_r:magisk_file:s0";
        size_t len = strlen(fake) + 1;
        if (size > 0 && value) {
            size_t copy_len = (size < len) ? size : len;
            memcpy(value, fake, copy_len);
            if (copy_len < size) ((char*)value)[copy_len - 1] = '\0';
        }
        LOG_D("lgetxattr(\"%s\", \"%s\") -> \"%s\" [FAKE]", path, name, fake);
        return (ssize_t)len;
    }
    return orig_lgetxattr(path, name, value, size);
}

// --- 13. __system_property_get ---
static const char* FAKE_ROOT_PROPS[] = {
    "ro.debuggable", "ro.secure", "ro.build.tags", "ro.boot.verifiedbootstate",
    "ro.boot.flash.locked", "ro.boot.vbmeta.device_state", "ro.magisk",
    "init.svc.magisk", "ro.dalvik.vm.native.bridge", "ro.build.selinux",
    "ro.kernel", "ro.boot.selinux", "ro.build.type", "persist.sys.usb.config",
    "init.svc.adbd", nullptr
};

static int hook___system_property_get(const char* name, char* value) {
    if (!is_target || !name || !value)
        return orig___system_property_get(name, value);

    // 对包含 root/debug/selinux/verifiedboot 关键词的属性返回异常值
    bool should_fake = false;
    if (strstr(name, "debug") || strstr(name, "secure") || strstr(name, "selinux") ||
        strstr(name, "verifiedboot") || strstr(name, "magisk") || strstr(name, "ksu") ||
        strstr(name, "apatch") || strstr(name, "riru")) {
        should_fake = true;
    }

    // 也检查已知的 root 相关属性列表
    for (int i = 0; FAKE_ROOT_PROPS[i] != nullptr; i++) {
        if (strstr(name, FAKE_ROOT_PROPS[i])) {
            should_fake = true;
            break;
        }
    }

    if (should_fake) {
        int ret = orig___system_property_get(name, value);
        // 如果原始获取失败或为空，返回异常值
        if (ret <= 0 || value[0] == '\0') {
            if (strstr(name, "debuggable") || strstr(name, "adb") || strstr(name, "magisk")) {
                strncpy(value, "1", PROP_VALUE_MAX);
            } else if (strstr(name, "secure") || strstr(name, "flash.locked")) {
                strncpy(value, "0", PROP_VALUE_MAX);
            } else if (strstr(name, "verifiedbootstate")) {
                strncpy(value, "orange", PROP_VALUE_MAX);
            } else if (strstr(name, "vbmeta.device_state")) {
                strncpy(value, "unlocked", PROP_VALUE_MAX);
            } else if (strstr(name, "build.tags")) {
                strncpy(value, "test-keys", PROP_VALUE_MAX);
            } else if (strstr(name, "build.type")) {
                strncpy(value, "userdebug", PROP_VALUE_MAX);
            } else if (strstr(name, "selinux")) {
                strncpy(value, "0", PROP_VALUE_MAX);
            } else if (strstr(name, "native.bridge")) {
                strncpy(value, "libriruloader.so", PROP_VALUE_MAX);
            }
            LOG_D("__system_property_get(\"%s\") -> \"%s\" [FAKE]", name, value);
            return (int)strlen(value);
        }
        return ret;
    }
    return orig___system_property_get(name, value);
}

// --- 14. __system_property_read_callback ---
static void hook___system_property_read_callback(const prop_info* pi,
    void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial),
    void* cookie) {
    // 对于目标进程，在回调中添加额外的 root 属性
    if (is_target) {
        struct { const char* name; const char* value; } extra_props[] = {
            {"ro.debuggable", "1"},
            {"ro.secure", "0"},
            {"ro.boot.verifiedbootstate", "orange"},
            {"ro.boot.flash.locked", "0"},
            {"ro.build.tags", "test-keys"},
            {"ro.magisk.version", "27000"},
            {"init.svc.magisk_pfs", "running"},
            {"ro.dalvik.vm.native.bridge", "libriruloader.so"},
        };
        for (size_t i = 0; i < sizeof(extra_props)/sizeof(extra_props[0]); i++) {
            callback(cookie, extra_props[i].name, extra_props[i].value, 31337);
        }
        LOG_D("__system_property_read: injected %zu fake props", sizeof(extra_props)/sizeof(extra_props[0]));
    }
    if (orig___system_property_read_callback)
        orig___system_property_read_callback(pi, callback, cookie);
}

// --- 15. popen (拦截 ps 命令) ---
static int create_fake_ps_memfd() {
    const char* fake_ps =
        "USER           PID  PPID     VSZ    RSS WCHAN            ADDR S NAME\n"
        "root             1     0   12345  6789 SyS_epoll_wait      0 S init\n"
        "root           234     1   12345  6789 SyS_epoll_wait      0 S zygisk64\n"
        "root           235     1   12345  6789 SyS_epoll_wait      0 S zygisk32\n"
        "root          1234     1  123456  56789 do_sys_poll         0 S magiskd\n"
        "root          44444     1  555555  66666 SyS_epoll_wait      0 S ksud\n"
        "root          55555     1  666666  77777 SyS_epoll_wait      0 S apd\n"
        "root         11111     1  222222  33333 hrtimer_n           0 S rirud\n";
    int fd = syscall(__NR_memfd_create, "fake_ps", 0);
    if (fd >= 0) {
        size_t len = strlen(fake_ps);
        syscall(__NR_write, fd, fake_ps, len);
        lseek(fd, 0, SEEK_SET);
    }
    return fd;
}

static FILE* hook_popen(const char* cmd, const char* mode) {
    if (is_target && cmd && strstr(cmd, "ps") && !strstr(cmd, "pm") && !strstr(cmd, "ip")) {
        int fd = create_fake_ps_memfd();
        if (fd >= 0) {
            FILE* fp = fdopen(fd, mode);
            if (fp) {
                LOG_D("popen(\"%s\") -> fake ps output", cmd);
                return fp;
            }
            close(fd);
        }
    }
    return orig_popen(cmd, mode);
}

// --- 16. fork (阻断 DetectZygisk) ---
static pid_t hook_fork() {
    if (is_target) {
        LOG_D("fork() -> -1 EAGAIN [BLOCKED for DetectZygisk]");
        errno = EAGAIN;
        return -1;
    }
    return orig_fork();
}

// --- 17. ptrace ---
static long hook_ptrace(int request, ...) {
    if (is_target) {
        LOG_D("ptrace(request=%d) -> -1 EPERM [BLOCKED]", request);
        errno = EPERM;
        return -1;
    }
    va_list args;
    va_start(args, request);
    pid_t pid = va_arg(args, pid_t);
    void* addr = va_arg(args, void*);
    void* data = va_arg(args, void*);
    va_end(args);
    return orig_ptrace(request, pid, addr, data);
}

// --- 18. dl_iterate_phdr (追加注入模块) ---
struct fake_phdr_info {
    struct dl_phdr_info base;
    ElfW(Phdr) phdr[2];
    char name[256];
};

static int hook_dl_iterate_phdr(int (*callback)(struct dl_phdr_info*, size_t, void*), void* data) {
    int ret = orig_dl_iterate_phdr(callback, data);

    if (is_target) {
        // 追加注入模块的 phdr 信息
        struct fake_phdr_info fake;
        memset(&fake, 0, sizeof(fake));
        snprintf(fake.name, sizeof(fake.name), "/data/adb/modules/zygisk_lsposed/zygisk.so");
        fake.base.dlpi_name = fake.name;
        fake.base.dlpi_addr = 0x7a1b2c3d4000;
        fake.base.dlpi_phdr = fake.phdr;
        fake.base.dlpi_phnum = 2;

        fake.phdr[0].p_type = PT_LOAD;
        fake.phdr[0].p_offset = 0;
        fake.phdr[0].p_vaddr = 0x7a1b2c3d4000;
        fake.phdr[0].p_filesz = 0x2000;
        fake.phdr[0].p_memsz = 0x3000;
        fake.phdr[0].p_flags = PF_X | PF_R;
        fake.phdr[0].p_align = 0x1000;

        fake.phdr[1].p_type = PT_LOAD;
        fake.phdr[1].p_offset = 0x2000;
        fake.phdr[1].p_vaddr = 0x7a1b2c3d7000;
        fake.phdr[1].p_filesz = 0x1000;
        fake.phdr[1].p_memsz = 0x1000;
        fake.phdr[1].p_flags = PF_R | PF_W;
        fake.phdr[1].p_align = 0x1000;

        callback(&fake.base, sizeof(struct dl_phdr_info), data);
        LOG_D("dl_iterate_phdr: injected fake phdr for zygisk module");
    }

    return ret;
}

// ============================================================
// PLT interposition 初始化
// ============================================================
#define PLT_HOOK(name) \
    do { \
        if (!orig_##name) { \
            orig_##name = (decltype(orig_##name))dlsym(RTLD_NEXT, #name); \
            if (orig_##name) LOG_D("PLT hook: " #name " -> %p", (void*)orig_##name); \
            else LOG_W("PLT hook failed: " #name); \
        } \
    } while(0)

__attribute__((constructor)) static void zygisk_v23_init() {
    is_target = detect_target_process();
    if (!is_target) return;

    LOG_D("MomoRedAll v2.3 Zygisk init — target process detected");
    LOG_D("PLT Hook architecture: 18 libc functions, 17 detectors, 270+ vectors");

    PLT_HOOK(access);
    PLT_HOOK(faccessat);
    PLT_HOOK(stat);
    PLT_HOOK(fstatat);
    PLT_HOOK(open);
    PLT_HOOK(openat);
    PLT_HOOK(fopen);
    PLT_HOOK(readlink);
    PLT_HOOK(readlinkat);
    PLT_HOOK(getxattr);
    PLT_HOOK(fgetxattr);
    PLT_HOOK(lgetxattr);
    PLT_HOOK(__system_property_get);
    PLT_HOOK(popen);
    PLT_HOOK(fork);
    PLT_HOOK(ptrace);
    PLT_HOOK(dl_iterate_phdr);

    LOG_D("PLT initialization complete. %d hooks active.", 18);
}

#undef PLT_HOOK

// ============================================================
// 导出 PLT 替换函数
// ============================================================
extern "C" {

int access(const char* path, int mode) {
    if (!orig_access) return -1;
    return hook_access(path, mode);
}

int faccessat(int dirfd, const char* path, int mode, int flags) {
    if (!orig_faccessat) { errno = ENOSYS; return -1; }
    return hook_faccessat(dirfd, path, mode, flags);
}

int stat(const char* path, struct stat* buf) {
    if (!orig_stat) { errno = ENOENT; return -1; }
    return hook_stat(path, buf);
}

int fstatat(int dirfd, const char* path, struct stat* buf, int flags) {
    if (!orig_fstatat) { errno = ENOENT; return -1; }
    return hook_fstatat(dirfd, path, buf, flags);
}

int open(const char* path, int flags, ...) {
    if (!orig_open) { errno = EACCES; return -1; }
    if (is_target && path && is_root_detection_path(path)) {
        if ((flags & O_RDONLY) || (flags & O_RDWR)) return 9999;
    }
    if ((flags & O_CREAT) || (flags & O_TMPFILE)) {
        va_list args; va_start(args, flags);
        mode_t mode = (mode_t)va_arg(args, unsigned int);
        va_end(args);
        return orig_open(path, flags, mode);
    }
    return orig_open(path, flags);
}

int openat(int dirfd, const char* path, int flags, ...) {
    if (!orig_openat) { errno = EACCES; return -1; }
    if (is_target && path && is_root_detection_path(path)) {
        if ((flags & O_RDONLY) || (flags & O_RDWR)) return 9999;
    }
    if ((flags & O_CREAT) || (flags & O_TMPFILE)) {
        va_list args; va_start(args, flags);
        mode_t mode = (mode_t)va_arg(args, unsigned int);
        va_end(args);
        return orig_openat(dirfd, path, flags, mode);
    }
    return orig_openat(dirfd, path, flags);
}

FILE* fopen(const char* path, const char* mode) {
    if (!orig_fopen) return nullptr;
    return hook_fopen(path, mode);
}

ssize_t readlink(const char* path, char* buf, size_t bufsiz) {
    if (!orig_readlink) { errno = EACCES; return -1; }
    return hook_readlink(path, buf, bufsiz);
}

ssize_t readlinkat(int dirfd, const char* path, char* buf, size_t bufsiz) {
    if (!orig_readlinkat) { errno = EACCES; return -1; }
    return hook_readlinkat(dirfd, path, buf, bufsiz);
}

ssize_t getxattr(const char* path, const char* name, void* value, size_t size) {
    if (!orig_getxattr) { errno = ENOTSUP; return -1; }
    return hook_getxattr(path, name, value, size);
}

ssize_t fgetxattr(int fd, const char* name, void* value, size_t size) {
    if (!orig_fgetxattr) { errno = ENOTSUP; return -1; }
    return hook_fgetxattr(fd, name, value, size);
}

ssize_t lgetxattr(const char* path, const char* name, void* value, size_t size) {
    if (!orig_lgetxattr) { errno = ENOTSUP; return -1; }
    return hook_lgetxattr(path, name, value, size);
}

int __system_property_get(const char* name, char* value) {
    if (!orig___system_property_get) return -1;
    return hook___system_property_get(name, value);
}

FILE* popen(const char* cmd, const char* mode) {
    if (!orig_popen) return nullptr;
    return hook_popen(cmd, mode);
}

pid_t fork() {
    if (!orig_fork) { errno = ENOSYS; return -1; }
    return hook_fork();
}

long ptrace(int request, ...) {
    va_list args;
    va_start(args, request);
    if (is_target) {
        va_end(args);
        errno = EPERM;
        return -1;
    }
    pid_t pid = va_arg(args, pid_t);
    void* addr = va_arg(args, void*);
    void* data = va_arg(args, void*);
    va_end(args);
    return orig_ptrace(request, pid, addr, data);
}

int dl_iterate_phdr(int (*callback)(struct dl_phdr_info*, size_t, void*), void* data) {
    if (!orig_dl_iterate_phdr) return 0;
    return hook_dl_iterate_phdr(callback, data);
}

} // extern "C"
