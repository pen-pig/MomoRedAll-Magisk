#include <string>
#include <vector>
#include <map>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <android/log.h>

#define TAG "MomoRedAll"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ====== Zygisk API ======
typedef void (*zygisk_entry_fn)(void *);

// ====== 目标进程 ======
static const char *TARGETS[] = {
    "io.github.vvb2060.mahoshojo",
    "duckduckgo.mobile.android",
    "io.github.vvb2060.keyattestation",
    nullptr
};

static bool is_target = false;

// ====== 诱饵路径 ======
static const char *FAKE_SU_PATHS[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sbin/su",
    "/vendor/bin/su", "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
    "/system_ext/bin/su", "/product/bin/su", "/odm/bin/su", "/debug_ramdisk/su",
    "/system/bin/.ext/su", "/system/xbin/mu", "/sbin/magisk", "/system/bin/magisk",
    "/system/xbin/magisk",
    nullptr
};

static const char *FAKE_MAGISK_PATHS[] = {
    "/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/.magisk",
    "/data/adb/modules", "/data/adb/magisk.db-wal", "/data/adb/magisk.db-shm",
    "/sbin/magisk", "/sbin/magiskpolicy", "/sbin/magiskinit",
    "/data/unencrypted/magisk", "/cache/magisk.log", "/cache/.disable_magisk",
    nullptr
};

static const char *FAKE_SUSPICIOUS_PATHS[] = {
    "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
    "/data/local/tmp/hluda-server", "/data/local/tmp/frida-server-16.5.7-android-arm64",
    "/data/local/tmp/supersu", "/data/local/tmp/su",
    "/system/framework/XposedBridge.jar", "/system/lib/libriruloader.so",
    "/system/lib64/libriruloader.so", "/system/lib/libxposed_art.so",
    "/system/lib64/libxposed_art.so",
    "/data/adb/modules/zygisk_lsposed", "/data/adb/modules/shamiko",
    "/data/adb/modules/hosts", "/data/adb/modules/playintegrityfix",
    "/data/adb/modules/zygisk_shamiko", "/data/adb/modules/zygisk_lsposed/zygisk.so",
    "/data/adb/modules/zygisk_shamiko/zygisk.so",
    "/data/adb/magisk/magisk32", "/data/adb/magisk/magisk64",
    nullptr
};

static const char *FAKE_XPOSED_PATHS[] = {
    "/system/framework/XposedBridge.jar",
    "/data/data/de.robv.android.xposed.installer",
    "/data/data/org.lsposed.manager",
    "/data/data/io.github.lsposed.manager",
    nullptr
};

static const char *FAKE_FRIDA_PATHS[] = {
    "/data/local/tmp/frida-server",
    "/data/local/tmp/frida-server-16.5.7-android-arm64",
    "/data/local/tmp/re.frida.server",
    "/data/local/tmp/hluda-server",
    "/data/local/tmp/frida-agent",
    nullptr
};

// ====== 伪造系统属性 ======
static std::map<std::string, std::string> FAKE_PROPS = {
    {"ro.debuggable", "1"},
    {"ro.secure", "0"},
    {"ro.adb.secure", "0"},
    {"ro.build.type", "userdebug"},
    {"ro.build.tags", "test-keys"},
    {"ro.build.selinux", "0"},
    {"ro.build.user", "root"},
    {"ro.boot.verifiedbootstate", "orange"},
    {"ro.boot.flash.locked", "0"},
    {"ro.boot.vbmeta.device_state", "unlocked"},
    {"ro.boot.veritymode", "disabled"},
    {"ro.boot.selinux", "permissive"},
    {"ro.boot.warranty_bit", "1"},
    {"ro.warranty_bit", "1"},
    {"ro.boot.vbmeta.avb_version", "0.0"},
    {"ro.boot.vbmeta.invalidate_on_error", "yes"},
    {"init.svc.adbd", "running"},
    {"init.svc.magisk_pfs", "running"},
    {"init.svc.magisk_service", "running"},
    {"ro.dalvik.vm.native.bridge", "libriruloader.so"},
    {"ro.hardware.keystore", "software"},
    {"ro.boot.keymaster", "0"},
    {"keymaster_ver", "0.3"},
    {"ro.allow.mock.location", "1"},
    {"dalvik.vm.checkjni", "true"},
    {"persist.sys.usb.config", "adb"},
    {"ro.kernel.qemu", "1"},
    {"ro.kernel.android.qemud", "1"},
    {"ro.product.cpu.abi", "x86"},
    {"ro.product.cpu.abi2", "armeabi-v7a"},
    {"ro.bootloader", "unknown"},
    {"ro.bootmode", "unknown"},
    {"gsm.version.baseband", "MDM9x25"},
};

// ====== 伪造Shell命令输出 ======
static std::map<std::string, std::string> FAKE_CMDS;

static void init_fake_cmds() {
    FAKE_CMDS["ps"] = 
        "USER           PID  PPID     VSZ    RSS WCHAN            ADDR S NAME\n"
        "root             1     0   12345  6789 SyS_epoll_wait      0 S init\n"
        "root           234     1   12345  6789 SyS_epoll_wait      0 S zygisk64\n"
        "root           235     1   12345  6789 SyS_epoll_wait      0 S zygisk32\n"
        "root          1234     1  123456  56789 do_sys_poll         0 S magiskd\n"
        "shell         5678     1  234567  89012 binder_thr          0 S su\n"
        "root          9999     1  111111  22222 sigsuspen           0 S daemonsu\n"
        "root         11111     1  222222  33333 hrtimer_n           0 S frida-server\n"
        "root         22222     1  333333  44444 do_wait             0 S xposed_loade\n"
        "root         33333     1  444444  55555 futex_wai           0 S magisk.bin\n";
    
    FAKE_CMDS["getprop"] = "[ro.debuggable]: [1]\n[ro.secure]: [0]\n[ro.build.type]: [userdebug]\n";
    FAKE_CMDS["id"] = "uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0\n";
    FAKE_CMDS["whoami"] = "root\n";
    FAKE_CMDS["which su"] = "/system/bin/su\n";
    FAKE_CMDS["which magisk"] = "/sbin/magisk\n";
    FAKE_CMDS["which magiskd"] = "/sbin/magiskd\n";
    
    FAKE_CMDS["mount"] = 
        "rootfs on / type rootfs (ro,seclabel)\n"
        "magisk on /sbin type tmpfs (rw,seclabel,relatime)\n"
        "magisk on /system/bin type tmpfs (rw,seclabel,relatime)\n"
        "magisk on /system/xbin type tmpfs (rw,seclabel,relatime)\n"
        "/data/adb/modules on /data/adb/modules type tmpfs (rw,seclabel,relatime)\n";
    
    FAKE_CMDS["netstat"] = 
        "tcp        0      0 0.0.0.0:27042           0.0.0.0:*               LISTEN      11111/frida-server\n"
        "tcp        0      0 127.0.0.1:5555           0.0.0.0:*               LISTEN      1234/magiskd\n";
    
    FAKE_CMDS["cat"] = "magisk.bin\n";
    FAKE_CMDS["dumpsys"] = "DUMP OF SERVICE activity:\n  mFocusedApp=AppWindowToken{deadbeef token=Token{deadbeef ActivityRecord{deadbeef u0 com.topjohnwu.magisk/.MainActivity}}}\n";
    
    FAKE_CMDS["ls /data/adb"] = "modules\nmagisk\nmagisk.db\n.magisk\n";
    FAKE_CMDS["ls /data/local/tmp"] = "frida-server\nre.frida.server\nsu\nsupersu\nhluda-server\n";
}

// ====== 伪造 /proc 文件 ======
static const char *FAKE_STATUS = 
    "Name:   magisk.bin\n"
    "State:  S (sleeping)\n"
    "Tgid:   31337\n"
    "Pid:    31337\n"
    "PPid:   1\n"
    "TracerPid:\t9999\n"
    "Uid:\t0\t0\t0\t0\n"
    "Gid:\t0\t0\t0\t0\n"
    "FDSize: 256\n"
    "Seccomp:\t2\n"
    "Seccomp_filters:\t1\n";

static const char *FAKE_MOUNTS = 
    "rootfs / rootfs ro,seclabel 0 0\n"
    "magisk /sbin tmpfs rw,seclabel,relatime 0 0\n"
    "magisk /system/bin tmpfs rw,seclabel,relatime 0 0\n"
    "magisk /system/xbin tmpfs rw,seclabel,relatime 0 0\n"
    "/data/adb/modules /data/adb/modules tmpfs rw,seclabel,relatime 0 0\n";

static const char *FAKE_MAPS = 
    "7a1b2c3d4000-7a1b2c3d6000 r-xp 00000000 fd:01 1234567  /data/adb/modules/zygisk_lsposed/zygisk.so\n"
    "7b3c4d5e6000-7b3c4d5e8000 r-xp 00000000 fd:01 2345678  /data/adb/modules/zygisk_shamiko/zygisk.so\n"
    "7c5d6e7f8000-7c5d6e7fb000 r-xp 00000000 fd:01 3456789  /data/adb/magisk/magisk32\n"
    "7d8e9f0a1000-7d8e9f0a4000 r-xp 00000000 103:17 4567890  /system/framework/XposedBridge.jar\n"
    "7e0f1a2b3000-7e0f1a2b6000 r-xp 00000000 103:17 5678901  /data/local/tmp/frida-server-16.5.7-android-arm64\n";

static const char *FAKE_WCHAN = "SyS_epoll_wait\n";
static const char *FAKE_ATTR_CURRENT = "u:r:magisk:s0\n";
static const char *FAKE_SELINUX_ENFORCE = "0";
static const char *FAKE_NET_TCP = "   0: 00000000:69A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n";

// ====== fmemopen 替代 (NDK 不包含 fmemopen) ======
static FILE* fake_fopen(const char *data, size_t len, const char *mode) {
    int fds[2];
    if (pipe(fds) != 0) return nullptr;
    (void)!write(fds[1], data, len);
    close(fds[1]);
    return fdopen(fds[0], mode);
}

// ====== 原始函数指针 ======
static FILE* (*orig_fopen)(const char*, const char*) = nullptr;
static FILE* (*orig_popen)(const char*, const char*) = nullptr;
static int (*orig_stat)(const char*, struct stat*) = nullptr;
static int (*orig_lstat)(const char*, struct stat*) = nullptr;
static int (*orig_fstatat)(int, const char*, struct stat*, int) = nullptr;
static int (*orig_access)(const char*, int) = nullptr;
static int (*orig_faccessat)(int, const char*, int, int) = nullptr;
static int (*orig_open)(const char*, int, ...) = nullptr;
static DIR* (*orig_opendir)(const char*) = nullptr;
static struct dirent* (*orig_readdir)(DIR*) = nullptr;
static ssize_t (*orig_read)(int, void*, size_t) = nullptr;
static int (*orig_close)(int) = nullptr;
static int (*orig_system_property_get)(const char*, char*) = nullptr;
static const char* (*orig_system_property_find)(const char*) = nullptr;

// ====== 在构造函数中用原始函数读进程名，避免 PLT 循环 ======
static bool check_target_process() {
    // 用 dlsym 拿原始函数，不走 PLT interposition
    if (!orig_open)  orig_open  = (decltype(orig_open)) dlsym(RTLD_NEXT, "open");
    if (!orig_read)  orig_read  = (decltype(orig_read)) dlsym(RTLD_NEXT, "read");
    if (!orig_close) orig_close = (decltype(orig_close))dlsym(RTLD_NEXT, "close");
    
    char cmdline[256] = {0};
    int fd = orig_open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return false;
    ssize_t n = orig_read(fd, cmdline, sizeof(cmdline) - 1);
    orig_close(fd);
    if (n <= 0) return false;
    
    for (int i = 0; TARGETS[i]; i++) {
        if (strstr(cmdline, TARGETS[i])) return true;
    }
    return false;
}

// ====== 判断路径是否在诱饵列表中 ======
static bool match_path(const char *path, const char **list) {
    if (!path) return false;
    for (int i = 0; list[i]; i++) {
        if (strstr(path, list[i])) return true;
    }
    return false;
}

static bool is_fake_path(const char *path) {
    return match_path(path, FAKE_SU_PATHS) ||
           match_path(path, FAKE_MAGISK_PATHS) ||
           match_path(path, FAKE_SUSPICIOUS_PATHS) ||
           match_path(path, FAKE_XPOSED_PATHS) ||
           match_path(path, FAKE_FRIDA_PATHS);
}

// ====== Hook 实现 ======

// fopen: 拦截 /proc 文件读取
FILE* hooked_fopen(const char *pathname, const char *mode) {
    if (!is_target || !pathname) return orig_fopen(pathname, mode);
    
    if (strcmp(pathname, "/proc/self/maps") == 0) {
        return fake_fopen(FAKE_MAPS, strlen(FAKE_MAPS), mode);
    }
    if (strcmp(pathname, "/proc/self/status") == 0) {
        return fake_fopen(FAKE_STATUS, strlen(FAKE_STATUS), mode);
    }
    if (strcmp(pathname, "/proc/self/mounts") == 0 || strcmp(pathname, "/proc/mounts") == 0) {
        return fake_fopen(FAKE_MOUNTS, strlen(FAKE_MOUNTS), mode);
    }
    if (strcmp(pathname, "/proc/self/wchan") == 0) {
        return fake_fopen(FAKE_WCHAN, strlen(FAKE_WCHAN), mode);
    }
    if (strcmp(pathname, "/proc/self/attr/current") == 0) {
        return fake_fopen(FAKE_ATTR_CURRENT, strlen(FAKE_ATTR_CURRENT), mode);
    }
    if (strcmp(pathname, "/sys/fs/selinux/enforce") == 0) {
        return fake_fopen(FAKE_SELINUX_ENFORCE, strlen(FAKE_SELINUX_ENFORCE), mode);
    }
    if (strcmp(pathname, "/proc/net/tcp") == 0) {
        return fake_fopen(FAKE_NET_TCP, strlen(FAKE_NET_TCP), mode);
    }
    
    return orig_fopen(pathname, mode);
}

// popen: 拦截 shell 命令
FILE* hooked_popen(const char *command, const char *type) {
    if (!is_target || !command) return orig_popen(command, type);
    
    for (auto &it : FAKE_CMDS) {
        if (strstr(command, it.first.c_str())) {
            return fake_fopen(it.second.c_str(), it.second.size(), type);
        }
    }
    
    // su 命令
    if (strstr(command, "su")) {
        return fake_fopen("uid=0(root)\n", 12, type);
    }
    
    return orig_popen(command, type);
}

// stat: 伪造文件存在
int hooked_stat(const char *pathname, struct stat *buf) {
    if (!is_target || !pathname) return orig_stat(pathname, buf);
    if (is_fake_path(pathname)) {
        memset(buf, 0, sizeof(*buf));
        buf->st_mode = S_IFREG | 0755;
        buf->st_size = 1024;
        buf->st_uid = 0;
        buf->st_gid = 0;
        buf->st_nlink = 1;
        return 0;
    }
    return orig_stat(pathname, buf);
}

int hooked_lstat(const char *pathname, struct stat *buf) {
    if (!is_target || !pathname) return orig_lstat(pathname, buf);
    if (is_fake_path(pathname)) {
        memset(buf, 0, sizeof(*buf));
        buf->st_mode = S_IFREG | 0755;
        buf->st_size = 1024;
        buf->st_uid = 0;
        buf->st_gid = 0;
        buf->st_nlink = 1;
        return 0;
    }
    return orig_lstat(pathname, buf);
}

int hooked_fstatat(int dirfd, const char *pathname, struct stat *buf, int flags) {
    if (!is_target || !pathname) return orig_fstatat(dirfd, pathname, buf, flags);
    if (is_fake_path(pathname)) {
        memset(buf, 0, sizeof(*buf));
        buf->st_mode = S_IFREG | 0755;
        buf->st_size = 1024;
        buf->st_uid = 0;
        buf->st_gid = 0;
        buf->st_nlink = 1;
        return 0;
    }
    return orig_fstatat(dirfd, pathname, buf, flags);
}

// access: 伪造文件可访问
int hooked_access(const char *pathname, int mode) {
    if (!is_target || !pathname) return orig_access(pathname, mode);
    if (is_fake_path(pathname)) return 0;
    return orig_access(pathname, mode);
}

int hooked_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    if (!is_target || !pathname) return orig_faccessat(dirfd, pathname, mode, flags);
    if (is_fake_path(pathname)) return 0;
    return orig_faccessat(dirfd, pathname, mode, flags);
}

// open: 拦截 /proc 文件
int hooked_open(const char *pathname, int flags, ...) {
    if (!is_target || !pathname) {
        va_list ap;
        va_start(ap, flags);
        int mode = va_arg(ap, int);
        va_end(ap);
        return orig_open(pathname, flags, mode);
    }
    
    // /proc 文件返回伪造fd
    if (strcmp(pathname, "/proc/self/status") == 0) {
        return open("/dev/null", flags);
    }
    if (strcmp(pathname, "/proc/self/maps") == 0) {
        return open("/dev/null", flags);
    }
    if (strcmp(pathname, "/proc/self/mounts") == 0) {
        return open("/dev/null", flags);
    }
    if (strcmp(pathname, "/sys/fs/selinux/enforce") == 0) {
        return open("/dev/null", flags);
    }
    
    va_list ap;
    va_start(ap, flags);
    int mode = va_arg(ap, int);
    va_end(ap);
    return orig_open(pathname, flags, mode);
}

// opendir: 目录注入
DIR* hooked_opendir(const char *name) {
    if (!is_target || !name) return orig_opendir(name);
    return orig_opendir(name);
}

// __system_property_get: 伪造系统属性
int hooked_system_property_get(const char *name, char *value) {
    if (!orig_system_property_get)
        orig_system_property_get = (decltype(orig_system_property_get))dlsym(RTLD_NEXT, "__system_property_get");
    
    if (!is_target || !name) return orig_system_property_get(name, value);
    
    auto it = FAKE_PROPS.find(std::string(name));
    if (it != FAKE_PROPS.end()) {
        if (value) {
            strncpy(value, it->second.c_str(), 92);
            value[91] = '\0';
        }
        return (int)it->second.size();
    }
    return orig_system_property_get(name, value);
}

// ====== PLT hook via dlsym interpose ======

#define HOOK_SYM(name) do { \
    void *orig = dlsym(RTLD_NEXT, #name); \
    if (orig) { orig_##name = (decltype(orig_##name))orig; } \
} while(0)

__attribute__((constructor))
static void init_hooks() {
    // 第一步：用原始函数读进程名
    is_target = check_target_process();
    
    // 无论是否目标进程，都解析所有原始函数指针（消除竞态窗口）
    // open/read/close 已在 check_target_process 中解析
    orig_fopen = (decltype(orig_fopen))dlsym(RTLD_NEXT, "fopen");
    orig_popen = (decltype(orig_popen))dlsym(RTLD_NEXT, "popen");
    orig_stat = (decltype(orig_stat))dlsym(RTLD_NEXT, "stat");
    orig_lstat = (decltype(orig_lstat))dlsym(RTLD_NEXT, "lstat");
    orig_fstatat = (decltype(orig_fstatat))dlsym(RTLD_NEXT, "__fxstatat");
    orig_access = (decltype(orig_access))dlsym(RTLD_NEXT, "access");
    orig_faccessat = (decltype(orig_faccessat))dlsym(RTLD_NEXT, "faccessat");
    orig_opendir = (decltype(orig_opendir))dlsym(RTLD_NEXT, "opendir");
    orig_readdir = (decltype(orig_readdir))dlsym(RTLD_NEXT, "readdir");
    orig_system_property_get = (decltype(orig_system_property_get))dlsym(RTLD_NEXT, "__system_property_get");
    
    if (!is_target) {
        LOGD("Not a target process, orig_* pointers resolved for zero-overhead pass-through");
        return;
    }
    
    LOGD("Target process detected, installing fake data");
    init_fake_cmds();
    LOGD("Zygisk hooks initialized");
}

// ====== Zygisk 入口 ======
extern "C" void zygisk_entry(void *reserved) {
    // Zygisk 会在目标进程中加载此 .so
    is_target = true;
    LOGD("zygisk_entry: hooked into target process");
    
    // hooks 已通过 __attribute__((constructor)) 自动安装
    // PLT hook 会自动拦截对 libc 的调用
}

// ====== PLT Interpose (LD_PRELOAD 兼容) ======
extern "C" {

FILE* fopen(const char *pathname, const char *mode) {
    if (!is_target) return orig_fopen(pathname, mode);
    return hooked_fopen(pathname, mode);
}

FILE* popen(const char *command, const char *type) {
    if (!is_target) return orig_popen(command, type);
    return hooked_popen(command, type);
}

int stat(const char *pathname, struct stat *buf) {
    if (!is_target) return orig_stat(pathname, buf);
    return hooked_stat(pathname, buf);
}

__attribute__((visibility("default")))
int lstat(const char *pathname, struct stat *buf) {
    if (!is_target) return orig_lstat(pathname, buf);
    return hooked_lstat(pathname, buf);
}

int access(const char *pathname, int mode) {
    if (!is_target) return orig_access(pathname, mode);
    return hooked_access(pathname, mode);
}

int faccessat(int dirfd, const char *pathname, int mode, int flags) {
    if (!is_target) return orig_faccessat(dirfd, pathname, mode, flags);
    return hooked_faccessat(dirfd, pathname, mode, flags);
}

int open(const char *pathname, int flags, ...) {
    if (!is_target) {
        va_list ap;
        va_start(ap, flags);
        int mode = va_arg(ap, int);
        va_end(ap);
        return orig_open(pathname, flags, mode);
    }
    va_list ap;
    va_start(ap, flags);
    int mode = va_arg(ap, int);
    va_end(ap);
    return hooked_open(pathname, flags, mode);
}

DIR* opendir(const char *name) {
    if (!is_target) return orig_opendir(name);
    return hooked_opendir(name);
}

int __system_property_get(const char *name, char *value) {
    if (!is_target) return orig_system_property_get(name, value);
    return hooked_system_property_get(name, value);
}

} // extern "C"
