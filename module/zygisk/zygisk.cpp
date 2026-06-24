/*
 * MomoRedAll-Magisk v3.1 — 爆红版（全面覆盖）
 * ============================================
 * 核心哲学反转：不再隐藏 Root 痕迹，而是主动注入脏数据，
 * 让所有检测器确认"此环境已被修改"（爆红）。
 *
 * 覆盖检测器（16+）：
 *   Momo, NativeTest, Applist Detector, Ruru, Detect Magisk Hide,
 *   Momo Strong, SafetyNet, Cat and Mouse, Android CTS,
 *   RootBeer, RootBeer Fresh, Key Attestation,
 *   Native Root Detector (reveny), CrackME (GarudaDefender),
 *   APTest (APatch), JingMatrix Demo
 *
 * v3.1 新增（对比 v3.0）：
 *   - 整合 MagiskDetection 仓库全部检测向量
 *   - 新增 Native Root Detector 全量检测对抗（bootloader/OEM/Keybox/TEE 等）
 *   - 新增 APatch 检测对抗（属性注入 + 文件暴露）
 *   - 新增 CrackME/GarudaDefender 对抗（调试器/模拟器/内存补丁检测）
 *   - 新增 JingMatrix soinfo/virtual maps 检测对抗
 *   - 扩展 Shell 命令注入（resetprop/pm list/sestatus）
 *   - 扩展 /proc 注入（sched/oom_score_adj/task/status）
 *   - 新增 4 个目标检测器进程
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
#include <sys/syscall.h>
#include <dirent.h>
#include <fstream>
#include <cerrno>

// ============================================================
// 配置读取
// ============================================================
#define CONFIG_PATH "/data/adb/modules/MomoRedAll-Native/config.json"

static bool config_loaded = false;
static bool config_enabled[16] = {true};
static bool config_hooks[13] = {true};

static void load_config() {
    if (config_loaded) return;
    config_loaded = true;
    std::ifstream f(CONFIG_PATH);
    if (!f.is_open()) {
        for (int i = 0; i < 16; i++) config_enabled[i] = true;
        for (int i = 0; i < 13; i++) config_hooks[i] = true;
        return;
    }
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();
    const char* target_keys[] = {
        "momo", "native_test", "applist_detector", "ruru", "detect_magisk_hide",
        "momo_strong", "safetynet", "safetynet_playstore", "cat_and_mouse",
        "android_cts", "rootbeer", "rootbeer_fresh",
        "native_root_detector", "crackme", "aptest", "rootbeer_sample"  // v3.1
    };
    for (int i = 0; i < 16; i++) {
        std::string key = "\"" + std::string(target_keys[i]) + "\":";
        size_t pos = content.find(key);
        if (pos != std::string::npos) {
            pos = content.find(":", pos + key.length());
            if (pos != std::string::npos)
                config_enabled[i] = (content.find("true", pos) < content.find("false", pos) ||
                                     content.find("false", pos) == std::string::npos);
        }
    }
    const char* hook_keys[] = {
        "proc_inject", "open", "stat", "access", "opendir",
        "popen_system", "readlink", "ptrace", "getenv",
        "property", "mounts", "proc", "extra"
    };
    for (int i = 0; i < 13; i++) {
        std::string key = "\"" + std::string(hook_keys[i]) + "\":";
        size_t pos = content.find(key);
        if (pos != std::string::npos) {
            pos = content.find(":", pos + key.length());
            if (pos != std::string::npos)
                config_hooks[i] = (content.find("true", pos) < content.find("false", pos) ||
                                   content.find("false", pos) == std::string::npos);
        }
    }
}

static bool is_hook_enabled(int hook_index) {
    load_config();
    if (hook_index < 0 || hook_index >= 13) return true;
    return config_hooks[hook_index];
}

// ============================================================
// 目标进程包名列表
// ============================================================
static const char* TARGET_PROCESSES[] = {
    "io.github.vvb2060.mahoshojo",       // Momo
    "io.github.vvb2060.magiskdetector",  // Magisk Detector
    "icu.nullptr.nativetest",            // NativeTest / MinotaurPoc
    "com.byxiaorun.detector",            // Ruru
    "com.zhenxi.hunter",                 // Hunter
    "com.godevelopers.OprekCek",         // Oprek Detector
    "com.ysh.hookapkverify",             // SafeCheck
    "com.test.detectz",                  // DetectZ
    "io.github.vvb2060.keyattestation",  // Key Attestation
    "duckduckgo.mobile.android",         // DuckDetector
    "org.lsposed.dirtysepolicy",         // DirtySepolicy
    "com.darvin.security",               // Detect Magisk
    "com.reveny.nativecheck",            // Native Root Detector (v3.1)
    "com.kikyps.crackme",                // CrackME / GarudaDefender (v3.1)
    "me.garfieldhan.hiapatch",           // APTest / APatch (v3.1)
    "com.scottyab.rootbeer.sample",      // Rootbeer Sample (v3.1)
};
static const int TARGET_COUNT = sizeof(TARGET_PROCESSES) / sizeof(TARGET_PROCESSES[0]);
static bool is_target = false;

// ============================================================
// 脏属性表（v3.1：扩展至 55+ 属性，覆盖 Native Root Detector + APatch + GarudaDefender 检测）
// ============================================================
static const char* DIRTY_PROPS[][2] = {
    // --- 调试 / 安全状态 ---
    {"ro.debuggable", "1"},
    {"ro.secure", "0"},
    {"ro.build.type", "userdebug"},
    {"ro.build.tags", "test-keys"},
    {"ro.build.selinux", "0"},
    {"ro.build.flavor", "userdebug"},
    {"ro.build.characteristics", "default"},
    {"ro.build.version.security_patch", "2019-01-01"},      // v3.1: 极老补丁日期
    {"ro.build.description", "marlin-userdebug 7.1.2 NJH47F 4146041 test-keys"},
    // --- Bootloader / Verified Boot (Native Root Detector) ---
    {"ro.boot.verifiedbootstate", "orange"},
    {"ro.boot.flash.locked", "0"},
    {"ro.boot.vbmeta.device_state", "unlocked"},
    {"ro.boot.vbmeta.digest", "0000000000000000000000000000000000000000000000000000000000000000"}, // v3.1
    {"ro.boot.vbmeta.size", "0"},                            // v3.1
    {"ro.boot.selinux", "permissive"},
    {"ro.boot.veritymode", "disabled"},
    {"ro.bootimage.build.fingerprint", "google/marlin/marlin:7.1.2/NJH47F/4146041:userdebug/test-keys"}, // v3.1
    {"ro.vendor.build.fingerprint", "google/marlin/marlin:7.1.2/NJH47F/4146041:userdebug/test-keys"},    // v3.1
    {"ro.odm.build.fingerprint", "google/marlin/marlin:7.1.2/NJH47F/4146041:userdebug/test-keys"},       // v3.1
    // --- OEM Unlock (Native Root Detector) ---
    {"ro.oem_unlock_supported", "1"},                        // v3.1
    {"sys.oem_unlock_allowed", "1"},                         // v3.1
    // --- ADB / USB ---
    {"init.svc.adbd", "running"},
    {"persist.sys.usb.config", "adb,mtp"},
    {"sys.usb.config", "adb"},
    {"sys.usb.state", "adb"},
    {"ro.adb.secure", "0"},
    // --- Magisk ---
    {"ro.magisk.version", "27000"},
    {"ro.magisk.hide", "1"},
    {"ro.dalvik.vm.native.bridge", "libriruloader.so"},
    {"init.svc.magisk_pfs", "running"},
    {"init.svc.magisk_service", "running"},
    {"persist.magisk", "1"},
    // --- APatch (v3.1 新增) ---
    {"ro.apatch.version", "11111"},                          // v3.1
    {"ro.boot.apatch", "1"},                                 // v3.1
    {"persist.apatch.version", "11111"},                     // v3.1
    // --- KernelSU ---
    {"ro.kernel.version", "KernelSU"},                       // v3.1
    {"ro.kernelsu.version", "11872"},                        // v3.1
    // --- KeyStore / TEE (v3.1: 标记 TEE 已损坏) ---
    {"ro.hardware.keystore", "software"},
    {"ro.hardware.keystore_desede", "software"},
    {"ro.crypto.state", "unencrypted"},
    {"ro.crypto.type", "none"},
    {"keymaster.tee.broken", "true"},                        // v3.1
    {"keystore.broken", "true"},                             // v3.1
    // --- SELinux ---
    {"ro.build.selinux.enforce", "1"},
    {"persist.sys.selinux.enforce", "0"},
    // --- Custom ROM (LineageOS / CM) ---
    {"ro.modversion", "LineageOS-20-20240101"},
    {"ro.lineage.version", "20.0"},
    {"ro.cm.version", "14.1"},
    // --- 模拟器 / 虚拟环境 ---
    {"ro.product.cpu.abi", "x86"},
    {"ro.product.cpu.abi2", "armeabi-v7a"},
    {"ro.kernel.qemu", "1"},
    // --- 调试 / Mock ---
    {"dalvik.vm.checkjni", "true"},
    {"ro.allow.mock.location", "1"},
    {"ro.monkey", "1"},
    {"ro.kernel.android.checkjni", "1"},                     // v3.1
    {"dalvik.vm.dex2oat-filter", "verify-none"},
    // --- 综合指纹 ---
    {"ro.build.fingerprint", "google/marlin/marlin:7.1.2/NJH47F/4146041:userdebug/test-keys"},
    {nullptr, nullptr}
};

// ============================================================
// /proc 伪造内容
// ============================================================
static const char* FAKE_MAPS_APPEND = R"(
7a1b2c3d4000-7a1b2c3d6000 r-xp 00000000 fd:01 1234567  /data/adb/modules/zygisk_lsposed/zygisk.so
7a1b2c3d6000-7a1b2c3d8000 r--p 00001000 fd:01 1234567  /data/adb/modules/zygisk_lsposed/zygisk.so
7a1b2c3d8000-7a1b2c3d9000 rw-p 00003000 fd:01 1234567  /data/adb/modules/zygisk_lsposed/zygisk.so
7b3c4d5e6000-7b3c4d5e8000 r-xp 00000000 fd:01 2345678  /data/adb/modules/zygisk_shamiko/zygisk.so
7b3c4d5e8000-7b3c4d5ea000 r--p 00001000 fd:01 2345678  /data/adb/modules/zygisk_shamiko/zygisk.so
7b3c4d5ea000-7b3c4d5eb000 rw-p 00003000 fd:01 2345678  /data/adb/modules/zygisk_shamiko/zygisk.so
7c5d6e7f8000-7c5d6e7fb000 r-xp 00000000 fd:01 3456789  /data/adb/magisk/magisk32
7c5d6e7fb000-7c5d6e7fc000 r--p 00002000 fd:01 3456789  /data/adb/magisk/magisk32
7c5d6e7fc000-7c5d6e7fd000 rw-p 00003000 fd:01 3456789  /data/adb/magisk/magisk32
7d8e9f0a1000-7d8e9f0a4000 r-xp 00000000 103:17 4567890  /system/framework/XposedBridge.jar
7e0f1a2b3000-7e0f1a2b6000 r-xp 00000000 103:17 5678901  /data/local/tmp/frida-server
7e0f1a2b6000-7e0f1a2b8000 r--p 00002000 103:17 5678901  /data/local/tmp/frida-server
7e0f1a2b8000-7e0f1a2b9000 rw-p 00004000 103:17 5678901  /data/local/tmp/frida-server
7f1a2b3c4000-7f1a2b3c7000 r-xp 00000000 103:17 6789012  /data/adb/modules/lsposed/lspd
8f1a2b3c4000-8f1a2b3c6000 r-xp 00000000 00:00 0          /data/adb/ksu/modules/zygisk_on_kernelsu.so
8a1b2c3d5000-8a1b2c3d8000 rwxp 00000000 00:00 0          [anon:libc_malloc_hook]
8a1b2c3d8000-8a1b2c3da000 r-xp 00000000 00:00 0          [anon:.bss_ART_hook]
)";

static const char* FAKE_STATUS =
"Name:   magisk.bin\n"
"Umask:  0077\n"
"State:  S (sleeping)\n"
"Tgid:   31337\n"
"Ngid:   0\n"
"Pid:    31337\n"
"PPid:   1\n"
"TracerPid:\t9999\n"
"Uid:\t0\t0\t0\t0\n"
"Gid:\t0\t0\t0\t0\n"
"FDSize:\t256\n"
"Groups:\t0 1004 1007 1011 1015 1028 3001 3002 3003 3006 3009 3011\n"
"VmPeak:\t  123456 kB\n"
"VmSize:\t  123456 kB\n"
"VmLck:\t       0 kB\n"
"VmPin:\t       0 kB\n"
"VmHWM:\t   56789 kB\n"
"VmRSS:\t   56789 kB\n"
"RssAnon:\t   23456 kB\n"
"RssFile:\t   33333 kB\n"
"RssShmem:\t       0 kB\n"
"VmData:\t   45678 kB\n"
"VmStk:\t     132 kB\n"
"VmExe:\t      44 kB\n"
"VmLib:\t    6789 kB\n"
"VmPTE:\t     123 kB\n"
"VmSwap:\t       0 kB\n"
"CoreDumping:\t0\n"
"THP_enabled:\t1\n"
"Threads:\t3\n"
"SigQ:\t0/12345\n"
"SigPnd:\t0000000000000000\n"
"ShdPnd:\t0000000000000000\n"
"SigBlk:\t0000000000001204\n"
"SigIgn:\t0000000000001000\n"
"SigCgt:\t00000001800146ef\n"
"CapInh:\t0000000000000000\n"
"CapPrm:\t000000ffffffffff\n"
"CapEff:\t000000ffffffffff\n"
"CapBnd:\t000000ffffffffff\n"
"CapAmb:\t0000000000000000\n"
"NoNewPrivs:\t0\n"
"Seccomp:\t2\n"
"Seccomp_filters:\t1\n"
"Speculation_Store_Bypass:\tthread vulnerable\n"
"SpeculationIndirectBranch:\talways enabled\n"
"Cpus_allowed:\tff\n"
"Cpus_allowed_list:\t0-7\n"
"Mems_allowed:\t1\n"
"Mems_allowed_list:\t0\n"
"voluntary_ctxt_switches:\t999\n"
"nonvoluntary_ctxt_switches:\t313\n";

static const char* FAKE_MOUNTS =
"rootfs / rootfs ro,seclabel,size=1844344k,nr_inodes=461086 0 0\n"
"tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,size=1861600k,nr_inodes=465400,mode=755 0 0\n"
"devpts /dev/pts devpts rw,seclabel,nosuid,noexec,relatime,mode=600,ptmxmode=000 0 0\n"
"magisk /sbin tmpfs rw,seclabel,relatime 0 0\n"
"magisk /system/bin tmpfs rw,seclabel,relatime 0 0\n"
"magisk /system/xbin tmpfs rw,seclabel,relatime 0 0\n"
"/data/adb/modules /data/adb/modules tmpfs rw,seclabel,relatime 0 0\n"
"/dev/block/mmcblk0p42 /system ext4 ro,seclabel,relatime 0 0\n"
"fuse /mnt/runtime/default/emulated fuse rw,nosuid,nodev,noexec,noatime,user_id=0,group_id=0,allow_other 0 0\n";

static const char* FAKE_WCHAN = "SyS_epoll_wait\n";
static const char* FAKE_ATTR_CURRENT = "u:r:magisk:s0\n";
static const char* FAKE_SELINUX_ENFORCE = "0";
static const char* FAKE_NET_TCP =
"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
"   0: 00000000:69A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
"   1: 00000000:69A3 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0\n";
static const char* FAKE_NET_TCP6 =
"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
"   0: 00000000000000000000000000000000:69A2 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0\n";

// v3.1 新增伪造内容 =============================================
static const char* FAKE_SCHED =
"magisk.bin (31337, #threads: 3)\n"
"--------------------------------------------------------------------\n"
"se.exec_start                                :     12345.678901\n"
"se.vruntime                                  :         3.141592\n"
"se.sum_exec_runtime                          :      9999.999999\n"
"se.nr_migrations                             :               313\n"
"nr_switches                                  :            99999\n"
"nr_voluntary_switches                        :            50000\n"
"nr_involuntary_switches                      :            49999\n"
"se.load.weight                               :             1024\n"
"se.avg.load_sum                              :         1234567\n"
"se.avg.runnable_sum                          :          456789\n"
"se.avg.util_sum                              :          234567\n"
"se.avg.last_update_time                      :     123456789012345\n"
"policy                                       :                 0\n"
"prio                                         :               120\n"
"clock-delta                                  :               123\n";

static const char* FAKE_OOM_SCORE_ADJ = "-1000\n";  // v3.1: 系统关键进程, 不会被 kill

// v3.1: 用于 /proc/self/task/*/status 通配替换
static const char* FAKE_TASK_STATUS =
"Name:   magisk.bin\n"
"Umask:  0077\n"
"State:  S (sleeping)\n"
"Tgid:   31337\n"
"Ngid:   0\n"
"Pid:    31337\n"
"PPid:   1\n"
"TracerPid:\t9999\n"
"Uid:\t0\t0\t0\t0\n"
"Gid:\t0\t0\t0\t0\n"
"FDSize:\t256\n"
"Groups:\t0 1004 1007 1011 1015 1028 3001 3002 3003 3006 3009 3011\n";

// ============================================================
// Shell 命令伪造输出
// ============================================================
static const char* FAKE_PS_OUTPUT =
"USER           PID  PPID     VSZ    RSS WCHAN            ADDR S NAME\n"
"root             1     0   12345  6789 SyS_epoll_wait      0 S init\n"
"root           234     1   12345  6789 SyS_epoll_wait      0 S zygisk64\n"
"root           235     1   12345  6789 SyS_epoll_wait      0 S zygisk32\n"
"root          1234     1  123456  56789 do_sys_poll         0 S magiskd\n"
"shell         5678     1  234567  89012 binder_thr          0 S su\n"
"root          9999     1  111111  22222 sigsuspen           0 S daemonsu\n"
"root         11111     1  222222  33333 hrtimer_n           0 S frida-server\n"
"root         22222     1  333333  44444 do_wait             0 S xposed_loade\n"
"root         33333     1  444444  55555 futex_wai           0 S magisk.bin\n"
"root         44444     1  555555  66666 SyS_epoll_wait      0 S ksud\n"
"root         55555     1  666666  77777 SyS_epoll_wait      0 S apd\n";

static const char* FAKE_GETPROP_OUTPUT =
"[ro.debuggable]: [1]\n"
"[ro.secure]: [0]\n"
"[ro.build.type]: [userdebug]\n"
"[ro.build.tags]: [test-keys]\n"
"[ro.boot.verifiedbootstate]: [orange]\n"
"[ro.boot.flash.locked]: [0]\n"
"[ro.boot.vbmeta.device_state]: [unlocked]\n"
"[init.svc.adbd]: [running]\n"
"[ro.build.selinux]: [0]\n"
"[init.svc.magisk_pfs]: [running]\n"
"[init.svc.magisk_service]: [running]\n"
"[ro.dalvik.vm.native.bridge]: [libriruloader.so]\n"
"[ro.hardware.keystore]: [software]\n"
"[ro.magisk.version]: [27000]\n";

static const char* FAKE_LS_ADB_OUTPUT =
"total 4096\n"
"drwxr-xr-x  2 root root 4096 2025-01-01 00:00 modules\n"
"drwxr-xr-x  2 root root 4096 2025-01-01 00:00 magisk\n"
"drwxr-xr-x  2 root root 4096 2025-01-01 00:00 ksu\n"
"drwxr-xr-x  2 root root 4096 2025-01-01 00:00 ap\n"
"-rw-r--r--  1 root root 8192 2025-01-01 00:00 magisk.db\n"
"-rw-r--r--  1 root root    0 2025-01-01 00:00 .magisk\n";

static const char* FAKE_LS_TMP_OUTPUT =
"total 4096\n"
"-rwxr-xr-x 1 root root 4567890 2025-01-01 00:00 frida-server\n"
"-rwxr-xr-x 1 root root   12345 2025-01-01 00:00 su\n"
"drwxr-xr-x 2 root root    4096 2025-01-01 00:00 supersu\n"
"drwxr-xr-x 2 root root    4096 2025-01-01 00:00 re.frida.server\n"
"-rwxr-xr-x 1 root root   54321 2025-01-01 00:00 hluda-server\n";

static const char* FAKE_NETSTAT_OUTPUT =
"tcp        0      0 0.0.0.0:27042           0.0.0.0:*               LISTEN      11111/frida-server\n"
"tcp        0      0 127.0.0.1:5555           0.0.0.0:*               LISTEN      1234/magiskd\n"
"tcp        0      0 0.0.0.0:27043           0.0.0.0:*               LISTEN      11111/frida-server\n";

// v3.1 新增 Shell 伪造输出 =====================================
static const char* FAKE_RESETPROP_OUTPUT =
"[ro.debuggable]: [1]\n"
"[ro.secure]: [0]\n"
"[ro.magisk.version]: [27000]\n"
"[ro.boot.verifiedbootstate]: [orange]\n"
"[ro.boot.flash.locked]: [0]\n";

static const char* FAKE_PM_LIST_ROOT_OUTPUT =
"package:com.topjohnwu.magisk\n"
"package:io.github.vvb2060.mahoshojo\n"
"package:com.byxiaorun.detector\n"
"package:de.robv.android.xposed.installer\n"
"package:org.meowcat.edxposed.manager\n"
"package:com.reveny.nativecheck\n";

static const char* FAKE_GREP_TRACER_OUTPUT = "TracerPid:\t9999\n";
static const char* FAKE_GREP_SU_OUTPUT = "/system/bin/su\n/system/xbin/su\n/data/local/tmp/su\n/sbin/su\n";

static const char* FAKE_LS_SYSTEM_ADDOND_OUTPUT =
"total 4096\n"
"-rwxr-xr-x 1 root root 1234 2025-01-01 00:00 50-magisk.sh\n"
"-rwxr-xr-x 1 root root 5678 2025-01-01 00:00 51-kernelsu.sh\n";

static const char* FAKE_DUMPSYS_PACKAGE_OUTPUT =
"Packages:\n"
"  Package [com.topjohnwu.magisk] (a1b2c3d):\n"
"    userId=0\n"
"    pkg=Package{...}\n"
"    codePath=/data/app/~~xxxx==/com.topjohnwu.magisk-xxxx==\n"
"  Package [de.robv.android.xposed.installer] (e4f5g6h):\n"
"    userId=0\n"
"    codePath=/data/app/~~yyyy==/de.robv.android.xposed.installer-yyyy==\n";

static const char* FAKE_APATCH_MODULES_OUTPUT =
"total 4096\n"
"-rw-r--r-- 1 root root 8192 2025-01-01 00:00 modules.img\n"
"drwxr-xr-x 2 root root 4096 2025-01-01 00:00 zygisk\n";

static const char* FAKE_LS_KSU_MODULES_OUTPUT =
"total 4096\n"
"-rw-r--r-- 1 root root 8192 2025-01-01 00:00 modules.img\n"
"drwxr-xr-x 2 root root 4096 2025-01-01 00:00 ksu_module\n";

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
static long (*orig_ptrace)(int, ...) = nullptr;
static char* (*orig_getenv)(const char*) = nullptr;
static char* (*orig_secure_getenv)(const char*) = nullptr;

// ============================================================
// 辅助函数
// ============================================================

static int create_memfd(const char* name) {
    return syscall(__NR_memfd_create, name, MFD_CLOEXEC);
}

static char* read_all_from_fd(int fd, size_t* out_len) {
    size_t cap = 16384;
    char* buf = (char*)malloc(cap);
    if (!buf) return nullptr;
    size_t total = 0;
    ssize_t n;
    while ((n = read(fd, buf + total, cap - total - 1)) > 0) {
        total += n;
        if (total >= cap - 1) {
            cap *= 2;
            char* newbuf = (char*)realloc(buf, cap);
            if (!newbuf) { free(buf); return nullptr; }
            buf = newbuf;
        }
    }
    buf[total] = '\0';
    *out_len = total;
    return buf;
}

static int memfd_from_content(const char* content, size_t len) {
    int fd = create_memfd("fake_proc");
    if (fd < 0) return -1;
    if (len > 0) {
        ssize_t written = write(fd, content, len);
        if (written < 0 || (size_t)written != len) {
            close(fd);
            return -1;
        }
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

// 判断是否是需要注入的 /proc 路径
static const char* get_proc_inject_content(const char* path, size_t* out_len, bool* is_replace) {
    *is_replace = false;
    *out_len = 0;
    if (!path) return nullptr;

    // v3.1: 通配符匹配 — 优先处理，避免被精确匹配误判
    if (strstr(path, "/proc/self/task/") && strstr(path, "/status")) {
        *is_replace = true;
        *out_len = strlen(FAKE_TASK_STATUS);
        return FAKE_TASK_STATUS;
    }
    if (strstr(path, "/proc/self/task/") && strstr(path, "/maps")) {
        *is_replace = false;  // 追加模式
        *out_len = strlen(FAKE_MAPS_APPEND);
        return FAKE_MAPS_APPEND;
    }

    struct {
        const char* path;
        const char* content;
        bool replace;
    } static const targets[] = {
        {"/proc/self/maps",         FAKE_MAPS_APPEND,    false},
        {"/proc/self/status",       FAKE_STATUS,         true},
        {"/proc/self/mounts",       FAKE_MOUNTS,         true},
        {"/proc/mounts",            FAKE_MOUNTS,         true},
        {"/proc/self/wchan",        FAKE_WCHAN,          true},
        {"/proc/self/attr/current", FAKE_ATTR_CURRENT,   true},
        // v3.1 新增 ==========================================
        {"/proc/self/sched",        FAKE_SCHED,          true},
        {"/proc/self/oom_score_adj",FAKE_OOM_SCORE_ADJ,  true},
        // ===============
        {"/proc/self/net/tcp",      FAKE_NET_TCP,        true},
        {"/proc/net/tcp",           FAKE_NET_TCP,        true},
        {"/proc/self/net/tcp6",     FAKE_NET_TCP6,       true},
        {"/proc/net/tcp6",          FAKE_NET_TCP6,       true},
        {"/sys/fs/selinux/enforce", FAKE_SELINUX_ENFORCE,true},
    };
    for (size_t i = 0; i < sizeof(targets)/sizeof(targets[0]); i++) {
        if (strcmp(path, targets[i].path) == 0) {
            *is_replace = targets[i].replace;
            *out_len = strlen(targets[i].content);
            return targets[i].content;
        }
    }
    return nullptr;
}

// 打开注入版 /proc 文件，返回新 fd
static int inject_proc_fd(const char* path) {
    size_t inject_len = 0;
    bool is_replace = false;
    const char* inject_content = get_proc_inject_content(path, &inject_len, &is_replace);
    if (!inject_content) return -1;

    if (is_replace) {
        return memfd_from_content(inject_content, inject_len);
    }

    int real_fd = orig_open(path, O_RDONLY);
    if (real_fd < 0) return -1;

    size_t real_len = 0;
    char* real_content = read_all_from_fd(real_fd, &real_len);
    close(real_fd);

    if (!real_content) {
        return memfd_from_content(inject_content, inject_len);
    }

    size_t total = real_len + inject_len;
    char* combined = (char*)malloc(total);
    if (!combined) {
        free(real_content);
        return -1;
    }
    memcpy(combined, real_content, real_len);
    memcpy(combined + real_len, inject_content, inject_len);
    free(real_content);

    int fd = memfd_from_content(combined, total);
    free(combined);
    return fd;
}

// 打开注入版 /proc 文件，返回 FILE*
static FILE* inject_proc_fopen(const char* path, const char* mode) {
    if (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+')) return nullptr;
    int fd = inject_proc_fd(path);
    if (fd < 0) return nullptr;
    FILE* fp = fdopen(fd, mode);
    if (!fp) close(fd);
    return fp;
}

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
// Hook 函数
// ============================================================

// --- fopen ---
static FILE* hook_fopen(const char* path, const char* mode) {
    if (is_target && path && is_hook_enabled(0)) {
        FILE* fake = inject_proc_fopen(path, mode);
        if (fake) return fake;
    }
    return orig_fopen(path, mode);
}

// --- open 辅助 ---
static int inject_or_orig_open(const char* path, int flags) {
    if (is_target && path && (flags & O_RDONLY) && is_hook_enabled(1)) {
        int fake_fd = inject_proc_fd(path);
        if (fake_fd >= 0) return fake_fd;
    }
    return -1;
}

// --- open / open64 / __open_2 ---
static int hook_open(const char* path, int flags, ...) {
    if (is_target && path && is_hook_enabled(1)) {
        int fake_fd = inject_or_orig_open(path, flags);
        if (fake_fd >= 0) return fake_fd;
    }
    va_list args; va_start(args, flags);
    unsigned int mode = va_arg(args, unsigned int); va_end(args);
    return orig_open(path, flags, (mode_t)mode);
}

static int hook_open64(const char* path, int flags, ...) {
    if (is_target && path && is_hook_enabled(1)) {
        int fake_fd = inject_or_orig_open(path, flags);
        if (fake_fd >= 0) return fake_fd;
    }
    va_list args; va_start(args, flags);
    unsigned int mode = va_arg(args, unsigned int); va_end(args);
    return orig_open64(path, flags, (mode_t)mode);
}

static int hook___open_2(const char* path, int flags) {
    if (is_target && path && is_hook_enabled(1)) {
        int fake_fd = inject_or_orig_open(path, flags);
        if (fake_fd >= 0) return fake_fd;
    }
    return orig___open_2(path, flags);
}

// --- stat 系列 (v3.0: 完全透传) ---
static int hook_stat(const char* path, struct stat* buf) {
    return orig_stat(path, buf);
}
static int hook_lstat(const char* path, struct stat* buf) {
    return orig_lstat(path, buf);
}
static int hook_fstatat(int dirfd, const char* path, struct stat* buf, int flags) {
    return orig_fstatat(dirfd, path, buf, flags);
}
static int hook___lxstat(int ver, const char* path, struct stat* buf) {
    return orig___lxstat(ver, path, buf);
}
static int hook___xstat(int ver, const char* path, struct stat* buf) {
    return orig___xstat(ver, path, buf);
}

// --- access (v3.0: 完全透传) ---
static int hook_access(const char* path, int mode) {
    return orig_access(path, mode);
}
static int hook_faccessat(int dirfd, const char* path, int mode, int flags) {
    return orig_faccessat(dirfd, path, mode, flags);
}

// --- opendir (v3.0: 完全透传) ---
static DIR* hook_opendir(const char* path) {
    return orig_opendir(path);
}
static DIR* hook_fdopendir(int fd) {
    return orig_fdopendir(fd);
}

// --- popen / system ---
static FILE* hook_popen(const char* cmd, const char* type) {
    if (!is_hook_enabled(5)) return orig_popen(cmd, type);
    if (is_target && cmd) {
        int fd = -1;
        // ps
        if (strstr(cmd, "ps") && !strstr(cmd, "pm") && !strstr(cmd, "ip"))
            fd = memfd_from_content(FAKE_PS_OUTPUT, strlen(FAKE_PS_OUTPUT));
        // getprop
        else if (strstr(cmd, "getprop"))
            fd = memfd_from_content(FAKE_GETPROP_OUTPUT, strlen(FAKE_GETPROP_OUTPUT));
        // mount
        else if (strstr(cmd, "mount"))
            fd = memfd_from_content(FAKE_MOUNTS, strlen(FAKE_MOUNTS));
        // ls /data/adb
        else if (strstr(cmd, "/data/adb") && !strstr(cmd, "ls /data/adb/ksu") && !strstr(cmd, "ls /data/adb/ap"))
            fd = memfd_from_content(FAKE_LS_ADB_OUTPUT, strlen(FAKE_LS_ADB_OUTPUT));
        // ls /data/adb/ksu → KernelSU modules (v3.1)
        else if (strstr(cmd, "/data/adb/ksu"))
            fd = memfd_from_content(FAKE_LS_KSU_MODULES_OUTPUT, strlen(FAKE_LS_KSU_MODULES_OUTPUT));
        // ls /data/adb/ap → APatch modules (v3.1)
        else if (strstr(cmd, "/data/adb/ap"))
            fd = memfd_from_content(FAKE_APATCH_MODULES_OUTPUT, strlen(FAKE_APATCH_MODULES_OUTPUT));
        // ls /data/local/tmp
        else if (strstr(cmd, "/data/local/tmp"))
            fd = memfd_from_content(FAKE_LS_TMP_OUTPUT, strlen(FAKE_LS_TMP_OUTPUT));
        // netstat / ss
        else if (strstr(cmd, "netstat") || strstr(cmd, "ss "))
            fd = memfd_from_content(FAKE_NETSTAT_OUTPUT, strlen(FAKE_NETSTAT_OUTPUT));
        // which su
        else if (strstr(cmd, "which su"))
            fd = memfd_from_content("/system/bin/su\n", 14);
        // which magisk
        else if (strstr(cmd, "which magisk"))
            fd = memfd_from_content("/sbin/magisk\n", 13);
        // whoami
        else if (strstr(cmd, "whoami"))
            fd = memfd_from_content("root\n", 5);
        // id
        else if (strstr(cmd, "id") && !strstr(cmd, "pidof") && !strstr(cmd, "wide"))
            fd = memfd_from_content("uid=0(root) gid=0(root) groups=0(root),1004,1007,1011,1015,1028,3001,3002,3003,3006,3009,3011 context=u:r:magisk:s0\n", 121);
        // getenforce
        else if (strstr(cmd, "getenforce"))
            fd = memfd_from_content("Permissive\n", 11);
        // sestatus
        else if (strstr(cmd, "sestatus"))
            fd = memfd_from_content("SELinux status:         disabled\n", 32);
        // pgrep magisk / pidof magisk
        else if ((strstr(cmd, "pgrep magisk") || strstr(cmd, "pidof magisk")))
            fd = memfd_from_content("1234\n", 5);
        // pgrep frida / pidof frida
        else if ((strstr(cmd, "pgrep frida") || strstr(cmd, "pidof frida")))
            fd = memfd_from_content("11111\n", 6);
        // v3.1 新增 =============================================
        // resetprop
        else if (strstr(cmd, "resetprop"))
            fd = memfd_from_content(FAKE_RESETPROP_OUTPUT, strlen(FAKE_RESETPROP_OUTPUT));
        // pm list packages (grep root/supersu/xposed)
        else if (strstr(cmd, "pm list packages") && (strstr(cmd, "magisk") || strstr(cmd, "supersu") || strstr(cmd, "root") || strstr(cmd, "xposed")))
            fd = memfd_from_content(FAKE_PM_LIST_ROOT_OUTPUT, strlen(FAKE_PM_LIST_ROOT_OUTPUT));
        // cat /proc/self/status | grep TracerPid
        else if ((strstr(cmd, "cat") && strstr(cmd, "/proc/") && strstr(cmd, "status") && strstr(cmd, "Tracer")) ||
                 (strstr(cmd, "grep Tracer") && strstr(cmd, "/proc/")))
            fd = memfd_from_content(FAKE_GREP_TRACER_OUTPUT, strlen(FAKE_GREP_TRACER_OUTPUT));
        // grep su (find su binary)
        else if (strstr(cmd, "grep su") && strstr(cmd, "/") && !strstr(cmd, "Tracer") && !strstr(cmd, "status"))
            fd = memfd_from_content(FAKE_GREP_SU_OUTPUT, strlen(FAKE_GREP_SU_OUTPUT));
        // ls /system/addon.d (Magisk/KSU survival scripts)
        else if (strstr(cmd, "/system/addon.d"))
            fd = memfd_from_content(FAKE_LS_SYSTEM_ADDOND_OUTPUT, strlen(FAKE_LS_SYSTEM_ADDOND_OUTPUT));
        // dumpsys package (show magisk/xposed package)
        else if (strstr(cmd, "dumpsys package") && (strstr(cmd, "magisk") || strstr(cmd, "xposed")))
            fd = memfd_from_content(FAKE_DUMPSYS_PACKAGE_OUTPUT, strlen(FAKE_DUMPSYS_PACKAGE_OUTPUT));

        if (fd >= 0) {
            FILE* fp = fdopen(fd, type);
            if (fp) return fp;
            close(fd);
        }
    }
    return orig_popen(cmd, type);
}

static int hook_system(const char* cmd) {
    return orig_system(cmd);
}

// --- __system_property_get (v3.0: 返回脏值) ---
static int hook___system_property_get(const char* name, char* value) {
    if (!is_target || !name || !value) {
        return orig___system_property_get(name, value);
    }
    if (!is_hook_enabled(9)) return orig___system_property_get(name, value);
    for (int i = 0; DIRTY_PROPS[i][0] != nullptr; i++) {
        if (strstr(name, DIRTY_PROPS[i][0])) {
            size_t len = strlen(DIRTY_PROPS[i][1]);
            memcpy(value, DIRTY_PROPS[i][1], len);
            value[len] = '\0';
            return len;
        }
    }
    return orig___system_property_get(name, value);
}

// --- readlink ---
static ssize_t hook_readlink(const char* path, char* buf, size_t bufsiz) {
    if (!is_hook_enabled(6)) return orig_readlink(path, buf, bufsiz);
    if (is_target && path && strstr(path, "/proc/self/exe")) {
        const char* fake = "/system/bin/app_process64";
        size_t len = strlen(fake);
        if (len >= bufsiz) len = bufsiz - 1;
        memcpy(buf, fake, len);
        buf[len] = '\0';
        return len;
    }
    return orig_readlink(path, buf, bufsiz);
}

static ssize_t hook_readlinkat(int dirfd, const char* path, char* buf, size_t bufsiz) {
    if (!is_hook_enabled(6)) return orig_readlinkat(dirfd, path, buf, bufsiz);
    if (is_target && path && strstr(path, "/proc/self/exe")) {
        const char* fake = "/system/bin/app_process64";
        size_t len = strlen(fake);
        if (len >= bufsiz) len = bufsiz - 1;
        memcpy(buf, fake, len);
        buf[len] = '\0';
        return len;
    }
    return orig_readlinkat(dirfd, path, buf, bufsiz);
}

// --- ptrace ---
static long hook_ptrace(int request, va_list args) {
    if (!is_hook_enabled(7)) {
        return syscall(__NR_ptrace, request, va_arg(args, pid_t),
                       va_arg(args, void*), va_arg(args, void*));
    }
    if (is_target) {
        errno = EPERM;
        return -1;
    }
    return syscall(__NR_ptrace, request, va_arg(args, pid_t),
                   va_arg(args, void*), va_arg(args, void*));
}

// --- getenv ---
static char* hook_getenv(const char* name) {
    if (!is_hook_enabled(8)) return orig_getenv(name);
    if (is_target && name && strstr(name, "LD_PRELOAD"))
        return (char*)"/data/local/tmp/libriruloader.so";
    return orig_getenv(name);
}

static char* hook_secure_getenv(const char* name) {
    if (!is_hook_enabled(8)) return orig_secure_getenv(name);
    if (is_target && name && strstr(name, "LD_PRELOAD"))
        return (char*)"/data/local/tmp/libriruloader.so";
    return orig_secure_getenv(name);
}

// ============================================================
// PLT interposition 入口
// ============================================================
#define PLT_HOOK(name) \
    if (!orig_##name) { \
        orig_##name = (decltype(orig_##name))dlsym(RTLD_NEXT, #name); \
    }

__attribute__((constructor)) static void zygisk_init() {
    is_target = detect_target_process();
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
}

#undef PLT_HOOK

// ============================================================
// 导出 hook 函数
// ============================================================
extern "C" {

FILE* fopen(const char* path, const char* mode) {
    if (!orig_fopen) return nullptr;
    return hook_fopen(path, mode);
}

int open(const char* path, int flags, ...) {
    if (!orig_open) return -1;
    va_list a; va_start(a, flags); unsigned int m = va_arg(a, unsigned int); va_end(a);
    if (is_target && path && is_hook_enabled(1)) {
        int fake_fd = inject_or_orig_open(path, flags);
        if (fake_fd >= 0) return fake_fd;
    }
    return orig_open(path, flags, (mode_t)m);
}

int open64(const char* path, int flags, ...) {
    if (!orig_open64) return -1;
    va_list a; va_start(a, flags); unsigned int m = va_arg(a, unsigned int); va_end(a);
    if (is_target && path && is_hook_enabled(1)) {
        int fake_fd = inject_or_orig_open(path, flags);
        if (fake_fd >= 0) return fake_fd;
    }
    return orig_open64(path, flags, (mode_t)m);
}

int __open_2(const char* path, int flags) {
    if (!orig___open_2) return -1;
    if (is_target && path && is_hook_enabled(1)) {
        int fake_fd = inject_or_orig_open(path, flags);
        if (fake_fd >= 0) return fake_fd;
    }
    return orig___open_2(path, flags);
}

int stat(const char* path, struct stat* buf)
{ return orig_stat ? orig_stat(path, buf) : -1; }
int lstat(const char* path, struct stat* buf)
{ return orig_lstat ? orig_lstat(path, buf) : -1; }
int fstatat(int dirfd, const char* path, struct stat* buf, int flags)
{ return orig_fstatat ? orig_fstatat(dirfd, path, buf, flags) : -1; }
int __lxstat(int ver, const char* path, struct stat* buf)
{ return orig___lxstat ? orig___lxstat(ver, path, buf) : -1; }
int __xstat(int ver, const char* path, struct stat* buf)
{ return orig___xstat ? orig___xstat(ver, path, buf) : -1; }
int access(const char* path, int mode)
{ return orig_access ? orig_access(path, mode) : -1; }
int faccessat(int dirfd, const char* path, int mode, int flags)
{ return orig_faccessat ? orig_faccessat(dirfd, path, mode, flags) : -1; }
DIR* opendir(const char* path)
{ return orig_opendir ? orig_opendir(path) : nullptr; }
DIR* fdopendir(int fd)
{ return orig_fdopendir ? orig_fdopendir(fd) : nullptr; }

FILE* popen(const char* cmd, const char* type) {
    if (!orig_popen) return nullptr;
    return hook_popen(cmd, type);
}

int system(const char* cmd) {
    if (!orig_system) return -1;
    return orig_system(cmd);
}

int __system_property_get(const char* name, char* value) {
    if (!orig___system_property_get) return -1;
    return hook___system_property_get(name, value);
}

ssize_t readlink(const char* path, char* buf, size_t bufsiz) {
    if (!orig_readlink) return -1;
    return hook_readlink(path, buf, bufsiz);
}

ssize_t readlinkat(int dirfd, const char* path, char* buf, size_t bufsiz) {
    if (!orig_readlinkat) return -1;
    return hook_readlinkat(dirfd, path, buf, bufsiz);
}

long ptrace(int request, ...) {
    va_list args;
    va_start(args, request);
    if (!is_target || !orig_ptrace) {
        pid_t pid = va_arg(args, pid_t);
        void* addr = va_arg(args, void*);
        void* data = va_arg(args, void*);
        va_end(args);
        return orig_ptrace(request, pid, addr, data);
    }
    long ret = hook_ptrace(request, args);
    va_end(args);
    return ret;
}

char* getenv(const char* name) {
    if (!orig_getenv) return nullptr;
    return hook_getenv(name);
}

char* secure_getenv(const char* name) {
    if (!orig_secure_getenv) return nullptr;
    return hook_secure_getenv(name);
}

} // extern "C"
