#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define BLKROSET   0x125d
#define KSUD_STAGE "/data/user_de/0/df.root/ksud"
#define KSUD       "/data/adb/ksud"
#define PREFS_PATH "/data/user_de/0/df.root/shared_prefs/dfroot.xml"
#define MODULES_DIR "/data/adb/modules"
#define INSMOD     "/vendor/bin/insmod"
/* The KernelSU LKM for this kernel. Staged from the APK assets when present;
 * /data/local/tmp used to be an adb-testing fallback but only masked staging
 * failures (see load_kernelsu), so it is no longer consulted. */
#define KSU_KO     "/data/user_de/0/df.root/kernelsu.ko"
/* Everything load_kernelsu() observes lands here: which paths it tried,
 * insmod's own stderr ("Exec format error", "Unknown symbol ...") and exit
 * codes. The UMH context has no other audience, and the kernel printk ring
 * is unreadable from the shell on this device. */
#define KSU_LOG    "/data/local/tmp/ksu-insmod.log"
#define KSU_DMESG_LOG "/data/local/tmp/ksu-dmesg.log"
#define KSU_PSTORE_LOG "/data/local/tmp/ksu-pstore.log"

struct ksu_get_info_cmd {
    uint32_t version;
    uint32_t flags;
    uint32_t features;
    uint32_t uapi_version;
};

struct ksu_get_feature_cmd {
    uint32_t feature_id;
    uint64_t value;
    uint8_t supported;
};

static int pref_true(const char *buf, const char *key)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "name=\"%s\"", key);
    char *p = strstr(buf, needle);
    if (!p) return 0;
    char *tag_end = strchr(p, '>');
    char *v = strstr(p, "value=\"true\"");
    return v && tag_end && v < tag_end;
}

static int read_prefs(char *su_manager, size_t su_manager_size, int *soft_reboot,
                      int *disable_modules)
{
    int fd = open(PREFS_PATH, O_RDONLY);
    if (fd < 0) return -1;

    char buf[4096];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    char *p = strstr(buf, "name=\"su_manager\">");
    if (!p) return -1;
    p += strlen("name=\"su_manager\">");
    char *end = strchr(p, '<');
    if (!end) return -1;
    size_t len = end - p;
    if (len == 0 || len >= su_manager_size) return -1;
    memcpy(su_manager, p, len);
    su_manager[len] = '\0';

    *soft_reboot = pref_true(buf, "soft_reboot");
    *disable_modules = pref_true(buf, "disable_modules");

    return 0;
}

static int adopt_zygote_env(void)
{
    FILE *f = popen("pidof zygote64 zygote", "r");
    if (!f) return -1;
    int pid = 0;
    fscanf(f, "%d", &pid);
    pclose(f);
    if (!pid) return -1;

    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    static char buf[16384];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    for (char *p = buf, *end = buf + n; p < end; p += strlen(p) + 1)
        putenv(p);
    return 0;
}

static int should_ro(const char *name)
{
    size_t len = strlen(name);
    if (!strcmp(name, "super"))  return 1;
    if (!strcmp(name, "misc"))   return 1;
    if (!strcmp(name, "steady")) return 1;
    if (len >= 2 && name[len - 2] == '_' &&
        (name[len - 1] == 'a' || name[len - 1] == 'b'))
        return 1;
    return 0;
}

static int set_partitions_ro(void)
{
    DIR *dir = opendir("/dev/block/by-name");
    if (!dir)
        return -1;

    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (!should_ro(ent->d_name))
            continue;

        char path[128];
        snprintf(path, sizeof(path), "/dev/block/by-name/%s", ent->d_name);

        int fd = open(path, O_RDONLY);
        if (fd < 0)
            continue;

        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)) {
            int on = 1;
            ioctl(fd, BLKROSET, &on);
        }
        close(fd);
    }

    closedir(dir);
    return 0;
}

static int late_load_running(void)
{
    DIR *d = opendir("/proc");
    if (!d)
        return 0;
    struct dirent *e;
    char path[64], buf[256];
    int found = 0;
    while ((e = readdir(d)) != NULL) {
        char *end;
        strtol(e->d_name, &end, 10);
        if (*end) continue;
        snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = '\0';
        for (int i = 0; i < n; i++)
            if (!buf[i]) buf[i] = ' ';
        if (strstr(buf, "ksud") && strstr(buf, "late-load")) {
            found = 1;
            break;
        }
    }
    closedir(d);
    return found;
}

static int run_ctx(const char *ctx, char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (ctx) {
            int fd = open("/proc/self/attr/exec", O_WRONLY);
            if (fd >= 0) { write(fd, ctx, strlen(ctx)); close(fd); }
        }
        execv(argv[0], argv);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void touch(const char *path)
{
    int fd = open(path, O_CREAT | O_WRONLY, 0666);
    if (fd >= 0)
        close(fd);
}

/* Mark every installed module disabled before ksud runs. A broken module
 * otherwise loads on the next boot and bootloops the device. */
static int disable_modules(void)
{
    DIR *dir = opendir(MODULES_DIR);
    if (!dir)
        return -1;

    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (ent->d_name[0] == '.')
            continue;
        char path[256];
        snprintf(path, sizeof(path), MODULES_DIR "/%s/disable", ent->d_name);
        touch(path);
    }
    closedir(dir);
    return 0;
}

static int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static int kernelsu_loaded(void)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f)
        return 0;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "kernelsu ", 9) == 0) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static void log_note(const char *msg)
{
    /* Keep the descriptor across finit_module's credential transition. */
    static int fd = -1;
    if (fd < 0)
        fd = open(KSU_LOG, O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd >= 0) {
        write(fd, msg, strlen(msg));
        fsync(fd);
    }
}

/* The probe child reports through a pipe and the PARENT writes the log line.
 * Writing the log from the child itself proved unreliable: installing the
 * driver fd can change the probing task's security context mid-syscall, and
 * on 2026-10-22 the probe's "# driver fd=..." line was silently lost that
 * way, hiding the actual probe result. */
struct probe_result {
    int driver_fd;
    long install_rc;
    int install_errno;
    int info_rc;
    int info_errno;
    struct ksu_get_info_cmd info;
    int hide_rc;
    uint8_t hide_supported;
    uint64_t hide_value;
};

static int kernelsu_responding(void)
{
    int fds[2];
    if (pipe(fds) != 0) {
        log_note("# driver probe: pipe failed\n");
        return 0;
    }
    pid_t pid = fork();
    if (pid < 0) {
        log_note("# driver probe: fork failed\n");
        close(fds[0]);
        close(fds[1]);
        return 0;
    }
    if (pid == 0) {
        close(fds[0]);
        struct probe_result r;
        memset(&r, 0, sizeof(r));
        r.driver_fd = -1;
        errno = 0;
        r.install_rc = syscall(SYS_reboot, 0xDEADBEEFUL, 0xCAFEBABEUL, 0UL, &r.driver_fd);
        r.install_errno = errno;
        errno = 0;
        r.info_rc = r.driver_fd < 0 ? -1 : ioctl(r.driver_fd, _IOR('K', 2, struct ksu_get_info_cmd), &r.info);
        r.info_errno = errno;
        struct ksu_get_feature_cmd feature = { .feature_id = 4 };
        r.hide_rc = r.driver_fd < 0 ? -1 :
            ioctl(r.driver_fd, _IOC(_IOC_READ | _IOC_WRITE, 'K', 13, 0), &feature);
        r.hide_supported = feature.supported;
        r.hide_value = feature.value;
        if (r.driver_fd >= 0)
            close(r.driver_fd);
        /* best effort: even if the pipe write fails, the exit status still
         * carries the verdict */
        write(fds[1], &r, sizeof(r));
        close(fds[1]);
        _exit(r.info_rc == 0 && r.info.version == 32680U && (r.info.flags & 5U) == 5U ? 0 : 1);
    }
    close(fds[1]);
    struct probe_result r;
    memset(&r, 0, sizeof(r));
    r.driver_fd = -1;
    ssize_t got = 0;
    while (got < (ssize_t)sizeof(r)) {
        ssize_t n = read(fds[0], (char *)&r + got, sizeof(r) - got);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
            break;
        }
        got += n;
    }
    close(fds[0]);
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            log_note("# driver probe: waitpid failed\n");
            return 0;
        }
    }
    int exited = WIFEXITED(status);
    int code = exited ? WEXITSTATUS(status) : -1;
    if (got == (ssize_t)sizeof(r)) {
        char note[256];
        snprintf(note, sizeof(note), "# driver fd=%d install_rc=%ld install_errno=%d ioctl_rc=%d ioctl_errno=%d version=%u flags=%u features=%u uapi_version=%u exit=%d\n",
                 r.driver_fd, r.install_rc, r.install_errno, r.info_rc, r.info_errno,
                 r.info.version, r.info.flags, r.info.features, r.info.uapi_version, code);
        log_note(note);
        snprintf(note, sizeof(note), "# selinux_hide ioctl_rc=%d supported=%u value=%llu\n",
                 r.hide_rc, r.hide_supported, (unsigned long long)r.hide_value);
        log_note(note);
    } else {
        char note[96];
        snprintf(note, sizeof(note), "# driver probe: no details (exit=%d)\n", code);
        log_note(note);
    }
    return exited && code == 0;
}

/* fork+exec with the child's stdout/stderr appended to KSU_LOG, so insmod's
 * own error line survives the UMH context. */
static int run_capture(char *const argv[], const char *log_path, int append)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int fd = open(log_path, O_CREAT | O_WRONLY | O_NOFOLLOW |
                      (append ? O_APPEND : O_TRUNC), 0644);
        if (fd >= 0) {
            fchmod(fd, 0644);
            dup2(fd, 1);
            dup2(fd, 2);
            close(fd);
        }
        execv(argv[0], argv);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Same, but the child's output travels through a pipe and the parent appends
 * it to the log. If the child cannot open the log itself (or dies before
 * writing), its stderr used to vanish silently - on 2026-10-22 an insmod
 * failure left no error line at all, which made the failure undiagnosable.
 * The parent's own writes to the same file have always been reliable. */
static int run_capture_piped(char *const argv[], const char *log_path)
{
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], 1);
        dup2(fds[1], 2);
        close(fds[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(fds[1]);
    int out = open(log_path, O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW, 0644);
    if (out >= 0) {
        char buf[4096];
        ssize_t n;
        while ((n = read(fds[0], buf, sizeof(buf))) > 0) {
            ssize_t off = 0;
            while (off < n) {
                ssize_t w = write(out, buf + off, n - off);
                if (w <= 0)
                    break;
                off += w;
            }
        }
        close(out);
    }
    close(fds[0]);
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void capture_pstore(void)
{
    int output_fd = open(KSU_PSTORE_LOG, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0644);
    if (output_fd < 0)
        return;
    fchmod(output_fd, 0644);
    FILE *output = fdopen(output_fd, "w");
    if (!output) {
        close(output_fd);
        return;
    }
    DIR *directory = opendir("/sys/fs/pstore");
    if (!directory) {
        fprintf(output, "pstore: %s\n", strerror(errno));
        fclose(output);
        return;
    }
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;
        fprintf(output, "=== %s ===\n", entry->d_name);
        int input_fd = openat(dirfd(directory), entry->d_name, O_RDONLY | O_NOFOLLOW);
        if (input_fd < 0) {
            fprintf(output, "read failed: %s\n", strerror(errno));
            continue;
        }
        char buffer[4096];
        ssize_t length;
        while ((length = read(input_fd, buffer, sizeof(buffer))) > 0)
            fwrite(buffer, 1, length, output);
        if (length < 0)
            fprintf(output, "\nread failed: %s\n", strerror(errno));
        close(input_fd);
        fputc('\n', output);
        count++;
    }
    if (!count)
        fputs("pstore: no records\n", output);
    closedir(directory);
    fclose(output);
}

/*
 * Load the KernelSU LKM built for this exact kernel (5.4.254-qgki — no KMI
 * module exists for it upstream; this APK carries one in its assets).
 *
 * insmod runs as a fork of this bootstrap: uid 0 in u:r:init:s0 with
 * pid != 1, so kernelsu_init() takes its late-load branch, installs the
 * syscall hooks and grants the loading process root. ksud's own late-load
 * cannot substitute for this: it resolves its LKM through KMI/BTF tables
 * this kernel does not have, which is why it returns 0 having done nothing.
 *
 * The driver probe below is the authoritative "is the kernel side alive"
 * check and runs FIRST: /proc/modules cannot be trusted (the module hides
 * itself once loaded), and re-running the chain in a boot where the module
 * is already active must never insmod a second copy.
 *
 * Only the module staged from the APK assets is loaded. /data/local/tmp/
 * kernelsu.ko used to be a fallback; on 2026-10-22 the staged insmod failed
 * quietly and the fallback silently loaded an older build instead, so the
 * manager kept talking to a stale kernel side while the app reported an
 * error. A stale fallback masks failures; a clear error does not.
 *
 * Markers: /dev/dfm7 loaded (or already loaded), /dev/dfme3 every attempt
 * failed. Details of each attempt go to KSU_LOG.
 */
static int load_kernelsu(void)
{
    if (kernelsu_responding()) {
        touch("/dev/dfm7");
        return 0;
    }
    if (kernelsu_loaded()) {
        log_note("# module listed in /proc/modules but driver not answering\n");
        touch("/dev/dfme3");
        return -1;
    }

    /* log_note can already have opened the log during the initial probe. */
    int reset_fd = open(KSU_LOG, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0644);
    if (reset_fd >= 0) {
        fchmod(reset_fd, 0644);
        close(reset_fd);
    }
    log_note("# bootstrap op9rt-release: in-process finit_module\n");

    char note[256];
    struct stat st;
    if (stat(KSU_KO, &st) != 0) {
        snprintf(note, sizeof(note), "# missing %s\n", KSU_KO);
        log_note(note);
        touch("/dev/dfme3");
        return -1;
    }
    uint32_t magic = 0;
    int mfd = open(KSU_KO, O_RDONLY);
    if (mfd >= 0) {
        read(mfd, &magic, sizeof(magic));
        close(mfd);
    }
    snprintf(note, sizeof(note),
             "# insmod %s size=%lld magic=%02x%02x%02x%02x\n", KSU_KO,
             (long long)st.st_size,
             (unsigned)(magic >> 24) & 0xff, (unsigned)(magic >> 16) & 0xff,
             (unsigned)(magic >> 8) & 0xff, (unsigned)magic & 0xff);
    log_note(note);

    // Load the module IN-PROCESS via finit_module() - not fork+exec of
    // /vendor/bin/insmod. kernelsu_init() converts the *calling* task into the
    // ksu domain before it re-enforces SELinux, so this bootstrap itself has
    // to be that caller. With a forked insmod the conversion landed on the
    // child, which exited immediately; the parent stayed u:r:init:s0 and once
    // the module turned Enforcing back on it could neither write the log, nor
    // probe the driver, nor exec ksud (2026-10-22 12:34 boot, marker dfme3).
    // enable_at_boot=1 switches selinux_hide on during init, while the backup
    // policy still exists. Shell access follows the Manager's saved grants.
    mfd = open(KSU_KO, O_RDONLY | O_NOFOLLOW);
    if (mfd < 0) {
        snprintf(note, sizeof(note), "# open %s: %s\n", KSU_KO, strerror(errno));
        log_note(note);
        touch("/dev/dfme3");
        return -1;
    }
    errno = 0;
    int rc = syscall(SYS_finit_module, mfd, "enable_at_boot=1", 0);
    int load_errno = errno;
    snprintf(note, sizeof(note), "# finit_module returned rc=%d errno=%d (%s)\n", rc,
             load_errno, strerror(load_errno));
    log_note(note);
    close(mfd);
    if (rc != 0) {
        snprintf(note, sizeof(note), "# finit_module rc=%d errno=%d (%s)\n", rc, load_errno,
                 strerror(load_errno));
        log_note(note);
    }
    snprintf(note, sizeof(note), "# rc=%d loaded=%d\n", rc, kernelsu_loaded());
    log_note(note);
    if (rc == 0 && kernelsu_loaded()) {
        if (kernelsu_responding()) {
            touch("/dev/dfm7");
            return 0;
        }
        log_note("# module loaded but driver probe failed after load\n");
    }
    touch("/dev/dfme3");
    return -1;
}

int main(void)
{
    touch("/dev/dfm1");
    capture_pstore();
    char su_manager[256];
    int soft_reboot, disable_mods;
    if (read_prefs(su_manager, sizeof(su_manager), &soft_reboot, &disable_mods) != 0) {
        touch("/dev/dfme0");
        return 1;
    }

    touch("/dev/dfm2");
    if (adopt_zygote_env())
        touch("/dev/dfmw0");

    touch("/dev/dfm3");
    if (set_partitions_ro())
        touch("/dev/dfmw1");

    if (disable_mods) {
        touch("/dev/dfm4");
        if (disable_modules()) {
            touch("/dev/dfme1");
            return 1;
        }
    }

    int load_rc = load_kernelsu();
    run_capture((char *[]){ "/system/bin/dmesg", NULL }, KSU_DMESG_LOG, 0);
    if (load_rc != 0)
        return 1;

    touch("/dev/dfm5");
    log_note("# ksud late-load\n");
    int ksud_rc = run_capture_piped((char *[]){ KSUD_STAGE, "late-load", "--package-name", su_manager, NULL }, KSU_LOG);
    char note[64];
    snprintf(note, sizeof(note), "# ksud rc=%d\n", ksud_rc);
    log_note(note);
    if (ksud_rc == 0) {
        touch("/dev/dfm6");
        if (soft_reboot) {
            while (late_load_running()) sleep(1);
            run_ctx("u:r:ksu:s0", (char *[]){ KSUD, "soft-reboot", NULL });
        }
    } else {
        touch("/dev/dfme2");
        return 1;
    }
        
    return 0;
}
