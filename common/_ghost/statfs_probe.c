#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

static const char *en(int e)
{
    switch (e) {
    case 0:       return "-";
    case ENOENT:  return "ENOENT";
    case EACCES:  return "EACCES";
    case EPERM:   return "EPERM";
    case ENOTDIR: return "ENOTDIR";
    default:      return strerror(e);
    }
}

/* statfs(2) against the guards that already answer for the same path.
 *
 * ghost_statfs.patch closes vfs_statfs(), the one function statfs, statfs64 and
 * both fstatfs forms reach. Before it, stat/access/open answered ENOENT for a
 * hidden path while statfs handed back a real f_type and f_blocks -- one caller,
 * two answers. The contradiction is the finding, not the f_type.
 *
 * Build: $NDK/aarch64-linux-android31-clang -O2 -static -o statfs_probe statfs_probe.c
 * Run AS A HIDE-LISTED UID (an adb shell is uid 2000 and the uid gate skips it,
 * so a clean run from adb proves nothing):
 *     run-as <pkg> ./statfs_probe /data/adb/modules/<module>
 */
int main(int argc, char **argv)
{
    const char *p = argc > 1 ? argv[1] : "/data/adb/modules";
    int e_stat, e_access, e_open, e_statfs, e_fstatfs = -1;
    struct statfs sf;
    struct stat st;
    int fd, denied, leak;

    errno = 0; e_stat   = stat(p, &st) ? errno : 0;
    errno = 0; e_access = access(p, F_OK) ? errno : 0;
    errno = 0; fd = open(p, O_RDONLY | O_PATH); e_open = fd < 0 ? errno : 0;
    errno = 0; e_statfs = statfs(p, &sf) ? errno : 0;
    if (fd >= 0) { errno = 0; e_fstatfs = fstatfs(fd, &sf) ? errno : 0; }

    printf("stat      %s\n", en(e_stat));
    printf("access    %s\n", en(e_access));
    printf("open      %s\n", en(e_open));
    printf("statfs    %s", en(e_statfs));
    if (!e_statfs)
        printf("        f_type=0x%lx f_blocks=%llu",
               (unsigned long)sf.f_type, (unsigned long long)sf.f_blocks);
    putchar('\n');
    if (e_fstatfs >= 0)
        printf("fstatfs   %s\n", en(e_fstatfs));
    if (fd >= 0)
        close(fd);

    /* The guards that were already closed. If they all answer, this uid is not
     * hide-listed or this path is not in the rule table -- which is not a pass,
     * it is a probe that measured nothing. */
    denied = e_stat && e_access && e_open;
    leak = denied && (!e_statfs || e_fstatfs == 0);

    putchar('\n');
    if (leak)
        puts("FAIL: statfs answers for a path stat, access and open all deny.\n"
             "      One caller, two answers -- that contradiction is the finding.");
    else if (denied)
        puts("PASS: every surface denies the path.");
    else
        puts("INCONCLUSIVE: the path is visible to this caller, so there is\n"
             "      nothing to contradict. Run as a HIDE-LISTED uid (not an adb\n"
             "      shell, uid 2000 is skipped by the uid gate) against a path\n"
             "      the rule table carries.");
    return leak;
}
