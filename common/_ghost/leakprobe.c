/* leakprobe - report the ERRNO of each existence oracle, for one path.
 *
 * The shell cannot do this. `[ -w p ]` collapses EROFS and ENOENT to the same
 * false, and every shell redirect carries O_CREAT, so the two probes that
 * matter most for the sb_permission() family -- access(W_OK) and a plain
 * O_WRONLY open -- are invisible from a script. common/_ghost/README.md says as
 * much ("use the compiled /data/local/tmp/leakprobe, not shell tools").
 *
 * BUILD (NDK, dynamic -- a -static link trips bionic's TLS alignment check):
 *
 *   $NDK/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android26-clang  *       -O2 -Wall -Wextra -o leakprobe leakprobe.c
 *
 * RUN as the hidden uid, against THREE paths at once:
 *
 *   su <hidden-uid> -c '/data/local/tmp/leakprobe <hidden> <absent> <visible>'
 *
 *   hidden  -- a path in the _ghost table (`nm l g`)
 *   absent  -- a name that does not exist, in the same directory
 *   visible -- a stock file in the same directory, NOT injected
 *
 * hidden and absent must agree on every line. The visible column is what a
 * hidden path USED to answer, so it is what proves a guard does anything at all;
 * without it a table of matching ENOENTs could equally mean the probe is broken.
 *
 * Do not treat a `su <uid> -c` run as final: that runs in the ksu domain, not an
 * app domain. common/_ghost/README.md records _pathhide getting the wrong answer
 * exactly that way.
 *
 * Usage: leakprobe <path>...     run as the uid under test.
 * Prints one line per probe: name, result, errno name.
 */
/* O_PATH is a GNU extension on glibc; bionic exposes it unconditionally. Define
 * it here so the file also compiles on a host, which is how it gets checked. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static const char *en(int e)
{
    switch (e) {
    case 0:            return "-";
    case ENOENT:       return "ENOENT";
    case EROFS:        return "EROFS";
    case EACCES:       return "EACCES";
    case EEXIST:       return "EEXIST";
    case ENOTDIR:      return "ENOTDIR";
    case EXDEV:        return "EXDEV";
    case EPERM:        return "EPERM";
    case EISDIR:       return "EISDIR";
    case ENODATA:      return "ENODATA";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    default:           return strerror(e);
    }
}

static void row(const char *name, int rc)
{
    printf("  %-22s %-4s %s\n", name, rc < 0 ? "fail" : "OK", rc < 0 ? en(errno) : "-");
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        const char *p = argv[i];
        char buf[256], sub[4096];
        struct stat st;
        int fd;

        printf("%s\n", p);

        errno = 0; row("lstat(2)",            lstat(p, &st));
        /* THE CHEAPEST ORACLE. sb_permission() answers -EROFS for a MAY_WRITE
         * query on a read-only superblock before do_inode_permission() ever
         * dispatches to the engine, so a hidden path used to answer exactly
         * like a stock visible one where an absent name answers ENOENT. */
        errno = 0; row("access(W_OK)",        access(p, W_OK));
        errno = 0; row("access(R_OK)",        access(p, R_OK));
        errno = 0; row("access(F_OK)",        access(p, F_OK));
        /* No O_CREAT: the shell cannot express this. */
        errno = 0; fd = open(p, O_WRONLY);                 row("open(O_WRONLY)", fd);
        if (fd >= 0) close(fd);
        errno = 0; fd = open(p, O_WRONLY | O_TRUNC);       row("open(O_WRONLY|TRUNC)", fd);
        if (fd >= 0) close(fd);
        errno = 0; fd = open(p, O_RDWR);                   row("open(O_RDWR)", fd);
        if (fd >= 0) close(fd);
        errno = 0; fd = open(p, O_CREAT | O_EXCL, 0600);   row("open(O_CREAT|O_EXCL)", fd);
        if (fd >= 0) close(fd);
        errno = 0; fd = open(p, O_CREAT | O_RDONLY, 0600); row("open(O_CREAT|O_RDONLY)", fd);
        if (fd >= 0) close(fd);
        errno = 0; fd = open(p, O_PATH);                   row("open(O_PATH)", fd);
        if (fd >= 0) close(fd);
        errno = 0; fd = open(p, O_RDONLY);                 row("open(O_RDONLY)", fd);
        if (fd >= 0) close(fd);
        errno = 0; fd = open(p, O_DIRECTORY);              row("open(O_DIRECTORY)", fd);
        if (fd >= 0) close(fd);
        errno = 0; row("chown(-1,-1)",        chown(p, (uid_t)-1, (gid_t)-1));
        errno = 0; row("chmod(0644)",         chmod(p, 0644));
        errno = 0; row("truncate(0)",         truncate(p, 0));
        errno = 0; row("getxattr(selinux)",   (int)getxattr(p, "security.selinux", buf, sizeof buf));
        errno = 0; row("listxattr",           (int)listxattr(p, buf, sizeof buf));
        errno = 0; row("setxattr(user.x)",    setxattr(p, "user.x", "y", 1, 0));
        errno = 0; row("removexattr(user.x)", removexattr(p, "user.x"));
        snprintf(sub, sizeof sub, "%s/zzz", p);
        errno = 0; row("stat(p/zzz)",         stat(sub, &st));
        errno = 0; row("link(p,/data/local/tmp/lp)", link(p, "/data/local/tmp/lp.probe"));
        unlink("/data/local/tmp/lp.probe");
        snprintf(sub, sizeof sub, "%s/d", p);
        errno = 0; row("mkdirat(p/d)",        mkdir(sub, 0700));
        printf("\n");
    }
    return 0;
}
