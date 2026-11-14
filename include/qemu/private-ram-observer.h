/* Linux observer primitive for verified private guest VMAs only.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Not a guest-access API: caller must hold mmap_lock, quiesce guest execution,
 * validate every target page's private ownership, and check g2h translation.
 * No protection changes, guest faults, writes, or arbitrary address requests.
 */
#ifndef QEMU_PRIVATE_RAM_OBSERVER_H
#define QEMU_PRIVATE_RAM_OBSERVER_H

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/magic.h>
#include <sys/vfs.h>
#endif

static inline bool qemu_private_ram_fd_is_owned(int fd, pid_t owner)
{
#ifdef __linux__
    char path[64];
    struct stat expected, actual;
    struct statfs filesystem;
    int descriptor_flags, access_flags;
    if (fd < 0 || owner <= 0 || owner != getpid()) {
        errno = EINVAL;
        return false;
    }
    int n = snprintf(path, sizeof(path), "/proc/%jd/mem", (intmax_t)owner);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        errno = EOVERFLOW;
        return false;
    }
    if (fstat(fd, &actual) < 0 || stat(path, &expected) < 0 ||
        fstatfs(fd, &filesystem) < 0) {
        return false;
    }
    descriptor_flags = fcntl(fd, F_GETFD);
    access_flags = fcntl(fd, F_GETFL);
    if (descriptor_flags < 0 || access_flags < 0) {
        return false;
    }
    if (!S_ISREG(actual.st_mode) || actual.st_dev != expected.st_dev ||
        actual.st_ino != expected.st_ino ||
        (unsigned long)filesystem.f_type != (unsigned long)PROC_SUPER_MAGIC ||
        !(descriptor_flags & FD_CLOEXEC) || (access_flags & O_ACCMODE) != O_RDONLY ||
        owner != getpid()) {
        errno = EACCES;
        return false;
    }
    return true;
#else
    (void)fd;
    (void)owner;
    errno = ENOSYS;
    return false;
#endif
}

static inline int qemu_private_ram_open_owned(pid_t owner)
{
#ifdef __linux__
    char path[64];
    if (owner <= 0 || owner != getpid()) {
        errno = EINVAL;
        return -1;
    }
    /* Explicit own PID avoids resolving /proc/self in a filesystem broker's
     * process. This is the same authorized process memory, not another PID. */
    int n = snprintf(path, sizeof(path), "/proc/%jd/mem", (intmax_t)owner);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        errno = EOVERFLOW;
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    if (!qemu_private_ram_fd_is_owned(fd, owner)) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
#else
    (void)owner;
    errno = ENOSYS;
    return -1;
#endif
}

static inline bool qemu_private_ram_pread_owned(int fd, pid_t owner,
                                               uintptr_t address,
                                               void *buffer, size_t size)
{
#ifdef __linux__
    size_t done = 0;
    if (fd < 0 || owner <= 0 || owner != getpid() || size == 0 ||
        size > 64u * 1024u * 1024u || address > UINTPTR_MAX - (size - 1) ||
        (off_t)address < 0 || (uintmax_t)(off_t)address != (uintmax_t)address ||
        (off_t)(address + size - 1) < 0 ||
        (uintmax_t)(off_t)(address + size - 1) != (uintmax_t)(address + size - 1)) {
        errno = EOVERFLOW;
        return false;
    }
    while (done < size) {
        ssize_t n = pread(fd, (uint8_t *)buffer + done, size - done,
                          (off_t)(address + done));
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            if (n == 0) {
                errno = EIO;
            }
            return false;
        }
        done += n;
    }
    return owner == getpid();
#else
    (void)fd;
    (void)owner;
    (void)address;
    (void)buffer;
    (void)size;
    errno = ENOSYS;
    return false;
#endif
}
#endif
