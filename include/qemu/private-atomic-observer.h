/* Bounded Linux-user private sequential atomic environment observer.
 * SPDX-License-Identifier: GPL-2.0-or-later
 * No instruction semantics, guest writes, or interleaving claims.
 * Caller owns a paused single-vCPU interval and mmap provenance inventory.
 * Pinned store backing requires the explicit launch no-host-tamper profile.
 */
#ifndef QEMU_PRIVATE_ATOMIC_OBSERVER_H
#define QEMU_PRIVATE_ATOMIC_OBSERVER_H
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>

/* Whitelist of synchronous x86-64 Linux-user services. Unknown services close
 * the policy permanently before execution. Registration of kernel background
 * writers (AIO, io_uring, rseq), timers, new agents and signaling is not allowed.
 * QEMU rseq is separately accepted ONLY after its known ENOSYS result. */
static inline bool qemu_private_atomic_sync_syscall(int64_t n, uint64_t a1,
                                                   uint64_t a2)
{
    switch (n) {
    case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8:
    case 9: case 10: case 11: case 12: case 13: case 14: case 17: case 18:
    case 19: case 20: case 21: case 23: case 24: case 25: case 28:
    case 32: case 33: case 39: case 41: case 42: case 43: case 44: case 45:
    case 46: case 47: case 48: case 49: case 50: case 51: case 52:
    case 54: case 55: case 60: case 63: case 74: case 75: case 76: case 77:
    case 78: case 79: case 80: case 81: case 82: case 83: case 84: case 85:
    case 86: case 87: case 88: case 89: case 90: case 91: case 92: case 93:
    case 95: case 96: case 97: case 98: case 99: case 100: case 102:
    case 104: case 107: case 108: case 110: case 111: case 112:
    case 131: case 137: case 138: case 158: case 186: case 201:
    case 204: case 217: case 218: case 228: case 229:
    case 231: case 232: case 233: case 257: case 258: case 262: case 263:
    case 264: case 265: case 266: case 267: case 269: case 270: case 271:
    case 273: case 281: case 288: case 289: case 292: case 293:
    case 295: case 296: case 302: case 318: case 332: case 436: case 439:
        return true;
    case 290: /* eventfd2: kernel counter only; no user-memory registration.
               * Admit only the nonblocking, close-on-exec flags.
               * This does not admit AIO/io_uring or other eventfd users. */
        return a1 == (0x800ull | 0x80000ull);
    case 202: { /* futex: no PI/requeue kernel-owned user-word protocols. */
        uint64_t op = a1 & 0x7f;
        return !(a1 & ~0x1ffull) && (op == 0 || op == 1 || op == 9 || op == 10);
    }
    case 16: /* ioctl: no device/async ownership configuration. */
        return a1 == 0x5401 || a1 == 0x5413 || a1 == 0x541b || a1 == 0x5421;
    case 72: /* fcntl: no F_SETOWN/F_SETSIG/O_ASYNC. */
        return a1 == 0 || a1 == 1 || a1 == 2 || a1 == 3 || a1 == 1030 ||
               (a1 == 4 && !(a2 & 0x2000));
    default:
        return false;
    }
}

/* A VMA's MAP_PRIVATE status does NOT prove stable file backing. Prove each
 * file-backed page already has private anonymous exclusive COW backing, or
 * admit a canonical Nix store VMA under the launch-bound no-host-tamper scope.
 * Never fault pages in, change permissions, read bytes or write guest state. */
static inline bool qemu_private_atomic_cow_pages(FILE *pagemap, uintptr_t start,
                                                 uintptr_t end)
{
    long ps = sysconf(_SC_PAGESIZE);
    if (!pagemap || ps <= 0 || (ps & (ps - 1))) return false;
    for (uintptr_t p = start & ~((uintptr_t)ps - 1); p < end;) {
        uint64_t entry;
        uint64_t offset = (p / (uint64_t)ps) * 8;
        if (offset > INT64_MAX || fseeko(pagemap, (off_t)offset, SEEK_SET) ||
            fread(&entry, sizeof(entry), 1, pagemap) != 1 ||
            !(entry & (1ull << 63)) || (entry & (1ull << 62)) ||
            (entry & (1ull << 61)) || !(entry & (1ull << 56))) return false;
        if (p > UINTPTR_MAX - ps) return false;
        p += ps;
    }
    return true;
}

static inline bool qemu_private_atomic_store_path(const char *path)
{
    static const char base32[] = "0123456789abcdfghijklmnpqrsvwxyz";
    if (strncmp(path, "/nix/store/", 11)) return false;
    path += 11;
    for (unsigned int i = 0; i < 32; i++) {
        if (!path[i] || !strchr(base32, path[i])) return false;
    }
    return path[32] == '-' && path[33] && !strstr(path, " (deleted)") &&
           !strstr(path, "/../");
}

typedef bool (*QemuPrivateAtomicImagePin)(const char *, const char *, uint64_t);

static inline bool qemu_private_atomic_backing_bound(uintptr_t start, uint64_t size,
                                               bool no_host_tamper,
                                               QemuPrivateAtomicImagePin pin_image)
{
    char name[80], line[8192];
    FILE *maps = NULL, *pagemap = NULL;
    uintptr_t cursor = start;
    bool ok = false;
    if (!size || size > UINTPTR_MAX - start || !no_host_tamper) return false;
    uintptr_t end = start + size;
    snprintf(name, sizeof(name), "/proc/%jd/maps", (intmax_t)getpid());
    maps = fopen(name, "re");
    snprintf(name, sizeof(name), "/proc/%jd/pagemap", (intmax_t)getpid());
    pagemap = fopen(name, "re");
    if (!maps) goto out;
    while (cursor < end && fgets(line, sizeof(line), maps)) {
        uintptr_t low, high;
        unsigned long long offset, inode;
        char perms[5], device[32];
        int consumed = 0;
        if (!strchr(line, '\n') || sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %llx %31s %llu %n",
                &low, &high, perms, &offset, device, &inode, &consumed) != 6 || high <= low) goto out;
        if (high <= cursor) continue;
        if (low > cursor || strlen(perms) != 4 || perms[3] != 'p') goto out;
        uintptr_t stop = high < end ? high : end;
        char *path = line + consumed;
        while (*path == ' ' || *path == '\t') path++;
        path[strcspn(path, "\n")] = 0;
        bool anonymous = inode == 0 && (!*path || !strcmp(path, "[heap]") ||
                         !strcmp(path, "[stack]") || !strncmp(path, "[anon:", 6));
        if (!anonymous && !qemu_private_atomic_store_path(path) &&
            !qemu_private_atomic_cow_pages(pagemap, cursor, stop) &&
            (!pin_image || !pin_image(path, device, inode))) goto out;
        cursor = stop;
    }
    ok = cursor == end;
out:
    if (maps) fclose(maps);
    if (pagemap) fclose(pagemap);
    return ok;
}

static inline bool qemu_private_atomic_backing(uintptr_t start, uint64_t size, bool no_host_tamper)
{
    return qemu_private_atomic_backing_bound(start, size, no_host_tamper, NULL);
}
#endif
