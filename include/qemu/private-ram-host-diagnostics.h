/* Read-only Linux host-mapping diagnostics. NOT guest ownership evidence.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef QEMU_PRIVATE_RAM_HOST_DIAGNOSTICS_H
#define QEMU_PRIVATE_RAM_HOST_DIAGNOSTICS_H
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/mman.h>
#endif

typedef struct QemuPrivateRamHostDiagnostics {
    bool maps_complete;
    bool maps_gap;
    unsigned int map_count;
    unsigned int prot_intersection;
    unsigned int prot_union;
    int maps_errno;
    int mincore_result;
    int mincore_errno;
    size_t pages;
    size_t resident;
} QemuPrivateRamHostDiagnostics;

static inline QemuPrivateRamHostDiagnostics
qemu_private_ram_diagnose_host(pid_t owner, uintptr_t address, size_t size, FILE *out)
{
    QemuPrivateRamHostDiagnostics result = { .prot_intersection = 7,
                                           .mincore_result = -1 };
#ifdef __linux__
    char path[64], line[8192];
    uintptr_t cursor = address;
    if (owner <= 0 || owner != getpid() || !size || size > 64u * 1024u * 1024u ||
        address > UINTPTR_MAX - size) {
        result.maps_errno = result.mincore_errno = EINVAL;
        return result;
    }
    uintptr_t end = address + size;
    snprintf(path, sizeof(path), "/proc/%jd/maps", (intmax_t)owner);
    FILE *maps = fopen(path, "re");
    if (!maps) {
        result.maps_errno = errno;
    } else {
        while (fgets(line, sizeof(line), maps)) {
            uintmax_t first, last;
            char prot[5];
            bool partial = strchr(line, '\n') == NULL;
            if (partial) {
                int ch;
                while ((ch = fgetc(maps)) != EOF && ch != '\n') { }
            }
            if (sscanf(line, "%jx-%jx %4s", &first, &last, prot) != 3 ||
                first >= last || last <= address || first >= end) continue;
            if (++result.map_count > 4096) {
                result.maps_errno = EOVERFLOW;
                break;
            }
            unsigned int permissions = (prot[0] == 'r' ? 1 : 0) |
                                       (prot[1] == 'w' ? 2 : 0) |
                                       (prot[2] == 'x' ? 4 : 0);
            result.prot_intersection &= permissions;
            result.prot_union |= permissions;
            if (first > cursor) result.maps_gap = true;
            if (last > cursor) cursor = last < end ? last : end;
            if (out) fprintf(out, "HOST_DIAGNOSTIC_ONLY vma=%s%s", line,
                             partial ? " [truncated path]\n" : "");
        }
        if (ferror(maps)) result.maps_errno = errno ? errno : EIO;
        fclose(maps);
        result.maps_complete = !result.maps_errno && !result.maps_gap && cursor == end;
    }
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || ((unsigned long)page & ((unsigned long)page - 1)) ||
        end - 1 > UINTPTR_MAX - ((uintptr_t)page - 1)) {
        result.mincore_errno = EOVERFLOW;
        return result;
    }
    uintptr_t aligned = address & ~((uintptr_t)page - 1);
    uintptr_t aligned_end = ((end - 1) | ((uintptr_t)page - 1)) + 1;
    if (aligned_end <= aligned) {
        result.mincore_errno = EOVERFLOW;
        return result;
    }
    result.pages = (aligned_end - aligned) / page;
    unsigned char *resident = calloc(result.pages, 1);
    if (!resident) {
        result.mincore_errno = ENOMEM;
        return result;
    }
    errno = 0;
    result.mincore_result = mincore((void *)aligned, aligned_end - aligned, resident);
    result.mincore_errno = result.mincore_result == 0 ? 0 : errno;
    if (result.mincore_result == 0) {
        for (size_t i = 0; i < result.pages; i++) result.resident += resident[i] & 1;
    }
    free(resident);
    if (out) fprintf(out,
        "HOST_DIAGNOSTIC_ONLY pid=%jd address=%" PRIxPTR " size=%zu maps_complete=%u gap=%u vmas=%u prot_and=%u prot_or=%u mincore=%d errno=%d pages=%zu resident=%zu\n",
        (intmax_t)owner, address, size, result.maps_complete, result.maps_gap,
        result.map_count, result.prot_intersection, result.prot_union,
        result.mincore_result, result.mincore_errno, result.pages, result.resident);
#else
    (void)owner; (void)address; (void)size; (void)out;
    result.maps_errno = result.mincore_errno = ENOSYS;
#endif
    return result;
}
#endif
