/*
 *  User emulator execution
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "accel/tcg/cpu-ops.h"
#include "disas/disas.h"
#include "exec/vaddr.h"
#include "exec/exec-all.h"
#include "tcg/tcg.h"
#include "qemu/bitops.h"
#include "qemu/rcu.h"
#include "exec/cpu_ldst.h"
#include "user/cpu_loop.h"
#include "qemu/main-loop.h"
#include "user/page-protection.h"
#include "exec/page-protection.h"
#include "exec/helper-proto.h"
#include "qemu/atomic128.h"
#include "qemu/qemu-plugin.h"
#include "qemu/bswap.h"
#include "qemu/log.h"
#include "qemu/private-ram-observer.h"
#include "qemu/private-ram-host-diagnostics.h"
#include "qemu/int128.h"
#include "trace.h"
#include "tcg/tcg-ldst.h"
#include "internal-common.h"
#include "internal-target.h"
#include "tb-internal.h"
#ifdef TARGET_X86_64
#include "target/i386/cpu.h"
#endif
#ifdef TARGET_AARCH64
#include "target/arm/cpu.h"
#include "target/arm/cpu-features.h"
#include "target/arm/internals.h"
#endif

__thread uintptr_t helper_retaddr;

//#define DEBUG_SIGNAL

void cpu_interrupt(CPUState *cpu, int mask)
{
    g_assert(bql_locked());
    cpu->interrupt_request |= mask;
    qatomic_set(&cpu->neg.icount_decr.u16.high, -1);
}

/*
 * Adjust the pc to pass to cpu_restore_state; return the memop type.
 */
MMUAccessType adjust_signal_pc(uintptr_t *pc, bool is_write)
{
    switch (helper_retaddr) {
    default:
        /*
         * Fault during host memory operation within a helper function.
         * The helper's host return address, saved here, gives us a
         * pointer into the generated code that will unwind to the
         * correct guest pc.
         */
        *pc = helper_retaddr;
        break;

    case 0:
        /*
         * Fault during host memory operation within generated code.
         * (Or, a unrelated bug within qemu, but we can't tell from here).
         *
         * We take the host pc from the signal frame.  However, we cannot
         * use that value directly.  Within cpu_restore_state_from_tb, we
         * assume PC comes from GETPC(), as used by the helper functions,
         * so we adjust the address by -GETPC_ADJ to form an address that
         * is within the call insn, so that the address does not accidentally
         * match the beginning of the next guest insn.  However, when the
         * pc comes from the signal frame it points to the actual faulting
         * host memory insn and not the return from a call insn.
         *
         * Therefore, adjust to compensate for what will be done later
         * by cpu_restore_state_from_tb.
         */
        *pc += GETPC_ADJ;
        break;

    case 1:
        /*
         * Fault during host read for translation, or loosely, "execution".
         *
         * The guest pc is already pointing to the start of the TB for which
         * code is being generated.  If the guest translator manages the
         * page crossings correctly, this is exactly the correct address
         * (and if the translator doesn't handle page boundaries correctly
         * there's little we can do about that here).  Therefore, do not
         * trigger the unwinder.
         */
        *pc = 0;
        return MMU_INST_FETCH;
    }

    return is_write ? MMU_DATA_STORE : MMU_DATA_LOAD;
}

/**
 * handle_sigsegv_accerr_write:
 * @cpu: the cpu context
 * @old_set: the sigset_t from the signal ucontext_t
 * @host_pc: the host pc, adjusted for the signal
 * @guest_addr: the guest address of the fault
 *
 * Return true if the write fault has been handled, and should be re-tried.
 *
 * Note that it is important that we don't call page_unprotect() unless
 * this is really a "write to nonwritable page" fault, because
 * page_unprotect() assumes that if it is called for an access to
 * a page that's writable this means we had two threads racing and
 * another thread got there first and already made the page writable;
 * so we will retry the access. If we were to call page_unprotect()
 * for some other kind of fault that should really be passed to the
 * guest, we'd end up in an infinite loop of retrying the faulting access.
 */
bool handle_sigsegv_accerr_write(CPUState *cpu, sigset_t *old_set,
                                 uintptr_t host_pc, abi_ptr guest_addr)
{
    switch (page_unprotect(guest_addr, host_pc)) {
    case 0:
        /*
         * Fault not caused by a page marked unwritable to protect
         * cached translations, must be the guest binary's problem.
         */
        return false;
    case 1:
        /*
         * Fault caused by protection of cached translation; TBs
         * invalidated, so resume execution.
         */
        return true;
    case 2:
        /*
         * Fault caused by protection of cached translation, and the
         * currently executing TB was modified and must be exited immediately.
         */
        sigprocmask(SIG_SETMASK, old_set, NULL);
        cpu_loop_exit_noexc(cpu);
        /* NORETURN */
    default:
        g_assert_not_reached();
    }
}

typedef struct PageFlagsNode {
    struct rcu_head rcu;
    IntervalTreeNode itree;
    int flags;
} PageFlagsNode;

static IntervalTreeRoot pageflags_root;
/* Protected by mmap_lock; provenance is never guessed from host VMAs. */
static uint64_t mapping_observation_generation = 1;
static bool mapping_observation_valid = true;

static void mapping_observation_changed(void)
{
    assert_memory_lock();
    if (mapping_observation_generation == UINT64_MAX) {
        mapping_observation_valid = false;
    } else {
        mapping_observation_generation++;
    }
}

void page_mapping_observation_invalidate(void)
{
    assert_memory_lock();
    mapping_observation_valid = false;
    mapping_observation_changed();
}

static PageFlagsNode *pageflags_find(target_ulong start, target_ulong last)
{
    IntervalTreeNode *n;

    n = interval_tree_iter_first(&pageflags_root, start, last);
    return n ? container_of(n, PageFlagsNode, itree) : NULL;
}

static PageFlagsNode *pageflags_next(PageFlagsNode *p, target_ulong start,
                                     target_ulong last)
{
    IntervalTreeNode *n;

    n = interval_tree_iter_next(&p->itree, start, last);
    return n ? container_of(n, PageFlagsNode, itree) : NULL;
}

bool page_mapping_observe_bti(target_ulong pc, QemuPluginBtiPage *result)
{
#if defined(TARGET_AARCH64) && defined(CONFIG_LINUX_USER)
    ARMCPU *cpu;
    CPUARMState *env;
    int flags;
    g_assert(result);
    memset(result, 0, sizeof(*result));
    mmap_lock();
    if (!mapping_observation_valid || TARGET_PAGE_BITS != 12 ||
        (pc & (TARGET_PAGE_SIZE - 1)) + 4 > TARGET_PAGE_SIZE) {
        mmap_unlock();
        return false;
    }
    flags = page_get_flags(pc);
    cpu = ARM_CPU(current_cpu);
    env = &cpu->env;
    if (!(flags & PAGE_VALID) ||
        (flags & (PAGE_MAP_PRIVATE | PAGE_MAP_SHARED)) != PAGE_MAP_PRIVATE ||
        !(flags & PAGE_EXEC) || (flags & (PAGE_WRITE | PAGE_WRITE_ORG))) {
        mmap_unlock();
        return false;
    }
    result->page_start = pc & TARGET_PAGE_MASK;
    result->generation = mapping_observation_generation;
    result->flags = (flags & PAGE_READ ? 1u : 0) |
                    (flags & PAGE_WRITE_ORG ? 2u : 0) |
                    (flags & PAGE_EXEC ? 4u : 0) |
                    (flags & PAGE_VALID ? 8u : 0) |
                    (flags & PAGE_MAP_PRIVATE ? 16u : 0) |
                    (flags & PAGE_BTI ? 32u : 0);
    result->features = (cpu_isar_feature(aa64_bti, cpu) ? 1u : 0) |
                       ((env->cp15.sctlr_el[1] & SCTLR_BT0) ? 2u : 0) |
                       ((env->aarch64 && arm_current_el(env) == 0) ? 4u : 0);
    mmap_unlock();
    return true;
#else
    (void)pc;
    (void)result;
    return false;
#endif
}

bool qemu_plugin_observe_bti_page(uint64_t pc, QemuPluginBtiPage *result)
{
    if (!result || (target_ulong)pc != pc) {
        return false;
    }
    return page_mapping_observe_bti((target_ulong)pc, result);
}

bool page_mapping_observation_uniform(target_ulong start, target_ulong len)
{
    const int mask = PAGE_VALID | PAGE_READ | PAGE_WRITE_ORG | PAGE_EXEC |
                     PAGE_MAP_PRIVATE | PAGE_MAP_SHARED;
    target_ulong cursor = start, last = start + len - 1;
    int first = -1;
    assert_memory_lock();
    if (len == 0 || last < start) return false;
    for (;;) {
        PageFlagsNode *p = pageflags_find(cursor, last);
        if (p == NULL || p->itree.start > cursor || !(p->flags & PAGE_VALID)) return false;
        int flags = p->flags & mask;
        int owner = flags & (PAGE_MAP_PRIVATE | PAGE_MAP_SHARED);
        if (owner != PAGE_MAP_PRIVATE && owner != PAGE_MAP_SHARED) return false;
        if (first == -1) first = flags;
        if (first != flags) return false;
        if (p->itree.last >= last) return true;
        cursor = p->itree.last + 1;
    }
}

static bool private_ram_read_verified(int fd, pid_t owner, uint64_t address,
                                      uint8_t *buffer, uint64_t size)
{
    assert_memory_lock();
    while (size) {
        uint64_t chunk = MIN(size, TARGET_PAGE_SIZE - (address & ~TARGET_PAGE_MASK));
        if ((target_ulong)address != address || address > UINT64_MAX - (chunk - 1) ||
            (target_ulong)(address + chunk - 1) != address + chunk - 1) {
            errno = EOVERFLOW;
            return false;
        }
        int flags = page_get_flags(address);
        if (!(flags & PAGE_VALID) ||
            (flags & (PAGE_MAP_PRIVATE | PAGE_MAP_SHARED)) != PAGE_MAP_PRIVATE) {
            errno = EACCES;
            return false;
        }
        uintptr_t host = (uintptr_t)g2h_untagged(address);
        uintptr_t last = (uintptr_t)g2h_untagged(address + chunk - 1);
        if (host > UINTPTR_MAX - (chunk - 1) || last != host + chunk - 1) {
            errno = EOVERFLOW;
            return false;
        }
        if (!qemu_private_ram_pread_owned(fd, owner, host, buffer, chunk)) return false;
        address += chunk;
        buffer += chunk;
        size -= chunk;
    }
    return true;
}

static bool private_ram_collect_locked(GArray *mappings, uint64_t max_bytes,
                                       uint32_t max_mappings, uint64_t *total)
{
    IntervalTreeNode *n;
    assert_memory_lock();
    *total = 0;
    g_array_set_size(mappings, 0);
    if (!mapping_observation_valid || !max_bytes || max_bytes > 64 * 1024 * 1024 ||
        !max_mappings || max_mappings > 4096 ||
        g_array_get_element_size(mappings) != sizeof(qemu_plugin_guest_mapping)) return false;
    for (n = interval_tree_iter_first(&pageflags_root, 0, -1); n != NULL;
         n = interval_tree_iter_next(n, 0, -1)) {
        PageFlagsNode *p = container_of(n, PageFlagsNode, itree);
        if (!(p->flags & PAGE_VALID)) continue;
        if ((p->flags & (PAGE_MAP_PRIVATE | PAGE_MAP_SHARED)) != PAGE_MAP_PRIVATE ||
            (p->flags & PAGE_EXEC_SERVICE) || n->last == UINT64_MAX) return false;
        uint64_t size = (uint64_t)n->last - n->start + 1;
        if (!size || size > max_bytes - *total) return false;
        uintptr_t host = (uintptr_t)g2h_untagged(n->start);
        uintptr_t last_host = (uintptr_t)g2h_untagged(n->last);
        if (host > UINTPTR_MAX - (size - 1) || last_host != host + size - 1 ||
            host > INT64_MAX || size - 1 > INT64_MAX - host) return false;
        uint32_t flags = 8 | 16;
        if (p->flags & PAGE_READ) flags |= 1;
        if (p->flags & PAGE_WRITE_ORG) flags |= 2;
        if (p->flags & PAGE_EXEC) flags |= 4;
        qemu_plugin_guest_mapping *previous = mappings->len ?
            &g_array_index(mappings, qemu_plugin_guest_mapping, mappings->len - 1) : NULL;
        if (previous && previous->start + previous->size == n->start && previous->flags == flags &&
            previous->host_start + previous->size == host) {
            previous->size += size;
        } else {
            if (mappings->len >= max_mappings) return false;
            qemu_plugin_guest_mapping item = { .start = n->start, .size = size,
                .flags = flags, .data_offset = *total, .host_start = host };
            g_array_append_val(mappings, item);
        }
        *total += size;
    }
    return mappings->len != 0 && *total != 0;
}

/* Unlike the existing RAM-only collectors, this atomic-specific view may
 * classify the one explicit synthetic execution service. It remains wholly
 * unbacked and cannot be used by either snapshot or external data readers. */
static bool private_atomic_collect_locked(GArray *mappings, uint64_t max_bytes,
                                          uint32_t max_mappings, uint64_t *total)
{
#if defined(TARGET_X86_64)
    IntervalTreeNode *n;
    assert_memory_lock();
    *total = 0;
    g_array_set_size(mappings, 0);
    if (!mapping_observation_valid || !max_bytes || max_bytes > 64 * 1024 * 1024 ||
        !max_mappings || max_mappings > 4096 ||
        g_array_get_element_size(mappings) != sizeof(qemu_plugin_guest_mapping)) return false;
    for (n = interval_tree_iter_first(&pageflags_root, 0, -1); n != NULL;
         n = interval_tree_iter_next(n, 0, -1)) {
        PageFlagsNode *p = container_of(n, PageFlagsNode, itree);
        qemu_plugin_guest_mapping item = {0};
        uint64_t size;
        if (!(p->flags & PAGE_VALID)) continue;
        if (n->last == UINT64_MAX) return false;
        size = (uint64_t)n->last - n->start + 1;
        if (!size) return false;
        if (p->flags & PAGE_EXEC_SERVICE) {
            if (mappings->len >= max_mappings) return false;
            if (p->flags != (PAGE_EXEC | PAGE_VALID | PAGE_EXEC_SERVICE) ||
                n->start != TARGET_VSYSCALL_PAGE || size != TARGET_PAGE_SIZE) return false;
            item = (qemu_plugin_guest_mapping) { .start = n->start, .size = size,
                .flags = 4 | 8 | 64, .reserved = 1, .data_offset = UINT64_MAX,
                .host_start = 0 };
        } else {
            uintptr_t host, last_host;
            uint32_t flags = 8 | 16;
            if ((p->flags & (PAGE_MAP_PRIVATE | PAGE_MAP_SHARED)) != PAGE_MAP_PRIVATE ||
                size > max_bytes - *total) return false;
            host = (uintptr_t)g2h_untagged(n->start);
            last_host = (uintptr_t)g2h_untagged(n->last);
            if (host > UINTPTR_MAX - (size - 1) || last_host != host + size - 1 ||
                host > INT64_MAX || size - 1 > INT64_MAX - host) return false;
            if (p->flags & PAGE_READ) flags |= 1;
            if (p->flags & PAGE_WRITE_ORG) flags |= 2;
            if (p->flags & PAGE_EXEC) flags |= 4;
            qemu_plugin_guest_mapping *previous = mappings->len ?
                &g_array_index(mappings, qemu_plugin_guest_mapping, mappings->len - 1) : NULL;
            if (previous && previous->reserved == 0 &&
                previous->start + previous->size == n->start && previous->flags == flags &&
                previous->host_start + previous->size == host &&
                previous->data_offset + previous->size == *total) {
                previous->size += size;
            } else {
                if (mappings->len >= max_mappings) return false;
                item = (qemu_plugin_guest_mapping) { .start = n->start, .size = size,
                    .flags = flags, .data_offset = *total, .host_start = host };
                g_array_append_val(mappings, item);
            }
            *total += size;
        }
        if (item.reserved == 1) {
            g_array_append_val(mappings, item);
        }
    }
    return mappings->len != 0 && *total != 0;
#else
    (void)mappings; (void)max_bytes; (void)max_mappings;
    *total = 0;
    return false;
#endif
}

bool qemu_plugin_private_atomic_inventory(GArray *mappings, uint64_t max_bytes,
                                          uint32_t max_mappings, uint64_t *generation)
{
    uint64_t total;
    bool captured;
    g_assert(current_cpu && mappings && generation);
    *generation = 0;
    mmap_lock();
    captured = private_atomic_collect_locked(mappings, max_bytes, max_mappings, &total);
    if (captured) *generation = mapping_observation_generation;
    else g_array_set_size(mappings, 0);
    mmap_unlock();
    return captured;
}

bool qemu_plugin_private_ram_inventory(GArray *mappings, uint64_t max_bytes,
                                      uint32_t max_mappings, uint64_t *generation)
{
    uint64_t total;
    bool captured;
    g_assert(current_cpu && mappings && generation);
    *generation = 0;
    mmap_lock();
    captured = private_ram_collect_locked(mappings, max_bytes, max_mappings, &total);
    if (captured) *generation = mapping_observation_generation;
    else g_array_set_size(mappings, 0);
    mmap_unlock();
    return captured;
}

bool qemu_plugin_private_ram_snapshot(GArray *mappings, GByteArray *memory,
                                     uint64_t max_bytes, uint32_t max_mappings,
                                     uint64_t *generation)
{
    bool success = false;
    uint64_t total = 0, captured_generation = 0;
    pid_t owner = getpid();
    int reader_fd = -1;
    g_assert(current_cpu);
    g_assert(mappings && memory && generation);
    g_array_set_size(mappings, 0);
    g_byte_array_set_size(memory, 0);
    *generation = 0;
    if (max_bytes == 0 || max_bytes > 64 * 1024 * 1024 ||
        max_mappings == 0 || max_mappings > 4096 ||
        g_array_get_element_size(mappings) != sizeof(qemu_plugin_guest_mapping)) return false;
    mmap_lock();
    if (!private_ram_collect_locked(mappings, max_bytes, max_mappings, &total)) goto out;
    captured_generation = mapping_observation_generation;
    reader_fd = qemu_private_ram_open_owned(owner);
    if (reader_fd < 0) {
        qemu_log_mask(CPU_LOG_PAGE, "private RAM unavailable: owned observer fd errno=%d (%s)\n", errno, strerror(errno));
        goto out;
    }
    g_byte_array_set_size(memory, total);
    for (guint i = 0; i < mappings->len; i++) {
        qemu_plugin_guest_mapping *item = &g_array_index(mappings, qemu_plugin_guest_mapping, i);
        /* Linux owned-process observer reads never alter guest/host protections.
         * Revalidate each page and g2h translation, even for PROT_NONE ranges. */
        if (!private_ram_read_verified(reader_fd, owner, item->start,
                                       memory->data + item->data_offset, item->size)) {
            qemu_log_mask(CPU_LOG_PAGE, "private RAM unavailable: observer read start=%" PRIx64 " size=%" PRIu64 " flags=%x errno=%d (%s)\n",
                          item->start, item->size, item->flags, errno, strerror(errno));
            if (qemu_loglevel_mask(CPU_LOG_PAGE)) {
                FILE *diagnostic = qemu_log_trylock();
                if (diagnostic) {
                    uintptr_t host = (uintptr_t)g2h_untagged(item->start);
                    fprintf(diagnostic, "HOST_DIAGNOSTIC_ONLY guest=%" PRIx64 " host=%" PRIxPTR " generation=%" PRIu64 "\n",
                            item->start, host, captured_generation);
                    qemu_private_ram_diagnose_host(owner, host, item->size, diagnostic);
                    qemu_log_unlock(diagnostic);
                }
            }
            goto out;
        }
    }
    if (!mapping_observation_valid || owner != getpid() ||
        captured_generation != mapping_observation_generation ||
        !qemu_private_ram_fd_is_owned(reader_fd, owner)) goto out;
    *generation = captured_generation;
    success = true;
out:
    if (reader_fd >= 0) {
        int saved = errno;
        close(reader_fd);
        errno = saved;
    }
    if (!success) {
        g_array_set_size(mappings, 0);
        g_byte_array_set_size(memory, 0);
    }
    mmap_unlock();
    return success;
}

int walk_memory_regions(void *priv, walk_memory_regions_fn fn)
{
    IntervalTreeNode *n;
    int rc = 0;

    mmap_lock();
    for (n = interval_tree_iter_first(&pageflags_root, 0, -1);
         n != NULL;
         n = interval_tree_iter_next(n, 0, -1)) {
        PageFlagsNode *p = container_of(n, PageFlagsNode, itree);

        rc = fn(priv, n->start, n->last + 1, p->flags);
        if (rc != 0) {
            break;
        }
    }
    mmap_unlock();

    return rc;
}

static int dump_region(void *priv, target_ulong start,
                       target_ulong end, unsigned long prot)
{
    FILE *f = (FILE *)priv;

    fprintf(f, TARGET_FMT_lx"-"TARGET_FMT_lx" "TARGET_FMT_lx" %c%c%c\n",
            start, end, end - start,
            ((prot & PAGE_READ) ? 'r' : '-'),
            ((prot & PAGE_WRITE) ? 'w' : '-'),
            ((prot & PAGE_EXEC) ? 'x' : '-'));
    return 0;
}

/* dump memory mappings */
void page_dump(FILE *f)
{
    const int length = sizeof(target_ulong) * 2;

    fprintf(f, "%-*s %-*s %-*s %s\n",
            length, "start", length, "end", length, "size", "prot");
    walk_memory_regions(f, dump_region);
}

uint32_t qemu_plugin_memory_permissions_vaddr(uint64_t addr, size_t len)
{
    uint32_t result = 15;
    bool locked = have_mmap_lock();
    uint64_t last;

    g_assert(current_cpu);
    if (len == 0 || len > 65536 || addr > UINT64_MAX - (len - 1)) {
        return UINT32_MAX;
    }
    last = addr + len - 1;
    if ((target_ulong)addr != addr || (target_ulong)last != last) {
        return UINT32_MAX;
    }
    if (!locked) {
        mmap_lock();
    }
    for (uint64_t cursor = addr;;) {
        int flags = page_get_flags((target_ulong)cursor);
        uint32_t permissions = 0;
        if (flags & PAGE_VALID) {
            permissions = 8;
            if (flags & PAGE_READ) {
                permissions |= 1;
            }
            if (flags & PAGE_WRITE_ORG) {
                permissions |= 2;
            }
            if (flags & PAGE_EXEC) {
                permissions |= 4;
            }
        }
        result &= permissions;
        uint64_t page_last = cursor | (TARGET_PAGE_SIZE - 1);
        if (page_last >= last) {
            break;
        }
        cursor = page_last + 1;
    }
    if (!locked) {
        mmap_unlock();
    }
    return result;
}

int page_get_flags(target_ulong address)
{
    PageFlagsNode *p = pageflags_find(address, address);

    /*
     * See util/interval-tree.c re lockless lookups: no false positives but
     * there are false negatives.  If we find nothing, retry with the mmap
     * lock acquired.
     */
    if (p) {
        return p->flags;
    }
    if (have_mmap_lock()) {
        return 0;
    }

    mmap_lock();
    p = pageflags_find(address, address);
    mmap_unlock();
    return p ? p->flags : 0;
}

/* A subroutine of page_set_flags: insert a new node for [start,last]. */
static void pageflags_create(target_ulong start, target_ulong last, int flags)
{
    PageFlagsNode *p = g_new(PageFlagsNode, 1);

    p->itree.start = start;
    p->itree.last = last;
    p->flags = flags;
    interval_tree_insert(&p->itree, &pageflags_root);
}

/* A subroutine of page_set_flags: remove everything in [start,last]. */
static bool pageflags_unset(target_ulong start, target_ulong last)
{
    bool inval_tb = false;

    while (true) {
        PageFlagsNode *p = pageflags_find(start, last);
        target_ulong p_last;

        if (!p) {
            break;
        }

        if (p->flags & PAGE_EXEC) {
            inval_tb = true;
        }

        interval_tree_remove(&p->itree, &pageflags_root);
        p_last = p->itree.last;

        if (p->itree.start < start) {
            /* Truncate the node from the end, or split out the middle. */
            p->itree.last = start - 1;
            interval_tree_insert(&p->itree, &pageflags_root);
            if (last < p_last) {
                pageflags_create(last + 1, p_last, p->flags);
                break;
            }
        } else if (p_last <= last) {
            /* Range completely covers node -- remove it. */
            g_free_rcu(p, rcu);
        } else {
            /* Truncate the node from the start. */
            p->itree.start = last + 1;
            interval_tree_insert(&p->itree, &pageflags_root);
            break;
        }
    }

    return inval_tb;
}

/*
 * A subroutine of page_set_flags: nothing overlaps [start,last],
 * but check adjacent mappings and maybe merge into a single range.
 */
static void pageflags_create_merge(target_ulong start, target_ulong last,
                                   int flags)
{
    PageFlagsNode *next = NULL, *prev = NULL;

    if (start > 0) {
        prev = pageflags_find(start - 1, start - 1);
        if (prev) {
            if (prev->flags == flags) {
                interval_tree_remove(&prev->itree, &pageflags_root);
            } else {
                prev = NULL;
            }
        }
    }
    if (last + 1 != 0) {
        next = pageflags_find(last + 1, last + 1);
        if (next) {
            if (next->flags == flags) {
                interval_tree_remove(&next->itree, &pageflags_root);
            } else {
                next = NULL;
            }
        }
    }

    if (prev) {
        if (next) {
            prev->itree.last = next->itree.last;
            g_free_rcu(next, rcu);
        } else {
            prev->itree.last = last;
        }
        interval_tree_insert(&prev->itree, &pageflags_root);
    } else if (next) {
        next->itree.start = start;
        interval_tree_insert(&next->itree, &pageflags_root);
    } else {
        pageflags_create(start, last, flags);
    }
}

/*
 * Allow the target to decide if PAGE_TARGET_[12] may be reset.
 * By default, they are not kept.
 */
#ifndef PAGE_TARGET_STICKY
#define PAGE_TARGET_STICKY  0
#endif
#define PAGE_STICKY  (PAGE_ANON | PAGE_PASSTHROUGH | PAGE_TARGET_STICKY | \
                     PAGE_MAP_PRIVATE | PAGE_MAP_SHARED)

/* A subroutine of page_set_flags: add flags to [start,last]. */
static bool pageflags_set_clear(target_ulong start, target_ulong last,
                                int set_flags, int clear_flags)
{
    PageFlagsNode *p;
    target_ulong p_start, p_last;
    int p_flags, merge_flags;
    bool inval_tb = false;

 restart:
    p = pageflags_find(start, last);
    if (!p) {
        if (set_flags) {
            pageflags_create_merge(start, last, set_flags);
        }
        goto done;
    }

    p_start = p->itree.start;
    p_last = p->itree.last;
    p_flags = p->flags;
    /* Using mprotect on a page does not change sticky bits. */
    merge_flags = (p_flags & ~clear_flags) | set_flags;

    /*
     * Need to flush if an overlapping executable region
     * removes exec, or adds write.
     */
    if ((p_flags & PAGE_EXEC)
        && (!(merge_flags & PAGE_EXEC)
            || (merge_flags & ~p_flags & PAGE_WRITE))) {
        inval_tb = true;
    }

    /*
     * If there is an exact range match, update and return without
     * attempting to merge with adjacent regions.
     */
    if (start == p_start && last == p_last) {
        if (merge_flags) {
            p->flags = merge_flags;
        } else {
            interval_tree_remove(&p->itree, &pageflags_root);
            g_free_rcu(p, rcu);
        }
        goto done;
    }

    /*
     * If sticky bits affect the original mapping, then we must be more
     * careful about the existing intervals and the separate flags.
     */
    if (set_flags != merge_flags) {
        if (p_start < start) {
            interval_tree_remove(&p->itree, &pageflags_root);
            p->itree.last = start - 1;
            interval_tree_insert(&p->itree, &pageflags_root);

            if (last < p_last) {
                if (merge_flags) {
                    pageflags_create(start, last, merge_flags);
                }
                pageflags_create(last + 1, p_last, p_flags);
            } else {
                if (merge_flags) {
                    pageflags_create(start, p_last, merge_flags);
                }
                if (p_last < last) {
                    start = p_last + 1;
                    goto restart;
                }
            }
        } else {
            if (start < p_start && set_flags) {
                pageflags_create(start, p_start - 1, set_flags);
            }
            if (last < p_last) {
                interval_tree_remove(&p->itree, &pageflags_root);
                p->itree.start = last + 1;
                interval_tree_insert(&p->itree, &pageflags_root);
                if (merge_flags) {
                    pageflags_create(start, last, merge_flags);
                }
            } else {
                if (merge_flags) {
                    p->flags = merge_flags;
                } else {
                    interval_tree_remove(&p->itree, &pageflags_root);
                    g_free_rcu(p, rcu);
                }
                if (p_last < last) {
                    start = p_last + 1;
                    goto restart;
                }
            }
        }
        goto done;
    }

    /* If flags are not changing for this range, incorporate it. */
    if (set_flags == p_flags) {
        if (start < p_start) {
            interval_tree_remove(&p->itree, &pageflags_root);
            p->itree.start = start;
            interval_tree_insert(&p->itree, &pageflags_root);
        }
        if (p_last < last) {
            start = p_last + 1;
            goto restart;
        }
        goto done;
    }

    /* Maybe split out head and/or tail ranges with the original flags. */
    interval_tree_remove(&p->itree, &pageflags_root);
    if (p_start < start) {
        p->itree.last = start - 1;
        interval_tree_insert(&p->itree, &pageflags_root);

        if (p_last < last) {
            goto restart;
        }
        if (last < p_last) {
            pageflags_create(last + 1, p_last, p_flags);
        }
    } else if (last < p_last) {
        p->itree.start = last + 1;
        interval_tree_insert(&p->itree, &pageflags_root);
    } else {
        g_free_rcu(p, rcu);
        goto restart;
    }
    if (set_flags) {
        pageflags_create(start, last, set_flags);
    }

 done:
    return inval_tb;
}

void page_set_flags(target_ulong start, target_ulong last, int flags)
{
    bool reset = false;
    bool inval_tb = false;

    /* This function should never be called with addresses outside the
       guest address space.  If this assert fires, it probably indicates
       a missing call to h2g_valid.  */
    assert(start <= last);
    assert(last <= GUEST_ADDR_MAX);
    /* Only set PAGE_ANON with new mappings. */
    assert(!(flags & PAGE_ANON) || (flags & PAGE_RESET));
    assert_memory_lock();
    mapping_observation_changed();

    start &= TARGET_PAGE_MASK;
    last |= ~TARGET_PAGE_MASK;

    if (!(flags & PAGE_VALID)) {
        flags = 0;
    } else {
        reset = flags & PAGE_RESET;
        flags &= ~PAGE_RESET;
        if (flags & PAGE_WRITE) {
            flags |= PAGE_WRITE_ORG;
        }
    }

    if (!flags || reset) {
        page_reset_target_data(start, last);
        inval_tb |= pageflags_unset(start, last);
    }
    if (flags) {
        inval_tb |= pageflags_set_clear(start, last, flags,
                                        ~(reset ? 0 : PAGE_STICKY));
    }
    if (inval_tb) {
        tb_invalidate_phys_range(start, last);
    }
}

bool page_check_range(target_ulong start, target_ulong len, int flags)
{
    target_ulong last;
    int locked;  /* tri-state: =0: unlocked, +1: global, -1: local */
    bool ret;

    if (len == 0) {
        return true;  /* trivial length */
    }

    last = start + len - 1;
    if (last < start) {
        return false; /* wrap around */
    }

    locked = have_mmap_lock();
    while (true) {
        PageFlagsNode *p = pageflags_find(start, last);
        int missing;

        if (!p) {
            if (!locked) {
                /*
                 * Lockless lookups have false negatives.
                 * Retry with the lock held.
                 */
                mmap_lock();
                locked = -1;
                p = pageflags_find(start, last);
            }
            if (!p) {
                ret = false; /* entire region invalid */
                break;
            }
        }
        if (start < p->itree.start) {
            ret = false; /* initial bytes invalid */
            break;
        }

        missing = flags & ~p->flags;
        if (missing & ~PAGE_WRITE) {
            ret = false; /* page doesn't match */
            break;
        }
        if (missing & PAGE_WRITE) {
            if (!(p->flags & PAGE_WRITE_ORG)) {
                ret = false; /* page not writable */
                break;
            }
            /* Asking about writable, but has been protected: undo. */
            if (!page_unprotect(start, 0)) {
                ret = false;
                break;
            }
            /* TODO: page_unprotect should take a range, not a single page. */
            if (last - start < TARGET_PAGE_SIZE) {
                ret = true; /* ok */
                break;
            }
            start += TARGET_PAGE_SIZE;
            continue;
        }

        if (last <= p->itree.last) {
            ret = true; /* ok */
            break;
        }
        start = p->itree.last + 1;
    }

    /* Release the lock if acquired locally. */
    if (locked < 0) {
        mmap_unlock();
    }
    return ret;
}

bool page_check_range_empty(target_ulong start, target_ulong last)
{
    assert(last >= start);
    assert_memory_lock();
    return pageflags_find(start, last) == NULL;
}

target_ulong page_find_range_empty(target_ulong min, target_ulong max,
                                   target_ulong len, target_ulong align)
{
    target_ulong len_m1, align_m1;

    assert(min <= max);
    assert(max <= GUEST_ADDR_MAX);
    assert(len != 0);
    assert(is_power_of_2(align));
    assert_memory_lock();

    len_m1 = len - 1;
    align_m1 = align - 1;

    /* Iteratively narrow the search region. */
    while (1) {
        PageFlagsNode *p;

        /* Align min and double-check there's enough space remaining. */
        min = (min + align_m1) & ~align_m1;
        if (min > max) {
            return -1;
        }
        if (len_m1 > max - min) {
            return -1;
        }

        p = pageflags_find(min, min + len_m1);
        if (p == NULL) {
            /* Found! */
            return min;
        }
        if (max <= p->itree.last) {
            /* Existing allocation fills the remainder of the search region. */
            return -1;
        }
        /* Skip across existing allocation. */
        min = p->itree.last + 1;
    }
}

void page_protect(tb_page_addr_t address)
{
    PageFlagsNode *p;
    target_ulong start, last;
    int host_page_size = qemu_real_host_page_size();
    int prot;

    assert_memory_lock();

    if (host_page_size <= TARGET_PAGE_SIZE) {
        start = address & TARGET_PAGE_MASK;
        last = start + TARGET_PAGE_SIZE - 1;
    } else {
        start = address & -host_page_size;
        last = start + host_page_size - 1;
    }

    p = pageflags_find(start, last);
    if (!p) {
        return;
    }
    prot = p->flags;

    if (unlikely(p->itree.last < last)) {
        /* More than one protection region covers the one host page. */
        assert(TARGET_PAGE_SIZE < host_page_size);
        while ((p = pageflags_next(p, start, last)) != NULL) {
            prot |= p->flags;
        }
    }

    if (prot & PAGE_WRITE) {
        pageflags_set_clear(start, last, 0, PAGE_WRITE);
        mprotect(g2h_untagged(start), last - start + 1,
                 prot & (PAGE_READ | PAGE_EXEC) ? PROT_READ : PROT_NONE);
    }
}

/*
 * Called from signal handler: invalidate the code and unprotect the
 * page. Return 0 if the fault was not handled, 1 if it was handled,
 * and 2 if it was handled but the caller must cause the TB to be
 * immediately exited. (We can only return 2 if the 'pc' argument is
 * non-zero.)
 */
int page_unprotect(tb_page_addr_t address, uintptr_t pc)
{
    PageFlagsNode *p;
    bool current_tb_invalidated;

    /*
     * Technically this isn't safe inside a signal handler.  However we
     * know this only ever happens in a synchronous SEGV handler, so in
     * practice it seems to be ok.
     */
    mmap_lock();

    p = pageflags_find(address, address);

    /* If this address was not really writable, nothing to do. */
    if (!p || !(p->flags & PAGE_WRITE_ORG)) {
        mmap_unlock();
        return 0;
    }

    current_tb_invalidated = false;
    if (p->flags & PAGE_WRITE) {
        /*
         * If the page is actually marked WRITE then assume this is because
         * this thread raced with another one which got here first and
         * set the page to PAGE_WRITE and did the TB invalidate for us.
         */
#ifdef TARGET_HAS_PRECISE_SMC
        TranslationBlock *current_tb = tcg_tb_lookup(pc);
        if (current_tb) {
            current_tb_invalidated = tb_cflags(current_tb) & CF_INVALID;
        }
#endif
    } else {
        int host_page_size = qemu_real_host_page_size();
        target_ulong start, len, i;
        int prot;

        if (host_page_size <= TARGET_PAGE_SIZE) {
            start = address & TARGET_PAGE_MASK;
            len = TARGET_PAGE_SIZE;
            prot = p->flags | PAGE_WRITE;
            pageflags_set_clear(start, start + len - 1, PAGE_WRITE, 0);
            current_tb_invalidated = tb_invalidate_phys_page_unwind(start, pc);
        } else {
            start = address & -host_page_size;
            len = host_page_size;
            prot = 0;

            for (i = 0; i < len; i += TARGET_PAGE_SIZE) {
                target_ulong addr = start + i;

                p = pageflags_find(addr, addr);
                if (p) {
                    prot |= p->flags;
                    if (p->flags & PAGE_WRITE_ORG) {
                        prot |= PAGE_WRITE;
                        pageflags_set_clear(addr, addr + TARGET_PAGE_SIZE - 1,
                                            PAGE_WRITE, 0);
                    }
                }
                /*
                 * Since the content will be modified, we must invalidate
                 * the corresponding translated code.
                 */
                current_tb_invalidated |=
                    tb_invalidate_phys_page_unwind(addr, pc);
            }
        }
        if (prot & PAGE_EXEC) {
            prot = (prot & ~PAGE_EXEC) | PAGE_READ;
        }
        mprotect((void *)g2h_untagged(start), len, prot & PAGE_RWX);
    }
    mmap_unlock();

    /* If current TB was invalidated return to main loop */
    return current_tb_invalidated ? 2 : 1;
}

static int probe_access_internal(CPUArchState *env, vaddr addr,
                                 int fault_size, MMUAccessType access_type,
                                 bool nonfault, uintptr_t ra)
{
    int acc_flag;
    bool maperr;

    switch (access_type) {
    case MMU_DATA_STORE:
        acc_flag = PAGE_WRITE_ORG;
        break;
    case MMU_DATA_LOAD:
        acc_flag = PAGE_READ;
        break;
    case MMU_INST_FETCH:
        acc_flag = PAGE_EXEC;
        break;
    default:
        g_assert_not_reached();
    }

    if (guest_addr_valid_untagged(addr)) {
        int page_flags = page_get_flags(addr);
        if (page_flags & acc_flag) {
            if (access_type != MMU_INST_FETCH
                && cpu_plugin_mem_cbs_enabled(env_cpu(env))) {
                return TLB_MMIO;
            }
            return 0; /* success */
        }
        maperr = !(page_flags & PAGE_VALID);
    } else {
        maperr = true;
    }

    if (nonfault) {
        return TLB_INVALID_MASK;
    }

    cpu_loop_exit_sigsegv(env_cpu(env), addr, access_type, maperr, ra);
}

int probe_access_flags(CPUArchState *env, vaddr addr, int size,
                       MMUAccessType access_type, int mmu_idx,
                       bool nonfault, void **phost, uintptr_t ra)
{
    int flags;

    g_assert(-(addr | TARGET_PAGE_MASK) >= size);
    flags = probe_access_internal(env, addr, size, access_type, nonfault, ra);
    *phost = (flags & TLB_INVALID_MASK) ? NULL : g2h(env_cpu(env), addr);
    return flags;
}

void *probe_access(CPUArchState *env, vaddr addr, int size,
                   MMUAccessType access_type, int mmu_idx, uintptr_t ra)
{
    int flags;

    g_assert(-(addr | TARGET_PAGE_MASK) >= size);
    flags = probe_access_internal(env, addr, size, access_type, false, ra);
    g_assert((flags & ~TLB_MMIO) == 0);

    return size ? g2h(env_cpu(env), addr) : NULL;
}

tb_page_addr_t get_page_addr_code_hostp(CPUArchState *env, vaddr addr,
                                        void **hostp)
{
    int flags;

    flags = probe_access_internal(env, addr, 1, MMU_INST_FETCH, false, 0);
    g_assert(flags == 0);

    if (hostp) {
        *hostp = g2h_untagged(addr);
    }
    return addr;
}

#ifdef TARGET_PAGE_DATA_SIZE
/*
 * Allocate chunks of target data together.  For the only current user,
 * if we allocate one hunk per page, we have overhead of 40/128 or 40%.
 * Therefore, allocate memory for 64 pages at a time for overhead < 1%.
 */
#define TPD_PAGES  64
#define TBD_MASK   (TARGET_PAGE_MASK * TPD_PAGES)

typedef struct TargetPageDataNode {
    struct rcu_head rcu;
    IntervalTreeNode itree;
    char data[] __attribute__((aligned));
} TargetPageDataNode;

static IntervalTreeRoot targetdata_root;

void page_reset_target_data(target_ulong start, target_ulong last)
{
    IntervalTreeNode *n, *next;

    assert_memory_lock();

    start &= TARGET_PAGE_MASK;
    last |= ~TARGET_PAGE_MASK;

    for (n = interval_tree_iter_first(&targetdata_root, start, last),
         next = n ? interval_tree_iter_next(n, start, last) : NULL;
         n != NULL;
         n = next,
         next = next ? interval_tree_iter_next(n, start, last) : NULL) {
        target_ulong n_start, n_last, p_ofs, p_len;
        TargetPageDataNode *t = container_of(n, TargetPageDataNode, itree);

        if (n->start >= start && n->last <= last) {
            interval_tree_remove(n, &targetdata_root);
            g_free_rcu(t, rcu);
            continue;
        }

        if (n->start < start) {
            n_start = start;
            p_ofs = (start - n->start) >> TARGET_PAGE_BITS;
        } else {
            n_start = n->start;
            p_ofs = 0;
        }
        n_last = MIN(last, n->last);
        p_len = (n_last + 1 - n_start) >> TARGET_PAGE_BITS;

        memset(t->data + p_ofs * TARGET_PAGE_DATA_SIZE, 0,
               p_len * TARGET_PAGE_DATA_SIZE);
    }
}

void *page_get_target_data(target_ulong address)
{
    IntervalTreeNode *n;
    TargetPageDataNode *t;
    target_ulong page, region, p_ofs;

    page = address & TARGET_PAGE_MASK;
    region = address & TBD_MASK;

    n = interval_tree_iter_first(&targetdata_root, page, page);
    if (!n) {
        /*
         * See util/interval-tree.c re lockless lookups: no false positives
         * but there are false negatives.  If we find nothing, retry with
         * the mmap lock acquired.  We also need the lock for the
         * allocation + insert.
         */
        mmap_lock();
        n = interval_tree_iter_first(&targetdata_root, page, page);
        if (!n) {
            t = g_malloc0(sizeof(TargetPageDataNode)
                          + TPD_PAGES * TARGET_PAGE_DATA_SIZE);
            n = &t->itree;
            n->start = region;
            n->last = region | ~TBD_MASK;
            interval_tree_insert(n, &targetdata_root);
        }
        mmap_unlock();
    }

    t = container_of(n, TargetPageDataNode, itree);
    p_ofs = (page - region) >> TARGET_PAGE_BITS;
    return t->data + p_ofs * TARGET_PAGE_DATA_SIZE;
}
#else
void page_reset_target_data(target_ulong start, target_ulong last) { }
#endif /* TARGET_PAGE_DATA_SIZE */

/* The system-mode versions of these helpers are in cputlb.c.  */

static void *cpu_mmu_lookup(CPUState *cpu, vaddr addr,
                            MemOp mop, uintptr_t ra, MMUAccessType type)
{
    int a_bits = memop_alignment_bits(mop);
    void *ret;

    /* Enforce guest required alignment.  */
    if (unlikely(addr & ((1 << a_bits) - 1))) {
        cpu_loop_exit_sigbus(cpu, addr, type, ra);
    }

    ret = g2h(cpu, addr);
    set_helper_retaddr(ra);
    return ret;
}

/* physical memory access (slow version, mainly for debug) */
int cpu_memory_rw_debug(CPUState *cpu, vaddr addr,
                        void *ptr, size_t len, bool is_write)
{
    int flags;
    vaddr l, page;
    uint8_t *buf = ptr;
    ssize_t written;
    int ret = -1;
    int fd = -1;

    mmap_lock();

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len) {
            l = len;
        }
        flags = page_get_flags(page);
        if (!(flags & PAGE_VALID)) {
            goto out_close;
        }
        if (is_write) {
            if (flags & PAGE_WRITE) {
                memcpy(g2h(cpu, addr), buf, l);
            } else {
                /* Bypass the host page protection using ptrace. */
                if (fd == -1) {
                    fd = open("/proc/self/mem", O_WRONLY);
                    if (fd == -1) {
                        goto out;
                    }
                }
                /*
                 * If there is a TranslationBlock and we weren't bypassing the
                 * host page protection, the memcpy() above would SEGV,
                 * ultimately leading to page_unprotect(). So invalidate the
                 * translations manually. Both invalidation and pwrite() must
                 * be under mmap_lock() in order to prevent the creation of
                 * another TranslationBlock in between.
                 */
                tb_invalidate_phys_range(addr, addr + l - 1);
                written = pwrite(fd, buf, l,
                                 (off_t)(uintptr_t)g2h_untagged(addr));
                if (written != l) {
                    goto out_close;
                }
            }
        } else if (flags & PAGE_READ) {
            memcpy(buf, g2h(cpu, addr), l);
        } else {
            /* Bypass the host page protection using ptrace. */
            if (fd == -1) {
                fd = open("/proc/self/mem", O_RDONLY);
                if (fd == -1) {
                    goto out;
                }
            }
            if (pread(fd, buf, l,
                      (off_t)(uintptr_t)g2h_untagged(addr)) != l) {
                goto out_close;
            }
        }
        len -= l;
        buf += l;
        addr += l;
    }
    ret = 0;
out_close:
    if (fd != -1) {
        close(fd);
    }
out:
    mmap_unlock();

    return ret;
}

#include "ldst_atomicity.c.inc"

static uint8_t do_ld1_mmu(CPUState *cpu, vaddr addr, MemOpIdx oi,
                          uintptr_t ra, MMUAccessType access_type)
{
    void *haddr;
    uint8_t ret;

    cpu_req_mo(TCG_MO_LD_LD | TCG_MO_ST_LD);
    haddr = cpu_mmu_lookup(cpu, addr, get_memop(oi), ra, access_type);
    ret = ldub_p(haddr);
    clear_helper_retaddr();
    return ret;
}

static uint16_t do_ld2_mmu(CPUState *cpu, vaddr addr, MemOpIdx oi,
                           uintptr_t ra, MMUAccessType access_type)
{
    void *haddr;
    uint16_t ret;
    MemOp mop = get_memop(oi);

    cpu_req_mo(TCG_MO_LD_LD | TCG_MO_ST_LD);
    haddr = cpu_mmu_lookup(cpu, addr, mop, ra, access_type);
    ret = load_atom_2(cpu, ra, haddr, mop);
    clear_helper_retaddr();

    if (mop & MO_BSWAP) {
        ret = bswap16(ret);
    }
    return ret;
}

static uint32_t do_ld4_mmu(CPUState *cpu, vaddr addr, MemOpIdx oi,
                           uintptr_t ra, MMUAccessType access_type)
{
    void *haddr;
    uint32_t ret;
    MemOp mop = get_memop(oi);

    cpu_req_mo(TCG_MO_LD_LD | TCG_MO_ST_LD);
    haddr = cpu_mmu_lookup(cpu, addr, mop, ra, access_type);
    ret = load_atom_4(cpu, ra, haddr, mop);
    clear_helper_retaddr();

    if (mop & MO_BSWAP) {
        ret = bswap32(ret);
    }
    return ret;
}

static uint64_t do_ld8_mmu(CPUState *cpu, vaddr addr, MemOpIdx oi,
                           uintptr_t ra, MMUAccessType access_type)
{
    void *haddr;
    uint64_t ret;
    MemOp mop = get_memop(oi);

    cpu_req_mo(TCG_MO_LD_LD | TCG_MO_ST_LD);
    haddr = cpu_mmu_lookup(cpu, addr, mop, ra, access_type);
    ret = load_atom_8(cpu, ra, haddr, mop);
    clear_helper_retaddr();

    if (mop & MO_BSWAP) {
        ret = bswap64(ret);
    }
    return ret;
}

static Int128 do_ld16_mmu(CPUState *cpu, abi_ptr addr,
                          MemOpIdx oi, uintptr_t ra)
{
    void *haddr;
    Int128 ret;
    MemOp mop = get_memop(oi);

    tcg_debug_assert((mop & MO_SIZE) == MO_128);
    cpu_req_mo(TCG_MO_LD_LD | TCG_MO_ST_LD);
    haddr = cpu_mmu_lookup(cpu, addr, mop, ra, MMU_DATA_LOAD);
    ret = load_atom_16(cpu, ra, haddr, mop);
    clear_helper_retaddr();

    if (mop & MO_BSWAP) {
        ret = bswap128(ret);
    }
    return ret;
}

static void do_st1_mmu(CPUState *cpu, vaddr addr, uint8_t val,
                       MemOpIdx oi, uintptr_t ra)
{
    void *haddr;

    cpu_req_mo(TCG_MO_LD_ST | TCG_MO_ST_ST);
    haddr = cpu_mmu_lookup(cpu, addr, get_memop(oi), ra, MMU_DATA_STORE);
    stb_p(haddr, val);
    clear_helper_retaddr();
}

static void do_st2_mmu(CPUState *cpu, vaddr addr, uint16_t val,
                       MemOpIdx oi, uintptr_t ra)
{
    void *haddr;
    MemOp mop = get_memop(oi);

    cpu_req_mo(TCG_MO_LD_ST | TCG_MO_ST_ST);
    haddr = cpu_mmu_lookup(cpu, addr, mop, ra, MMU_DATA_STORE);

    if (mop & MO_BSWAP) {
        val = bswap16(val);
    }
    store_atom_2(cpu, ra, haddr, mop, val);
    clear_helper_retaddr();
}

static void do_st4_mmu(CPUState *cpu, vaddr addr, uint32_t val,
                       MemOpIdx oi, uintptr_t ra)
{
    void *haddr;
    MemOp mop = get_memop(oi);

    cpu_req_mo(TCG_MO_LD_ST | TCG_MO_ST_ST);
    haddr = cpu_mmu_lookup(cpu, addr, mop, ra, MMU_DATA_STORE);

    if (mop & MO_BSWAP) {
        val = bswap32(val);
    }
    store_atom_4(cpu, ra, haddr, mop, val);
    clear_helper_retaddr();
}

static void do_st8_mmu(CPUState *cpu, vaddr addr, uint64_t val,
                       MemOpIdx oi, uintptr_t ra)
{
    void *haddr;
    MemOp mop = get_memop(oi);

    cpu_req_mo(TCG_MO_LD_ST | TCG_MO_ST_ST);
    haddr = cpu_mmu_lookup(cpu, addr, mop, ra, MMU_DATA_STORE);

    if (mop & MO_BSWAP) {
        val = bswap64(val);
    }
    store_atom_8(cpu, ra, haddr, mop, val);
    clear_helper_retaddr();
}

static void do_st16_mmu(CPUState *cpu, vaddr addr, Int128 val,
                        MemOpIdx oi, uintptr_t ra)
{
    void *haddr;
    MemOpIdx mop = get_memop(oi);

    cpu_req_mo(TCG_MO_LD_ST | TCG_MO_ST_ST);
    haddr = cpu_mmu_lookup(cpu, addr, mop, ra, MMU_DATA_STORE);

    if (mop & MO_BSWAP) {
        val = bswap128(val);
    }
    store_atom_16(cpu, ra, haddr, mop, val);
    clear_helper_retaddr();
}

uint32_t cpu_ldub_code(CPUArchState *env, abi_ptr ptr)
{
    uint32_t ret;

    set_helper_retaddr(1);
    ret = ldub_p(g2h_untagged(ptr));
    clear_helper_retaddr();
    return ret;
}

uint32_t cpu_lduw_code(CPUArchState *env, abi_ptr ptr)
{
    uint32_t ret;

    set_helper_retaddr(1);
    ret = lduw_p(g2h_untagged(ptr));
    clear_helper_retaddr();
    return ret;
}

uint32_t cpu_ldl_code(CPUArchState *env, abi_ptr ptr)
{
    uint32_t ret;

    set_helper_retaddr(1);
    ret = ldl_p(g2h_untagged(ptr));
    clear_helper_retaddr();
    return ret;
}

uint64_t cpu_ldq_code(CPUArchState *env, abi_ptr ptr)
{
    uint64_t ret;

    set_helper_retaddr(1);
    ret = ldq_p(g2h_untagged(ptr));
    clear_helper_retaddr();
    return ret;
}

uint8_t cpu_ldb_code_mmu(CPUArchState *env, abi_ptr addr,
                         MemOpIdx oi, uintptr_t ra)
{
    void *haddr;
    uint8_t ret;

    haddr = cpu_mmu_lookup(env_cpu(env), addr, oi, ra, MMU_INST_FETCH);
    ret = ldub_p(haddr);
    clear_helper_retaddr();
    return ret;
}

uint16_t cpu_ldw_code_mmu(CPUArchState *env, abi_ptr addr,
                          MemOpIdx oi, uintptr_t ra)
{
    void *haddr;
    uint16_t ret;

    haddr = cpu_mmu_lookup(env_cpu(env), addr, oi, ra, MMU_INST_FETCH);
    ret = lduw_p(haddr);
    clear_helper_retaddr();
    if (get_memop(oi) & MO_BSWAP) {
        ret = bswap16(ret);
    }
    return ret;
}

uint32_t cpu_ldl_code_mmu(CPUArchState *env, abi_ptr addr,
                          MemOpIdx oi, uintptr_t ra)
{
    void *haddr;
    uint32_t ret;

    haddr = cpu_mmu_lookup(env_cpu(env), addr, oi, ra, MMU_INST_FETCH);
    ret = ldl_p(haddr);
    clear_helper_retaddr();
    if (get_memop(oi) & MO_BSWAP) {
        ret = bswap32(ret);
    }
    return ret;
}

uint64_t cpu_ldq_code_mmu(CPUArchState *env, abi_ptr addr,
                          MemOpIdx oi, uintptr_t ra)
{
    void *haddr;
    uint64_t ret;

    haddr = cpu_mmu_lookup(env_cpu(env), addr, oi, ra, MMU_DATA_LOAD);
    ret = ldq_p(haddr);
    clear_helper_retaddr();
    if (get_memop(oi) & MO_BSWAP) {
        ret = bswap64(ret);
    }
    return ret;
}

#include "ldst_common.c.inc"

/*
 * Do not allow unaligned operations to proceed.  Return the host address.
 */
static void *atomic_mmu_lookup(CPUState *cpu, vaddr addr, MemOpIdx oi,
                               int size, uintptr_t retaddr)
{
    MemOp mop = get_memop(oi);
    int a_bits = memop_alignment_bits(mop);
    void *ret;

    /* Enforce guest required alignment.  */
    if (unlikely(addr & ((1 << a_bits) - 1))) {
        cpu_loop_exit_sigbus(cpu, addr, MMU_DATA_STORE, retaddr);
    }

    /* Enforce qemu required alignment.  */
    if (unlikely(addr & (size - 1))) {
        cpu_loop_exit_atomic(cpu, retaddr);
    }

    ret = g2h(cpu, addr);
    set_helper_retaddr(retaddr);
    return ret;
}

#include "atomic_common.c.inc"

/*
 * First set of functions passes in OI and RETADDR.
 * This makes them callable from other helpers.
 */

#define ATOMIC_NAME(X) \
    glue(glue(glue(cpu_atomic_ ## X, SUFFIX), END), _mmu)
#define ATOMIC_MMU_CLEANUP do { clear_helper_retaddr(); } while (0)

#define DATA_SIZE 1
#include "atomic_template.h"

#define DATA_SIZE 2
#include "atomic_template.h"

#define DATA_SIZE 4
#include "atomic_template.h"

#ifdef CONFIG_ATOMIC64
#define DATA_SIZE 8
#include "atomic_template.h"
#endif

#if defined(CONFIG_ATOMIC128) || HAVE_CMPXCHG128
#define DATA_SIZE 16
#include "atomic_template.h"
#endif
