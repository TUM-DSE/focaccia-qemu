/* Read-only synchronous Linux-user AArch64 signal-frame boundary notifications.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The observer is supplied by the Focaccia user-mode bridge. It must not alter
 * CPU/frame state, guest memory, scheduling, or translate/execute guest code.
 * PRE events run synchronously at the source boundary before QEMU's operation;
 * POST events run only after the source operation succeeded. Callers must
 * independently qualify asynchronous origin, ownership, and supported profile.
 */
#ifndef QEMU_PRIVATE_SIGNAL_OBSERVER_H
#define QEMU_PRIVATE_SIGNAL_OBSERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Fixed little-endian CPU snapshot wire format. X0..X30, SP, PC, PSTATE,
 * each SIMD register as two aa64_vfp_qreg() 64-bit halves, FPCR, FPSR, BTYPE,
 * SVCR, TPIDR_EL0, and exception fault address. All offsets are byte offsets;
 * scalar fields are LE.
 */
#define QEMU_PRIVATE_SIGNAL_CPU_X_OFFSET       0u
#define QEMU_PRIVATE_SIGNAL_CPU_X_COUNT         32u
#define QEMU_PRIVATE_SIGNAL_CPU_X_BYTES        256u
#define QEMU_PRIVATE_SIGNAL_CPU_PC_OFFSET      256u
#define QEMU_PRIVATE_SIGNAL_CPU_PSTATE_OFFSET  264u
#define QEMU_PRIVATE_SIGNAL_CPU_SIMD_OFFSET    272u
#define QEMU_PRIVATE_SIGNAL_CPU_SIMD_COUNT      32u
#define QEMU_PRIVATE_SIGNAL_CPU_SIMD_STRIDE     16u
#define QEMU_PRIVATE_SIGNAL_CPU_FPCR_OFFSET    784u
#define QEMU_PRIVATE_SIGNAL_CPU_FPSR_OFFSET    788u
#define QEMU_PRIVATE_SIGNAL_CPU_BTYPE_OFFSET   792u
#define QEMU_PRIVATE_SIGNAL_CPU_SVCR_OFFSET    800u
#define QEMU_PRIVATE_SIGNAL_CPU_TPIDR_EL0_OFFSET 808u
#define QEMU_PRIVATE_SIGNAL_CPU_FAULT_ADDRESS_OFFSET 816u
#define QEMU_PRIVATE_SIGNAL_CPU_WIRE_SIZE      824u

/* Serialize a complete AArch64 user CPU snapshot, or fail without writing
 * unless cpu_state and wire are non-NULL and size is exactly WIRE_SIZE.
 */
bool qemu_linux_user_signal_cpu_snapshot(const void *cpu_state,
                                         uint8_t *wire, size_t size);

/* Frozen target-LE input facts for one AArch64 delivery. action fields are the
 * 32-byte Linux target_sigaction (handler, flags, restorer, mask), followed by
 * the 8-byte saved pre-delivery mask, info_present, seven zero reserved bytes,
 * and the 128-byte target_siginfo (zero when absent). Total size is 176 bytes.
 */
typedef struct QemuPrivateSignalDeliveryInputs {
    uint8_t action_handler_le[8];
    uint8_t action_flags_le[8];
    uint8_t action_restorer_le[8];
    uint8_t action_mask_le[8];
    uint8_t saved_mask_le[8];
    uint8_t info_present;
    uint8_t reserved[7];
    uint8_t info[128];
} QemuPrivateSignalDeliveryInputs;
#define QEMU_PRIVATE_SIGNAL_DELIVERY_INPUTS_SIZE 176u

typedef enum QemuPrivateSignalEvent {
    QEMU_PRIVATE_SIGNAL_DELIVERY_PRE = 1,
    QEMU_PRIVATE_SIGNAL_DELIVERY_POST = 2,
    QEMU_PRIVATE_SIGNAL_DELIVERY_FAIL = 3,
    QEMU_PRIVATE_SIGNAL_RETURN_PRE = 4,
    QEMU_PRIVATE_SIGNAL_RETURN_POST = 5,
    QEMU_PRIVATE_SIGNAL_RETURN_FAIL = 6,
} QemuPrivateSignalEvent;

/* cpu_state is a read-only CPUARMState pointer. For DELIVERY_PRE it is the
 * interrupted state and frame_addr/frame_size name the exact destination to
 * be initialized. DELIVERY_POST carries the installed handler state and
 * fully written frame. RETURN_PRE carries the handler state and attempted
 * frame; RETURN_POST carries the restored state after altstack restoration.
 * FAIL reports the actual failing return/lock path, with result nonzero.
 * delivery result is zero on POST and nonzero on FAIL; return result is zero
 * on POST and nonzero on FAIL. frame_size is zero on RETURN events because
 * the AArch64 frame contains variable extension records; frame_addr is x31.
 * DELIVERY events receive the same frozen inputs object; RETURN events receive
 * NULL. The callback is synchronous and must copy anything it needs to retain.
 */
#ifdef CONFIG_PLUGIN
void qemu_private_signal_observe(QemuPrivateSignalEvent event,
                                 const void *cpu_state,
                                 uint64_t frame_addr, uint64_t frame_size,
                                 int signal, int result,
                                 const QemuPrivateSignalDeliveryInputs *inputs);
#else
static inline void qemu_private_signal_observe(
    QemuPrivateSignalEvent event, const void *cpu_state,
    uint64_t frame_addr, uint64_t frame_size, int signal, int result,
    const QemuPrivateSignalDeliveryInputs *inputs)
{
    (void)event;
    (void)cpu_state;
    (void)frame_addr;
    (void)frame_size;
    (void)signal;
    (void)result;
    (void)inputs;
}
#endif

#endif /* QEMU_PRIVATE_SIGNAL_OBSERVER_H */
