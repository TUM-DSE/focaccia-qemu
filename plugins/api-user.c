/*
 * QEMU Plugin API - user-mode only implementations
 *
 * This provides the APIs that have a user-mode specific
 * implementations or are only relevant to user-mode.
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019-2025, Linaro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/plugin.h"
#include "exec/log.h"
#include "qemu/private-signal-observer.h"

extern bool qemu_linux_user_signal_cpu_snapshot(const void *, uint8_t *, size_t)
    __attribute__((weak));
static qemu_plugin_async_signal_cb_t private_signal_callback;
static void *private_signal_userdata;

bool qemu_plugin_register_async_signal_observer(qemu_plugin_id_t id,
    qemu_plugin_async_signal_cb_t callback, void *userdata)
{
    (void)id;
    if (!callback || private_signal_callback ||
        !qemu_linux_user_signal_cpu_snapshot) return false;
    private_signal_callback = callback;
    private_signal_userdata = userdata;
    return true;
}

void qemu_private_signal_observe(QemuPrivateSignalEvent event,
    const void *cpu_state, uint64_t frame_addr, uint64_t frame_size,
    int signal, int result, const QemuPrivateSignalDeliveryInputs *inputs)
{
    if (!private_signal_callback) return;
    QemuPluginAsyncSignalState state = { .version = 1 };
    if (qemu_linux_user_signal_cpu_snapshot &&
        qemu_linux_user_signal_cpu_snapshot(cpu_state, state.cpu_le, sizeof(state.cpu_le)))
        state.valid |= 1;
    if (inputs) {
        QEMU_BUILD_BUG_ON(sizeof(*inputs) != sizeof(state.delivery_inputs_le));
        memcpy(state.delivery_inputs_le, inputs, sizeof(*inputs));
        state.valid |= 2;
    }
    QemuPluginGuestLogicalSignalStateV2 logical;
    if (qemu_plugin_guest_logical_signal_state_v2(&logical)) {
        memcpy(state.logical_mask_le, logical.target_mask_le, 8);
        memcpy(state.sigint_action_le, logical.sigint_action_le, 32);
        memcpy(state.sigpipe_action_le, logical.sigpipe_action_le, 32);
        state.valid |= 4;
    }
    private_signal_callback(current_cpu ? current_cpu->cpu_index : UINT_MAX,
        event, frame_addr, frame_size, signal, result, &state,
        private_signal_userdata);
}

/* Present only in Linux-user target binaries; weak so BSD-user stays inert. */
extern bool qemu_linux_user_guest_logical_signal_state(
    CPUState *cpu, uint8_t mask[8], uint8_t sigpipe_action[32])
    __attribute__((weak));
extern bool qemu_linux_user_guest_logical_signal_state_v2(
    CPUState *cpu, uint8_t mask[8], uint8_t sigint_action[32],
    uint8_t sigpipe_action[32]) __attribute__((weak));

/*
 * Virtual Memory queries - these are all NOPs for user-mode which
 * only ever has visibility of virtual addresses.
 */

struct qemu_plugin_hwaddr *qemu_plugin_get_hwaddr(qemu_plugin_meminfo_t info,
                                                  uint64_t vaddr)
{
    return NULL;
}

bool qemu_plugin_hwaddr_is_io(const struct qemu_plugin_hwaddr *haddr)
{
    return false;
}

uint64_t qemu_plugin_hwaddr_phys_addr(const struct qemu_plugin_hwaddr *haddr)
{
    return 0;
}

const char *qemu_plugin_hwaddr_device_name(const struct qemu_plugin_hwaddr *h)
{
    return g_intern_static_string("Invalid");
}

/*
 * Time control - for user mode the only real time is wall clock time
 * so realistically all you can do in user mode is slow down execution
 * which doesn't require the ability to mess with the clock.
 */

const void *qemu_plugin_request_time_control(void)
{
    return NULL;
}

void qemu_plugin_update_ns(const void *handle, int64_t new_time)
{
    qemu_log_mask(LOG_UNIMP, "user-mode can't control time");
}

bool qemu_plugin_guest_logical_signal_state_v2(
    QemuPluginGuestLogicalSignalStateV2 *result)
{
    if (!result || !current_cpu ||
        qemu_linux_user_guest_logical_signal_state_v2 == NULL) {
        if (result) {
            memset(result, 0, sizeof(*result));
        }
        return false;
    }
    return qemu_linux_user_guest_logical_signal_state_v2(
        current_cpu, result->target_mask_le, result->sigint_action_le,
        result->sigpipe_action_le);
}

bool qemu_plugin_guest_logical_signal_state(
    QemuPluginGuestLogicalSignalState *result)
{
    if (!result || !current_cpu ||
        qemu_linux_user_guest_logical_signal_state == NULL) {
        if (result) {
            memset(result, 0, sizeof(*result));
        }
        return false;
    }
    return qemu_linux_user_guest_logical_signal_state(
        current_cpu, result->target_mask_le, result->sigpipe_action_le);
}
