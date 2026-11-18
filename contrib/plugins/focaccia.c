#include <errno.h>
#include <glib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#include <qemu-plugin.h>

#include "focaccia-plan.h"
#include "private-atomic-observer.h"
#include "focaccia-dmb.h"

/* Declared in qemu-plugin.h; weak so the plugin still loads in QEMU builds
 * without these APIs (callers check the address before use). */
#pragma weak qemu_plugin_insn_dmb_translation
#pragma weak qemu_plugin_register_async_signal_observer

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define DEFAULT_SOCKET_PATH "/tmp/focaccia.sock"
#define PROTOCOL_FAILURE_STATUS 125
#define HANDSHAKE_SIZE 176u
#define COMMAND_SIZE 32u
#define REGISTER_RESPONSE_SIZE 104u
#define MEMORY_RESPONSE_SIZE 24u
#define ACK_SIZE 16u
#define MAX_REGISTER_BYTES 64u
#define IDENTITY_DIGEST_SIZE 32u
#define MAX_SNAPSHOT_PLANS 4096u
#define MAX_PLAN_REGISTERS 32u
#define MAX_PLAN_MEMORY 32u
#define MAX_RECIPE_BYTES 640u
#define MAX_SNAPSHOT_MEMORY_BYTES 65536u
#define PLAN_REGISTER_SIZE 16u
#define PLAN_ACK_SIZE 32u
#define SNAPSHOT_HEADER_SIZE 40u
#define SNAPSHOT_VALUE_SIZE 64u

#define CAP_PC (1ull << 0)
#define CAP_INTEGER (1ull << 1)
#define CAP_STATUS (1ull << 2)
#define CAP_VECTOR (1ull << 3)
#define CAP_TLS (1ull << 4)
#define CAP_AARCH64_SVC (1ull << 5)
#define CAP_BOUNDARY_SNAPSHOTS (1ull << 6)
#define CAP_MEMORY_PERMISSIONS (1ull << 7)
#define CAP_STORE_FOOTPRINT (1ull << 8)
#define CAP_PINNED_VDSO (1ull << 9)
#define CAP_PRIVATE_RAM (1ull << 10)
#define CAP_EXTERNAL_PRIVATE_RAM (1ull << 11)
#define CAP_PRIVATE_ATOMIC_ENV (1ull << 13)
#define MAX_PRIVATE_RAM_BYTES (64u * 1024u * 1024u)
#define MAX_PRIVATE_RAM_INVENTORY_BYTES (UINT64_C(1) << 30)
#define MAX_PRIVATE_RAM_MAPPINGS 4096u
#define MAX_PINNED_VDSO_BYTES 65536u
#define MAX_VDSO_PHDRS 32u
#define MAX_STORE_FOOTPRINT 65536u
#define REGISTER_NAME_SIZE 32u

#define COMMAND_READ_REGISTER 1u
#define COMMAND_READ_MEMORY 2u
#define COMMAND_STEP 3u
#define COMMAND_FINISH 4u
#define COMMAND_ABORT 5u
#define COMMAND_INSTALL_PLAN 6u
#define COMMAND_CAPTURE_PLAN 7u
#define COMMAND_MEMORY_PERMISSIONS 8u
#define COMMAND_DRAIN_STORE_FOOTPRINT 9u
#define COMMAND_PIN_VDSO 10u
#define COMMAND_PRIVATE_RAM 11u
#define COMMAND_PRIVATE_INVENTORY 12u
#define COMMAND_VERIFY_INVENTORY 13u
#define CAP_BTI_PAGE (1ull << 12)
#define COMMAND_OBSERVE_BTI_PAGE 14u
#define COMMAND_PRIVATE_ATOMIC_ENV 15u
#define COMMAND_RECLAIM_PLAN 16u
#define CAP_PLAN_RECLAMATION (1ull << 14)
#define CAP_GUEST_LOGICAL_SIGNAL (1ull << 15)
#define COMMAND_GUEST_LOGICAL_SIGNAL 17u
#define GUEST_SIGNAL_RESPONSE_SIZE 88u
#define CAP_GUEST_LOGICAL_SIGNAL_V2 (1ull << 16)
#define COMMAND_GUEST_LOGICAL_SIGNAL_V2 18u
#define GUEST_SIGNAL_V2_RESPONSE_SIZE 120u
#define BTI_PAGE_RESPONSE_SIZE 64u
#define CAP_DMB_TRACE (1ull << 17)
#define COMMAND_DMB_TRACE 19u
#define DMB_TRACE_HEADER_SIZE 128u
#define DMB_TRACE_ROW_SIZE 80u
#define CAP_ASYNC_SIGNAL_TRACE (1ull << 18)
#define CAP_DMB_SVC_PREFIX (1ull << 19)
#define COMMAND_ASYNC_SIGNAL_TRACE 20u
#define ASYNC_SIGNAL_HEADER_SIZE 96u

#define EVENT_CUTPOINT 1u
#define EVENT_STORE 2u
#define EVENT_AARCH64_SVC_ENTRY 3u
#define EVENT_AARCH64_SVC_SUCCESSOR 4u
#define EVENT_TRANSLATION_BLOCK 5u
#define EVENT_ASYNC_SIGNAL 6u
#define EVENT_SIZE 96u

#define RESPONSE_OK 0u
#define RESPONSE_UNAVAILABLE 1u

#define TARGET_LITTLE_ENDIAN 1u
#define TARGET_BIG_ENDIAN 2u

static const uint8_t protocol_magic[8] = {
    'F', 'O', 'C', 'P', 'L', 'U', 'G', 0,
};
static const uint8_t handshake_ack_magic[8] = {
    'F', 'O', 'C', 'A', 'C', 'P', 'T', 0,
};
static const uint8_t finish_ack[ACK_SIZE] = {
    'F', 'O', 'C', 'F', 'I', 'N', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};
static const uint8_t abort_ack[ACK_SIZE] = {
    'F', 'O', 'C', 'A', 'B', 'R', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

typedef struct {
    uint64_t instruction_address;
} FocacciaScoreboard;

typedef struct {
    uint64_t pc;
    uint64_t address;
    uint64_t size;
    uint8_t value[16];
} PendingStore;

typedef struct {
    uint64_t address;
    bool cutpoint;
    bool svc;
} InstructionMetadata;

typedef struct {
    uint64_t first_pc;
    uint64_t last_pc;
    uint64_t instruction_count;
    bool pinned_vdso;
    uint8_t code_sha256[32];
} TranslationBlockMetadata;

typedef struct {
    uint64_t pc, ordinal;
    QemuPluginDmbTranslation translation;
} DmbInstructionMetadata;
static bool async_signal_enabled;
static QemuPluginAsyncSignalState async_signal_state;
static uint64_t async_signal_stage, async_signal_frame, async_signal_size;
static int32_t async_signal_number, async_signal_result;
static bool async_signal_pending;
static uint32_t async_signal_pre_stage;
static void observe_async_signal(unsigned int cpu_index, uint32_t stage,
    uint64_t frame_address, uint64_t frame_size, int32_t signal, int32_t result,
    const QemuPluginAsyncSignalState *state, void *userdata);
static bool dmb_trace_enabled;
static FocDmbTrace dmb_traces[2];
static FocDmbTrace *dmb_active = &dmb_traces[0];
static FocDmbTrace *dmb_frozen = &dmb_traces[1];

typedef struct {
    uint64_t start, end;
} ExecutableSpan;

typedef struct {
    uint64_t base, size;
    uint8_t *bytes;
    uint32_t span_count;
    ExecutableSpan spans[MAX_VDSO_PHDRS];
} PinnedVdso;

static PinnedVdso *pinned_vdso;
typedef struct {
    uint64_t sequence, epoch, generation, token, total, budget;
    GArray *mappings;
    GByteArray *wire;
    uint8_t digest[32];
    bool preflight, sealed, atomic_scope;
} FrozenPrivateInventory;
static FrozenPrivateInventory *frozen_inventory;
static uint64_t inventory_token;
static uint64_t read_register_u64(const char *name);

typedef struct {
    uint16_t size;
    uint16_t recipe_size;
    uint8_t recipe[MAX_RECIPE_BYTES];
} SnapshotMemoryPlan;

typedef struct {
    uint64_t pc;
    uint64_t generation;
    uint64_t occurrences;
    uint64_t predecessor_pc;
    uint32_t register_count;
    uint32_t memory_count;
    char registers[MAX_PLAN_REGISTERS][PLAN_REGISTER_SIZE];
    SnapshotMemoryPlan memory[MAX_PLAN_MEMORY];
} SnapshotPlan;

typedef struct {
    SnapshotPlan *plan;
    uint8_t (*register_values)[SNAPSHOT_VALUE_SIZE + 8];
} RecipeCapture;

static int socket_fd = -1;
static char *socket_path;
static char target_name[16];
static const char *pc_register;
static uint8_t target_endianness;
static uint8_t plugin_api_min;
static uint8_t plugin_api_current;
static uint64_t start_address;
static uint64_t stop_address = UINT64_MAX;
static bool coarse_cutpoints;
static bool online_blocks;
static bool online_store_footprint;
typedef struct { uint64_t address, size; } StoreSpan;
static StoreSpan store_footprint[MAX_STORE_FOOTPRINT];
static uint32_t store_footprint_count;
static uint64_t footprint_from_sequence, footprint_from_epoch;
static bool footprint_drained;
static bool automatic_snapshots = true;
static GArray *explicit_cutpoints;
static bool initialized;
static bool finished;
static uint8_t launch_identity[4][IDENTITY_DIGEST_SIZE];
static uint8_t atomic_model_sha256[32], atomic_profile_sha256[32];
static bool atomic_model_present, atomic_profile_present, atomic_no_host_tamper;
static bool atomic_policy_valid = true, atomic_syscall_pending;
static uint64_t atomic_vcpu_count, atomic_execution_actor;
static GArray *atomic_image_pins;
static bool identity_present[4];
static uint64_t capabilities;
static uint64_t event_sequence;
static uint64_t event_epoch;
static bool pending_svc;
static uint64_t pending_svc_pc;
static uint64_t online_tb_last_pc;
static GArray *pending_stores;
static GHashTable *snapshot_plans;
/* A bounded replay barrier replaces per-retired-PC tombstones. */
static uint64_t snapshot_generation_floor, snapshot_max_generation;
static uint64_t boundary_pc;
static uint64_t previous_boundary_pc = UINT64_MAX;
static bool at_tb_boundary;
static uint8_t current_event_kind;
static uint64_t current_event_pc;
static unsigned int current_event_vcpu;

static GHashTable *registers;
static struct qemu_plugin_scoreboard *scoreboard;
static qemu_plugin_u64 instruction_address;

static void put_u32_le(uint8_t *destination, uint32_t value)
{
    for (size_t index = 0; index < 4; index++) {
        destination[index] = (uint8_t)(value >> (index * 8));
    }
}

static void put_u64_le(uint8_t *destination, uint64_t value)
{
    for (size_t index = 0; index < 8; index++) {
        destination[index] = (uint8_t)(value >> (index * 8));
    }
}

static uint32_t get_u32_le(const uint8_t *source)
{
    uint32_t value = 0;
    for (size_t index = 0; index < 4; index++) {
        value |= (uint32_t)source[index] << (index * 8);
    }
    return value;
}

static uint64_t get_u64_le(const uint8_t *source)
{
    uint64_t value = 0;
    for (size_t index = 0; index < 8; index++) {
        value |= (uint64_t)source[index] << (index * 8);
    }
    return value;
}

static void put_target_u64(uint8_t *destination, uint64_t value)
{
    if (target_endianness == TARGET_BIG_ENDIAN) {
        for (size_t index = 0; index < 8; index++) {
            destination[7 - index] = (uint8_t)(value >> (index * 8));
        }
    } else {
        put_u64_le(destination, value);
    }
}

static bool read_full(int fd, void *buffer, size_t size)
{
    uint8_t *bytes = buffer;
    size_t received = 0;

    while (received < size) {
        ssize_t result = recv(fd, bytes + received, size - received, 0);
        if (result > 0) {
            received += (size_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

static bool write_full(int fd, const void *buffer, size_t size)
{
    const uint8_t *bytes = buffer;
    size_t written = 0;

    while (written < size) {
        ssize_t result = send(fd, bytes + written, size - written, MSG_NOSIGNAL);
        if (result > 0) {
            written += (size_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

static G_NORETURN void protocol_failure(const char *message)
{
    fprintf(stderr, "Focaccia plugin protocol failure: %s\n", message);
    if (socket_fd != -1) {
        close(socket_fd);
        socket_fd = -1;
    }
    _exit(PROTOCOL_FAILURE_STATUS);
}

static bool parse_address(const char *text, uint64_t *result)
{
    char *end = NULL;
    errno = 0;
    unsigned long long value = g_ascii_strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') {
        return false;
    }
    *result = (uint64_t)value;
    return true;
}

static bool select_target(const qemu_info_t *info)
{
    size_t length = strlen(info->target_name);
    if (length == 0 || length >= sizeof(target_name)) {
        return false;
    }
    memcpy(target_name, info->target_name, length + 1);

    if (strcmp(target_name, "aarch64") == 0) {
        pc_register = "pc";
        target_endianness = TARGET_LITTLE_ENDIAN;
    } else if (strcmp(target_name, "aarch64_be") == 0) {
        pc_register = "pc";
        target_endianness = TARGET_BIG_ENDIAN;
    } else if (strcmp(target_name, "x86_64") == 0) {
        pc_register = "rip";
        target_endianness = TARGET_LITTLE_ENDIAN;
    } else {
        return false;
    }

    if (info->version.min < 0 || info->version.min > UINT8_MAX ||
        info->version.cur < 0 || info->version.cur > UINT8_MAX) {
        return false;
    }
    plugin_api_min = (uint8_t)info->version.min;
    plugin_api_current = (uint8_t)info->version.cur;
    return true;
}

static bool parse_hex_digest(const char *text, uint8_t destination[IDENTITY_DIGEST_SIZE])
{
    if (strlen(text) != IDENTITY_DIGEST_SIZE * 2) {
        return false;
    }
    for (size_t index = 0; index < IDENTITY_DIGEST_SIZE; index++) {
        int high = g_ascii_xdigit_value(text[index * 2]);
        int low = g_ascii_xdigit_value(text[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        destination[index] = (uint8_t)((high << 4) | low);
    }
    return true;
}

static bool parse_options(int argc, char **argv)
{
    socket_path = g_strdup(DEFAULT_SOCKET_PATH);
    for (int index = 0; index < argc; index++) {
        const char *option = argv[index];
        if (g_str_has_prefix(option, "socket=")) {
            const char *value = option + strlen("socket=");
            if (*value == '\0') {
                return false;
            }
            g_free(socket_path);
            socket_path = g_strdup(value);
        } else if (g_str_has_prefix(option, "start=")) {
            if (!parse_address(option + strlen("start="), &start_address)) {
                return false;
            }
        } else if (g_str_has_prefix(option, "stop=")) {
            if (!parse_address(option + strlen("stop="), &stop_address)) {
                return false;
            }
        } else if (strcmp(option, "coarse=on") == 0) {
            coarse_cutpoints = true;
        } else if (strcmp(option, "online-blocks=on") == 0) {
            online_blocks = true;
        } else if (strcmp(option, "async-signals=on") == 0) {
            async_signal_enabled = true;
        } else if (strcmp(option, "dmb-trace=on") == 0) {
            dmb_trace_enabled = true;
        } else if (strcmp(option, "online-store-footprint=on") == 0) {
            online_store_footprint = true;
        } else if (strcmp(option, "automatic-snapshots=off") == 0) {
            automatic_snapshots = false;
        } else if (g_str_has_prefix(option, "cutpoint=")) {
            uint64_t address;
            if (!parse_address(option + strlen("cutpoint="), &address)) {
                return false;
            }
            g_array_append_val(explicit_cutpoints, address);
        } else if (g_str_has_prefix(option, "atomic-model-sha256=")) {
            atomic_model_present = parse_hex_digest(option + strlen("atomic-model-sha256="), atomic_model_sha256);
            if (!atomic_model_present) return false;
        } else if (g_str_has_prefix(option, "atomic-profile-sha256=")) {
            atomic_profile_present = parse_hex_digest(option + strlen("atomic-profile-sha256="), atomic_profile_sha256);
            if (!atomic_profile_present) return false;
        } else if (!strcmp(option, "atomic-no-host-tamper=on")) {
            atomic_no_host_tamper = true;
        } else if (g_str_has_prefix(option, "binary-sha256=")) {
            identity_present[0] = parse_hex_digest(option + 14, launch_identity[0]);
            if (!identity_present[0]) return false;
        } else if (g_str_has_prefix(option, "argv-sha256=")) {
            identity_present[1] = parse_hex_digest(option + 12, launch_identity[1]);
            if (!identity_present[1]) return false;
        } else if (g_str_has_prefix(option, "env-sha256=")) {
            identity_present[2] = parse_hex_digest(option + 11, launch_identity[2]);
            if (!identity_present[2]) return false;
        } else if (g_str_has_prefix(option, "cpu-sha256=")) {
            identity_present[3] = parse_hex_digest(option + 11, launch_identity[3]);
            if (!identity_present[3]) return false;
        } else {
            fprintf(stderr, "Unknown Focaccia plugin option: %s\n", option);
            return false;
        }
    }

    /* Sequential DMB scope does not mean signals cannot interrupt a TB. */
    async_signal_enabled = async_signal_enabled || dmb_trace_enabled;
    if (async_signal_enabled) {
        if (!online_blocks || strcmp(target_name, "aarch64") ||
            !qemu_plugin_register_async_signal_observer) return false;
        automatic_snapshots = false;
    }
    if (dmb_trace_enabled) {
        if (!online_blocks || strcmp(target_name, "aarch64") ||
            !qemu_plugin_insn_dmb_translation) return false;
        automatic_snapshots = false;
    }
    if (online_store_footprint) {
        if (!online_blocks) return false;
        /* Every footprint must be drained while its terminating event is paused. */
        automatic_snapshots = false;
    }
    if (start_address > stop_address ||
        !identity_present[0] || !identity_present[1] ||
        !identity_present[2] || !identity_present[3] ||
        strlen(socket_path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        return false;
    }
    for (guint index = 0; index < explicit_cutpoints->len; index++) {
        uint64_t address = g_array_index(explicit_cutpoints, uint64_t, index);
        if (address < start_address || address > stop_address) {
            return false;
        }
        for (guint previous = 0; previous < index; previous++) {
            if (address == g_array_index(explicit_cutpoints, uint64_t, previous)) {
                return false;
            }
        }
    }
    return true;
}

static void connect_to_validator(void)
{
    struct sockaddr_un address;
    uint8_t handshake[HANDSHAKE_SIZE] = {0};
    uint8_t acknowledgement[ACK_SIZE];

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        protocol_failure("unable to create Unix socket");
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1);
    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
        protocol_failure("unable to connect to validator socket");
    }

    memcpy(handshake, protocol_magic, sizeof(protocol_magic));
    /* Bytes 8..11 are reserved in the single lockstep wire format. */
    put_u32_le(handshake + 12, (uint32_t)getpid());
    memcpy(handshake + 16, target_name, strlen(target_name));
    handshake[32] = target_endianness;
    handshake[33] = 64;
    handshake[34] = plugin_api_min;
    handshake[35] = plugin_api_current;
    put_u64_le(handshake + 40, capabilities);
    memcpy(handshake + 48, launch_identity, sizeof(launch_identity));

    if (!write_full(socket_fd, handshake, sizeof(handshake)) ||
        !read_full(socket_fd, acknowledgement, sizeof(acknowledgement)) ||
        memcmp(acknowledgement, handshake_ack_magic,
               sizeof(handshake_ack_magic)) != 0 ||
        get_u64_le(acknowledgement + 8) == 0 ||
        (get_u64_le(acknowledgement + 8) & capabilities) !=
            get_u64_le(acknowledgement + 8)) {
        protocol_failure("protocol/capability negotiation failed");
    }
}

static void initialize_vcpu(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    (void)id;
    atomic_vcpu_count++;
#ifdef __linux__
    atomic_execution_actor = (uint64_t)syscall(SYS_gettid);
#else
    atomic_execution_actor = 0;
#endif
    if (initialized || vcpu_index != 0 || atomic_vcpu_count != 1) {
        atomic_policy_valid = false;
        protocol_failure("only one vCPU is supported");
    }
    initialized = true;

    g_autoptr(GArray) register_list = qemu_plugin_get_registers();
    for (guint index = 0; index < register_list->len; index++) {
        qemu_plugin_reg_descriptor *descriptor =
            &g_array_index(register_list, qemu_plugin_reg_descriptor, index);
        if (descriptor->name == NULL || descriptor->handle == NULL ||
            strlen(descriptor->name) >= REGISTER_NAME_SIZE) {
            continue;
        }
        g_hash_table_insert(registers, g_strdup(descriptor->name), descriptor->handle);
    }

    if (g_hash_table_lookup(registers, pc_register) == NULL) {
        protocol_failure("program counter register is unavailable");
    }
    capabilities = CAP_PC | CAP_BOUNDARY_SNAPSHOTS | CAP_MEMORY_PERMISSIONS | CAP_PLAN_RECLAMATION;
    if (online_blocks && strcmp(target_name, "aarch64") == 0 &&
        target_endianness == TARGET_LITTLE_ENDIAN) {
        capabilities |= CAP_GUEST_LOGICAL_SIGNAL | CAP_GUEST_LOGICAL_SIGNAL_V2;
    }
    if (online_store_footprint) capabilities |= CAP_STORE_FOOTPRINT;
    if (dmb_trace_enabled) capabilities |= CAP_DMB_TRACE | CAP_DMB_SVC_PREFIX;
    if (async_signal_enabled) capabilities |= CAP_ASYNC_SIGNAL_TRACE;
    if (online_blocks && strcmp(target_name, "aarch64") == 0 &&
        target_endianness == TARGET_LITTLE_ENDIAN) {
        capabilities |= CAP_PINNED_VDSO;
#ifdef __linux__
        capabilities |= CAP_BTI_PAGE | CAP_PRIVATE_RAM | CAP_EXTERNAL_PRIVATE_RAM;
#endif
    }
    if (strcmp(target_name, "x86_64") == 0) {
#ifdef __linux__
        /* Complete private guest RAM (command 11) needs only the paused
         * online boundary and target mmap provenance, as on AArch64; it does
         * not depend on the atomic launch assumptions. The external inventory
         * also certifies address-space generations for reusable snapshot
         * plans, and the atomic environment needs its no-host-tamper launch
         * profile, so both stay bound to the atomic-* options. */
        if (online_blocks) capabilities |= CAP_PRIVATE_RAM;
        if (online_blocks && atomic_model_present && atomic_profile_present && atomic_no_host_tamper) {
            capabilities |= CAP_EXTERNAL_PRIVATE_RAM | CAP_PRIVATE_ATOMIC_ENV;
        }
#endif
        if (g_hash_table_lookup(registers, "rax") != NULL) capabilities |= CAP_INTEGER;
        if (g_hash_table_lookup(registers, "eflags") != NULL) capabilities |= CAP_STATUS;
        if (g_hash_table_lookup(registers, "xmm0") != NULL) capabilities |= CAP_VECTOR;
        if (g_hash_table_lookup(registers, "fs_base") != NULL) capabilities |= CAP_TLS;
    } else {
        if (g_hash_table_lookup(registers, "x0") != NULL &&
            g_hash_table_lookup(registers, "x8") != NULL) {
            capabilities |= CAP_INTEGER | CAP_AARCH64_SVC;
        }
        if (g_hash_table_lookup(registers, "cpsr") != NULL) capabilities |= CAP_STATUS;
        if (g_hash_table_lookup(registers, "v0") != NULL) capabilities |= CAP_VECTOR;
        if (g_hash_table_lookup(registers, "TPIDR_EL0") != NULL) capabilities |= CAP_TLS;
    }
    connect_to_validator();
}

static void send_register(unsigned int cpu_index, const uint8_t *command)
{
    uint8_t response[REGISTER_RESPONSE_SIZE] = {0};
    char requested[17] = {0};
    memcpy(requested, command + 8, 16);
    if (memchr(requested, '\0', sizeof(requested) - 1) == NULL || requested[0] == '\0') {
        protocol_failure("malformed register name");
    }

    if (strcmp(requested, pc_register) == 0) {
        memcpy(response + 8, pc_register, strlen(pc_register));
        if (online_blocks && !at_tb_boundary) {
            /* Online mode has no per-instruction scoreboard updates. At an
             * action callback it must not advertise the initial/stale zero as
             * an observed PC. Check successor PC at the resumed TB instead. */
            response[0] = RESPONSE_UNAVAILABLE;
        } else {
            response[0] = RESPONSE_OK;
            response[1] = 8;
            put_target_u64(response + 40, online_blocks ? boundary_pc :
                qemu_plugin_u64_get(instruction_address, cpu_index));
        }
    } else {
        struct qemu_plugin_register *handle = g_hash_table_lookup(registers, requested);
        if (handle == NULL) {
            response[0] = RESPONSE_UNAVAILABLE;
            memcpy(response + 8, requested, strlen(requested));
        } else {
            g_autoptr(GByteArray) value = g_byte_array_new();
            int size = qemu_plugin_read_register(handle, value);
            if (size <= 0 || (unsigned int)size > MAX_REGISTER_BYTES ||
                value->len != (guint)size) {
                response[0] = RESPONSE_UNAVAILABLE;
                memcpy(response + 8, requested, strlen(requested));
            } else {
                response[0] = RESPONSE_OK;
                response[1] = (uint8_t)size;
                memcpy(response + 8, requested, strlen(requested));
                memcpy(response + 40, value->data, (size_t)size);
            }
        }
    }

    if (!write_full(socket_fd, response, sizeof(response))) {
        protocol_failure("unable to send register response");
    }
}

static void send_memory(const uint8_t *command)
{
    uint64_t address = get_u64_le(command + 8);
    uint64_t size = get_u64_le(command + 16);
    uint8_t response[MEMORY_RESPONSE_SIZE] = {0};

    put_u64_le(response + 8, address);
    if (size == 0 || size > G_MAXSIZE) {
        response[0] = RESPONSE_UNAVAILABLE;
    } else {
        g_autoptr(GByteArray) data = g_byte_array_new();
        if (!qemu_plugin_read_memory_vaddr(address, data, (size_t)size) ||
            data->len != size) {
            response[0] = RESPONSE_UNAVAILABLE;
        } else {
            response[0] = RESPONSE_OK;
            put_u64_le(response + 16, size);
            if (!write_full(socket_fd, response, sizeof(response)) ||
                !write_full(socket_fd, data->data, data->len)) {
                protocol_failure("unable to send memory response");
            }
            return;
        }
    }

    if (!write_full(socket_fd, response, sizeof(response))) {
        protocol_failure("unable to send unavailable-memory response");
    }
}

static void send_memory_permissions(const uint8_t *command)
{
    uint8_t response[MEMORY_RESPONSE_SIZE] = {0};
    uint64_t address = get_u64_le(command + 8);
    uint64_t size = get_u64_le(command + 16);
    uint32_t flags = UINT32_MAX;
    if (size > 0 && size <= MAX_SNAPSHOT_MEMORY_BYTES &&
        address <= UINT64_MAX - (size - 1)) {
        flags = qemu_plugin_memory_permissions_vaddr(address, size);
    }
    response[0] = flags == UINT32_MAX ? RESPONSE_UNAVAILABLE : RESPONSE_OK;
    response[1] = flags == UINT32_MAX ? 0 : flags;
    put_u64_le(response + 8, address);
    put_u64_le(response + 16, size);
    if (!write_full(socket_fd, response, sizeof(response))) {
        protocol_failure("unable to send guest memory permissions");
    }
}

static uint64_t initial_stack_word(uint64_t sp, uint64_t index)
{
    g_autoptr(GByteArray) data = g_byte_array_new();
    if (index > 8500 || sp > UINT64_MAX - index * 8 - 8) {
        protocol_failure("initial auxv scan exceeds bounds");
    }
    uint64_t address = sp + index * 8;
    uint32_t flags = qemu_plugin_memory_permissions_vaddr(address, 8);
    if (flags == UINT32_MAX || (flags & 9) != 9 ||
        !qemu_plugin_read_memory_vaddr(address, data, 8) || data->len != 8) {
        protocol_failure("initial auxv stack is unavailable");
    }
    return get_u64_le(data->data);
}

static uint64_t initial_auxv_vdso(void)
{
    uint64_t sp = read_register_u64("sp");
    uint64_t argc = initial_stack_word(sp, 0);
    if (sp % 16 || argc > 4096 || initial_stack_word(sp, argc + 1) != 0) {
        protocol_failure("malformed initial argv stack");
    }
    /* Require non-NULL argv entries, not just a conveniently placed sentinel. */
    for (uint64_t i = 1; i <= argc; i++) {
        if (initial_stack_word(sp, i) == 0) protocol_failure("early initial argv terminator");
    }
    uint64_t cursor = argc + 2, env_count = 0;
    while (initial_stack_word(sp, cursor++) != 0) {
        if (++env_count > 4096) protocol_failure("initial environment exceeds bounds");
    }
    uint64_t base = 0;
    bool seen = false;
    for (unsigned i = 0; i < 128; i++) {
        uint64_t tag = initial_stack_word(sp, cursor++);
        uint64_t value = initial_stack_word(sp, cursor++);
        if (tag == 0) {
            if (value != 0 || !seen || base == 0) protocol_failure("missing initial vDSO auxv anchor");
            return base;
        }
        if (tag == 33) {
            if (seen) protocol_failure("duplicate initial vDSO auxv anchor");
            seen = true;
            base = value;
        }
    }
    protocol_failure("unterminated initial auxv");
    return 0;
}

static bool vdso_instruction_span(uint64_t address, uint64_t size)
{
    if (pinned_vdso == NULL || size == 0 || address > UINT64_MAX - size) return false;
    for (uint32_t i = 0; i < pinned_vdso->span_count; i++) {
        if (address >= pinned_vdso->spans[i].start &&
            address + size <= pinned_vdso->spans[i].end) return true;
    }
    return false;
}

static void verify_pinned_vdso(void)
{
    if (pinned_vdso == NULL) protocol_failure("vDSO has no initial pin");
    /* Permission bits are common across a range: check every page so that one
     * writable page cannot be hidden by a non-writable neighboring page. */
    for (uint64_t offset = 0; offset < pinned_vdso->size; offset += 4096) {
        uint32_t flags = qemu_plugin_memory_permissions_vaddr(pinned_vdso->base + offset, 4096);
        if (flags == UINT32_MAX || (flags & 15) != 13) {
            protocol_failure("pinned vDSO mapping is not read-execute/non-writable");
        }
    }
    g_autoptr(GByteArray) live = g_byte_array_new();
    if (!qemu_plugin_read_memory_vaddr(pinned_vdso->base, live, pinned_vdso->size) ||
        live->len != pinned_vdso->size ||
        memcmp(live->data, pinned_vdso->bytes, pinned_vdso->size)) {
        protocol_failure("vDSO image differs from initial pin");
    }
}

static void pin_initial_vdso(const uint8_t *command)
{
    uint64_t base = get_u64_le(command + 8);
    uint64_t size = get_u64_le(command + 16);
    uint64_t sequence = get_u64_le(command + 24);
    if (!online_blocks || !at_tb_boundary || event_sequence != 1 || sequence != 1 ||
        pinned_vdso != NULL || !(capabilities & CAP_PINNED_VDSO) ||
        base == 0 || base % 4096 || size < 4096 || size > MAX_PINNED_VDSO_BYTES ||
        size % 4096 || base > UINT64_MAX - size ||
        (base <= stop_address && base + size > start_address) ||
        initial_auxv_vdso() != base) {
        protocol_failure("invalid initial vDSO admission boundary/identity");
    }
    PinnedVdso *image = g_new0(PinnedVdso, 1);
    image->base = base;
    image->size = size;
    image->bytes = g_malloc(size);
    if (!read_full(socket_fd, image->bytes, size)) protocol_failure("short initial vDSO payload");
    const uint8_t *elf = image->bytes;
    uint16_t type = elf[16] | ((uint16_t)elf[17] << 8);
    uint16_t machine = elf[18] | ((uint16_t)elf[19] << 8);
    uint16_t ehsize = elf[52] | ((uint16_t)elf[53] << 8);
    uint16_t phsize = elf[54] | ((uint16_t)elf[55] << 8);
    uint16_t phnum = elf[56] | ((uint16_t)elf[57] << 8);
    uint64_t phoff = get_u64_le(elf + 32);
    if (memcmp(elf, "\177ELF\002\001\001", 7) || type != 3 || machine != 183 ||
        get_u32_le(elf + 20) != 1 || ehsize != 64 || phsize != 56 ||
        phnum == 0 || phnum > MAX_VDSO_PHDRS || phoff < 64 ||
        phoff > size - (uint64_t)phnum * 56) {
        protocol_failure("malformed initial vDSO ELF header");
    }
    bool header_load = false;
    uint64_t mapped_end = 0, load_bias = 0;
    /* QEMU's loader relocates every program-header vaddr/paddr. Also accept
     * a conventional relative ELF, but never mix origins or admit extra code. */
    for (uint16_t i = 0; i < phnum; i++) {
        const uint8_t *ph = elf + phoff + (uint64_t)i * 56;
        if (get_u32_le(ph) == 1 && get_u64_le(ph + 8) == 0 &&
            get_u64_le(ph + 32) >= phoff + (uint64_t)phnum * 56) {
            uint64_t origin = get_u64_le(ph + 16);
            if (header_load || (origin != 0 && origin != base)) {
                protocol_failure("vDSO lacks a unique auxv-relative LOAD origin");
            }
            header_load = true;
            load_bias = origin;
        }
    }
    if (!header_load) protocol_failure("vDSO header has no covering LOAD");
    for (uint16_t i = 0; i < phnum; i++) {
        const uint8_t *ph = elf + phoff + (uint64_t)i * 56;
        uint32_t kind = get_u32_le(ph), flags = get_u32_le(ph + 4);
        if (kind == 3) protocol_failure("vDSO interpreter is unsupported");
        if (kind != 1) continue;
        uint64_t offset = get_u64_le(ph + 8), vaddr = get_u64_le(ph + 16);
        uint64_t filesz = get_u64_le(ph + 32), memsz = get_u64_le(ph + 40);
        if (vaddr < load_bias) protocol_failure("inconsistent vDSO LOAD relocation");
        vaddr -= load_bias;
        if ((flags & ~7u) || offset != vaddr || filesz > memsz || vaddr > size ||
            memsz > size - vaddr) protocol_failure("malformed initial vDSO LOAD range");
        if (vaddr + memsz > mapped_end) mapped_end = vaddr + memsz;
        if ((flags & 1) && filesz) {
            ExecutableSpan span = { base + vaddr, base + vaddr + filesz };
            for (uint32_t j = 0; j < image->span_count; j++) {
                if (span.start < image->spans[j].end && span.end > image->spans[j].start) {
                    protocol_failure("overlapping initial vDSO executable spans");
                }
            }
            image->spans[image->span_count++] = span;
        }
    }
    if (!header_load || image->span_count == 0 || mapped_end == 0 ||
        ((mapped_end + 4095) & ~4095ull) != size) {
        protocol_failure("initial vDSO capture does not match bounded LOAD image");
    }
    pinned_vdso = image;
    verify_pinned_vdso();
    uint8_t response[32] = { RESPONSE_OK };
    put_u64_le(response + 8, base);
    put_u64_le(response + 16, size);
    put_u64_le(response + 24, sequence);
    if (!write_full(socket_fd, response, sizeof(response))) protocol_failure("vDSO admission acknowledgement failed");
}

static void clear_private_inventory(void)
{
    if (atomic_image_pins) {
        for (guint i = 0; i < atomic_image_pins->len; i++) close(g_array_index(atomic_image_pins, int, i));
        g_array_free(atomic_image_pins, true);
        atomic_image_pins = NULL;
    }
    if (frozen_inventory) {
        g_array_free(frozen_inventory->mappings, true);
        g_byte_array_free(frozen_inventory->wire, true);
        g_free(frozen_inventory);
        frozen_inventory = NULL;
    }
}

static void private_inventory_header(uint8_t header[64], const char magic[8],
                                     uint8_t status, const FrozenPrivateInventory *item,
                                     uint32_t scope)
{
    memcpy(header, magic, 8);
    header[8] = status;
    put_u64_le(header + 16, item->sequence);
    put_u64_le(header + 24, item->epoch);
    put_u64_le(header + 32, status == RESPONSE_OK || status == 2 ? item->generation : 0);
    put_u32_le(header + 40, status == RESPONSE_OK || status == 2 ? item->mappings->len : 0);
    put_u32_le(header + 44, scope);
    put_u64_le(header + 48, status == RESPONSE_OK || status == 2 ? item->total : 0);
    put_u64_le(header + 56, item->token);
}

static void send_private_inventory(const uint8_t *command)
{
    uint64_t sequence = get_u64_le(command + 8), epoch = get_u64_le(command + 16);
    uint64_t budget = get_u64_le(command + 24);
    if (!online_blocks || !(capabilities & CAP_EXTERNAL_PRIVATE_RAM) ||
        sequence != event_sequence || epoch != event_epoch || !budget ||
        budget > MAX_PRIVATE_RAM_INVENTORY_BYTES || inventory_token == UINT64_MAX) {
        protocol_failure("invalid external private inventory input boundary");
    }
    clear_private_inventory();
    FrozenPrivateInventory *item = g_new0(FrozenPrivateInventory, 1);
    item->sequence = sequence; item->epoch = epoch; item->budget = budget;
    item->token = ++inventory_token;
    item->mappings = g_array_new(false, false, sizeof(qemu_plugin_guest_mapping));
    item->wire = g_byte_array_new();
    bool available = qemu_plugin_private_ram_inventory(item->mappings, budget,
        MAX_PRIVATE_RAM_MAPPINGS, &item->generation);
    for (guint i = 0; i < item->mappings->len; i++) {
        const qemu_plugin_guest_mapping *mapping = &g_array_index(item->mappings, qemu_plugin_guest_mapping, i);
        uint8_t descriptor[40] = {0};
        put_u64_le(descriptor, mapping->start);
        put_u64_le(descriptor + 8, mapping->size);
        put_u64_le(descriptor + 16, mapping->host_start);
        put_u32_le(descriptor + 24, mapping->flags);
        put_u64_le(descriptor + 32, mapping->data_offset);
        g_byte_array_append(item->wire, descriptor, sizeof(descriptor));
        item->total += mapping->size;
    }
    uint8_t header[64] = {0};
    private_inventory_header(header, "FOCINV\0\0", available ? 2 : RESPONSE_UNAVAILABLE,
                             item, available ? 2 : 0); /* requires external bytes */
    if (!write_full(socket_fd, header, sizeof(header))) protocol_failure("inventory header send failed");
    if (!available) {
        g_array_free(item->mappings, true); g_byte_array_free(item->wire, true); g_free(item);
        return;
    }
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(checksum, header, sizeof(header));
    g_checksum_update(checksum, item->wire->data, item->wire->len);
    gsize length = sizeof(item->digest);
    g_checksum_get_digest(checksum, item->digest, &length);
    g_checksum_free(checksum);
    if (!write_full(socket_fd, item->wire->data, item->wire->len) ||
        !write_full(socket_fd, item->digest, sizeof(item->digest))) protocol_failure("inventory certificate send failed");
    frozen_inventory = item;
}

static void verify_private_inventory(const uint8_t *command)
{
    uint8_t payload[88];
    FrozenPrivateInventory *item = frozen_inventory;
    if (!item || item->atomic_scope || get_u64_le(command + 8) != event_sequence ||
        get_u64_le(command + 16) != event_epoch || get_u64_le(command + 24) != item->token ||
        item->sequence != event_sequence || item->epoch != event_epoch ||
        !read_full(socket_fd, payload, sizeof(payload))) protocol_failure("stale external inventory token/event");
    uint32_t phase = get_u32_le(payload + 8);
    uint64_t captured = get_u64_le(payload + 16);
    if (get_u64_le(payload) != item->generation || get_u32_le(payload + 12) ||
        memcmp(payload + 24, item->digest, 32) || phase > 1 || item->sealed ||
        (phase == 0 && (item->preflight || captured || memcmp(payload + 56, (uint8_t[32]){0}, 32))) ||
        (phase == 1 && (!item->preflight || captured > item->total))) {
        protocol_failure("invalid external inventory certificate/phase");
    }
    g_autoptr(GArray) current = g_array_new(false, false, sizeof(qemu_plugin_guest_mapping));
    uint64_t generation = 0;
    if (!qemu_plugin_private_ram_inventory(current, item->budget, MAX_PRIVATE_RAM_MAPPINGS, &generation) ||
        generation != item->generation || current->len != item->mappings->len ||
        memcmp(current->data, item->mappings->data, current->len * sizeof(qemu_plugin_guest_mapping)) ||
        item->sequence != event_sequence || item->epoch != event_epoch) {
        protocol_failure("external inventory mappings/generation changed while paused");
    }
    if (phase == 0) item->preflight = true;
    else item->sealed = true;
    uint8_t response[64] = {0};
    private_inventory_header(response, "FOCIVFY\0", RESPONSE_OK, item,
                             phase == 0 ? 3 : (captured == item->total ? 4 : 5));
    if (!write_full(socket_fd, response, sizeof(response)) ||
        !write_full(socket_fd, payload + 56, 32)) protocol_failure("inventory verification acknowledgement failed");
}

#include "focaccia-atomic.h"

static void send_private_ram(const uint8_t *command)
{
    uint64_t sequence = get_u64_le(command + 8), epoch = get_u64_le(command + 16);
    uint64_t budget = get_u64_le(command + 24), generation = 0;
    if (!online_blocks || !(capabilities & CAP_PRIVATE_RAM) ||
        sequence != event_sequence || epoch != event_epoch ||
        budget == 0 || budget > MAX_PRIVATE_RAM_BYTES) {
        protocol_failure("private RAM request lacks paused boundary identity/budget");
    }
    g_autoptr(GArray) mappings = g_array_new(false, false, sizeof(qemu_plugin_guest_mapping));
    g_autoptr(GByteArray) memory = g_byte_array_new();
    bool captured = qemu_plugin_private_ram_snapshot(mappings, memory, budget,
                                                    MAX_PRIVATE_RAM_MAPPINGS, &generation);
    if (sequence != event_sequence || epoch != event_epoch) {
        protocol_failure("private RAM event identity changed during capture");
    }
    uint8_t header[64] = { 'F', 'O', 'C', 'R', 'A', 'M', 0, 0 };
    header[8] = captured ? RESPONSE_OK : RESPONSE_UNAVAILABLE;
    put_u64_le(header + 16, sequence);
    put_u64_le(header + 24, epoch);
    put_u64_le(header + 32, captured ? generation : 0);
    put_u32_le(header + 40, captured ? mappings->len : 0);
    put_u32_le(header + 44, captured ? 1 : 0); /* Complete private guest RAM. */
    put_u64_le(header + 48, captured ? memory->len : 0);
    if (!write_full(socket_fd, header, sizeof(header))) protocol_failure("private RAM header send failed");
    if (!captured) return;
    for (guint i = 0; i < mappings->len; i++) {
        const qemu_plugin_guest_mapping *item = &g_array_index(mappings, qemu_plugin_guest_mapping, i);
        uint8_t descriptor[32] = {0};
        put_u64_le(descriptor, item->start);
        put_u64_le(descriptor + 8, item->size);
        put_u32_le(descriptor + 16, item->flags);
        put_u64_le(descriptor + 24, item->data_offset);
        if (!write_full(socket_fd, descriptor, sizeof(descriptor))) protocol_failure("private RAM descriptor send failed");
    }
    if (!write_full(socket_fd, memory->data, memory->len)) protocol_failure("private RAM bytes send failed");
}

static void reclaim_snapshot_plan(const uint8_t *command)
{
    uint64_t pc = get_u64_le(command + 8);
    uint64_t generation = get_u64_le(command + 16);
    uint64_t sequence = get_u64_le(command + 24);
    SnapshotPlan *plan = g_hash_table_lookup(snapshot_plans, &pc);
    if (memcmp(command + 1, (uint8_t[7]){0}, 7) != 0 ||
        !online_blocks || !at_tb_boundary || pc == boundary_pc ||
        sequence != event_sequence || plan == NULL || generation != plan->generation) {
        protocol_failure("invalid snapshot plan reclamation identity or lifetime");
    }
    /* All future installations must be newer than every historical plan.
     * Live older plans remain valid; retired identities cannot be replayed. */
    snapshot_generation_floor = snapshot_max_generation;
    g_hash_table_remove(snapshot_plans, &pc);
    uint8_t acknowledgement[PLAN_ACK_SIZE] = {0};
    acknowledgement[0] = RESPONSE_OK;
    put_u64_le(acknowledgement + 8, pc);
    put_u64_le(acknowledgement + 16, generation);
    put_u64_le(acknowledgement + 24, sequence);
    if (!write_full(socket_fd, acknowledgement, sizeof(acknowledgement))) {
        protocol_failure("snapshot plan reclamation acknowledgement failed");
    }
}

static void install_snapshot_plan(const uint8_t *command)
{
    uint64_t pc = get_u64_le(command + 8);
    uint64_t generation = get_u64_le(command + 16);
    uint32_t count = get_u32_le(command + 24);
    uint32_t memory_count = get_u32_le(command + 28);
    uint8_t acknowledgement[PLAN_ACK_SIZE] = {0};

    if (!online_blocks || !at_tb_boundary || pc != boundary_pc || generation == 0 ||
        count > MAX_PLAN_REGISTERS || memory_count > MAX_PLAN_MEMORY ||
        count + memory_count == 0 || generation <= snapshot_generation_floor) {
        protocol_failure("invalid snapshot plan identity or bounds");
    }
    SnapshotPlan *old = g_hash_table_lookup(snapshot_plans, &pc);
    if ((old == NULL && g_hash_table_size(snapshot_plans) >= MAX_SNAPSHOT_PLANS) ||
        (old != NULL && generation <= old->generation)) {
        protocol_failure("stale or overflowing snapshot plan installation");
    }

    SnapshotPlan *plan = g_new0(SnapshotPlan, 1);
    plan->pc = pc;
    plan->generation = generation;
    plan->predecessor_pc = previous_boundary_pc;
    plan->register_count = count;
    plan->memory_count = memory_count;
    for (uint32_t index = 0; index < count; index++) {
        if (!read_full(socket_fd, plan->registers[index], PLAN_REGISTER_SIZE) ||
            memchr(plan->registers[index], '\0', PLAN_REGISTER_SIZE) == NULL ||
            plan->registers[index][0] == '\0' ||
            g_hash_table_lookup(registers, plan->registers[index]) == NULL) {
            fprintf(stderr, "Rejected snapshot register: %.*s\n",
                    (int)PLAN_REGISTER_SIZE, plan->registers[index]);
            g_free(plan);
            protocol_failure("invalid snapshot plan register");
        }
        for (uint32_t previous = 0; previous < index; previous++) {
            if (strcmp(plan->registers[index], plan->registers[previous]) == 0) {
                g_free(plan);
                protocol_failure("duplicate snapshot plan register");
            }
        }
    }
    size_t total_memory = 0;
    for (uint32_t index = 0; index < memory_count; index++) {
        uint8_t descriptor[8];
        if (!read_full(socket_fd, descriptor, sizeof(descriptor))) {
            g_free(plan);
            protocol_failure("truncated snapshot memory descriptor");
        }
        SnapshotMemoryPlan *memory = &plan->memory[index];
        memory->size = (uint16_t)(descriptor[0] | descriptor[1] << 8);
        memory->recipe_size = (uint16_t)(descriptor[2] | descriptor[3] << 8);
        if (descriptor[4] || descriptor[5] || descriptor[6] || descriptor[7] ||
            memory->size == 0 || memory->recipe_size == 0 ||
            memory->recipe_size > MAX_RECIPE_BYTES ||
            total_memory + memory->size > MAX_SNAPSHOT_MEMORY_BYTES ||
            !read_full(socket_fd, memory->recipe, memory->recipe_size)) {
            g_free(plan);
            protocol_failure("invalid snapshot memory descriptor");
        }
        total_memory += memory->size;
    }
    g_hash_table_replace(snapshot_plans, &plan->pc, plan);
    if (generation > snapshot_max_generation) snapshot_max_generation = generation;
    acknowledgement[0] = RESPONSE_OK;
    put_u64_le(acknowledgement + 8, pc);
    put_u64_le(acknowledgement + 16, generation);
    put_u32_le(acknowledgement + 24, count);
    put_u32_le(acknowledgement + 28, memory_count);
    if (!write_full(socket_fd, acknowledgement, sizeof(acknowledgement))) {
        protocol_failure("unable to acknowledge snapshot plan");
    }
}

static bool recipe_read_register(void *opaque, uint8_t index,
                                 FocacciaRecipeValue *value)
{
    RecipeCapture *capture = opaque;
    if (index >= capture->plan->register_count) {
        return false;
    }
    uint8_t *wire = capture->register_values[index];
    uint8_t size = wire[0];
    if (size == 0 || size > 8) {
        return false;
    }
    value->width = size * 8;
    value->bits = 0;
    for (uint8_t offset = 0; offset < size; offset++) {
        uint8_t source = target_endianness == TARGET_BIG_ENDIAN ?
            size - offset - 1 : offset;
        value->bits |= (uint64_t)wire[8 + source] << (offset * 8);
    }
    return true;
}

static bool recipe_read_memory(void *opaque, uint64_t address,
                               uint8_t *bytes, size_t size)
{
    g_autoptr(GByteArray) value = g_byte_array_new();
    (void)opaque;
    if (size == 0 || size > 8 ||
        !qemu_plugin_read_memory_vaddr(address, value, size) ||
        value->len != size) {
        return false;
    }
    memcpy(bytes, value->data, size);
    return true;
}

static bool capture_snapshot_plan(unsigned int cpu_index, const uint8_t *command)
{
    uint64_t pc = get_u64_le(command + 8);
    uint64_t generation = get_u64_le(command + 16);
    SnapshotPlan *plan = g_hash_table_lookup(snapshot_plans, &pc);
    uint8_t header[SNAPSHOT_HEADER_SIZE] = {0};
    uint8_t values[MAX_PLAN_REGISTERS][SNAPSHOT_VALUE_SIZE + 8] = {{0}};
    g_autoptr(GByteArray) memory_values = g_byte_array_new();

    if (!online_blocks || !at_tb_boundary || pc != boundary_pc || plan == NULL ||
        plan->generation != generation) {
        protocol_failure("snapshot capture does not match current boundary plan");
    }
    for (uint32_t index = 0; index < plan->register_count; index++) {
        const char *name = plan->registers[index];
        if (strcmp(name, pc_register) == 0) {
            values[index][0] = 8;
            put_target_u64(values[index] + 8, boundary_pc);
        } else {
            struct qemu_plugin_register *handle = g_hash_table_lookup(registers, name);
            g_autoptr(GByteArray) value = g_byte_array_new();
            int size = handle == NULL ? -1 : qemu_plugin_read_register(handle, value);
            if (size <= 0 || size > MAX_REGISTER_BYTES || value->len != (guint)size) {
                header[0] = RESPONSE_UNAVAILABLE;
                put_u64_le(header + 8, pc);
                put_u64_le(header + 16, generation);
                put_u64_le(header + 24, plan->occurrences);
                if (!write_full(socket_fd, header, sizeof(header))) {
                    protocol_failure("unable to send unavailable snapshot");
                }
                return false;
            }
            values[index][0] = (uint8_t)size;
            memcpy(values[index] + 8, value->data, size);
        }
    }
    RecipeCapture capture = { plan, values };
    FocacciaRecipeContext context = {
        recipe_read_register, recipe_read_memory, &capture
    };
    for (uint32_t index = 0; index < plan->memory_count; index++) {
        SnapshotMemoryPlan *memory = &plan->memory[index];
        FocacciaRecipeValue address;
        g_autoptr(GByteArray) data = g_byte_array_new();
        if (!focaccia_recipe_eval(memory->recipe, memory->recipe_size,
                                  &context, &address) ||
            address.width != 64 ||
            !qemu_plugin_read_memory_vaddr(address.bits, data, memory->size) ||
            data->len != memory->size) {
            header[0] = RESPONSE_UNAVAILABLE;
            put_u64_le(header + 8, pc);
            put_u64_le(header + 16, generation);
            put_u64_le(header + 24, plan->occurrences);
            if (!write_full(socket_fd, header, sizeof(header))) {
                protocol_failure("unable to send unavailable memory snapshot");
            }
            return false;
        }
        uint8_t descriptor[16] = {0};
        put_u64_le(descriptor, address.bits);
        put_u32_le(descriptor + 8, memory->size);
        g_byte_array_append(memory_values, descriptor, sizeof(descriptor));
        g_byte_array_append(memory_values, data->data, data->len);
    }
    plan->occurrences++;
    header[0] = RESPONSE_OK;
    header[2] = (uint8_t)plan->memory_count;
    put_u32_le(header + 4, plan->register_count);
    put_u64_le(header + 8, pc);
    put_u64_le(header + 16, generation);
    put_u64_le(header + 24, plan->occurrences);
    put_u64_le(header + 32, event_sequence);
    if (!write_full(socket_fd, header, sizeof(header)) ||
        !write_full(socket_fd, values,
                    plan->register_count * (SNAPSHOT_VALUE_SIZE + 8)) ||
        !write_full(socket_fd, memory_values->data, memory_values->len)) {
        protocol_failure("unable to send boundary snapshot");
    }
    (void)cpu_index;
    return true;
}

static bool reserved_command_bytes_are_zero(const uint8_t *command)
{
    for (size_t index = 1; index < 8; index++) {
        if (command[index] != 0) {
            return false;
        }
    }
    return true;
}

static void drain_store_footprint(const uint8_t *command)
{
    uint8_t header[48] = { 'F', 'O', 'C', 'S', 'T', 'O', 'R', 0 };
    if (!online_store_footprint || footprint_drained ||
        get_u64_le(command + 8) != event_sequence ||
        get_u64_le(command + 16) != event_epoch ||
        get_u64_le(command + 24) != 0) {
        protocol_failure("invalid or duplicate store-footprint drain");
    }
    put_u32_le(header + 12, store_footprint_count);
    put_u64_le(header + 16, footprint_from_sequence);
    put_u64_le(header + 24, footprint_from_epoch);
    put_u64_le(header + 32, event_sequence);
    put_u64_le(header + 40, event_epoch);
    if (!write_full(socket_fd, header, sizeof(header))) {
        protocol_failure("unable to send store-footprint header");
    }
    for (uint32_t i = 0; i < store_footprint_count; i++) {
        uint8_t span[16];
        put_u64_le(span, store_footprint[i].address);
        put_u64_le(span + 8, store_footprint[i].size);
        if (!write_full(socket_fd, span, sizeof(span))) {
            protocol_failure("unable to send store footprint");
        }
    }
    store_footprint_count = 0;
    footprint_from_sequence = event_sequence;
    footprint_from_epoch = event_epoch;
    footprint_drained = true;
}

static void observe_bti_page(const uint8_t command[COMMAND_SIZE])
{
    uint8_t response[BTI_PAGE_RESPONSE_SIZE] = {0};
    uint64_t sequence = get_u64_le(command + 8);
    uint64_t epoch = get_u64_le(command + 16);
    uint64_t pc = get_u64_le(command + 24);
    QemuPluginBtiPage page;
    memcpy(response, "FOCBTI", 6);
    response[8] = RESPONSE_UNAVAILABLE;
    put_u64_le(response + 16, sequence);
    put_u64_le(response + 24, epoch);
    if (!online_blocks || !at_tb_boundary || sequence != event_sequence ||
        epoch != event_epoch || !pc || (pc & 3) ||
        !qemu_plugin_observe_bti_page(pc, &page)) {
        if (!write_full(socket_fd, response, sizeof(response)))
            protocol_failure("unable to send BTI metadata response");
        return;
    }
    response[8] = RESPONSE_OK;
    put_u64_le(response + 32, page.generation);
    put_u64_le(response + 40, pc);
    put_u64_le(response + 48, page.page_start);
    put_u32_le(response + 56, page.flags);
    put_u32_le(response + 60, page.features);
    if (!write_full(socket_fd, response, sizeof(response)))
        protocol_failure("unable to send BTI metadata response");
}

static void observe_guest_logical_signal(const uint8_t *command,
                                         unsigned int cpu_index)
{
    uint8_t response[GUEST_SIGNAL_RESPONSE_SIZE] = { 'F', 'O', 'C', 'S', 'I', 'G', 0, 0 };
    QemuPluginGuestLogicalSignalState state = {0};
    uint64_t sequence = get_u64_le(command + 8);
    uint64_t epoch = get_u64_le(command + 16);
    uint64_t pc = get_u64_le(command + 24);

    put_u64_le(response + 16, sequence);
    put_u64_le(response + 24, epoch);
    put_u64_le(response + 32, pc);
    put_u64_le(response + 40, cpu_index);
    if (!(capabilities & CAP_GUEST_LOGICAL_SIGNAL) || cpu_index != 0 ||
        sequence != event_sequence || epoch != event_epoch ||
        pc != current_event_pc || cpu_index != current_event_vcpu ||
        (current_event_kind != EVENT_AARCH64_SVC_ENTRY &&
         current_event_kind != EVENT_TRANSLATION_BLOCK) ||
        !qemu_plugin_guest_logical_signal_state(&state)) {
        response[8] = RESPONSE_UNAVAILABLE;
    } else {
        response[8] = RESPONSE_OK;
        memcpy(response + 48, state.target_mask_le, sizeof(state.target_mask_le));
        memcpy(response + 56, state.sigpipe_action_le,
               sizeof(state.sigpipe_action_le));
    }
    if (!write_full(socket_fd, response, sizeof(response))) {
        protocol_failure("unable to send guest logical-signal inventory");
    }
}

static void observe_guest_logical_signal_v2(const uint8_t *command,
                                            unsigned int cpu_index)
{
    uint8_t response[GUEST_SIGNAL_V2_RESPONSE_SIZE] = {
        'F', 'O', 'C', 'S', 'G', '2', 0, 0
    };
    QemuPluginGuestLogicalSignalStateV2 state = {0};
    uint64_t sequence = get_u64_le(command + 8);
    uint64_t epoch = get_u64_le(command + 16);
    uint64_t pc = get_u64_le(command + 24);

    put_u64_le(response + 16, sequence);
    put_u64_le(response + 24, epoch);
    put_u64_le(response + 32, pc);
    put_u64_le(response + 40, cpu_index);
    if (!(capabilities & CAP_GUEST_LOGICAL_SIGNAL_V2) || cpu_index != 0 ||
        sequence != event_sequence || epoch != event_epoch ||
        pc != current_event_pc || cpu_index != current_event_vcpu ||
        (current_event_kind != EVENT_AARCH64_SVC_ENTRY &&
         current_event_kind != EVENT_TRANSLATION_BLOCK) ||
        !qemu_plugin_guest_logical_signal_state_v2(&state)) {
        response[8] = RESPONSE_UNAVAILABLE;
    } else {
        response[8] = RESPONSE_OK;
        memcpy(response + 48, state.target_mask_le, 8);
        memcpy(response + 56, state.sigint_action_le, 32);
        memcpy(response + 88, state.sigpipe_action_le, 32);
    }
    if (!write_full(socket_fd, response, sizeof(response))) {
        protocol_failure("unable to send guest logical-signal v2 inventory");
    }
}

static void query_async_signal(const uint8_t command[COMMAND_SIZE],
                                 unsigned int cpu_index)
{
    uint8_t h[ASYNC_SIGNAL_HEADER_SIZE] = {'F','O','C','A','S','G','1',0};
    if (!async_signal_enabled || !(capabilities & CAP_ASYNC_SIGNAL_TRACE) ||
        cpu_index || current_event_kind != EVENT_ASYNC_SIGNAL ||
        get_u64_le(command + 8) != event_sequence ||
        get_u64_le(command + 16) != event_epoch ||
        get_u64_le(command + 24) != current_event_pc)
        protocol_failure("invalid async signal source event identity");
    put_u32_le(h + 8, RESPONSE_OK); put_u32_le(h + 12, async_signal_state.version);
    put_u64_le(h + 16, event_sequence); put_u64_le(h + 24, event_epoch);
    put_u64_le(h + 32, current_event_pc); put_u64_le(h + 40, getpid());
    put_u64_le(h + 48, cpu_index); put_u64_le(h + 56, async_signal_stage);
    put_u64_le(h + 64, async_signal_frame); put_u64_le(h + 72, async_signal_size);
    put_u32_le(h + 80, async_signal_number); put_u32_le(h + 84, async_signal_result);
    put_u32_le(h + 88, async_signal_state.valid);
    if (!write_full(socket_fd, h, sizeof(h)) ||
        !write_full(socket_fd, async_signal_state.cpu_le, sizeof(async_signal_state.cpu_le)) ||
        !write_full(socket_fd, async_signal_state.delivery_inputs_le, sizeof(async_signal_state.delivery_inputs_le)) ||
        !write_full(socket_fd, async_signal_state.logical_mask_le, 8) ||
        !write_full(socket_fd, async_signal_state.sigint_action_le, 32) ||
        !write_full(socket_fd, async_signal_state.sigpipe_action_le, 32))
        protocol_failure("async signal source snapshot send failed");
}

static void observe_dmb_trace(const uint8_t command[COMMAND_SIZE],
                               unsigned int cpu_index)
{
    uint8_t header[DMB_TRACE_HEADER_SIZE] = {'F','O','C','D','M','B','1',0};
    bool prefix = current_event_kind == EVENT_AARCH64_SVC_ENTRY;
    const FocDmbTrace *trace = prefix ? dmb_active : dmb_frozen;
    if (!dmb_trace_enabled || !(capabilities & CAP_DMB_TRACE) || cpu_index ||
        (!prefix && (!at_tb_boundary || current_event_kind != EVENT_TRANSLATION_BLOCK)) ||
        (prefix && current_event_pc != trace->last_pc) ||
        get_u64_le(command + 8) != event_sequence ||
        get_u64_le(command + 16) != event_epoch ||
        get_u64_le(command + 24) != current_event_pc) {
        protocol_failure("invalid DMB trace event identity");
    }
    put_u32_le(header + 8, trace->valid ? RESPONSE_OK : RESPONSE_UNAVAILABLE);
    /* 1: completed previous TB; 2: current SVC-final prefix, before kernel.
     * Both retain the FULL original TB code identity; neither proves ordering. */
    put_u32_le(header + 12, prefix ? 2 : 1);
    put_u64_le(header + 16, event_sequence);
    put_u64_le(header + 24, event_epoch);
    put_u64_le(header + 32, current_event_pc);
    put_u64_le(header + 40, getpid());
    put_u64_le(header + 48, cpu_index);
    put_u64_le(header + 56, trace->valid ? trace->count : 0);
    put_u64_le(header + 64, trace->sequence);
    put_u64_le(header + 72, trace->first_pc);
    put_u64_le(header + 80, trace->last_pc);
    put_u64_le(header + 88, trace->instruction_count);
    memcpy(header + 96, trace->code_sha256, 32);
    if (!write_full(socket_fd, header, sizeof(header))) protocol_failure("DMB trace header write");
    for (uint32_t i = 0; trace->valid && i < trace->count; i++) {
        const FocDmbRow *r = &trace->rows[i];
        uint8_t row[DMB_TRACE_ROW_SIZE] = {0};
        put_u64_le(row, r->ordinal); put_u64_le(row + 8, r->instruction_ordinal);
        put_u64_le(row + 16, r->pc); put_u64_le(row + 24, r->address);
        put_u64_le(row + 32, r->size); put_u32_le(row + 40, r->kind);
        put_u32_le(row + 44, r->domain); put_u32_le(row + 48, r->types);
        put_u32_le(row + 52, r->word); put_u32_le(row + 56, r->cflags);
        put_u32_le(row + 60, r->bar); put_u32_le(row + 64, r->emitted);
        if (!write_full(socket_fd, row, sizeof(row))) protocol_failure("DMB trace row write");
    }
}

static void command_loop(unsigned int cpu_index)
{
    uint8_t command[COMMAND_SIZE];
    while (true) {
        if (!read_full(socket_fd, command, sizeof(command))) {
            protocol_failure("validator disconnected during an instruction callback");
        }
        if (!reserved_command_bytes_are_zero(command)) {
            protocol_failure("command reserved bytes are nonzero");
        }

        switch (command[0]) {
        case COMMAND_READ_REGISTER:
            send_register(cpu_index, command);
            break;
        case COMMAND_READ_MEMORY:
            send_memory(command);
            break;
        case COMMAND_MEMORY_PERMISSIONS:
            send_memory_permissions(command);
            break;
        case COMMAND_PIN_VDSO:
            pin_initial_vdso(command);
            break;
        case COMMAND_PRIVATE_RAM:
            send_private_ram(command);
            break;
        case COMMAND_PRIVATE_INVENTORY:
            send_private_inventory(command);
            break;
        case COMMAND_VERIFY_INVENTORY:
            verify_private_inventory(command);
            break;
        case COMMAND_PRIVATE_ATOMIC_ENV:
            send_private_atomic_environment(command);
            break;
        case COMMAND_OBSERVE_BTI_PAGE:
            observe_bti_page(command);
            break;
        case COMMAND_RECLAIM_PLAN:
            reclaim_snapshot_plan(command);
            break;
        case COMMAND_ASYNC_SIGNAL_TRACE:
            query_async_signal(command, cpu_index);
            break;
        case COMMAND_DMB_TRACE:
            observe_dmb_trace(command, cpu_index);
            break;
        case COMMAND_GUEST_LOGICAL_SIGNAL:
            observe_guest_logical_signal(command, cpu_index);
            break;
        case COMMAND_GUEST_LOGICAL_SIGNAL_V2:
            observe_guest_logical_signal_v2(command, cpu_index);
            break;
        case COMMAND_INSTALL_PLAN:
            install_snapshot_plan(command);
            break;
        case COMMAND_CAPTURE_PLAN:
            (void)capture_snapshot_plan(cpu_index, command);
            break;
        case COMMAND_DRAIN_STORE_FOOTPRINT:
            drain_store_footprint(command);
            break;
        case COMMAND_STEP:
            clear_private_inventory();
            if (online_store_footprint && !footprint_drained) {
                protocol_failure("advance without draining store footprint");
            }
            at_tb_boundary = false;
            return;
        case COMMAND_FINISH:
            clear_private_inventory();
            if (!write_full(socket_fd, finish_ack, sizeof(finish_ack))) {
                protocol_failure("unable to acknowledge finish command");
            }
            finished = true;
            close(socket_fd);
            socket_fd = -1;
            return;
        case COMMAND_ABORT:
            clear_private_inventory();
            write_full(socket_fd, abort_ack, sizeof(abort_ack));
            close(socket_fd);
            socket_fd = -1;
            _exit(PROTOCOL_FAILURE_STATUS);
        default:
            protocol_failure("unknown command opcode");
        }
    }
}

static void send_event_wait(unsigned int cpu_index, uint8_t kind, uint64_t pc,
                       uint64_t address, uint64_t size, uint64_t auxiliary,
                       const uint8_t value[16], bool automatic)
{
    uint8_t event[EVENT_SIZE] = {0};
    footprint_drained = false;
    event[0] = kind;
    event[1] = automatic;
    current_event_kind = kind;
    current_event_pc = pc;
    current_event_vcpu = cpu_index;
    put_u64_le(event + 8, ++event_sequence);
    put_u64_le(event + 16, ++event_epoch);
    put_u64_le(event + 24, pc);
    put_u64_le(event + 32, address);
    put_u64_le(event + 40, size);
    put_u64_le(event + 48, auxiliary);
    if (value != NULL) memcpy(event + 56, value, 16);
    if (!write_full(socket_fd, event, sizeof(event))) {
        protocol_failure("unable to send ordered event");
    }
    if (!automatic) command_loop(cpu_index);
}

static void send_event(unsigned int cpu_index, uint8_t kind, uint64_t pc,
                       uint64_t address, uint64_t size, uint64_t auxiliary,
                       const uint8_t value[16])
{
    send_event_wait(cpu_index, kind, pc, address, size, auxiliary, value, false);
}

static void observe_async_signal(unsigned int cpu_index, uint32_t stage,
    uint64_t frame_address, uint64_t frame_size, int32_t signal, int32_t result,
    const QemuPluginAsyncSignalState *state, void *userdata)
{
    (void)userdata;
    if (finished) return;
    if (!async_signal_enabled || cpu_index || !event_sequence || !state ||
        state->version != 1 || stage < 1 || stage > 6 ||
        state->valid != (stage <= 3 ? 7u : 5u))
        protocol_failure("unsupported async signal source snapshot");
    if (dmb_trace_enabled) dmb_active->valid = false;
    bool pre = stage == 1 || stage == 4;
    if (pre) {
        if (async_signal_pending || result) protocol_failure("nested async source transition");
        async_signal_pending = true; async_signal_pre_stage = stage;
    } else {
        if (!async_signal_pending ||
            !((async_signal_pre_stage == 1 && (stage == 2 || stage == 3)) ||
              (async_signal_pre_stage == 4 && (stage == 5 || stage == 6))) ||
            frame_address != async_signal_frame || frame_size != async_signal_size ||
            signal != async_signal_number ||
            ((stage == 2 || stage == 5) ? result != 0 : result == 0))
            protocol_failure("unpaired async signal source transition");
        async_signal_pending = false;
    }
    async_signal_state = *state;
    async_signal_stage = stage; async_signal_frame = frame_address;
    async_signal_size = frame_size; async_signal_number = signal;
    async_signal_result = result;
    uint64_t pc = get_u64_le(state->cpu_le + 256);
    send_event(cpu_index, EVENT_ASYNC_SIGNAL, pc, frame_address, frame_size, stage, NULL);
}

static uint64_t read_register_u64(const char *name)
{
    struct qemu_plugin_register *handle = g_hash_table_lookup(registers, name);
    g_autoptr(GByteArray) value = g_byte_array_new();
    if (handle == NULL || qemu_plugin_read_register(handle, value) <= 0 ||
        value->len < sizeof(uint64_t)) {
        protocol_failure("required event register became unavailable");
    }
    return get_u64_le(value->data);
}

static void flush_pending_events(unsigned int cpu_index, uint64_t successor_pc)
{
    for (guint index = 0; index < pending_stores->len; index++) {
        PendingStore *store = &g_array_index(pending_stores, PendingStore, index);
        send_event(cpu_index, EVENT_STORE, store->pc, store->address,
                   store->size, 0, store->value);
    }
    g_array_set_size(pending_stores, 0);

    if (pending_svc) {
        uint64_t result = read_register_u64("x0");
        send_event(cpu_index, EVENT_AARCH64_SVC_SUCCESSOR, successor_pc,
                   pending_svc_pc, 0, result, NULL);
        pending_svc = false;
    }
}

static void execute_translation_block(unsigned int cpu_index, void *userdata)
{
    TranslationBlockMetadata *metadata = userdata;
    if (finished) return;
    if (metadata->pinned_vdso) verify_pinned_vdso();

    if (dmb_trace_enabled) {
        FocDmbTrace *swap = dmb_frozen;
        dmb_frozen = dmb_active;
        dmb_active = swap;
        dmb_active->valid = false;
    }
    online_tb_last_pc = metadata->last_pc;
    boundary_pc = metadata->first_pc;
    at_tb_boundary = true;
    SnapshotPlan *plan = g_hash_table_lookup(snapshot_plans, &boundary_pc);
    if (automatic_snapshots && plan != NULL && plan->memory_count == 0 &&
        plan->predecessor_pc == previous_boundary_pc) {
        uint8_t command[COMMAND_SIZE] = { COMMAND_CAPTURE_PLAN };
        put_u64_le(command + 8, boundary_pc);
        put_u64_le(command + 16, plan->generation);
        send_event_wait(cpu_index, EVENT_TRANSLATION_BLOCK, metadata->first_pc,
                        metadata->last_pc, metadata->instruction_count, 0, NULL, true);
        if (capture_snapshot_plan(cpu_index, command)) {
            at_tb_boundary = false;
            previous_boundary_pc = boundary_pc;
            return;
        }
        command_loop(cpu_index);
    } else {
        send_event(cpu_index, EVENT_TRANSLATION_BLOCK, metadata->first_pc,
                   metadata->last_pc, metadata->instruction_count, 0, NULL);
    }
    if (dmb_trace_enabled) {
        foc_dmb_begin(dmb_active, event_sequence, metadata->first_pc,
                      metadata->last_pc, metadata->instruction_count,
                      metadata->code_sha256);
    }
    previous_boundary_pc = boundary_pc;
}

static void execute_instruction(unsigned int cpu_index, void *userdata)
{
    InstructionMetadata *metadata = userdata;
    if (finished) return;

    if (!online_blocks) {
        flush_pending_events(cpu_index, metadata->address);
    } else {
        /* Preserve program order for stores followed by another instruction in
         * the same TB.  Final stores are flushed by the next TB callback. */
        for (guint index = 0; index < pending_stores->len; index++) {
            PendingStore *store = &g_array_index(pending_stores, PendingStore, index);
            send_event(cpu_index, EVENT_STORE, store->pc, store->address,
                       store->size, 0, store->value);
        }
        g_array_set_size(pending_stores, 0);
    }
    if (metadata->svc) {
        uint64_t number = read_register_u64("x8");
        uint64_t argument = read_register_u64("x0");
        send_event(cpu_index, EVENT_AARCH64_SVC_ENTRY, metadata->address,
                   argument, 0, number, NULL);
        pending_svc = true;
        pending_svc_pc = metadata->address;
    }
    if (metadata->cutpoint) {
        send_event(cpu_index, EVENT_CUTPOINT, metadata->address, 0, 0, 0, NULL);
    }
}

static void syscall_entry(qemu_plugin_id_t id, unsigned int cpu_index,
                          int64_t number, uint64_t argument0, uint64_t argument1,
                          uint64_t argument2, uint64_t argument3, uint64_t argument4,
                          uint64_t argument5, uint64_t argument6, uint64_t argument7)
{
    (void)id;
    (void)argument1;
    (void)argument2;
    (void)argument3;
    (void)argument4;
    (void)argument5;
    (void)argument6;
    (void)argument7;
    if (atomic_model_present && !strcmp(target_name, "x86_64")) {
        if (atomic_syscall_pending || cpu_index != 0) atomic_policy_valid = false;
        atomic_syscall_pending = true;
        if (number != 334 && !qemu_private_atomic_sync_syscall(number, argument1, argument2)) atomic_policy_valid = false;
    }
    if (!online_blocks || finished) return;
    if (pending_svc) protocol_failure("nested online syscall entry");
    send_event(cpu_index, EVENT_AARCH64_SVC_ENTRY, online_tb_last_pc,
               argument0, 0, (uint64_t)number, NULL);
    pending_svc = true;
    pending_svc_pc = online_tb_last_pc;
}

static void syscall_return(qemu_plugin_id_t id, unsigned int cpu_index,
                           int64_t number, int64_t result)
{
    (void)id;
    (void)number;
    if (atomic_model_present && !strcmp(target_name, "x86_64")) {
        if (!atomic_syscall_pending || cpu_index != 0 || (number == 334 && result != -ENOSYS)) atomic_policy_valid = false;
        atomic_syscall_pending = false;
    }
    if (!online_blocks || finished) return;
    if (!pending_svc) protocol_failure("online syscall return without entry");
    send_event(cpu_index, EVENT_AARCH64_SVC_SUCCESSOR, 0,
               pending_svc_pc, 0, (uint64_t)result, NULL);
    pending_svc = false;
}

/* Passive address/size evidence only. NO_REGS maps to TCG_CALL_NO_RWG:
 * this callback neither reads nor writes guest CPU globals. No register/value
 * observation, instruction execution callback, allocation, or socket stop is
 * introduced at individual stores. Stores from translated helper paths are
 * also delivered by QEMU's memory callback API. */
static void record_store_footprint(unsigned int cpu_index,
                                   qemu_plugin_meminfo_t info,
                                   uint64_t address, void *userdata)
{
    unsigned int shift = qemu_plugin_mem_size_shift(info);
    (void)userdata;
    if (finished) return;
    if (cpu_index != 0 || event_sequence == 0 || shift > 4 ||
        store_footprint_count == MAX_STORE_FOOTPRINT) {
        protocol_failure("invalid or overflowing store footprint");
    }
    uint64_t size = 1ull << shift;
    if (address > UINT64_MAX - (size - 1)) {
        protocol_failure("wrapping store footprint");
    }
    store_footprint[store_footprint_count++] = (StoreSpan){ address, size };
}

static void record_store(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                         uint64_t vaddr, void *userdata)
{
    (void)cpu_index;
    (void)userdata;
    qemu_plugin_mem_value accessed = qemu_plugin_mem_get_value(info);
    InstructionMetadata *metadata = userdata;
    PendingStore store = { .pc = metadata->address, .address = vaddr };
    switch (accessed.type) {
    case QEMU_PLUGIN_MEM_VALUE_U8: store.size = 1; store.value[0] = accessed.data.u8; break;
    case QEMU_PLUGIN_MEM_VALUE_U16: store.size = 2; memcpy(store.value, &accessed.data.u16, 2); break;
    case QEMU_PLUGIN_MEM_VALUE_U32: store.size = 4; memcpy(store.value, &accessed.data.u32, 4); break;
    case QEMU_PLUGIN_MEM_VALUE_U64: store.size = 8; memcpy(store.value, &accessed.data.u64, 8); break;
    case QEMU_PLUGIN_MEM_VALUE_U128:
        store.size = 16;
        memcpy(store.value, &accessed.data.u128.low, 8);
        memcpy(store.value + 8, &accessed.data.u128.high, 8);
        break;
    default: protocol_failure("unsupported store width");
    }
    g_array_append_val(pending_stores, store);
}

static bool is_explicit_cutpoint(uint64_t address)
{
    for (guint index = 0; index < explicit_cutpoints->len; index++) {
        if (address == g_array_index(explicit_cutpoints, uint64_t, index)) {
            return true;
        }
    }
    return false;
}

static void record_dmb_execution(unsigned int cpu_index, void *userdata)
{
    DmbInstructionMetadata *m = userdata;
    const QemuPluginDmbTranslation *t = &m->translation;
    FocDmbRow row = { .instruction_ordinal = m->ordinal, .pc = m->pc,
        .kind = FOC_DMB_BARRIER, .domain = t->domain, .types = t->types,
        .word = t->word, .cflags = t->cflags, .bar = t->bar,
        .emitted = t->emitted };
    if (!finished) foc_dmb_append(dmb_active, row, cpu_index);
}

static void record_dmb_memory(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                               uint64_t address, void *userdata)
{
    DmbInstructionMetadata *m = userdata;
    unsigned int shift = qemu_plugin_mem_size_shift(info);
    FocDmbRow row = { .instruction_ordinal = m->ordinal, .pc = m->pc,
        .address = address, .size = shift <= 4 ? 1ull << shift : 0,
        .kind = qemu_plugin_mem_is_store(info) ? FOC_DMB_WRITE : FOC_DMB_READ };
    if (!finished) foc_dmb_append(dmb_active, row, cpu_index);
}

static void instrument_translation_block(
    qemu_plugin_id_t id,
    struct qemu_plugin_tb *translation_block
)
{
    (void)id;
    size_t instruction_count = qemu_plugin_tb_n_insns(translation_block);
    if (online_blocks) {
        if (instruction_count == 0) {
            protocol_failure("translated an empty block");
        }
        TranslationBlockMetadata *block = g_new0(TranslationBlockMetadata, 1);
        block->instruction_count = instruction_count;
        GChecksum *dmb_code = dmb_trace_enabled ? g_checksum_new(G_CHECKSUM_SHA256) : NULL;
        uint64_t expected_address = 0;
        for (size_t index = 0; index < instruction_count; index++) {
            uint64_t address = qemu_plugin_insn_vaddr(
                qemu_plugin_tb_get_insn(translation_block, index)
            );
            uint64_t instruction_size = qemu_plugin_insn_size(
                qemu_plugin_tb_get_insn(translation_block, index)
            );
            bool root = address >= start_address && address <= stop_address;
            bool vdso = vdso_instruction_span(address, instruction_size);
            if ((index != 0 && address != expected_address) || instruction_size == 0 ||
                instruction_size > UINT64_MAX - address || (!root && !vdso) || (index != 0 && block->pinned_vdso != vdso)) {
                protocol_failure("online block is not contiguous in a declared executable image");
            }
            if (vdso) {
                uint8_t code[4];
                if (instruction_size != 4 || address % 4 ||
                    qemu_plugin_insn_data(qemu_plugin_tb_get_insn(translation_block, index),
                                          code, sizeof(code)) != sizeof(code) ||
                    memcmp(code, pinned_vdso->bytes + (address - pinned_vdso->base), sizeof(code))) {
                    protocol_failure("translated vDSO instruction differs from initial pin");
                }
            }
            if (index == 0) {
                block->first_pc = address;
                block->pinned_vdso = vdso;
            }
            block->last_pc = address;
            expected_address = address + instruction_size;
            if (dmb_trace_enabled) {
                struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(translation_block, index);
                uint8_t bytes[4];
                if (instruction_size != 4 || qemu_plugin_insn_data(insn, bytes, 4) != 4)
                    protocol_failure("DMB trace requires complete A64 instruction bytes");
                g_checksum_update(dmb_code, bytes, 4);
                DmbInstructionMetadata *m = g_new0(DmbInstructionMetadata, 1);
                m->pc = address; m->ordinal = index;
                if (qemu_plugin_insn_dmb_translation(insn, &m->translation)) {
                    qemu_plugin_register_vcpu_insn_exec_cb(insn, record_dmb_execution,
                        QEMU_PLUGIN_CB_NO_REGS, m);
                }
                qemu_plugin_register_vcpu_mem_cb(insn, record_dmb_memory,
                    QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, m);
            }
            if (online_store_footprint) {
                qemu_plugin_register_vcpu_mem_cb(
                    qemu_plugin_tb_get_insn(translation_block, index),
                    record_store_footprint, QEMU_PLUGIN_CB_NO_REGS,
                    QEMU_PLUGIN_MEM_W, NULL);
            }
        }
        if (dmb_code) {
            gsize digest_size = sizeof(block->code_sha256);
            g_checksum_get_digest(dmb_code, block->code_sha256, &digest_size);
            g_checksum_free(dmb_code);
        }
        qemu_plugin_register_vcpu_tb_exec_cb(
            translation_block, execute_translation_block,
            QEMU_PLUGIN_CB_R_REGS, block
        );
        /* No register-observing instruction callbacks or inline observations.
         * DMB trace uses only nonblocking NO_REGS execution/memory markers.
         * The opt-in passive memory callback has NO_RWG, unlike register-reading
         * callbacks that synchronize globals and inhibit cross-insn folding. */
        return;
    }
    for (size_t index = 0; index < instruction_count; index++) {
        struct qemu_plugin_insn *instruction =
            qemu_plugin_tb_get_insn(translation_block, index);
        uint64_t address = qemu_plugin_insn_vaddr(instruction);
        if (address < start_address || address > stop_address) continue;
        uint32_t opcode = 0;
        bool svc = false;
        if (strcmp(target_name, "aarch64") == 0 ||
            strcmp(target_name, "aarch64_be") == 0) {
            if (qemu_plugin_insn_data(instruction, &opcode, sizeof(opcode)) == sizeof(opcode)) {
                svc = (opcode & 0xffe0001fu) == 0xd4000001u;
            }
        }
        InstructionMetadata *metadata = g_new0(InstructionMetadata, 1);
        metadata->address = address;
        metadata->svc = svc;
        metadata->cutpoint = !coarse_cutpoints || address == start_address ||
                             address == stop_address || is_explicit_cutpoint(address);
        qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
            instruction,
            QEMU_PLUGIN_INLINE_STORE_U64,
            instruction_address,
            address
        );
        qemu_plugin_register_vcpu_insn_exec_cb(
            instruction,
            execute_instruction,
            QEMU_PLUGIN_CB_R_REGS,
            metadata
        );
        qemu_plugin_register_vcpu_mem_cb(
            instruction, record_store, QEMU_PLUGIN_CB_NO_REGS,
            QEMU_PLUGIN_MEM_W, metadata
        );
    }
}

static void plugin_exit(qemu_plugin_id_t id, void *userdata)
{
    (void)id;
    (void)userdata;
    if (socket_fd != -1) {
        close(socket_fd);
        socket_fd = -1;
    }
    if (registers != NULL) {
        g_hash_table_destroy(registers);
        registers = NULL;
    }
    if (snapshot_plans != NULL) {
        g_hash_table_destroy(snapshot_plans);
        snapshot_plans = NULL;
    }
    if (pending_stores != NULL) {
        g_array_free(pending_stores, true);
        pending_stores = NULL;
    }
    if (explicit_cutpoints != NULL) {
        g_array_free(explicit_cutpoints, true);
        explicit_cutpoints = NULL;
    }
    if (scoreboard != NULL) {
        qemu_plugin_scoreboard_free(scoreboard);
        scoreboard = NULL;
    }
    g_clear_pointer(&socket_path, g_free);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(
    qemu_plugin_id_t id,
    const qemu_info_t *info,
    int argc,
    char **argv
)
{
    explicit_cutpoints = g_array_new(false, false, sizeof(uint64_t));
    if (info->system_emulation || !select_target(info) || !parse_options(argc, argv)) {
        fprintf(stderr, "Unsupported Focaccia plugin target or options\n");
        return -1;
    }

    registers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    pending_stores = g_array_new(false, false, sizeof(PendingStore));
    snapshot_plans = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
    scoreboard = qemu_plugin_scoreboard_new(sizeof(FocacciaScoreboard));
    instruction_address = qemu_plugin_scoreboard_u64_in_struct(
        scoreboard,
        FocacciaScoreboard,
        instruction_address
    );

    if (async_signal_enabled && !qemu_plugin_register_async_signal_observer(
            id, observe_async_signal, NULL)) {
        fprintf(stderr, "Async signal source observer unavailable or already registered\n");
        return -1;
    }
    qemu_plugin_register_vcpu_init_cb(id, initialize_vcpu);
    qemu_plugin_register_vcpu_tb_trans_cb(id, instrument_translation_block);
    qemu_plugin_register_vcpu_syscall_cb(id, syscall_entry);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, syscall_return);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
