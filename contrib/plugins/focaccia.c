#include <errno.h>
#include <glib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <qemu-plugin.h>

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

#define CAP_PC (1ull << 0)
#define CAP_INTEGER (1ull << 1)
#define CAP_STATUS (1ull << 2)
#define CAP_VECTOR (1ull << 3)
#define CAP_TLS (1ull << 4)
#define CAP_AARCH64_SVC (1ull << 5)
#define REGISTER_NAME_SIZE 32u

#define COMMAND_READ_REGISTER 1u
#define COMMAND_READ_MEMORY 2u
#define COMMAND_STEP 3u
#define COMMAND_FINISH 4u
#define COMMAND_ABORT 5u

#define EVENT_CUTPOINT 1u
#define EVENT_STORE 2u
#define EVENT_AARCH64_SVC_ENTRY 3u
#define EVENT_AARCH64_SVC_SUCCESSOR 4u
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
    uint64_t address;
    uint64_t size;
    uint8_t value[16];
} PendingStore;

typedef struct {
    uint64_t address;
    bool cutpoint;
    bool svc;
} InstructionMetadata;

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
static GArray *explicit_cutpoints;
static bool initialized;
static bool finished;
static uint8_t launch_identity[4][IDENTITY_DIGEST_SIZE];
static bool identity_present[4];
static uint64_t capabilities;
static uint64_t event_sequence;
static uint64_t event_epoch;
static bool pending_svc;
static uint64_t pending_svc_pc;
static GArray *pending_stores;

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
        } else if (g_str_has_prefix(option, "cutpoint=")) {
            uint64_t address;
            if (!parse_address(option + strlen("cutpoint="), &address)) {
                return false;
            }
            g_array_append_val(explicit_cutpoints, address);
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
    if (initialized || vcpu_index != 0) {
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
    capabilities = CAP_PC;
    if (strcmp(target_name, "x86_64") == 0) {
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
        response[0] = RESPONSE_OK;
        response[1] = 8;
        memcpy(response + 8, pc_register, strlen(pc_register));
        put_target_u64(
            response + 40,
            qemu_plugin_u64_get(instruction_address, cpu_index)
        );
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

static bool reserved_command_bytes_are_zero(const uint8_t *command)
{
    for (size_t index = 1; index < 8; index++) {
        if (command[index] != 0) {
            return false;
        }
    }
    return true;
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
        case COMMAND_STEP:
            return;
        case COMMAND_FINISH:
            if (!write_full(socket_fd, finish_ack, sizeof(finish_ack))) {
                protocol_failure("unable to acknowledge finish command");
            }
            finished = true;
            close(socket_fd);
            socket_fd = -1;
            return;
        case COMMAND_ABORT:
            write_full(socket_fd, abort_ack, sizeof(abort_ack));
            close(socket_fd);
            socket_fd = -1;
            _exit(PROTOCOL_FAILURE_STATUS);
        default:
            protocol_failure("unknown command opcode");
        }
    }
}

static void send_event(unsigned int cpu_index, uint8_t kind, uint64_t pc,
                       uint64_t address, uint64_t size, uint64_t auxiliary,
                       const uint8_t value[16])
{
    uint8_t event[EVENT_SIZE] = {0};
    event[0] = kind;
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
    command_loop(cpu_index);
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

static void execute_instruction(unsigned int cpu_index, void *userdata)
{
    InstructionMetadata *metadata = userdata;
    if (finished) return;

    for (guint index = 0; index < pending_stores->len; index++) {
        PendingStore *store = &g_array_index(pending_stores, PendingStore, index);
        send_event(cpu_index, EVENT_STORE, metadata->address, store->address,
                   store->size, 0, store->value);
    }
    g_array_set_size(pending_stores, 0);

    if (pending_svc) {
        uint64_t result = read_register_u64("x0");
        send_event(cpu_index, EVENT_AARCH64_SVC_SUCCESSOR, metadata->address,
                   pending_svc_pc, 0, result, NULL);
        pending_svc = false;
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

static void record_store(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                         uint64_t vaddr, void *userdata)
{
    (void)cpu_index;
    (void)userdata;
    qemu_plugin_mem_value accessed = qemu_plugin_mem_get_value(info);
    PendingStore store = { .address = vaddr };
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

static void instrument_translation_block(
    qemu_plugin_id_t id,
    struct qemu_plugin_tb *translation_block
)
{
    (void)id;
    size_t instruction_count = qemu_plugin_tb_n_insns(translation_block);
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
            QEMU_PLUGIN_MEM_W, NULL
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
    scoreboard = qemu_plugin_scoreboard_new(sizeof(FocacciaScoreboard));
    instruction_address = qemu_plugin_scoreboard_u64_in_struct(
        scoreboard,
        FocacciaScoreboard,
        instruction_address
    );

    qemu_plugin_register_vcpu_init_cb(id, initialize_vcpu);
    qemu_plugin_register_vcpu_tb_trans_cb(id, instrument_translation_block);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
