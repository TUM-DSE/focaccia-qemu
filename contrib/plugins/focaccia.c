#include <glib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>


#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct {
    unsigned long long pc;
    unsigned long long virt;
    unsigned long long offset;
    unsigned long long length;
} PCTracker;

enum Granularity {
    UNDEF = -1,
    BASIC_BLOCK,
    INSTRUCTION
};

typedef struct __attribute__((packed)) Command {
    union {
        struct {
            long long addr;
            long long val;
        } _mem;
        struct {
            char reg_name[16];
        } _reg;
        struct {
            char unused[16];
        } _step;
    } data;
    char cmd[9];
} Command;

typedef struct __attribute__((packed)) Register {
    char name[108];
    unsigned long nr_bytes;
    char value[64];
} Register;

typedef struct __attribute__((packed)) Memory {
    unsigned long long addr;
    unsigned long nr_bytes;
} Memory;

static int SockFD = -1;

struct qemu_plugin_scoreboard *state;
qemu_plugin_u64 PC;
qemu_plugin_u64 Virt;
qemu_plugin_u64 Offset;
qemu_plugin_u64 Len;

GHashTable *reg_map;

#define SOCK_PATH "/tmp/focaccia.sock"


static void plugin_init(void) {

    state = qemu_plugin_scoreboard_new(sizeof(PCTracker));
    PC = qemu_plugin_scoreboard_u64_in_struct(state, PCTracker, pc);
    Virt = qemu_plugin_scoreboard_u64_in_struct(state, PCTracker, virt);
    Offset = qemu_plugin_scoreboard_u64_in_struct(state, PCTracker, offset);
    Len = qemu_plugin_scoreboard_u64_in_struct(state, PCTracker, length);

    reg_map = g_hash_table_new(g_str_hash, g_str_equal);
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    // New execution
    // Save register indexes

    g_autoptr(GArray) reg_list = qemu_plugin_get_registers();
    for (int r = 0; r < reg_list->len; r++) {
        qemu_plugin_reg_descriptor *rd = &g_array_index(reg_list, qemu_plugin_reg_descriptor, r);
        g_hash_table_insert(reg_map, g_strdup(rd->name), GINT_TO_POINTER(r+1)); // g_hash_table cannot deal with NULL values
    }

    // Register with focaccia over a socket

    // Connect to socket and send initial handshake
    SockFD = socket(AF_UNIX, SOCK_STREAM, 0);
    if (SockFD == -1) {
        perror("socket");
        exit(-1);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);
    if (connect(SockFD, &addr, sizeof(addr)) == -1) {
        perror("connect");
        close(SockFD);
        exit(-1);
    }

    // Send ping
    const int pid = getpid();
    int r = write(SockFD, &pid, sizeof(int));
    if (r != sizeof(int)) {
        fprintf(stderr, "Error writing PID to socket\n");
    }
}

static void plugin_exit(qemu_plugin_id_t id, void* p) {
    if (SockFD != -1) {
        close(SockFD);
    }
    printf("Plugin has completed!\n");
}

static void read_register(unsigned int cpu_index, Command cmd) {
    // printf("Read register command received for register: %s\n", cmd.data._reg.reg_name);
    // Get all exposed registers
    g_autoptr(GArray) reg_list = qemu_plugin_get_registers();

    gpointer map_val = g_hash_table_lookup(reg_map, cmd.data._reg.reg_name);

    if (map_val == NULL) {
        printf("Register %s unknown to QEMU\n", cmd.data._reg.reg_name);
        Register fail;
        memset(&fail, 0, sizeof(Register));
        strncpy(fail.name, "UNKNOWN", sizeof(fail.name) - 1);
        int ret = write(SockFD, &fail, sizeof(Register));
        if (ret != sizeof(Register)) {
            fprintf(stderr, "Error writing unknown response\n");
        }

        return;
    }

    Register reg;
    if (strncmp(cmd.data._reg.reg_name, "rip", 4) == 0) {
        unsigned long long rip = qemu_plugin_u64_get(Virt, cpu_index);
        strncpy(reg.name, "rip", sizeof(reg.name) - 1);
        reg.nr_bytes = sizeof(rip);
        memcpy(reg.value, &rip, sizeof(rip));
    } else {


        int idx = GPOINTER_TO_INT(map_val)-1;
        qemu_plugin_reg_descriptor *rd = &g_array_index(reg_list, qemu_plugin_reg_descriptor, idx);

        GByteArray *buf = g_byte_array_new();
        int sz = qemu_plugin_read_register(rd->handle, buf);

        if (sz <= 0) {
            fprintf(stderr, "Error reading register %s\n", rd->name);
            g_byte_array_free(buf, TRUE);
            exit(-1);
        }

        strncpy(reg.name, rd->name, sizeof(reg.name) - 1);
        reg.nr_bytes = sz;
        memcpy(reg.value, buf->data, sz);
    }

    // Send PC value over socket
    int ret = write(SockFD, &reg, sizeof(Register));
    if (ret != sizeof(Register)) {
        fprintf(stderr, "Error writing register %s to socket\n", cmd.data._reg.reg_name);
    }
}

static void read_memory(Command cmd) {

    GByteArray *data = g_byte_array_new();
    if (!qemu_plugin_read_memory_vaddr(cmd.data._mem.addr, data, cmd.data._mem.val)) {
        fprintf(stderr, "Error reading memory at address 0x%llx\n", cmd.data._mem.addr);
        g_byte_array_free(data, TRUE);

        Memory fail = {0, 0};
        int ret = write(SockFD, &fail, sizeof(fail));
        if (ret != sizeof(fail)) {
            fprintf(stderr, "Error writing failing response\n");
        }

        return;
    }

    if (data->len != cmd.data._mem.val)
        fprintf(stderr, "Read memory size mismatch at address 0x%llx\n", cmd.data._mem.addr);

    Memory mem;
    mem.addr = cmd.data._mem.addr;
    mem.nr_bytes = data->len;

    int ret = write(SockFD, &mem, sizeof(Memory));
    if (ret != sizeof(Memory)) {
        fprintf(stderr, "Error writing memory header to socket\n");
    }

    int written = 0;
    while (written < data->len) {
        int _ret = write(SockFD, data->data + written, data->len - written);
        if (_ret == -1) {
            fprintf(stderr, "Error sending memory content\n");
        }
        written += _ret;
    }
}

static void execute_step(unsigned int cpu_index, void *udata) {

    // Conceptually we can now read the state *before* the instruction executes
    Command cmd;

    // Reset PC and Offset if it does not match $rip
    g_autoptr(GArray) reg_list = qemu_plugin_get_registers();

    gpointer map_val = g_hash_table_lookup(reg_map, "rip");

    if (map_val == NULL) {
        printf("RIP not cached\n");
        Register fail;
        memset(&fail, 0, sizeof(Register));
        strncpy(fail.name, "UNKNOWN", sizeof(fail.name) - 1);
        int ret = write(SockFD, &fail, sizeof(Register));
        if (ret != sizeof(Register)) {
            fprintf(stderr, "Error writing unknown response\n");
        }

        exit(-1);
    }

    int idx = GPOINTER_TO_INT(map_val)-1;
    qemu_plugin_reg_descriptor *rd = &g_array_index(reg_list, qemu_plugin_reg_descriptor, idx);

    GByteArray *buf = g_byte_array_new();
    int sz = qemu_plugin_read_register(rd->handle, buf);
    if (sz <= 0) {
        fprintf(stderr, "Error reading register %s\n", rd->name);
        g_byte_array_free(buf, TRUE);
        exit(-1);
    }
    unsigned long long rip = 0;
    memcpy(&rip, buf->data, sz);
    if (qemu_plugin_u64_get(PC, cpu_index) != rip) {
        qemu_plugin_u64_set(PC, cpu_index, rip);
        qemu_plugin_u64_set(Offset, cpu_index, 0);
    }

    while (1) {
        // assume we read 23bytes at once
        ssize_t n = read(SockFD, &cmd, sizeof(Command));
        if (n < 0) {
            perror("Error reading from socket\n");
            exit(-1);
        }
        if (n == 0) {
            printf("Facaccia server disconnected\n");
            exit(0);
        }
        if (n != sizeof(Command)) {
            printf("Only recieved partial command\n");
            exit(-1);
        }

        if (strncmp(cmd.cmd, "STEP ONE", 9) == 0) {
            qemu_plugin_u64_add(Offset, cpu_index, qemu_plugin_u64_get(Len, cpu_index));
            return; // proceed with execution
        } else if (strncmp(cmd.cmd, "READ REG", 9) == 0) {
            // Read register command
            read_register(cpu_index, cmd);
        } else if (strncmp(cmd.cmd, "READ MEM", 9) == 0) {
            // Write register command
            read_memory(cmd);
        } else {
            printf("Unknown command received: %s\n", cmd.cmd);
            exit(-1);
        }
    }

}

static void register_tracer(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {

    struct qemu_plugin_insn *insn;
    size_t n_insns = qemu_plugin_tb_n_insns(tb);

    // TODO: If granularity is BASIC_BLOCK, only register the first
    for (size_t i = 0; i < n_insns; i++) {
        insn = qemu_plugin_tb_get_insn(tb, i);
        qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn,
                                                      QEMU_PLUGIN_INLINE_STORE_U64,
                                                    Virt, qemu_plugin_insn_vaddr(insn));
        qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn,
                                                      QEMU_PLUGIN_INLINE_STORE_U64,
                                                      Len,
                                                      qemu_plugin_insn_size(insn));

        qemu_plugin_register_vcpu_insn_exec_cb(insn, execute_step, QEMU_PLUGIN_CB_R_REGS, NULL);
    }
}

// argc and argv correspond to the arguments passed via -plugin focaccia.so,arg1=<arg1>,arg2=<arg2>
QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv) {
    int i;

    // Process plugin arguments
    printf("Received plugin options:\n");
    for (i = 0; i < argc; i++) {
        printf("%s\n", argv[i]);
    }

    plugin_init();

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, register_tracer);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}

