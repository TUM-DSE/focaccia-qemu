#include <stdio.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static void plugin_init(void) {
}

static void plugin_exit(qemu_plugin_id_t id, void* p) {
    printf("Plugin has completed!\n");
}

static void concolic_trace(unsigned int cpu_index, void *udata) {
    printf("Translation executed on CPU %u\n", cpu_index);
}

static void register_tracer(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    qemu_plugin_register_vcpu_tb_exec_cb(tb, concolic_trace,
                                         QEMU_PLUGIN_CB_R_REGS, NULL);
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

    qemu_plugin_register_vcpu_tb_trans_cb(id, register_tracer);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}

