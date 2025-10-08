#include <stdio.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static void plugin_init(void) {
}

static void plugin_exit(qemu_plugin_id_t id, void* p) {
    printf("Plugin has completed!\n");
}

// argc and argv correspond to the arguments passed via -plugin focaccia.so,arg1=<arg1>,arg2=<arg2>
QEMU_PLUGIN_EXPORT 
int qemu_plugin_install(qemu_plugin_id_t id,
                        const qemu_info_t *info,
                        int argc, char **argv)
{
    int i;

    // Process plugin arguments
    printf("Received plugin options:\n");
    for (i = 0; i < argc; i++) {
        printf("%s\n", argv[i]);
    }

    plugin_init();

    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}

