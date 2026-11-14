/* Guard-only source environment evidence; never a CPU/poststate snapshot. */
static void atomic_digest(const uint8_t *bytes, size_t size, uint8_t result[32])
{
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(sum, bytes, size);
    gsize length = 32;
    g_checksum_get_digest(sum, result, &length);
    g_checksum_free(sum);
}

static bool atomic_pin_launch_image(const char *path, const char *device, uint64_t inode)
{
    unsigned int device_major, device_minor;
    struct stat before, after;
    if (!atomic_no_host_tamper || !path[0] || path[0] != '/' ||
        strstr(path, " (deleted)") || sscanf(device, "%x:%x", &device_major, &device_minor) != 2) return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = false;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_ino != inode ||
        major(before.st_dev) != device_major || minor(before.st_dev) != device_minor ||
        before.st_size <= 0 || before.st_size > 256 * 1024 * 1024) goto out;
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    uint8_t buffer[65536], digest[32];
    off_t offset = 0;
    while (offset < before.st_size) {
        ssize_t n = pread(fd, buffer, MIN(sizeof(buffer), (size_t)(before.st_size - offset)), offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { g_checksum_free(sum); goto out; }
        g_checksum_update(sum, buffer, n);
        offset += n;
    }
    gsize length = sizeof(digest);
    g_checksum_get_digest(sum, digest, &length);
    g_checksum_free(sum);
    if (memcmp(digest, launch_identity[0], 32) || fstat(fd, &after) ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) goto out;
    if (!atomic_image_pins) atomic_image_pins = g_array_new(false, false, sizeof(int));
    for (guint i = 0; i < atomic_image_pins->len; i++) {
        struct stat pinned;
        int previous = g_array_index(atomic_image_pins, int, i);
        if (!fstat(previous, &pinned) && pinned.st_dev == after.st_dev && pinned.st_ino == after.st_ino) {
            ok = true; goto out;
        }
    }
    if (atomic_image_pins->len >= MAX_PRIVATE_RAM_MAPPINGS) goto out;
    g_array_append_val(atomic_image_pins, fd);
    fd = -1;
    ok = true;
out:
    if (fd >= 0) close(fd);
    return ok;
}

/* Metadata-only scope6: every valid node is normal private RAM or an
 * explicitly classified, unbacked, non-readable/non-writable service. This
 * view is NEVER admissible to command13/external RAM byte readers. */
static void freeze_private_atomic_inventory(const uint8_t *command)
{
    uint8_t header[64] = {0};
    memcpy(header, "FOCATIV\0", 8);
    header[8] = RESPONSE_UNAVAILABLE;
    if (!(capabilities & CAP_PRIVATE_ATOMIC_ENV) ||
        get_u64_le(command + 8) != event_sequence || get_u64_le(command + 16) != event_epoch ||
        get_u64_le(command + 24) || inventory_token == UINT64_MAX) goto unavailable;
    clear_private_inventory();
    FrozenPrivateInventory *item = g_new0(FrozenPrivateInventory, 1);
    item->sequence = event_sequence; item->epoch = event_epoch;
    item->token = ++inventory_token; item->budget = MAX_PRIVATE_RAM_BYTES;
    item->atomic_scope = true;
    item->mappings = g_array_new(false, false, sizeof(qemu_plugin_guest_mapping));
    item->wire = g_byte_array_new();
    if (!qemu_plugin_private_atomic_inventory(item->mappings, item->budget,
            MAX_PRIVATE_RAM_MAPPINGS, &item->generation)) {
        g_array_free(item->mappings, true); g_byte_array_free(item->wire, true); g_free(item);
        goto unavailable;
    }
    for (guint i = 0; i < item->mappings->len; i++) {
        const qemu_plugin_guest_mapping *row = &g_array_index(item->mappings, qemu_plugin_guest_mapping, i);
        uint8_t descriptor[40] = {0};
        put_u64_le(descriptor, row->start); put_u64_le(descriptor + 8, row->size);
        put_u64_le(descriptor + 16, row->host_start); put_u32_le(descriptor + 24, row->flags);
        put_u32_le(descriptor + 28, row->reserved); put_u64_le(descriptor + 32, row->data_offset);
        g_byte_array_append(item->wire, descriptor, sizeof(descriptor));
        if (row->reserved == 0) item->total += row->size;
    }
    private_inventory_header(header, "FOCATIV\0", 2, item, 6);
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(sum, header, sizeof(header));
    g_checksum_update(sum, item->wire->data, item->wire->len);
    gsize digest_size = 32;
    g_checksum_get_digest(sum, item->digest, &digest_size); g_checksum_free(sum);
    if (!write_full(socket_fd, header, sizeof(header)) ||
        !write_full(socket_fd, item->wire->data, item->wire->len) ||
        !write_full(socket_fd, item->digest, 32)) protocol_failure("atomic inventory send failed");
    item->preflight = true; /* Metadata only: attestation independently recollects. */
    frozen_inventory = item;
    return;
unavailable:
    if (!write_full(socket_fd, header, sizeof(header))) protocol_failure("atomic inventory unavailable send failed");
}

static void send_private_atomic_environment(const uint8_t *command)
{
    uint8_t request[120], response[248] = {0};
    uint64_t unavailable_reason = 1;
    g_autoptr(GArray) current = NULL;
    g_autoptr(GByteArray) code = NULL;
    memcpy(response, "FOCATOM\0", 8);
    response[8] = RESPONSE_UNAVAILABLE;
    if (!read_full(socket_fd, request, sizeof(request))) protocol_failure("atomic request truncated");
    if (!memcmp(request, (uint8_t[120]){0}, sizeof(request))) {
        freeze_private_atomic_inventory(command);
        return;
    }
    uint64_t generation = get_u64_le(request), pc = get_u64_le(request + 8);
    uint64_t length = get_u64_le(request + 16);
    FrozenPrivateInventory *item = frozen_inventory;
    if (!atomic_policy_valid) unavailable_reason = 2;
    else if (atomic_syscall_pending || atomic_vcpu_count != 1) unavailable_reason = 3;
    if (!(capabilities & CAP_PRIVATE_ATOMIC_ENV) || !item || !item->atomic_scope || !item->preflight ||
        get_u64_le(command + 8) != event_sequence || get_u64_le(command + 16) != event_epoch ||
        get_u64_le(command + 24) != item->token || item->sequence != event_sequence ||
        item->epoch != event_epoch || generation != item->generation ||
        !atomic_policy_valid || atomic_syscall_pending || !initialized || atomic_vcpu_count != 1 || atomic_execution_actor != (uint64_t)getpid() ||
        !length || length > 15 || pc >= (1ull << 47) || length > (1ull << 47) - pc ||
        memcmp(request + 56, atomic_model_sha256, 32) ||
        memcmp(request + 88, atomic_profile_sha256, 32)) goto unavailable;
    unavailable_reason = 4;
    current = g_array_new(false, false, sizeof(qemu_plugin_guest_mapping));
    uint64_t current_generation = 0;
    if (!qemu_plugin_private_atomic_inventory(current, item->budget, MAX_PRIVATE_RAM_MAPPINGS, &current_generation) ||
        current_generation != generation || current->len != item->mappings->len ||
        memcmp(current->data, item->mappings->data, current->len * sizeof(qemu_plugin_guest_mapping))) goto unavailable;
    unavailable_reason = 5;
    bool executable = false;
    for (guint i = 0; i < current->len; i++) {
        const qemu_plugin_guest_mapping *row = &g_array_index(current, qemu_plugin_guest_mapping, i);
        if (row->reserved == 1) {
            if (row->flags != 76 || row->start != 0xffffffffff600000ull || row->size != 4096 ||
                row->host_start != 0 || row->data_offset != UINT64_MAX) goto unavailable;
            continue; /* Explicit non-RAM service: no byte read or g2h. */
        }
        if (row->reserved != 0 || (row->flags & 24) != 24 || (row->flags & ~31u) ||
            !qemu_private_atomic_backing_bound(row->host_start, row->size, atomic_no_host_tamper, atomic_pin_launch_image)) goto unavailable;
        if (pc >= row->start && pc - row->start < row->size &&
            length <= row->size - (pc - row->start) && (row->flags & 12) == 12 && !(row->flags & 2)) executable = true;
    }
    unavailable_reason = 6;
    if (!executable) goto unavailable;
    unavailable_reason = 7;
    code = g_byte_array_new();
    g_byte_array_set_size(code, length);
    if (!qemu_plugin_read_memory_vaddr(pc, code, length) || code->len != length) goto unavailable;
    uint8_t code_digest[32], launch_digest[32], launch_bytes[193];
    atomic_digest(code->data, length, code_digest);
    unavailable_reason = 8;
    if (memcmp(code_digest, request + 24, 32)) goto unavailable;
    memcpy(launch_bytes, launch_identity, 128);
    memcpy(launch_bytes + 128, atomic_model_sha256, 32);
    memcpy(launch_bytes + 160, atomic_profile_sha256, 32);
    launch_bytes[192] = 1; /* explicit bounded no-host-tamper launch profile */
    atomic_digest(launch_bytes, sizeof(launch_bytes), launch_digest);
    response[8] = RESPONSE_OK;
    put_u64_le(response + 16, event_sequence);
    put_u64_le(response + 24, event_epoch);
    put_u64_le(response + 32, generation);
    put_u64_le(response + 40, item->token);
    put_u64_le(response + 48, getpid());
    put_u64_le(response + 56, atomic_execution_actor); /* observed native execution TID, sole main guest CPU */
    put_u64_le(response + 64, 255); /* complete reviewed private sequential policy */
    put_u64_le(response + 72, pc);
    put_u64_le(response + 80, length);
    memcpy(response + 88, launch_digest, 32);
    memcpy(response + 120, item->digest, 32);
    memcpy(response + 152, code_digest, 32);
    memcpy(response + 184, atomic_model_sha256, 32);
    memcpy(response + 216, atomic_profile_sha256, 32);
unavailable:
    if (response[8] == RESPONSE_UNAVAILABLE) put_u64_le(response + 64, unavailable_reason);
    if (!write_full(socket_fd, response, sizeof(response))) protocol_failure("atomic response failed");
}

