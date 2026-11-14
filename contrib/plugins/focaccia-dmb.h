/* Bounded passive sequential trace. Translation facts are not ordering evidence. */
#ifndef FOCACCIA_DMB_H
#define FOCACCIA_DMB_H
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#define FOC_DMB_MAX_ROWS 4096u
#define FOC_DMB_BARRIER 1u
#define FOC_DMB_READ 2u
#define FOC_DMB_WRITE 3u
typedef struct {
    uint64_t ordinal, instruction_ordinal, pc, address, size;
    uint32_t kind, domain, types, word, cflags, bar, emitted;
} FocDmbRow;
typedef struct {
    bool valid;
    uint64_t sequence, first_pc, last_pc, instruction_count;
    uint8_t code_sha256[32];
    uint32_t count;
    FocDmbRow rows[FOC_DMB_MAX_ROWS];
} FocDmbTrace;
static inline void foc_dmb_begin(FocDmbTrace *t, uint64_t sequence,
                                 uint64_t first, uint64_t last, uint64_t n,
                                 const uint8_t sha256[32])
{
    t->valid = sequence && n && first <= last;
    t->sequence = sequence;
    t->first_pc = first; t->last_pc = last; t->instruction_count = n;
    t->count = 0;
    memcpy(t->code_sha256, sha256, 32);
}
static inline bool foc_dmb_append(FocDmbTrace *t, FocDmbRow row,
                                  unsigned int cpu_index)
{
    if (!t->valid || cpu_index || t->count == FOC_DMB_MAX_ROWS ||
        row.instruction_ordinal >= t->instruction_count ||
        row.pc < t->first_pc || row.pc > t->last_pc ||
        row.kind < FOC_DMB_BARRIER || row.kind > FOC_DMB_WRITE ||
        (row.kind == FOC_DMB_BARRIER && (row.address || row.size || row.emitted > 1)) ||
        (row.kind != FOC_DMB_BARRIER && (!row.size || row.size > 16 ||
                                       row.address > UINT64_MAX - (row.size - 1)))) {
        t->valid = false;
        return false;
    }
    if (t->count && t->rows[t->count - 1].instruction_ordinal > row.instruction_ordinal) {
        t->valid = false;
        return false;
    }
    row.ordinal = t->count;
    t->rows[t->count++] = row;
    return true;
}
#endif
