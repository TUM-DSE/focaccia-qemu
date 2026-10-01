#include <string.h>

#include "focaccia-plan.h"

static uint64_t mask(uint8_t width)
{
    return width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1;
}

static uint64_t get_u64_le(const uint8_t *bytes)
{
    uint64_t value = 0;
    unsigned int i;

    for (i = 0; i < 8; i++) {
        value |= (uint64_t)bytes[i] << (8 * i);
    }
    return value;
}

bool focaccia_recipe_eval(const uint8_t *code, size_t size,
                          const FocacciaRecipeContext *ctx,
                          FocacciaRecipeValue *out)
{
    FocacciaRecipeValue stack[FOCACCIA_RECIPE_MAX_STACK];
    size_t pc = 0, sp = 0, ops = 0, reads = 0;
#define NEED(n) do { if ((n) > size - pc) return false; } while (0)
#define PUSH(v) do { if (sp == FOCACCIA_RECIPE_MAX_STACK) return false; stack[sp++] = (v); } while (0)
    while (pc < size && ++ops <= FOCACCIA_RECIPE_MAX_OPS) {
        uint8_t op = code[pc++];
        FocacciaRecipeValue a, b, v;
        uint8_t width;
        if (op == FOCACCIA_RECIPE_END) {
            if (pc != size || sp != 1) return false;
            *out = stack[0];
            return true;
        }
        if (op == FOCACCIA_RECIPE_CONST) {
            NEED(9); width = code[pc++];
            if (!width || width > 64) return false;
            v.bits = get_u64_le(code + pc); pc += 8;
            v.width = width; v.bits &= mask(width); PUSH(v); continue;
        }
        if (op == FOCACCIA_RECIPE_REG) {
            NEED(2); width = code[pc++]; uint8_t index = code[pc++];
            if (!width || width > 64 || !ctx->read_register ||
                !ctx->read_register(ctx->opaque, index, &v) || v.width != width) return false;
            v.bits &= mask(width); PUSH(v); continue;
        }
        if (op == FOCACCIA_RECIPE_LOAD) {
            NEED(1); width = code[pc++];
            if (!width || width > 64 || (width & 7) || !sp || ++reads > FOCACCIA_RECIPE_MAX_READS) return false;
            a = stack[--sp]; v.width = width;
            uint8_t bytes[8] = {0};
            if (!ctx->read_memory || !ctx->read_memory(ctx->opaque, a.bits,
                                                       bytes, width / 8)) return false;
            v.bits = get_u64_le(bytes) & mask(width); PUSH(v); continue;
        }
        if (op == FOCACCIA_RECIPE_ZEXT || op == FOCACCIA_RECIPE_SEXT) {
            NEED(1); width = code[pc++]; if (!sp || !width || width > 64) return false;
            a = stack[--sp]; if (width < a.width) return false;
            v.bits = a.bits;
            if (op == FOCACCIA_RECIPE_SEXT && a.width < 64 && (a.bits >> (a.width - 1))) v.bits |= ~mask(a.width);
            v.bits &= mask(width); v.width = width; PUSH(v); continue;
        }
        if (sp < 2) return false;
        b = stack[--sp]; a = stack[--sp];
        if (a.width != b.width) return false;
        v.width = a.width;
        switch (op) {
        case FOCACCIA_RECIPE_ADD: v.bits = a.bits + b.bits; break;
        case FOCACCIA_RECIPE_SUB: v.bits = a.bits - b.bits; break;
        case FOCACCIA_RECIPE_AND: v.bits = a.bits & b.bits; break;
        case FOCACCIA_RECIPE_OR: v.bits = a.bits | b.bits; break;
        case FOCACCIA_RECIPE_XOR: v.bits = a.bits ^ b.bits; break;
        case FOCACCIA_RECIPE_SHL: if (b.bits >= a.width) return false; v.bits = a.bits << b.bits; break;
        case FOCACCIA_RECIPE_LSHR: if (b.bits >= a.width) return false; v.bits = a.bits >> b.bits; break;
        default: return false;
        }
        v.bits &= mask(v.width); PUSH(v);
    }
    return false;
#undef NEED
#undef PUSH
}
