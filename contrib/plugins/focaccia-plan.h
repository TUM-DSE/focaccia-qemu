/* Target-neutral bounded snapshot address recipes. */
#ifndef FOCACCIA_PLAN_H
#define FOCACCIA_PLAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FOCACCIA_RECIPE_MAX_OPS 64u
#define FOCACCIA_RECIPE_MAX_STACK 16u
#define FOCACCIA_RECIPE_MAX_READS 8u

enum FocacciaRecipeOp {
    FOCACCIA_RECIPE_END = 0,
    FOCACCIA_RECIPE_CONST = 1, /* u8 width, u64 little-endian value */
    FOCACCIA_RECIPE_REG = 2,   /* u8 width, u8 register-plan index */
    FOCACCIA_RECIPE_ADD = 3,
    FOCACCIA_RECIPE_SUB = 4,
    FOCACCIA_RECIPE_AND = 5,
    FOCACCIA_RECIPE_OR = 6,
    FOCACCIA_RECIPE_XOR = 7,
    FOCACCIA_RECIPE_SHL = 8,
    FOCACCIA_RECIPE_LSHR = 9,
    FOCACCIA_RECIPE_ZEXT = 10, /* u8 destination width */
    FOCACCIA_RECIPE_SEXT = 11, /* u8 destination width */
    FOCACCIA_RECIPE_LOAD = 12, /* u8 result width; little-endian prestate read */
};

typedef struct FocacciaRecipeValue {
    uint64_t bits;
    uint8_t width;
} FocacciaRecipeValue;

typedef bool (*FocacciaRecipeRegister)(void *opaque, uint8_t index,
                                       FocacciaRecipeValue *value);
typedef bool (*FocacciaRecipeMemory)(void *opaque, uint64_t address,
                                     uint8_t *bytes, size_t size);

typedef struct FocacciaRecipeContext {
    FocacciaRecipeRegister read_register;
    FocacciaRecipeMemory read_memory;
    void *opaque;
} FocacciaRecipeContext;

bool focaccia_recipe_eval(const uint8_t *code, size_t code_size,
                          const FocacciaRecipeContext *context,
                          FocacciaRecipeValue *result);
#endif
