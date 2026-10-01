#include "qemu/osdep.h"
#include "../../contrib/plugins/focaccia-plan.h"

typedef struct Fixture { uint64_t reg; uint8_t mem[8]; bool fail; } Fixture;
static bool reg_read(void *p, uint8_t i, FocacciaRecipeValue *v)
{ Fixture *f=p; if (f->fail || i) return false; *v=(FocacciaRecipeValue){f->reg,64}; return true; }
static bool mem_read(void *p, uint64_t a, uint8_t *b, size_t n)
{ Fixture *f=p; if (f->fail || a != 0x1000 || n > 8) return false; memcpy(b,f->mem,n); return true; }
static void eval(void)
{
    Fixture f={.reg=0xff8,.mem={0x78,0x56,0x34,0x12}};
    FocacciaRecipeContext c={reg_read,mem_read,&f}; FocacciaRecipeValue v;
    uint8_t pointer[]={FOCACCIA_RECIPE_REG,64,0, FOCACCIA_RECIPE_CONST,64,8,0,0,0,0,0,0,0,
      FOCACCIA_RECIPE_ADD, FOCACCIA_RECIPE_LOAD,32, FOCACCIA_RECIPE_END};
    g_assert_true(focaccia_recipe_eval(pointer,sizeof(pointer),&c,&v));
    g_assert_cmpuint(v.width,==,32); g_assert_cmphex(v.bits,==,0x12345678);
    f.fail=true; g_assert_false(focaccia_recipe_eval(pointer,sizeof(pointer),&c,&v));
}
static void reject(void)
{
    FocacciaRecipeContext c={0}; FocacciaRecipeValue v;
    uint8_t underflow[]={FOCACCIA_RECIPE_ADD,FOCACCIA_RECIPE_END};
    uint8_t width[]={FOCACCIA_RECIPE_CONST,0,0,0,0,0,0,0,0,0,FOCACCIA_RECIPE_END};
    uint8_t trailing[]={FOCACCIA_RECIPE_CONST,8,1,0,0,0,0,0,0,0,FOCACCIA_RECIPE_END,0};
    g_assert_false(focaccia_recipe_eval(underflow,sizeof underflow,&c,&v));
    g_assert_false(focaccia_recipe_eval(width,sizeof width,&c,&v));
    g_assert_false(focaccia_recipe_eval(trailing,sizeof trailing,&c,&v));
}
int main(int argc,char **argv){g_test_init(&argc,&argv,NULL);g_test_add_func("/focaccia/recipe/eval",eval);g_test_add_func("/focaccia/recipe/reject",reject);return g_test_run();}
