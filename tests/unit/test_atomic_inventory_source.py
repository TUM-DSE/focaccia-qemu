"""Compile and execute the actual inventory functions extracted from user-exec.c.

This small mock supplies interval-tree/GArray/lock and translation primitives;
collector and public-wrapper C bodies are copied verbatim with balanced-brace
extraction, so assertions exercise QEMU source rather than a policy duplicate.
"""
import os
import pathlib
import shutil
import shlex
import subprocess
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "accel/tcg/user-exec.c"


def extract_function(text, signature):
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise AssertionError(f"unbalanced source function: {signature}")


MOCK = r'''
#include <glib.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#define TARGET_X86_64 1
#define TARGET_PAGE_SIZE 4096
#define TARGET_VSYSCALL_PAGE UINT64_C(0xffffffffff600000)
#define PAGE_READ 1
#define PAGE_WRITE 2
#define PAGE_EXEC 4
#define PAGE_VALID 8
#define PAGE_WRITE_ORG 16
#define PAGE_ANON 128
#define PAGE_MAP_PRIVATE 256
#define PAGE_MAP_SHARED 4096
#define PAGE_EXEC_SERVICE 8192
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
typedef uint64_t target_ulong;
typedef struct IntervalTreeNode { uint64_t start, last; } IntervalTreeNode;
typedef struct PageFlagsNode { IntervalTreeNode itree; int flags; } PageFlagsNode;
typedef struct { uint64_t start,size; uint32_t flags,reserved; uint64_t data_offset,host_start; } qemu_plugin_guest_mapping;
static PageFlagsNode nodes[16]; static unsigned node_count, iter_pos;
static IntervalTreeNode *pageflags_root;
static bool mapping_observation_valid = true;
static uint64_t mapping_observation_generation = 77;
static int lock_depth, lock_count, unlock_count, g2h_calls;
static void *current_cpu = (void *)1;
static uint64_t fail_g2h_at = UINT64_MAX;
static void assert_memory_lock(void) { assert(lock_depth == 1); }
static void mmap_lock(void) { lock_depth++; lock_count++; }
static void mmap_unlock(void) { assert(lock_depth == 1); lock_depth--; unlock_count++; }
static void *g2h_untagged(uint64_t a) { g2h_calls++; assert(a != TARGET_VSYSCALL_PAGE && a != TARGET_VSYSCALL_PAGE+4095); return (void *)(uintptr_t)(a == fail_g2h_at ? UINT64_MAX-4 : a+UINT64_C(0x100000)); }
static IntervalTreeNode *interval_tree_iter_first(void *root, uint64_t low, uint64_t high) { (void)root;(void)low;(void)high; iter_pos=0; return node_count?&nodes[0].itree:NULL; }
static IntervalTreeNode *interval_tree_iter_next(IntervalTreeNode *n, uint64_t low, uint64_t high) { (void)low;(void)high; for(unsigned j=0;j<node_count;j++) if(&nodes[j].itree==n) return ++j<node_count?&nodes[j].itree:NULL; assert(0); return NULL; }
static PageFlagsNode *container_node(IntervalTreeNode *n) { for(unsigned i=0;i<node_count;i++) if(&nodes[i].itree==n)return &nodes[i]; assert(0);return NULL; }
#define container_of(p,t,m) container_node(p)
static GArray *arr(void) { return g_array_new(FALSE,FALSE,sizeof(qemu_plugin_guest_mapping)); }
static void set_nodes(const int *flags,const uint64_t *starts,const uint64_t *ends,unsigned n) { node_count=n; for(unsigned i=0;i<n;i++){nodes[i].flags=flags[i];nodes[i].itree.start=starts[i];nodes[i].itree.last=ends[i];} }
'''

TEST = r'''
static void clear_state(void) { g2h_calls=lock_depth=lock_count=unlock_count=0; fail_g2h_at=UINT64_MAX; }
static void test_service_and_ram(void) {
 GArray *a=arr(); uint64_t gen=0; int f[]={PAGE_VALID|PAGE_MAP_PRIVATE,PAGE_VALID|PAGE_MAP_PRIVATE,PAGE_EXEC|PAGE_VALID|PAGE_EXEC_SERVICE};
 uint64_t s[]={0x1000,0x2000,TARGET_VSYSCALL_PAGE},e[]={0x1fff,0x2fff,TARGET_VSYSCALL_PAGE+4095};set_nodes(f,s,e,3);clear_state();
 assert(qemu_plugin_private_atomic_inventory(a,8192,2,&gen)); assert(a->len==2 && gen==77 && lock_count==1 && unlock_count==1 && !lock_depth);
 qemu_plugin_guest_mapping *r=(void*)a->data;assert(r[0].start==0x1000&&r[0].size==8192&&r[0].flags==(8|16)&&r[0].host_start==0x101000&&r[0].data_offset==0);
 assert(r[1].flags==(4|8|64)&&r[1].reserved==1&&r[1].data_offset==UINT64_MAX&&r[1].host_start==0&&r[1].size==4096);
 assert(g2h_calls==4); /* service provokes no g2h */
 clear_state();assert(!qemu_plugin_private_ram_inventory(a,8192,4,&gen));assert(a->len==0&&gen==0&&lock_count==1&&unlock_count==1);
 /* Exact max row count permits two adjacent RAM nodes to coalesce. */
 set_nodes(f,s,e,2);clear_state();assert(qemu_plugin_private_atomic_inventory(a,8192,1,&gen));assert(a->len==1);
 g_array_free(a,TRUE);
}
static void bad_one(int flags,uint64_t start,uint64_t end) { GArray*a=arr();uint64_t gen=9;set_nodes(&flags,&start,&end,1);clear_state();fail_g2h_at=start;assert(!qemu_plugin_private_atomic_inventory(a,8192,4,&gen));assert(a->len==0&&gen==0&&lock_count==1&&unlock_count==1&&!lock_depth);g_array_free(a,TRUE); }
static void test_rejections(void) {
 int f;uint64_t s=TARGET_VSYSCALL_PAGE,e=s+4095;
 bad_one(PAGE_EXEC|PAGE_VALID|PAGE_EXEC_SERVICE|PAGE_READ,s,e);bad_one(PAGE_EXEC|PAGE_VALID|PAGE_EXEC_SERVICE|PAGE_WRITE,s,e);
 bad_one(PAGE_EXEC|PAGE_VALID|PAGE_EXEC_SERVICE|PAGE_WRITE_ORG,s,e);
 bad_one(PAGE_EXEC|PAGE_VALID,s,e); /* same address without creation provenance is unavailable */
 bad_one(PAGE_EXEC|PAGE_VALID|PAGE_EXEC_SERVICE|PAGE_MAP_PRIVATE,s,e);bad_one(PAGE_EXEC|PAGE_VALID|PAGE_EXEC_SERVICE|PAGE_MAP_SHARED,s,e);bad_one(PAGE_EXEC|PAGE_VALID|PAGE_EXEC_SERVICE|PAGE_ANON,s,e);
 bad_one(PAGE_EXEC|PAGE_VALID|PAGE_EXEC_SERVICE,s+4096,e+4096);bad_one(PAGE_EXEC|PAGE_VALID|PAGE_EXEC_SERVICE,s,e+4096);
 f=PAGE_VALID;bad_one(f,0x4000,0x4fff);f=PAGE_VALID|PAGE_MAP_SHARED;bad_one(f,0x4000,0x4fff);
 f=PAGE_VALID|PAGE_MAP_PRIVATE;bad_one(f,0x4000,0x4fff); /* mocked g2h overflow */
}
static void test_budgets_generation_and_invalid(void) {
 GArray*a=arr();uint64_t gen=0;int f[]={PAGE_VALID|PAGE_MAP_PRIVATE,PAGE_EXEC|PAGE_VALID|PAGE_EXEC_SERVICE};uint64_t s[]={0x1000,TARGET_VSYSCALL_PAGE},e[]={0x1fff,TARGET_VSYSCALL_PAGE+4095};set_nodes(f,s,e,2);mapping_observation_valid=true;clear_state();assert(qemu_plugin_private_atomic_inventory(a,4096,2,&gen));
 clear_state();assert(!qemu_plugin_private_atomic_inventory(a,4095,2,&gen)&&a->len==0&&gen==0);
 clear_state();assert(!qemu_plugin_private_atomic_inventory(a,4096,1,&gen)&&a->len==0&&gen==0);
 mapping_observation_valid=false;clear_state();assert(!qemu_plugin_private_atomic_inventory(a,4096,2,&gen)&&gen==0&&lock_count==1&&unlock_count==1);mapping_observation_valid=true;
 mapping_observation_generation++;clear_state();assert(qemu_plugin_private_atomic_inventory(a,4096,2,&gen)&&gen==78);
 g_array_free(a,TRUE);
}
int main(void){test_service_and_ram();test_rejections();test_budgets_generation_and_invalid();puts("direct user-exec source collector tests PASS");return 0;}
'''


def test_extracted_qemu_inventory_functions():
    compiler = shutil.which("gcc") or shutil.which("cc")
    if not compiler:
        pytest.skip("C compiler unavailable")
    if os.environ.get("FOCACCIA_PLUGIN_TEST_CFLAGS") and os.environ.get("FOCACCIA_PLUGIN_TEST_LDFLAGS"):
        glib_cflags = shlex.split(os.environ["FOCACCIA_PLUGIN_TEST_CFLAGS"])
        glib_libs = shlex.split(os.environ["FOCACCIA_PLUGIN_TEST_LDFLAGS"])
    else:
        if not shutil.which("pkg-config"):
            pytest.skip("GLib build flags or pkg-config required")
        glib_cflags = subprocess.check_output(["pkg-config", "--cflags", "glib-2.0"], text=True).split()
        glib_libs = subprocess.check_output(["pkg-config", "--libs", "glib-2.0"], text=True).split()
    text = SOURCE.read_text()
    functions = "\n".join([
        extract_function(text, "static bool private_ram_collect_locked("),
        extract_function(text, "static bool private_atomic_collect_locked("),
        extract_function(text, "bool qemu_plugin_private_atomic_inventory("),
        extract_function(text, "bool qemu_plugin_private_ram_inventory("),
    ])
    # Add aliases needed by the extracted QEMU source bodies.
    prelude = MOCK.replace("static IntervalTreeNode *pageflags_root;", "static int pageflags_root_storage; static void *pageflags_root = &pageflags_root_storage;")
    source = prelude + "\n" + functions + "\n" + TEST
    with tempfile.TemporaryDirectory() as d:
        cfile = pathlib.Path(d) / "harness.c"
        exe = pathlib.Path(d) / "harness"
        cfile.write_text(source)
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror", *glib_cflags, str(cfile), *glib_libs, "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
