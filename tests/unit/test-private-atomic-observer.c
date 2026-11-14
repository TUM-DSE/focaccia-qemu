#define _GNU_SOURCE
#include "private-atomic-observer.h"
#include <assert.h>
#include <sys/mman.h>
int main(void) {
 unsigned bad[] = {56,57,58,62,101,200,206,222,240,250,282,283,298,323,334,425,426,427,435};
 for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++) assert(!qemu_private_atomic_sync_syscall(bad[i],0,0));
 assert(qemu_private_atomic_sync_syscall(0,0,0));
 assert(qemu_private_atomic_sync_syscall(290,0x80800,0));
 assert(!qemu_private_atomic_sync_syscall(290,0,0));
 assert(!qemu_private_atomic_sync_syscall(290,0x80801,0));
 assert(!qemu_private_atomic_sync_syscall(290,0x800,0));
 assert(!qemu_private_atomic_sync_syscall(290,0x80000,0));
 assert(!qemu_private_atomic_sync_syscall(290,0x100080800ull,0));
 assert(qemu_private_atomic_sync_syscall(202,128,0));
 assert(!qemu_private_atomic_sync_syscall(202,134,0));
 assert(qemu_private_atomic_sync_syscall(72,4,0x800));
 assert(!qemu_private_atomic_sync_syscall(72,4,0x2000));
 assert(!qemu_private_atomic_sync_syscall(72,8,0));
 assert(!qemu_private_atomic_sync_syscall(16,0,0));
 assert(qemu_private_atomic_sync_syscall(16,0x5413,0));
 assert(!qemu_private_atomic_store_path("/tmp/program.elf"));
 assert(!qemu_private_atomic_store_path("/nix/store/not-a-hash-program"));
 assert(qemu_private_atomic_store_path("/nix/store/00000000000000000000000000000000-test/program"));
 char *a=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); assert(a!=MAP_FAILED);a[0]=1;
 assert(qemu_private_atomic_backing((uintptr_t)a,4096,true));
 assert(!qemu_private_atomic_backing((uintptr_t)a,4096,false));
 char *s=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);assert(s!=MAP_FAILED);s[0]=1;
 assert(!qemu_private_atomic_backing((uintptr_t)s,4096,true));
 char path[]="/tmp/focaccia-atomic-backing-XXXXXX";int fd=mkstemp(path);assert(fd>=0);assert(!ftruncate(fd,4096));
 char *f=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0);assert(f!=MAP_FAILED);
 assert(!qemu_private_atomic_backing((uintptr_t)f,4096,true));
 f[0]=7;assert(qemu_private_atomic_backing((uintptr_t)f,4096,true));
 assert(!munmap(f,4096));close(fd);unlink(path);munmap(a,4096);munmap(s,4096);
 puts("native observer: syscall/agent/async-policy, anonymous/private-COW/shared/temp-backing and explicit-scope controls PASS");
}
