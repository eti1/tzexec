#ifndef DEF_TZEXEC_H
#define DEF_TZEXEC_H
#include <linux/types.h>

int tz_memcpy(u32 dst, u32 src, u32 size);
int tz_mmu_map( u32 p_addr, u32 v_addr, u32 n_pages, u32 flags );

int copy_to_tz(u32 dst, const void *src, u32 size);
int copy_from_tz(void *dst, u32 src, u32 size);

int tz_manual_init_image(u32 proc, u32 elf);

#endif
