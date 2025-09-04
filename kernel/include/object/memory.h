/*
 * Copyright (c) 2023 Institute of Parallel And Distributed Systems (IPADS), Shanghai Jiao Tong University (SJTU)
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef OBJECT_MEMORY_H
#define OBJECT_MEMORY_H

#include <common/radix.h>
#include <object/cap_group.h>
#ifdef CHCORE_OH_TEE
#include <common/tee_uuid.h>
#endif /* CHCORE_OH_TEE */

typedef unsigned pmo_type_t;
#define PMO_ANONYM       0 /* lazy allocation */
#define PMO_DATA         1 /* immediate allocation */
#define PMO_FILE         2 /* file backed */
#define PMO_SHM          3 /* shared memory */
#define PMO_USER_PAGER   4 /* support user pager */
#define PMO_DEVICE       5 /* memory mapped device registers */
#define PMO_DATA_NOCACHE 6 /* non-cacheable immediate allocation */
#ifdef CHCORE_OH_TEE
#define PMO_TZ_NS 7 /* TrustZone non-secure memory */
#endif /* CHCORE_OH_TEE */
#define PMO_S2 8
#define PMO_TZASC_CMA 9

#define PMO_FORBID 10 /* Forbidden area: avoid overflow */

struct tzasc_cma_entry {
	unsigned long offset;
	unsigned long size;
	void *cma_pages;
};

struct tzasc_cma_meta {
	unsigned long base;
	unsigned long size;
	unsigned long count;
	struct tzasc_cma_entry entry[0];
};

struct s2_l0_meta_entry {
    unsigned long paddr;
    unsigned long size;
};

struct s2_l0_meta {
    unsigned long entry_nr;
    struct s2_l0_meta_entry entry[0];
};

struct s2_l1_meta_entry {
    unsigned long paddr;
    unsigned long size;
};

struct s2_l1_meta {
    struct s2_l1_meta_entry entry[0];
};

#ifdef CHCORE_OH_TEE
struct ns_pmo_private {
    bool mapped;
    struct cap_group *creater;
    vaddr_t vaddr;
    size_t len;
};
struct tee_shm_private {
    struct tee_uuid uuid;
    struct cap_group *owner;
};
#endif /* CHCORE_OH_TEE */

/* This struct represents some physical memory resource */
struct pmobject {
    paddr_t start;
    size_t size;
    pmo_type_t type;
    /* record physical pages for on-demand-paging pmo */
    struct radix *radix;
    /*
     * The field of 'private' depends on 'type'.
     * PMO_FILE: it points to fmap_fault_pool
     * others: NULL
     */
    void *private;
#ifdef CHCORE_OH_TEE
    struct lock owner_lock;
    struct cap_group *owner;
#endif /* CHCORE_OH_TEE */
    unsigned long entry_begin;
    unsigned long entry_end;
};

void s2_meta_init(unsigned long s2_meta_paddr);
cap_t sys_create_s2_pmo(unsigned long entry_begin, unsigned long entry_end);
cap_t sys_create_tzasc_cma_pmo(unsigned long paddr, unsigned long size);
int sys_map_tzasc_cma_meta(unsigned long vaddr);
int sys_map_tzasc_cma_pmo(unsigned long vaddr, unsigned long len, paddr_t paddr);
struct s2_l1_meta *get_s2_l1_meta(void);

/* kernel internal interfaces */
cap_t create_pmo(size_t size, pmo_type_t type, struct cap_group *cap_group,
                 paddr_t paddr, struct pmobject **new_pmo);
void commit_page_to_pmo(struct pmobject *pmo, unsigned long index, paddr_t pa);
paddr_t get_page_from_pmo(struct pmobject *pmo, unsigned long index);
int map_pmo_in_current_cap_group(cap_t pmo_cap, unsigned long addr,
                                 unsigned long perm);
void pmo_deinit(void *pmo_ptr);

/* syscalls */
cap_t sys_create_device_pmo(unsigned long paddr, unsigned long size);
cap_t sys_create_pmo(unsigned long size, pmo_type_t type);
int sys_write_pmo(cap_t pmo_cap, unsigned long offset, unsigned long user_ptr,
                  unsigned long len);
int sys_read_pmo(cap_t pmo_cap, unsigned long offset, unsigned long user_ptr,
                 unsigned long len);
int sys_get_phys_addr(vaddr_t va, paddr_t *pa_buf);
int sys_map_pmo(cap_t target_cap_group_cap, cap_t pmo_cap, unsigned long addr,
                unsigned long perm, unsigned long len);
int sys_unmap_pmo(cap_t target_cap_group_cap, cap_t pmo_cap,
                  unsigned long addr);
unsigned long sys_handle_brk(unsigned long addr, unsigned long heap_start);
int sys_handle_mprotect(unsigned long addr, unsigned long length, int prot);
unsigned long sys_get_free_mem_size(void);
int sys_tee_create_ns_pmo(unsigned long paddr, unsigned long size);

#ifdef CHCORE_OH_TEE

cap_t sys_create_ns_pmo(cap_t cap_group, unsigned long paddr,
                        unsigned long size);
int sys_destroy_ns_pmo(cap_t cap_group, cap_t pmo);

cap_t sys_create_tee_shared_pmo(cap_t cap_group, struct tee_uuid *uuid,
                                unsigned long size, cap_t *self_cap);
int sys_transfer_pmo_owner(cap_t pmo, cap_t cap_group);

int sys_config_tzasc(int rgn_id, unsigned long base_addr, unsigned long top_addr);

#endif /* CHCORE_OH_TEE */

#endif /* OBJECT_MEMORY_H */
