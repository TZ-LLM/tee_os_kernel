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

#pragma once

#include <chcore/type.h>
#include <chcore/container/list.h>

struct gp_regs {
    u64 x[31];
};

/* System registers for EL1 */
struct sys_regs {
    u64 spsr;
    u64 elr;
    u64 sctlr;
    u64 sp_el1;
    u64 sp_el0;
    u64 esr;
    u64 vbar;
    u64 ttbr0;
    u64 ttbr1;
    u64 mair;
    u64 amair;
    u64 tcr;
    u64 tpidr_el0;
    u64 tpidr_el1;
    u64 cpacr;
    u64 mdscr;
};

/* Hypervisor registers to control VCPU in EL2 */
struct hyp_regs {
    u64 far_el2;
    u64 hpfar_el2;
    u64 vmpidr_el2;
    u64 esr_el2;
    u64 hcr_el2;
    u64 spsr_el2;
    u64 elr_el2;
};

struct ipa_region_config_request {
    cap_t pmo_cap;
    u64 ipa_start;
    size_t size;
    u32 attr;
};

#define EXIT_REASON_UNKNOWN          1
#define EXIT_REASON_NOMAPPING        2
#define EXIT_REASON_EACCES           3
#define EXIT_REASON_ADAGIO_IRQ       4
#define EXIT_REASON_RERUN            5
#define EXIT_REASON_SYNC_UART_STATUS 6
#define EXIT_REASON_FINISH_VMTEST    256

#define ADAGIO_IRQ_BUF_SIZE 32

#define GIC_INTID_INVALID    0x3ff
#define GIC_INTID_VIRT_TIMER 0x1b
#define GIC_INTID_VIRT_UART  0x21

#ifndef BIT
#define BIT(x) (1 << (x))
#endif
#define ADAGIO_FEAT_VGIC BIT(0)
#define ADAGIO_FEAT_PSCI BIT(1)

#define MMU_ATTR_PAGE_NONE 0
#define MMU_ATTR_PAGE_EO   1
#define MMU_ATTR_PAGE_WO   2
#define MMU_ATTR_PAGE_WE   3
#define MMU_ATTR_PAGE_RO   4
#define MMU_ATTR_PAGE_RE   5
#define MMU_ATTR_PAGE_RW   6
#define MMU_ATTR_PAGE_RWE  7

#define asmoffsetof(TYPE, MEMBER) ((u64) & ((TYPE *)0)->MEMBER)

#define ADAGIO_GPREG_PREFIX    0x1000000000000000
#define ADAGIO_SYSREG_PREFIX   0x2000000000000000
#define ADAGIO_HYPREG_PREFIX   0x3000000000000000
#define ADAGIO_REG_PREFIX_MASK 0xf000000000000000
#define ADAGIO_GPREG_ID(x) \
    (ADAGIO_GPREG_PREFIX | asmoffsetof(struct gp_regs, x))
#define ADAGIO_SYSREG_ID(x) \
    (ADAGIO_SYSREG_PREFIX | asmoffsetof(struct sys_regs, x))
#define ADAGIO_HYPREG_ID(x) \
    (ADAGIO_HYPREG_PREFIX | asmoffsetof(struct hyp_regs, x))

#define ESR_ELx_EC_UNKNOWN (0x00)
#define ESR_ELx_EC_WFx     (0x01)
/* Unallocated EC: 0x02 */
#define ESR_ELx_EC_CP15_32  (0x03)
#define ESR_ELx_EC_CP15_64  (0x04)
#define ESR_ELx_EC_CP14_MR  (0x05)
#define ESR_ELx_EC_CP14_LS  (0x06)
#define ESR_ELx_EC_FP_ASIMD (0x07)
#define ESR_ELx_EC_CP10_ID  (0x08) /* EL2 only */
#define ESR_ELx_EC_PAC      (0x09) /* EL2 and above */
/* Unallocated EC: 0x0A - 0x0B */
#define ESR_ELx_EC_CP14_64 (0x0C)
/* Unallocated EC: 0x0d */
#define ESR_ELx_EC_ILL (0x0E)
/* Unallocated EC: 0x0F - 0x10 */
#define ESR_ELx_EC_SVC32 (0x11)
#define ESR_ELx_EC_HVC32 (0x12) /* EL2 only */
#define ESR_ELx_EC_SMC32 (0x13) /* EL2 and above */
/* Unallocated EC: 0x14 */
#define ESR_ELx_EC_SVC64 (0x15)
#define ESR_ELx_EC_HVC64 (0x16) /* EL2 and above */
#define ESR_ELx_EC_SMC64 (0x17) /* EL2 and above */
#define ESR_ELx_EC_SYS64 (0x18)
#define ESR_ELx_EC_SVE   (0x19)
/* Unallocated EC: 0x1A - 0x1E */
#define ESR_ELx_EC_IMP_DEF  (0x1f) /* EL3 only */
#define ESR_ELx_EC_IABT_LOW (0x20)
#define ESR_ELx_EC_IABT_CUR (0x21)
#define ESR_ELx_EC_PC_ALIGN (0x22)
/* Unallocated EC: 0x23 */
#define ESR_ELx_EC_DABT_LOW (0x24)
#define ESR_ELx_EC_DABT_CUR (0x25)
#define ESR_ELx_EC_SP_ALIGN (0x26)
/* Unallocated EC: 0x27 */
#define ESR_ELx_EC_FP_EXC32 (0x28)
/* Unallocated EC: 0x29 - 0x2B */
#define ESR_ELx_EC_FP_EXC64 (0x2C)
/* Unallocated EC: 0x2D - 0x2E */
#define ESR_ELx_EC_SERROR      (0x2F)
#define ESR_ELx_EC_BREAKPT_LOW (0x30)
#define ESR_ELx_EC_BREAKPT_CUR (0x31)
#define ESR_ELx_EC_SOFTSTP_LOW (0x32)
#define ESR_ELx_EC_SOFTSTP_CUR (0x33)
#define ESR_ELx_EC_WATCHPT_LOW (0x34)
#define ESR_ELx_EC_WATCHPT_CUR (0x35)
/* Unallocated EC: 0x36 - 0x37 */
#define ESR_ELx_EC_BKPT32 (0x38)
/* Unallocated EC: 0x39 */
#define ESR_ELx_EC_VECTOR32 (0x3A) /* EL2 only */
/* Unallocted EC: 0x3B */
#define ESR_ELx_EC_BRK64 (0x3C)
/* Unallocated EC: 0x3D - 0x3F */

#define ESR_ELx_EC_MAX (0x3F)

#define ESR_EL_EC_SHIFT (26)
#define ESR_EL_EC_MASK  ((0x3F) << ESR_EL_EC_SHIFT)
#define ESR_EL_EC(esr)  (((esr)&ESR_EL_EC_MASK) >> ESR_EL_EC_SHIFT)

/* Shared ISS field definitions for Data/Instruction aborts */
#define ESR_ELx_SET_SHIFT   (11)
#define ESR_ELx_SET_MASK    ((3) << ESR_ELx_SET_SHIFT)
#define ESR_ELx_FnV_SHIFT   (10)
#define ESR_ELx_FnV         ((1) << ESR_ELx_FnV_SHIFT)
#define ESR_ELx_EA_SHIFT    (9)
#define ESR_ELx_EA          ((1) << ESR_ELx_EA_SHIFT)
#define ESR_ELx_S1PTW_SHIFT (7)
#define ESR_ELx_S1PTW       ((1) << ESR_ELx_S1PTW_SHIFT)

/* Shared ISS fault status code(IFSC/DFSC) for Data/Instruction aborts */
#define ESR_ELx_FSC        (0x3F)
#define ESR_ELx_FSC_TYPE   (0x3C)
#define ESR_ELx_FSC_EXTABT (0x10)
#define ESR_ELx_FSC_SERROR (0x11)
#define ESR_ELx_FSC_ACCESS (0x08)
#define ESR_ELx_FSC_FAULT  (0x04)
#define ESR_ELx_FSC_PERM   (0x0C)

/* ISS field definitions for Data Aborts */
#define ESR_ELx_ISV_SHIFT  (24)
#define ESR_ELx_ISV        ((1) << ESR_ELx_ISV_SHIFT)
#define ESR_ELx_SAS_SHIFT  (22)
#define ESR_ELx_SAS        ((3) << ESR_ELx_SAS_SHIFT)
#define ESR_ELx_SSE_SHIFT  (21)
#define ESR_ELx_SSE        ((1) << ESR_ELx_SSE_SHIFT)
#define ESR_ELx_SRT_SHIFT  (16)
#define ESR_ELx_SRT        ((0x1F) << ESR_ELx_SRT_SHIFT)
#define ESR_ELx_SF_SHIFT   (15)
#define ESR_ELx_SF         ((1) << ESR_ELx_SF_SHIFT)
#define ESR_ELx_AR_SHIFT   (14)
#define ESR_ELx_AR         ((1) << ESR_ELx_AR_SHIFT)
#define ESR_ELx_VNCR_SHIFT (13)
#define ESR_ELx_VNCR       ((1) << ESR_ELx_VNCR_SHIFT)
#define ESR_ELx_CM_SHIFT   (8)
#define ESR_ELx_CM         ((1) << ESR_ELx_CM_SHIFT)
#define ESR_ELx_WNR_SHIFT  (6)
#define ESR_ELx_WNR        ((1) << ESR_ELx_WNR_SHIFT)
