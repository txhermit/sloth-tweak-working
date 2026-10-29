#include "runner.h"
#include "privdrop.h"

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#endif

/* Privilege drop (#140 upstream) — FORK TWEAK (txhermit sloth-tweak,
 * 2026-10-28): the drop is dead in this fork by the fork owner's
 * ruling. The operator runs sloth under sudo and keeps the privileges
 * it was started with for the whole run. These tests pin the new
 * contract: privdrop_resolve() always resolves to PRIVDROP_DISABLED
 * (nothing shed, nothing switched, no refusal, no account consulted),
 * privdrop_describe() is always silent, and privdrop_apply() on that
 * plan is a true no-op. --user and --no-privdrop are still parsed by
 * main and are ignored here. */

/* Sentinel ids: never a real account's, never 0. */
#define PD_UID 4242u
#define PD_GID 4343u

static privdrop_req_t root_req(void) {
    privdrop_req_t r;
    memset(&r, 0, sizeof(r));
    r.euid_is_root       = 1;
    r.have_cap_setuid    = 1;
    r.have_cap_setpcap   = 1;
    r.have_cap_net_admin = 1;
    r.have_cap_net_raw   = 1;
    r.user_resolved      = 1;
    r.uid                = (uid_t)PD_UID;
    r.gid                = (gid_t)PD_GID;
    return r;
}

static privdrop_req_t unpriv_req(void) {
    privdrop_req_t r;
    memset(&r, 0, sizeof(r));
    return r;
}

static void assert_disabled_plan(const privdrop_req_t *r,
                                 const privdrop_plan_t *p) {
    ASSERT_EQ(p->action, PRIVDROP_DISABLED);
    ASSERT_EQ(p->shed_caps, 0);
    ASSERT_EQ(p->change_uid, 0);
    ASSERT_EQ(p->drop_bounding, 0);
    ASSERT_EQ(p->set_no_new_privs, 0);
    ASSERT_EQ(p->exit_code, 0);
    ASSERT(p->reason == NULL);
    /* The plan describes what stays: whatever the process holds. */
    ASSERT_EQ(p->keep_net_admin, r->have_cap_net_admin);
    ASSERT_EQ(p->keep_net_raw, r->have_cap_net_raw);
}

/* Every input combination resolves the same way: disabled. */
static void test_every_combination_is_disabled(void) {
    int checked = 0;
    for (int root = 0; root < 2; root++)
    for (int hop = 0; hop < 2; hop++)
    for (int act = 0; act < 2; act++)
    for (int res = 0; res < 2; res++)
    for (int given = 0; given < 2; given++)
    for (int npd = 0; npd < 2; npd++)
    for (int su = 0; su < 2; su++) {
        privdrop_req_t r = root ? root_req() : unpriv_req();
        r.hop = hop; r.allow_active = act;
        r.user_resolved = res; r.user_given = given;
        r.no_privdrop = npd; r.have_cap_setuid = su;
        privdrop_plan_t p;
        privdrop_resolve(&r, &p);
        assert_disabled_plan(&r, &p);
        checked++;
    }
    ASSERT_EQ(checked, 128);
}

/* Upstream refused an unresolved --user with exit 2. The fork does
 * not consult accounts at all. */
static void test_unknown_user_is_not_refused(void) {
    privdrop_req_t r = root_req();
    r.user_given    = 1;
    r.user_resolved = 0;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    assert_disabled_plan(&r, &p);
}

/* Upstream treated --user with --no-privdrop as a contradiction.
 * Both flags are inert here. */
static void test_user_with_no_privdrop_does_not_contradict(void) {
    privdrop_req_t r = root_req();
    r.no_privdrop = 1;
    r.user_given  = 1;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    assert_disabled_plan(&r, &p);
}

/* Root with a resolvable default account used to drop to it. The
 * fork stays exactly as started. */
static void test_root_with_account_stays_root(void) {
    privdrop_req_t r = root_req();
    r.hop = 1;
    privdrop_plan_t p;
    privdrop_resolve(&r, &p);
    assert_disabled_plan(&r, &p);
}

/* ── The announcement: there isn't one ───────────────────── */

static void test_describe_is_always_silent(void) {
    char buf[320];
    privdrop_plan_t p;

    privdrop_req_t r = root_req();
    privdrop_resolve(&r, &p);
    buf[0] = 'X';
    privdrop_describe(&r, &p, "sloth", buf, sizeof(buf));
    ASSERT_STR(buf, "");

    r = unpriv_req();
    privdrop_resolve(&r, &p);
    buf[0] = 'X';
    privdrop_describe(&r, &p, "sloth", buf, sizeof(buf));
    ASSERT_STR(buf, "");
}

/* ── apply ───────────────────────────────────────────────── */

/* apply still guards itself: a hand-built refusal plan (which
 * resolve can no longer produce) is not applicable. */
static void test_apply_refuses_a_refusal_plan(void) {
    privdrop_plan_t p;
    memset(&p, 0, sizeof(p));
    p.action = PRIVDROP_REFUSE_CANNOT;
    char err[160];
    ASSERT_EQ(privdrop_apply(&p, err, sizeof(err)), -1);
    ASSERT(err[0] != '\0');
}

#ifdef __linux__
/* Applying the resolved plan changes nothing: uid, capabilities and
 * no_new_privs are byte-identical afterwards. Carried out in a child
 * so a regression that DID shed would go red here without harming
 * the suite. Child exit status: 0 ok, 9 wrong action, 10 apply
 * failed, 11 NNP changed, 12 caps changed, 13 uid changed. */
static void test_apply_disabled_plan_is_a_true_noop(void) {
    fflush(NULL);
    pid_t pid = fork();
    ASSERT(pid >= 0);
    if (pid < 0) return;
    if (pid == 0) {
        privdrop_req_t r;
        memset(&r, 0, sizeof(r));
        privdrop_probe(&r);
        privdrop_plan_t p;
        privdrop_resolve(&r, &p);
        if (p.action != PRIVDROP_DISABLED) _exit(9);

        uid_t uid_before = geteuid();
        int nnp_before = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
        struct __user_cap_header_struct h =
            { _LINUX_CAPABILITY_VERSION_3, 0 };
        struct __user_cap_data_struct before[2], after[2];
        memset(before, 0, sizeof(before));
        if (syscall(SYS_capget, &h, before) != 0) _exit(12);

        char err[160];
        if (privdrop_apply(&p, err, sizeof(err)) != 0) _exit(10);

        if (geteuid() != uid_before) _exit(13);
        if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != nnp_before)
            _exit(11);
        memset(after, 0, sizeof(after));
        if (syscall(SYS_capget, &h, after) != 0) _exit(12);
        if (memcmp(before, after, sizeof(before)) != 0) _exit(12);
        _exit(0);
    }
    int st = 0;
    ASSERT_EQ(waitpid(pid, &st, 0), pid);
    ASSERT(WIFEXITED(st));
    if (WIFEXITED(st) && WEXITSTATUS(st) != 0)
        fprintf(stderr, "    privdrop child exited %d\n", WEXITSTATUS(st));
    ASSERT_EQ(WEXITSTATUS(st), 0);
}
#endif

void run_privdrop_tests(void) {
    TEST_SUITE("privdrop (fork: disabled)");
    RUN_TEST(test_every_combination_is_disabled);
    RUN_TEST(test_unknown_user_is_not_refused);
    RUN_TEST(test_user_with_no_privdrop_does_not_contradict);
    RUN_TEST(test_root_with_account_stays_root);
    RUN_TEST(test_describe_is_always_silent);
    RUN_TEST(test_apply_refuses_a_refusal_plan);
#ifdef __linux__
    RUN_TEST(test_apply_disabled_plan_is_a_true_noop);
#endif
}
