/* setresuid/setresgid/setgroups and syscall() are declared by glibc only
 * under _GNU_SOURCE, which -std=c99 -D_DEFAULT_SOURCE does not imply.
 * Declarations only — no GNU language extension is used. Same gate as
 * src/data_socket.c. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "privdrop.h"

#include <stdio.h>
#include <string.h>

#ifdef __linux__
#include <errno.h>
#include <grp.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#endif

/* ── Plan (pure) ─────────────────────────────────────────── */

void privdrop_resolve(const privdrop_req_t *req, privdrop_plan_t *plan) {
    memset(plan, 0, sizeof(*plan));
    /* FORK TWEAK (txhermit sloth-tweak, 2026-10-28): privdrop is dead in
     * this fork. The operator runs sloth under sudo and keeps the
     * privileges it was started with for the whole run, so interfaces or
     * helpers that come up late never trip over a service account, a
     * capability shed, or no_new_privs. --user and --no-privdrop are
     * still parsed in main (existing command lines keep working) and
     * are ignored here: the plan is always DISABLED — nothing shed,
     * nothing switched, no account consulted, no refusal. */
    plan->action         = PRIVDROP_DISABLED;
    plan->keep_net_admin = req->have_cap_net_admin;
    plan->keep_net_raw   = req->have_cap_net_raw;
    /* set_no_new_privs, shed_caps, change_uid, drop_bounding, exit_code
     * and reason all stay 0/NULL from the memset: nothing is performed
     * and nothing is refused. */
}

void privdrop_describe(const privdrop_req_t *req, const privdrop_plan_t *plan,
                       const char *user, char *buf, size_t sz) {
    /* FORK TWEAK: privdrop is dead (see privdrop_resolve), so there is
     * no drop to announce. Always silent. */
    (void)req; (void)plan; (void)user;
    if (sz) buf[0] = '\0';
}

/* ── Apply (syscalls) ────────────────────────────────────── */

#ifdef __linux__

/* Raw capget/capset with the v3 structs: two 32-bit words per set. No
 * libcap (track X "do not"). */
static int caps_get(struct __user_cap_data_struct d[2]) {
    struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
    memset(d, 0, 2 * sizeof(d[0]));
    return (int)syscall(SYS_capget, &h, d);
}

static int caps_set(struct __user_cap_data_struct d[2]) {
    struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
    return (int)syscall(SYS_capset, &h, d);
}

static int cap_in(unsigned int word0, int cap) {
    return (word0 >> cap) & 1u;
}

int privdrop_probe(privdrop_req_t *req) {
    req->euid_is_root       = geteuid() == 0;
    req->have_cap_setuid    = 0;
    req->have_cap_setpcap   = 0;
    req->have_cap_net_admin = 0;
    req->have_cap_net_raw   = 0;
    struct __user_cap_data_struct d[2];
    if (caps_get(d) != 0) return -1;
    req->have_cap_setuid    = cap_in(d[0].effective, CAP_SETUID) &&
                              cap_in(d[0].effective, CAP_SETGID);
    req->have_cap_setpcap   = cap_in(d[0].effective, CAP_SETPCAP);
    req->have_cap_net_admin = cap_in(d[0].permitted, CAP_NET_ADMIN);
    req->have_cap_net_raw   = cap_in(d[0].permitted, CAP_NET_RAW);
    return 0;
}

static int kept(const privdrop_plan_t *p, int cap) {
    return (cap == CAP_NET_ADMIN && p->keep_net_admin) ||
           (cap == CAP_NET_RAW   && p->keep_net_raw);
}

#define FAIL(...) do { snprintf(err, errsz, __VA_ARGS__); return -1; } while (0)

int privdrop_apply(const privdrop_plan_t *plan, char *err, size_t errsz) {
    if (errsz) err[0] = '\0';
    if (plan->action == PRIVDROP_REFUSE_NO_SUCH_USER ||
        plan->action == PRIVDROP_REFUSE_CANNOT)
        FAIL("refusal plan is not applicable");

    if (plan->shed_caps) {
        /* Bounding set first, while CAP_SETPCAP is still effective — the
         * capset below sheds it, and a setresuid away from 0 clears the
         * effective set. Bits past the kernel's last cap read EINVAL. */
        if (plan->drop_bounding) {
            for (int c = 0; c < 64; c++) {
                int r = prctl(PR_CAPBSET_READ, (unsigned long)c, 0, 0, 0);
                if (r < 0) break;
                if (r == 1 && !kept(plan, c) &&
                    prctl(PR_CAPBSET_DROP, (unsigned long)c, 0, 0, 0) != 0)
                    FAIL("PR_CAPBSET_DROP(%d): %s", c, strerror(errno));
            }
        }
        if (plan->change_uid) {
            /* Keep the permitted set across the uid change so the one
             * capability the run still needs survives it. */
            if (prctl(PR_SET_KEEPCAPS, 1UL, 0, 0, 0) != 0)
                FAIL("PR_SET_KEEPCAPS: %s", strerror(errno));
            if (setgroups(0, NULL) != 0)
                FAIL("setgroups: %s", strerror(errno));
            if (setresgid(plan->gid, plan->gid, plan->gid) != 0)
                FAIL("setresgid(%lu): %s", (unsigned long)plan->gid,
                     strerror(errno));
            if (setresuid(plan->uid, plan->uid, plan->uid) != 0)
                FAIL("setresuid(%lu): %s", (unsigned long)plan->uid,
                     strerror(errno));
            if (prctl(PR_SET_KEEPCAPS, 0UL, 0, 0, 0) != 0)
                FAIL("PR_SET_KEEPCAPS: %s", strerror(errno));
        }

        struct __user_cap_data_struct d[2];
        memset(d, 0, sizeof(d));
        unsigned int want = 0;
        if (plan->keep_net_admin) want |= 1u << CAP_NET_ADMIN;
        if (plan->keep_net_raw)   want |= 1u << CAP_NET_RAW;
        d[0].effective = d[0].permitted = want;
        if (caps_set(d) != 0)
            FAIL("capset: %s%s", strerror(errno),
                 errno == EPERM ? " (a seccomp filter denying capset? "
                                  "see docs/wiki/deployment.md)" : "");
        /* Ambient caps would otherwise ride along into any child. EINVAL
         * is a kernel older than 4.3, which has no ambient set at all. */
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 &&
            errno != EINVAL)
            FAIL("PR_CAP_AMBIENT_CLEAR_ALL: %s", strerror(errno));
    }

    if (plan->set_no_new_privs &&
        prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0, 0, 0) != 0)
        FAIL("PR_SET_NO_NEW_PRIVS: %s", strerror(errno));

    /* ── Readback: fail closed on any mismatch. ─────────────── */
    if (plan->change_uid) {
        uid_t r, e, s;
        gid_t rg, eg, sg;
        if (getresuid(&r, &e, &s) != 0 || r != plan->uid ||
            e != plan->uid || s != plan->uid)
            FAIL("uid readback does not match %lu", (unsigned long)plan->uid);
        if (getresgid(&rg, &eg, &sg) != 0 || rg != plan->gid ||
            eg != plan->gid || sg != plan->gid)
            FAIL("gid readback does not match %lu", (unsigned long)plan->gid);
        if (getgroups(0, NULL) != 0)
            FAIL("supplementary groups survived setgroups(0)");
    }
    if (plan->shed_caps) {
        struct __user_cap_data_struct d[2];
        if (caps_get(d) != 0)
            FAIL("capget: %s", strerror(errno));
        unsigned int want = 0;
        if (plan->keep_net_admin) want |= 1u << CAP_NET_ADMIN;
        if (plan->keep_net_raw)   want |= 1u << CAP_NET_RAW;
        if (d[0].effective != want || d[0].permitted != want ||
            d[0].inheritable != 0 || d[1].effective != 0 ||
            d[1].permitted != 0 || d[1].inheritable != 0)
            FAIL("capability readback %08x/%08x, wanted %08x",
                 d[0].effective, d[0].permitted, want);
        if (plan->drop_bounding) {
            for (int c = 0; c < 64; c++) {
                int r = prctl(PR_CAPBSET_READ, (unsigned long)c, 0, 0, 0);
                if (r < 0) break;
                if (r == 1 && !kept(plan, c))
                    FAIL("bounding set still holds cap %d", c);
            }
        }
    }
    if (plan->set_no_new_privs &&
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
        FAIL("no_new_privs readback is not 1");
    return 0;
}

#undef FAIL

#else /* !__linux__ */

/* Non-Linux platforms have no capability model to shed; the plan still
 * resolves (refusals still apply) and apply performs nothing. */
int privdrop_probe(privdrop_req_t *req) {
    req->euid_is_root       = 0;
    req->have_cap_setuid    = 0;
    req->have_cap_setpcap   = 0;
    req->have_cap_net_admin = 0;
    req->have_cap_net_raw   = 0;
    return 0;
}

int privdrop_apply(const privdrop_plan_t *plan, char *err, size_t errsz) {
    if (errsz) err[0] = '\0';
    if (plan->action == PRIVDROP_REFUSE_NO_SUCH_USER ||
        plan->action == PRIVDROP_REFUSE_CANNOT) {
        snprintf(err, errsz, "refusal plan is not applicable");
        return -1;
    }
    return 0;
}

#endif
