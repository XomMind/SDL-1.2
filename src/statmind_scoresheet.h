#ifndef STATMIND_SCORESHEET_H
#define STATMIND_SCORESHEET_H

//==================================================================
// Live scoresheet dumps  (Cogmind Beta 17.1, Win32 PE)
//==================================================================
// Cogmind already knows how to serialise its entire run state: it links
// protobuf 3.5.1, compiles src/web/scoresheet.pb.cc, and writes a ~32KB
// scoresheet (text, plus JSON when advanced.cfg has jsonScoresheet /
// jsonStatDump) at the end of every run. The manual says the same machinery
// can run *mid-run*: "Create a scoresheet for the current run in progress,
// including most data up until this point", bound to Alt-Shift-S
// (CMD_BS_DEFAULT_OUTPUT_DUMP).
//
// That is a far better observation channel than anything this harness can
// reverse by hand. It reports part loadouts by slot and name, resource
// maxima (which are *derived* from parts and so exist nowhere in memory to
// be scanned for), per-map stats, discovered exits with their destinations,
// and the whole known map as text. Rather than hand-model any of it we let
// the game emit its own state and read the file back. The schema comes from
// the same binary -- see harness/extract_proto.py.
//
// Why not just send the keystroke
// -------------------------------
// Sending Alt-Shift-S through the mailbox works and needs no patching, but
// it only fires inside one UI domain (CMD_DOMAIN_BS_DEFAULT). With a menu,
// an inventory pane or the evolution screen up, the key does nothing and the
// caller cannot tell that from "the dump is still being written". Calling
// the writer directly works in any UI state and reports its own completion.
// The keystroke remains a valid fallback: no code here is required for it.
//
// What is being called
// --------------------
//   std::string __thiscall Scorekeeper::outputScoresheet(bool isDump)
//
// compiled by MSVC 2010 /Od as, in ABI terms:
//
//   this   -> ecx                  (the Scorekeeper singleton)
//   arg1   -> [ebp+0x08]           hidden return buffer for the std::string
//   arg2   -> [ebp+0x0C]           bool isDump: 0 = run ended, 1 = manual dump
//   eax    <- the return buffer    (MSVC returns it back out)
//   ret 8                          callee pops both stack arguments
//
// isDump=1 is not merely cosmetic, and both of its effects matter here:
//
//   * At 0x00474BD0 it skips the "no scoresheet for suicides below depth 9"
//     gate and a decrement of a global at 0x00D25740, so a dump does not
//     consume anything.
//   * At 0x0047E920 it skips the call that appends a row to
//     scorehistory.txt. That is what makes this safe for the benchmark:
//     episode.py detects the end of a run by watching that file, so a dump
//     that appended to it would fake a completed run on every call.
//
// It also selects the output directory: "dumps" instead of "scores"
// (0x0047E354 / 0x0047E3A5), so dumps never collide with the real scoresheet
// that episode.py reads at the end of a run.
//
// Resolution and safety
// ---------------------
// The image has no .reloc and no DYNAMIC_BASE, so these addresses are
// literal at runtime; they are still expressed as RVAs off
// GetModuleHandle(NULL). Nothing is called unless four independent
// fingerprints match: the function prologue, the two `movzx ...,[ebp+0xc]`
// sites that prove where the bool lives and that scorehistory.txt is
// guarded, and the `ret 8` epilogue that proves the calling convention. The
// singleton pointer is *not* hardcoded -- it is read out of the `mov ecx,
// imm32` at the game's own call site, which fails loudly rather than
// silently calling a member function on a wrong object.
//
// The call runs on the game's main thread at a frame boundary (see
// Statmind_ServiceMainThread), never on the IPC thread. Cogmind is
// single-threaded: calling into it from the IPC thread would race every
// piece of state the writer reads.

#ifdef _WIN32
#include <windows.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define STATMIND_SS_MAGIC 0xBADBEEF5
#define STATMIND_SS_CHECK 0x79533EDD

// status: resolution outcome, decided once at startup
#define SS_ST_UNTRIED        0
#define SS_ST_READY          1
#define SS_ST_DISABLED      -1  // suppressed by STATMIND_SCORESHEET=0
#define SS_ST_NO_MODULE     -2
#define SS_ST_NOT_PE        -3
#define SS_ST_SIG_MISMATCH  -4  // not Beta 17.1: writer fingerprint failed
#define SS_ST_CALLSITE      -5  // call site did not match; no singleton to use
#define SS_ST_UNSUPPORTED   -6  // not a Win32 build

// last_result: outcome of the most recent dump
#define SS_R_NONE            0
#define SS_R_OK              1
#define SS_R_NOT_READY      -1
#define SS_R_REENTRANT      -2

#define STATMIND_SS_TEXT 192

typedef struct {
    unsigned int magic;             // +0x00  STATMIND_SS_MAGIC
    unsigned int check;             // +0x04  STATMIND_SS_CHECK
    volatile int status;            // +0x08  SS_ST_*
    unsigned int module_base;       // +0x0C
    unsigned int fn_addr;           // +0x10  resolved outputScoresheet
    unsigned int self_addr;         // +0x14  Scorekeeper singleton, from the call site
    volatile unsigned int req;      // +0x18  bumped by the IPC thread
    volatile unsigned int done;     // +0x1C  copied from req by the main thread
    volatile int last_result;       // +0x20  SS_R_*
    volatile unsigned int calls;    // +0x24  successful calls so far
    volatile unsigned int text_len; // +0x28  bytes valid in `text`
    char text[STATMIND_SS_TEXT];    // +0x2C  the std::string the call returned
    // The first bytes of the hidden return buffer, verbatim. std::string is not
    // an ABI: its field offsets are an implementation detail of whichever MSVC
    // built the game, so publishing the raw head means a future build that
    // moves them can be diagnosed from a dump status instead of a rebuild.
    unsigned char ret_raw[32];      // +0xEC
} StatmindScoresheet;

__attribute__((dllexport))
__attribute__((used))
StatmindScoresheet g_statmind_scoresheet = {
    STATMIND_SS_MAGIC, STATMIND_SS_CHECK, SS_ST_UNTRIED,
    0, 0, 0, 0, 0, SS_R_NONE, 0, 0, {0}, {0}
};

#ifdef _WIN32

// Scorekeeper::outputScoresheet
#define SS_RVA_FN        0x00074B90U  // -> VA 0x00474B90
// movzx eax,BYTE PTR [ebp+0xc] / test / jne  -- the isDump parameter
#define SS_RVA_BOOL      0x00074BD0U  // -> VA 0x00474BD0
// movzx ecx,BYTE PTR [ebp+0xc] / test / jne over the scorehistory.txt append
#define SS_RVA_GUARD     0x0007E920U  // -> VA 0x0047E920
// mov esp,ebp / pop ebp / ret 8
#define SS_RVA_EPILOGUE  0x0007F43DU  // -> VA 0x0047F43D
// push 1 / lea eax,[ebp-0x2c] / push eax / mov ecx,<singleton> / call fn
#define SS_RVA_CALLSITE  0x003D640BU  // -> VA 0x007D640B

static const unsigned char SS_SIG_FN[10] = {
    0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xBA, 0x26, 0xAE, 0x00
};
static const unsigned char SS_SIG_BOOL[8] = {
    0x0F, 0xB6, 0x45, 0x0C, 0x85, 0xC0, 0x0F, 0x85
};
static const unsigned char SS_SIG_GUARD[8] = {
    0x0F, 0xB6, 0x4D, 0x0C, 0x85, 0xC9, 0x75, 0x0B
};
static const unsigned char SS_SIG_EPILOGUE[6] = {
    0x8B, 0xE5, 0x5D, 0xC2, 0x08, 0x00
};
// The imm32 at +6 is the singleton and is deliberately not compared.
static const unsigned char SS_SIG_CALLSITE[7] = {
    0x6A, 0x01, 0x8D, 0x45, 0xD4, 0x50, 0xB9
};

static int Statmind_SsMatch(const unsigned char *at,
                            const unsigned char *sig, unsigned int n)
{
    unsigned int i;
    for (i = 0; i < n; ++i) {
        if (at[i] != sig[i]) {
            return 0;
        }
    }
    return 1;
}

// MSVC 2010 std::basic_string<char>:
//   +0x00 union { char buf[16]; char *ptr; }
//   +0x10 size_type size
//   +0x14 size_type capacity
// Short strings live in the buffer; longer ones are heap-allocated and the
// union holds the pointer, and `capacity` is what selects between them. Read
// out of the game's own code rather than assumed from a header: _Tidy at
// 0x009BBF20 branches on `cmp [ecx+0x14], 0x10` (capacity at +0x14 against a
// 16-byte buffer), and the copy constructor at 0x009AF1B0 copy-constructs the
// allocator from `src + 0x18`, which puts it after both size fields and makes
// the whole object 28 bytes.
#define SS_STR_SIZE 0x10
#define SS_STR_RES  0x14
#define SS_STR_BUF  16

static void Statmind_SsReadString(const unsigned char *s)
{
    unsigned int size = *(const unsigned int *)(s + SS_STR_SIZE);
    unsigned int res  = *(const unsigned int *)(s + SS_STR_RES);
    const char *p;
    unsigned int n;

    if (res < SS_STR_BUF) {
        p = (const char *)s;
    } else {
        p = *(const char *const *)s;
    }
    if (!p || size > 0x10000u) {         // nonsense length: report nothing
        g_statmind_scoresheet.text_len = 0;
        g_statmind_scoresheet.text[0] = '\0';
        return;
    }
    n = size < (STATMIND_SS_TEXT - 1) ? size : (STATMIND_SS_TEXT - 1);
    memcpy(g_statmind_scoresheet.text, p, n);
    g_statmind_scoresheet.text[n] = '\0';
    g_statmind_scoresheet.text_len = n;
}

// __thiscall with two stack arguments and a callee that pops them (ret 8), so
// esp is balanced across the call and needs no fixup here.
//
// Every operand is pinned to a named register, which is not fussiness:
//
//   * `"r"` on i386 includes **esp**, and GCC will happily use it. Given a
//     stack buffer at the bottom of the frame it emitted `pushl %esp` for the
//     pointer -- pushing esp *after* the first push had already moved it, so
//     the callee constructed its return value four bytes below the buffer.
//     Everything still appeared to work (the dump was written) and only the
//     returned string came back as garbage. Hence esi/edi/ebx here.
//   * ebx, esi and edi are the registers a __thiscall callee must preserve, so
//     inputs held there survive the call. eax, ecx and edx do not, which is
//     why `this` is an in-out operand rather than an input: as a plain input,
//     GCC would go on believing ecx still held `self`.
static void *Statmind_ThisCall2(void *fn, void *self, void *a1, unsigned int a2)
{
    void *ret;
    void *ecx = self;

    __asm__ __volatile__(
        "pushl %[arg2]\n\t"
        "pushl %[arg1]\n\t"
        "call  *%[func]\n\t"
        : "=a"(ret), "+c"(ecx)
        : [func] "S"(fn), [arg1] "D"(a1), [arg2] "b"(a2)
        : "edx", "cc", "memory");
    (void)ecx;
    return ret;
}

static int Statmind_ResolveScoresheet(void)
{
    const char *env = getenv("STATMIND_SCORESHEET");
    unsigned char *base;
    unsigned char *fn;
    unsigned char *cs;
    unsigned int self;
    int rel;

    if (env && env[0] == '0') {
        g_statmind_scoresheet.status = SS_ST_DISABLED;
        printf("[Statmind_Scoresheet] disabled by STATMIND_SCORESHEET=0\n");
        fflush(stdout);
        return 0;
    }

    base = (unsigned char *)GetModuleHandleA(NULL);
    if (!base) {
        g_statmind_scoresheet.status = SS_ST_NO_MODULE;
        return 0;
    }
    g_statmind_scoresheet.module_base = (unsigned int)(size_t)base;

    if (base[0] != 'M' || base[1] != 'Z') {
        g_statmind_scoresheet.status = SS_ST_NOT_PE;
        return 0;
    }

    fn = base + SS_RVA_FN;
    cs = base + SS_RVA_CALLSITE;

    // Four checks on the writer itself. The prologue pins the function; the
    // two [ebp+0xc] sites pin where the bool lives and that the
    // scorehistory.txt append really is guarded by it; the epilogue pins the
    // calling convention. Any mismatch means this is not the build these
    // offsets were read from, and calling would be a wild jump.
    if (!Statmind_SsMatch(fn, SS_SIG_FN, sizeof(SS_SIG_FN)) ||
        !Statmind_SsMatch(base + SS_RVA_BOOL, SS_SIG_BOOL, sizeof(SS_SIG_BOOL)) ||
        !Statmind_SsMatch(base + SS_RVA_GUARD, SS_SIG_GUARD, sizeof(SS_SIG_GUARD)) ||
        !Statmind_SsMatch(base + SS_RVA_EPILOGUE, SS_SIG_EPILOGUE,
                          sizeof(SS_SIG_EPILOGUE))) {
        g_statmind_scoresheet.status = SS_ST_SIG_MISMATCH;
        printf("[Statmind_Scoresheet] writer fingerprint failed at base 0x%08X"
               " -- not Beta 17.1; dumps disabled\n",
               g_statmind_scoresheet.module_base);
        fflush(stdout);
        return 0;
    }

    // The singleton comes from the game's own call site rather than a
    // literal, and the relative call there must land on the function we just
    // fingerprinted. That cross-check is what makes the `this` pointer
    // trustworthy.
    rel = *(const int *)(cs + 11 + 1);
    if (!Statmind_SsMatch(cs, SS_SIG_CALLSITE, sizeof(SS_SIG_CALLSITE)) ||
        cs[11] != 0xE8 ||
        (unsigned char *)(cs + 11 + 5 + rel) != fn) {
        g_statmind_scoresheet.status = SS_ST_CALLSITE;
        printf("[Statmind_Scoresheet] call site at RVA 0x%08X did not match;"
               " no Scorekeeper pointer, dumps disabled\n", SS_RVA_CALLSITE);
        fflush(stdout);
        return 0;
    }
    self = *(const unsigned int *)(cs + 6 + 1);

    g_statmind_scoresheet.fn_addr   = (unsigned int)(size_t)fn;
    g_statmind_scoresheet.self_addr = self;
    g_statmind_scoresheet.status    = SS_ST_READY;
    printf("[Statmind_Scoresheet] ready: base=0x%08X fn=0x%08X this=0x%08X\n",
           g_statmind_scoresheet.module_base, g_statmind_scoresheet.fn_addr,
           g_statmind_scoresheet.self_addr);
    fflush(stdout);
    return 1;
}

// Runs on the game's main thread only. `ret` is the hidden return buffer the
// writer constructs a std::string into; 64 bytes is comfortably more than the
// 28 MSVC 2010 needs, and zeroing it means a writer that returns early leaves
// a readable empty string rather than stack garbage.
static void Statmind_DoScoresheetDump(void)
{
    static int in_call = 0;
    unsigned char ret[64];

    if (g_statmind_scoresheet.status != SS_ST_READY) {
        g_statmind_scoresheet.last_result = SS_R_NOT_READY;
        return;
    }
    if (in_call) {
        // The writer touching SDL would re-enter the frame hook that called
        // us. Refuse rather than recurse into a half-built dump.
        g_statmind_scoresheet.last_result = SS_R_REENTRANT;
        return;
    }
    in_call = 1;

    memset(ret, 0, sizeof(ret));
    Statmind_ThisCall2((void *)(size_t)g_statmind_scoresheet.fn_addr,
                       (void *)(size_t)g_statmind_scoresheet.self_addr,
                       ret, 1u /* isDump */);
    memcpy(g_statmind_scoresheet.ret_raw, ret,
           sizeof(g_statmind_scoresheet.ret_raw));
    Statmind_SsReadString(ret);

    // The returned std::string is left to leak if the writer heap-allocated
    // it: destroying it needs the game's own operator delete, and one small
    // allocation per explicit dump is not worth reaching for it.
    g_statmind_scoresheet.calls++;
    g_statmind_scoresheet.last_result = SS_R_OK;
    in_call = 0;
}

#else /* !_WIN32 */

static int Statmind_ResolveScoresheet(void)
{
    g_statmind_scoresheet.status = SS_ST_UNSUPPORTED;
    return 0;
}

static void Statmind_DoScoresheetDump(void)
{
    g_statmind_scoresheet.last_result = SS_R_NOT_READY;
}

#endif /* _WIN32 */

// Called from the frame hook, i.e. on the game's main thread between frames.
// The IPC thread only ever bumps `req`; every call into the game happens here.
static void Statmind_ServiceMainThread(void)
{
    unsigned int req = g_statmind_scoresheet.req;

    if (req != g_statmind_scoresheet.done) {
        Statmind_DoScoresheetDump();
        g_statmind_scoresheet.done = req;   // publish completion LAST
    }
}

#endif /* STATMIND_SCORESHEET_H */
