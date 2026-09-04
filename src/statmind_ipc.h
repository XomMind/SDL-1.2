#include "statmind_blit.h"
#include "statmind_scoresheet.h"
#include "SDL_events.h"
#include "SDL_keyboard.h"
#include "SDL_mouse.h"
#include "SDL_thread.h"
#include "SDL_timer.h"
#include <stdio.h> // For printf
#include <stdlib.h> // For getenv
#include <string.h> // For memcmp

#ifdef _WIN32
#include <windows.h>
#endif

// Magic number to identify the mailbox in memory
#define STATMIND_MAGIC 0x64ADFA4D
#define STATMIND_CHECK 0x79533ED8

// Mailbox protocol version.
//
// v1 was `{u32 magic; u32 check; char command; u8 data; char pad[2];}` -- a single
// keysym with no modifiers, no unicode, and no mouse, which cannot express most of
// Cogmind's input grammar. commands.cfg has 329 commands across 33 UI domains, and
// 96 of the 493 bindings carry at least one modifier; text fields (hacking codes,
// manual seeds) need SDL_keysym.unicode, which v1 always left at 0.
//
// v2 keeps magic/check at +0x00/+0x04 so existing memory scans still locate it,
// and adds a seq/ack handshake. That handshake matters beyond bookkeeping: it
// separates "the keystroke was delivered" from "a game turn advanced". The old
// code inferred delivery from LuigiAi.actionReady changing, so any key that only
// opened a menu looked like a 5-second timeout.
#define STATMIND_MAILBOX_VERSION 2
#define STATMIND_TEXT_MAX 64

// mailbox.command
#define STATMIND_CMD_NONE   0
#define STATMIND_CMD_KEY    'K'   // keysym + modifiers + unicode, `repeat` times
#define STATMIND_CMD_TEXT   'T'   // type text[0..text_len) as keystrokes
#define STATMIND_CMD_MOUSE  'M'   // warp the cursor to (mouse_x, mouse_y)
#define STATMIND_CMD_BUTTON 'B'   // click `button` at (mouse_x, mouse_y)
#define STATMIND_CMD_DUMP   'D'   // write a mid-run scoresheet to dumps/

// mailbox.status
#define STATMIND_OK             1
#define STATMIND_ERR_COMMAND   -1
#define STATMIND_ERR_KEYSYM    -2
#define STATMIND_ERR_TEXT_LEN  -3
#define STATMIND_ERR_DUMP      -4  // writer unavailable, or it never ran

typedef volatile struct {
    unsigned int   magic;       // +0x00  STATMIND_MAGIC
    unsigned int   check;       // +0x04  STATMIND_CHECK
    unsigned int   version;     // +0x08  STATMIND_MAILBOX_VERSION
    unsigned int   seq;         // +0x0C  writer increments this LAST to submit
    unsigned int   ack;         // +0x10  shim copies seq here when done
    int            status;      // +0x14  result of the last completed command
    unsigned char  command;     // +0x18  STATMIND_CMD_*
    unsigned char  button;      // +0x19  mouse button, 1-based
    unsigned short keysym;      // +0x1A  SDLK_*
    unsigned short modifiers;   // +0x1C  KMOD_*
    unsigned short unicode;     // +0x1E  SDL_keysym.unicode
    unsigned short repeat;      // +0x20  0 and 1 both mean once
    unsigned short text_len;    // +0x22
    int            mouse_x;     // +0x24
    int            mouse_y;     // +0x28
    char           text[STATMIND_TEXT_MAX]; // +0x2C
} StatmindMailbox;              // sizeof == 0x6C == 108

// Global mailbox instance - accessible via memory scanning
__attribute__((dllexport))
__attribute__((used))
StatmindMailbox g_statmind_mailbox = {
    STATMIND_MAGIC, STATMIND_CHECK, STATMIND_MAILBOX_VERSION,
    0, 0, 0, STATMIND_CMD_NONE, 0, 0, 0, 0, 0, 0, 0, 0, {0}
};

// Struct for IPC thread status
typedef struct {
    unsigned int magic; // Magic number for this struct
    unsigned int check; // Magic number for this struct
    volatile int status; // 0 = not started, 1 = started
} StatmindThreadStatus;

#define THREAD_STATUS_MAGIC 0xBADBEEF1
#define THREAD_STATUS_CHECK 0x79533ED9

__attribute__((dllexport))
__attribute__((used))
StatmindThreadStatus g_ipc_thread_status = {THREAD_STATUS_MAGIC, THREAD_STATUS_CHECK, 0};

//==================================================================
// Blit sniffer
//==================================================================
// See statmind_blit.h for why this exists. Two buffers so a reader always sees a
// complete frame: blits accumulate into one while the other stays published.

#define STATMIND_BLIT_MAGIC 0xBADBEEF3
#define STATMIND_BLIT_CHECK 0x79533EDB
#define STATMIND_DRAW_MAX   16384

/* One draw operation. 20 bytes; verified with offsetof rather than assumed. */
typedef struct {
    short dx, dy;          /* destination on screen */
    short w, h;            /* size actually drawn, post-clipping */
    short sx, sy;          /* blit: source in the atlas. fill: unused */
    unsigned short kind;   /* SM_DRAW_BLIT | SM_DRAW_FILL */
    unsigned short pad;
    unsigned int arg;      /* blit: source surface id. fill: colour */
} StatmindDraw;

/*
 * Beta 17.1 does NOT recomposite the whole screen each frame -- while idle it
 * redraws a single 12x24 cell. So a single frame is not the field of view, and
 * the log accumulates instead: the reader bumps `clear_req` to start a fresh
 * capture, injects an action, waits for the redraw to settle, and reads back
 * everything that was drawn in between.
 *
 * Single buffer, because accumulation and double-buffering do not mix. A reader
 * that samples mid-redraw sees a short tail, which is harmless: read once the
 * frame counter stops moving.
 */
typedef struct {
    unsigned int magic;
    unsigned int check;
    volatile int enabled;              /* off by default */
    volatile unsigned int clear_req;   /* reader increments to reset */
    volatile unsigned int clear_seen;  /* shim mirrors it back */
    volatile unsigned int frame;       /* publishes since the last clear */
    volatile unsigned int count;       /* entries accumulated */
    volatile unsigned int dropped;     /* lost to overflow since the clear */
    volatile unsigned int total;       /* lifetime draw ops */
    unsigned int max;                  /* STATMIND_DRAW_MAX */
    StatmindDraw d[STATMIND_DRAW_MAX];
} StatmindDrawLog;

__attribute__((dllexport))
__attribute__((used))
StatmindDrawLog g_statmind_blit = {
    STATMIND_BLIT_MAGIC, STATMIND_BLIT_CHECK,
    0, 0, 0, 0, 0, 0, 0, STATMIND_DRAW_MAX, {{0}}
};

/* Call-site census, kept: it is how we learned FillRect dominates. */
#define STATMIND_CALLS_MAGIC 0xBADBEEF4
#define STATMIND_CALLS_CHECK 0x79533EDC

typedef struct {
    unsigned int magic;
    unsigned int check;
    volatile unsigned int n[SMC_MAX];
} StatmindCalls;

__attribute__((dllexport))
__attribute__((used))
StatmindCalls g_statmind_calls = { STATMIND_CALLS_MAGIC, STATMIND_CALLS_CHECK, {0} };

void Statmind_Count(int which)
{
    if (which >= 0 && which < SMC_MAX) {
        g_statmind_calls.n[which]++;
    }
}

static void Statmind_MaybeClear(void)
{
    if (g_statmind_blit.clear_req != g_statmind_blit.clear_seen) {
        g_statmind_blit.count = 0;
        g_statmind_blit.dropped = 0;
        g_statmind_blit.frame = 0;
        g_statmind_blit.clear_seen = g_statmind_blit.clear_req;
    }
}

static StatmindDraw *Statmind_Slot(void)
{
    unsigned int i;

    if (!g_statmind_blit.enabled) {
        return 0;
    }
    Statmind_MaybeClear();
    g_statmind_blit.total++;
    i = g_statmind_blit.count;
    if (i >= STATMIND_DRAW_MAX) {
        g_statmind_blit.dropped++;
        return 0;
    }
    g_statmind_blit.count = i + 1;
    return (StatmindDraw *)&g_statmind_blit.d[i];
}

void Statmind_RecordBlit(void *src, int sx, int sy, int dx, int dy, int w, int h)
{
    StatmindDraw *e = Statmind_Slot();
    if (!e) {
        return;
    }
    e->dx = (short)dx; e->dy = (short)dy;
    e->w = (short)w;   e->h = (short)h;
    e->sx = (short)sx; e->sy = (short)sy;
    e->kind = SM_DRAW_BLIT;
    e->pad = 0;
    e->arg = (unsigned int)(size_t)src;
}

void Statmind_RecordFill(int dx, int dy, int w, int h, unsigned int color)
{
    StatmindDraw *e = Statmind_Slot();
    if (!e) {
        return;
    }
    e->dx = (short)dx; e->dy = (short)dy;
    e->w = (short)w;   e->h = (short)h;
    e->sx = 0;         e->sy = 0;
    e->kind = SM_DRAW_FILL;
    e->pad = 0;
    e->arg = color;
}

void Statmind_PublishFrame(void)
{
    // The one hook this shim has on the game's own thread. Anything that must
    // call into Cogmind runs here, not on the IPC thread, and it runs even when
    // blit capture is off -- hence ahead of the early return below.
    Statmind_ServiceMainThread();

    if (!g_statmind_blit.enabled) {
        return;
    }
    Statmind_MaybeClear();
    g_statmind_blit.frame++;
}

//==================================================================
// LuigiAI re-enable  (Cogmind Beta 17.1, Win32 PE)
//==================================================================
// Beta 17 and 17.1 dropped the "-luigiAi" / "-luigiAiTest" switch strings
// and the twelve "luigiAi/" path literals that Beta 14 still carries, so
// the command-line switch no longer does anything. The *code* is intact:
// LuigiAi::initialize() is present in .text and writes all eleven fields
// exactly as luigiai.h declares them. Every one of its call sites is
// gated on a single byte, luigiAiActive.
//
// That byte lives past the end of .data's raw data (RVA 0x8EFB3E, raw
// covers RVA < 0x8EAC00), i.e. in the zero-fill tail, so it does not
// exist in the file on disk and cannot be patched there. It has to be
// written into the loaded image -- which is exactly where this shim
// already runs.
//
// The image has no .reloc section and DllCharacteristics 0x8100 (no
// DYNAMIC_BASE), so it cannot be relocated and always loads at its
// 0x00400000 ImageBase. We resolve through GetModuleHandle(NULL) anyway
// so the offsets below stay honest RVAs rather than absolute addresses.

#define LUIGI_STATUS_MAGIC 0xBADBEEF2
#define LUIGI_STATUS_CHECK 0x79533EDA

// Status codes for StatmindLuigiStatus.status
#define LUIGI_ST_UNTRIED       0
#define LUIGI_ST_ENABLED       1  // flag is set, subsystem should populate
#define LUIGI_ST_ALREADY_SET   2  // flag was already non-zero, left alone
#define LUIGI_ST_DISABLED     -1  // suppressed by STATMIND_LUIGI=0
#define LUIGI_ST_NO_MODULE    -2  // GetModuleHandle(NULL) failed
#define LUIGI_ST_NOT_PE       -3  // no MZ/PE header at the module base
#define LUIGI_ST_SIG_MISMATCH -4  // not Beta 17.1: initialize() fingerprint failed
#define LUIGI_ST_NOT_WRITABLE -5  // flag page refused to become writable
#define LUIGI_ST_UNSUPPORTED  -6  // not a Win32 build

typedef struct {
    unsigned int magic;
    unsigned int check;
    volatile int status;        // one of LUIGI_ST_*
    unsigned int module_base;   // resolved image base
    unsigned int flag_addr;     // absolute address of luigiAiActive
    unsigned int struct_addr;   // absolute address of the LuigiAi instance
} StatmindLuigiStatus;

__attribute__((dllexport))
__attribute__((used))
StatmindLuigiStatus g_statmind_luigi = {
    LUIGI_STATUS_MAGIC, LUIGI_STATUS_CHECK, LUIGI_ST_UNTRIED, 0, 0, 0
};

#ifdef _WIN32

// RVAs, Beta 17.1 (COGMIND.exe, 9347072 bytes).
// Add ImageBase 0x00400000 for the VAs quoted in the analysis notes.
#define LUIGI_RVA_SIG1    0x00034C0AU  // movl $0x64adfa4c, (%eax)      -> VA 0x00434C0A
#define LUIGI_RVA_SIG2    0x00034C13U  // movl $0x79533ed9, 0x4(%ecx)   -> VA 0x00434C13
#define LUIGI_RVA_ACTIVE  0x0008EFB3EU // luigiAiActive : bool          -> VA 0x00CEFB3E
#define LUIGI_RVA_TEST    0x0008EFB36U // luigiAiTest   : bool (probable)-> VA 0x00CEFB36
#define LUIGI_RVA_STRUCT  0x0008EBFFCU // LuigiAi luigiAi               -> VA 0x00CEBFFC

// The two magic-number stores at the head of LuigiAi::initialize().
// These are build immediates, not strings, so they survive whatever the
// string table is doing and pin the build far more tightly than a version
// check would.
static const unsigned char LUIGI_SIG1[6] = { 0xC7, 0x00, 0x4C, 0xFA, 0xAD, 0x64 };
static const unsigned char LUIGI_SIG2[7] = { 0xC7, 0x41, 0x04, 0xD9, 0x3E, 0x53, 0x79 };

// Make one byte writable if it isn't already. .data is normally mapped
// read/write, so this is belt-and-braces: a write to a read-only page
// would take the whole game down, and we are aiming to run hundreds of
// these unattended.
static int Statmind_MakeWritable(void *addr)
{
    MEMORY_BASIC_INFORMATION mbi;
    DWORD old;

    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) {
        return 0;
    }
    if (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        return 1;
    }
    if (!VirtualProtect(addr, 1, PAGE_READWRITE, &old)) {
        return 0;
    }
    return 1;
}

static int Statmind_EnableLuigiAi(void)
{
    unsigned char *base;
    unsigned char *flag;
    unsigned int   e_lfanew;
    const char    *env;

    env = getenv("STATMIND_LUIGI");
    if (env != NULL && env[0] == '0') {
        g_statmind_luigi.status = LUIGI_ST_DISABLED;
        printf("[Statmind_Luigi] Disabled by STATMIND_LUIGI=0.\n");
        fflush(stdout);
        return 0;
    }

    base = (unsigned char *)GetModuleHandleA(NULL);
    if (base == NULL) {
        g_statmind_luigi.status = LUIGI_ST_NO_MODULE;
        printf("[Statmind_Luigi] GetModuleHandle(NULL) failed.\n");
        fflush(stdout);
        return 0;
    }
    g_statmind_luigi.module_base = (unsigned int)(size_t)base;

    // Confirm we are looking at a PE image before trusting any RVA.
    if (base[0] != 'M' || base[1] != 'Z') {
        g_statmind_luigi.status = LUIGI_ST_NOT_PE;
        printf("[Statmind_Luigi] No MZ header at base 0x%08X.\n",
               g_statmind_luigi.module_base);
        fflush(stdout);
        return 0;
    }
    e_lfanew = *(const unsigned int *)(base + 0x3C);
    if (e_lfanew > 0x1000 || memcmp(base + e_lfanew, "PE\0\0", 4) != 0) {
        g_statmind_luigi.status = LUIGI_ST_NOT_PE;
        printf("[Statmind_Luigi] No PE signature at base 0x%08X + 0x%X.\n",
               g_statmind_luigi.module_base, e_lfanew);
        fflush(stdout);
        return 0;
    }

    // Build fingerprint: the two magic stores in LuigiAi::initialize().
    // Any other build lands here and we leave its memory alone.
    if (memcmp(base + LUIGI_RVA_SIG1, LUIGI_SIG1, sizeof(LUIGI_SIG1)) != 0 ||
        memcmp(base + LUIGI_RVA_SIG2, LUIGI_SIG2, sizeof(LUIGI_SIG2)) != 0) {
        g_statmind_luigi.status = LUIGI_ST_SIG_MISMATCH;
        printf("[Statmind_Luigi] initialize() fingerprint mismatch at base 0x%08X"
               " -- not Beta 17.1, leaving memory untouched.\n",
               g_statmind_luigi.module_base);
        fflush(stdout);
        return 0;
    }

    flag = base + LUIGI_RVA_ACTIVE;
    g_statmind_luigi.flag_addr   = (unsigned int)(size_t)flag;
    g_statmind_luigi.struct_addr = (unsigned int)(size_t)(base + LUIGI_RVA_STRUCT);

    if (!Statmind_MakeWritable(flag)) {
        g_statmind_luigi.status = LUIGI_ST_NOT_WRITABLE;
        printf("[Statmind_Luigi] luigiAiActive at 0x%08X is not writable.\n",
               g_statmind_luigi.flag_addr);
        fflush(stdout);
        return 0;
    }

    if (*flag != 0) {
        g_statmind_luigi.status = LUIGI_ST_ALREADY_SET;
        printf("[Statmind_Luigi] luigiAiActive already %u at 0x%08X.\n",
               (unsigned)*flag, g_statmind_luigi.flag_addr);
        fflush(stdout);
        return 1;
    }

    *flag = 1;
    g_statmind_luigi.status = LUIGI_ST_ENABLED;
    printf("[Statmind_Luigi] Enabled. base=0x%08X luigiAiActive=0x%08X luigiAi=0x%08X\n",
           g_statmind_luigi.module_base,
           g_statmind_luigi.flag_addr,
           g_statmind_luigi.struct_addr);
    fflush(stdout);

    // Optional: the second byte tested along the map-load path, believed to
    // be luigiAiTest. Off by default -- it dumps the FOV area to a file every
    // single action, and its path literal is one of the ones that went away
    // in Beta 17, so the write target is unverified. Opt in to identify which
    // of the two bytes is actually which.
    env = getenv("STATMIND_LUIGI_TEST");
    if (env != NULL && env[0] == '1') {
        unsigned char *tflag = base + LUIGI_RVA_TEST;
        if (Statmind_MakeWritable(tflag)) {
            *tflag = 1;
            printf("[Statmind_Luigi] luigiAiTest candidate set at 0x%08X.\n",
                   (unsigned)(size_t)tflag);
        } else {
            printf("[Statmind_Luigi] luigiAiTest candidate at 0x%08X is not writable.\n",
                   (unsigned)(size_t)tflag);
        }
        fflush(stdout);
    }

    return 1;
}

// Re-assert the flag. Nothing in Beta 17.1 is known to clear it -- the only
// writer was the argument parser, which is gone -- but the check is two
// instructions and the failure mode it guards against is a silently dead
// harness partway through a run.
static void Statmind_ReassertLuigiAi(void)
{
    unsigned char *flag;

    if (g_statmind_luigi.status != LUIGI_ST_ENABLED &&
        g_statmind_luigi.status != LUIGI_ST_ALREADY_SET) {
        return;
    }
    flag = (unsigned char *)(size_t)g_statmind_luigi.flag_addr;
    if (flag != NULL && *flag == 0) {
        *flag = 1;
        printf("[Statmind_Luigi] luigiAiActive was cleared; re-asserted.\n");
        fflush(stdout);
    }
}

#else /* !_WIN32 */

// Native (non-PE) builds load at entirely different addresses; the RVAs
// above are meaningless there. Report unsupported rather than guessing.
static int Statmind_EnableLuigiAi(void)
{
    g_statmind_luigi.status = LUIGI_ST_UNSUPPORTED;
    return 0;
}

static void Statmind_ReassertLuigiAi(void) {}

#endif /* _WIN32 */

static int Statmind_IPCThread(void *data);

static int ipc_thread_running = 0;

/* Push a bare key event with no modifier bookkeeping. */
static void Statmind_PushRaw(SDLKey sym, SDLMod mods, unsigned short uni, int down)
{
    SDL_Event event;

    memset(&event, 0, sizeof(event));
    event.type = down ? SDL_KEYDOWN : SDL_KEYUP;
    event.key.state = down ? SDL_PRESSED : SDL_RELEASED;
    event.key.keysym.sym = sym;
    event.key.keysym.mod = mods;
    event.key.keysym.unicode = uni;
    SDL_PushEvent(&event);
}

/*
 * Cogmind reads modifiers three ways, and only satisfying one of them is not
 * enough: SDL_keysym.mod on the event, SDL_GetModState(), and -- for at least
 * some commands -- the modifier's own key state, which only updates when real
 * key events for it pass through. Alt+F10 (New Game) produced *zero* redraws
 * with mod state alone, so the modifiers are now pressed as actual keys around
 * the keystroke, which is what a physical keyboard does.
 */
static void Statmind_PushKey(SDLKey sym, SDLMod mods, unsigned short uni)
{
    SDL_Event event;
    SDLMod saved = SDL_GetModState();

    if (mods != KMOD_NONE) {
        SDL_SetModState(mods);
        if (mods & KMOD_SHIFT) Statmind_PushRaw(SDLK_LSHIFT, mods, 0, 1);
        if (mods & KMOD_CTRL)  Statmind_PushRaw(SDLK_LCTRL,  mods, 0, 1);
        if (mods & KMOD_ALT)   Statmind_PushRaw(SDLK_LALT,   mods, 0, 1);
    }

    memset(&event, 0, sizeof(event));
    event.type = SDL_KEYDOWN;
    event.key.state = SDL_PRESSED;
    event.key.keysym.sym = sym;
    event.key.keysym.mod = mods;
    event.key.keysym.unicode = uni;
    SDL_PushEvent(&event);

    memset(&event, 0, sizeof(event));
    event.type = SDL_KEYUP;
    event.key.state = SDL_RELEASED;
    event.key.keysym.sym = sym;
    event.key.keysym.mod = mods;
    event.key.keysym.unicode = uni;
    SDL_PushEvent(&event);

    if (mods != KMOD_NONE) {
        /* Release in reverse order, then restore the previous mod state. */
        if (mods & KMOD_ALT)   Statmind_PushRaw(SDLK_LALT,   mods, 0, 0);
        if (mods & KMOD_CTRL)  Statmind_PushRaw(SDLK_LCTRL,  mods, 0, 0);
        if (mods & KMOD_SHIFT) Statmind_PushRaw(SDLK_LSHIFT, mods, 0, 0);
        SDL_SetModState(saved);
    }
}

// Type one character: derive the keysym and the shift state the way a real
// keyboard would, so text fields (hacking codes, manual seeds) receive both a
// plausible keysym and a correct unicode value.
static void Statmind_PushChar(char c)
{
    unsigned char u = (unsigned char)c;
    SDLKey sym;
    SDLMod mods = KMOD_NONE;

    if (u >= 'A' && u <= 'Z') {
        sym = (SDLKey)(u - 'A' + 'a');
        mods = KMOD_LSHIFT;
    } else if (u == '\n' || u == '\r') {
        sym = SDLK_RETURN;
    } else if (u == '\t') {
        sym = SDLK_TAB;
    } else if (u == '\b') {
        sym = SDLK_BACKSPACE;
    } else if (u < 0x80) {
        sym = (SDLKey)u;   // SDLK_* matches ASCII below 0x80
    } else {
        return;            // non-ASCII: no SDL 1.2 keysym to use
    }

    Statmind_PushKey(sym, mods, (unsigned short)u);
}

static void Statmind_PushButton(unsigned char button, int x, int y)
{
    SDL_Event event;

    memset(&event, 0, sizeof(event));
    event.type = SDL_MOUSEBUTTONDOWN;
    event.button.button = button;
    event.button.state = SDL_PRESSED;
    event.button.x = (Uint16)x;
    event.button.y = (Uint16)y;
    SDL_PushEvent(&event);

    memset(&event, 0, sizeof(event));
    event.type = SDL_MOUSEBUTTONUP;
    event.button.button = button;
    event.button.state = SDL_RELEASED;
    event.button.x = (Uint16)x;
    event.button.y = (Uint16)y;
    SDL_PushEvent(&event);
}

static void Statmind_StartIPC()
{
    if (!ipc_thread_running) {
        // Do this before the thread exists and long before any map loads.
        // The guard we are opening is only read on the map-load path.
        Statmind_EnableLuigiAi();
        Statmind_ResolveScoresheet();

        printf("[Statmind_StartIPC] Creating IPC thread.\n");
        fflush(stdout);
        SDL_CreateThread(Statmind_IPCThread, NULL);
        ipc_thread_running = 1;
    } else {
        printf("[Statmind_StartIPC] IPC thread already running.\n");
        fflush(stdout);
    }
}

static int Statmind_IPCThread(void *data)
{
    (void)data; // Suppress unused parameter warning
    g_ipc_thread_status.status = 1; // Mark as started
    printf("[Statmind_IPCThread] started. mailbox magic=0x%X version=%u\n",
           g_statmind_mailbox.magic, g_statmind_mailbox.version);
    fflush(stdout);

    unsigned int poll_count = 0;

    while (1)
    {
        // Poll at 1ms rather than spinning. The old loop had its SDL_Delay
        // commented out and printed on every iteration, which pinned a core and
        // flooded stdout -- survivable for one instance, not for a few hundred.
        SDL_Delay(1);

        if (++poll_count >= 1000) { // ~1s
            poll_count = 0;
            Statmind_ReassertLuigiAi();
        }

        if (g_statmind_mailbox.seq == g_statmind_mailbox.ack) {
            continue;
        }

        // Snapshot before acting: the writer must not mutate a command in flight,
        // but a torn read here would be silent and awful to debug.
        unsigned int   seq   = g_statmind_mailbox.seq;
        unsigned char  cmd   = g_statmind_mailbox.command;
        unsigned short sym   = g_statmind_mailbox.keysym;
        unsigned short mods  = g_statmind_mailbox.modifiers;
        unsigned short uni   = g_statmind_mailbox.unicode;
        unsigned short rep   = g_statmind_mailbox.repeat ? g_statmind_mailbox.repeat : 1;
        unsigned short tlen  = g_statmind_mailbox.text_len;
        unsigned char  btn   = g_statmind_mailbox.button ? g_statmind_mailbox.button : 1;
        int            mx    = g_statmind_mailbox.mouse_x;
        int            my    = g_statmind_mailbox.mouse_y;
        char           text[STATMIND_TEXT_MAX];
        unsigned short i;

        for (i = 0; i < STATMIND_TEXT_MAX; ++i) {
            text[i] = g_statmind_mailbox.text[i];
        }

        int status = STATMIND_OK;

        switch (cmd) {
        case STATMIND_CMD_KEY:
            if (sym == SDLK_UNKNOWN) {
                status = STATMIND_ERR_KEYSYM;
            } else {
                for (i = 0; i < rep; ++i) {
                    Statmind_PushKey((SDLKey)sym, (SDLMod)mods, uni);
                }
            }
            break;

        case STATMIND_CMD_TEXT:
            if (tlen > STATMIND_TEXT_MAX) {
                status = STATMIND_ERR_TEXT_LEN;
            } else {
                for (i = 0; i < tlen; ++i) {
                    Statmind_PushChar(text[i]);
                }
            }
            break;

        case STATMIND_CMD_MOUSE:
            // Warp rather than synthesising motion: Cogmind's cursor-driven
            // targeting reads the real mouse position, not just the event queue.
            SDL_WarpMouse((Uint16)mx, (Uint16)my);
            break;

        case STATMIND_CMD_BUTTON:
            SDL_WarpMouse((Uint16)mx, (Uint16)my);
            Statmind_PushButton(btn, mx, my);
            break;

        case STATMIND_CMD_DUMP:
            // Hand the work to the main thread and wait for it, so the ack
            // means "the file is on disk" rather than "the request was
            // queued". The wait is bounded because a game that has stopped
            // presenting frames -- minimised, or wedged -- would otherwise
            // wedge the mailbox with it. `repeat` carries an optional
            // deadline in milliseconds.
            {
                unsigned int want = g_statmind_scoresheet.req + 1;
                unsigned int budget = rep > 1 ? rep : 5000;
                unsigned int waited = 0;

                if (g_statmind_scoresheet.status != SS_ST_READY) {
                    status = STATMIND_ERR_DUMP;
                    break;
                }
                g_statmind_scoresheet.req = want;
                while (g_statmind_scoresheet.done != want && waited < budget) {
                    SDL_Delay(1);
                    waited++;
                }
                if (g_statmind_scoresheet.done != want ||
                    g_statmind_scoresheet.last_result != SS_R_OK) {
                    status = STATMIND_ERR_DUMP;
                }
            }
            break;

        default:
            status = STATMIND_ERR_COMMAND;
            break;
        }

        g_statmind_mailbox.status  = status;
        g_statmind_mailbox.command = STATMIND_CMD_NONE;
        g_statmind_mailbox.ack     = seq;   // publish completion LAST
    }
    return 0;
}
