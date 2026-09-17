#ifndef STATMIND_BUILD_H
#define STATMIND_BUILD_H

#include <stdint.h>
#include <string.h>

/* Every Cogmind executable this harness supports. Nothing here is shared
 * between builds: three Beta 17.1 executables carry the same version string
 * and none of their addresses are interchangeable.
 *
 * Evidence, and the procedure for adding the next one: harness/notes/retail-17.1.md.
 *
 * The first two differ only in .text -- their .data sits at the same RVA with
 * the same virtual size, so their data addresses coincide. The Steam build
 * breaks that: steam_api pushes .text past a page boundary, .rdata and .data
 * both move up 0x1000, and every global moves with them by a slightly
 * different amount. So data addresses live in the table, per build, and are
 * never assumed to carry over.
 *
 * Fingerprints only ever read .text. Live .data reads as the linker left it
 * during SDL_Init and as the game left it a moment later, so a check over it
 * would pass or fail depending on when it ran. The static data addresses are
 * verified from the file on disk by harness/verify_retail.py. */
typedef struct {
    uint32_t timestamp;
    uint32_t image_size;
    /* .text RVAs, each checked against an instruction below. */
    uint32_t init, writer, dump_bool, history_guard, epilogue, callsite,
             luigi_gate, cell_at, map_callsite;
    /* Absolute VAs. The first four are proved by the instruction anchors:
     * the gate encodes active and luigi, the call sites encode map_object and
     * scorekeeper, so a fingerprint match confirms them outright. */
    uint32_t active, luigi, map_object, scorekeeper;
    /* No code refers to these two, so nothing can confirm them here. The
     * view origin is at least initialised data and verify_retail.py checks it
     * against its (27, 8) initialiser; the player record is zero-fill reached
     * through a pointer, and only a live reading settles it. Zero means
     * unknown, and the reader must refuse rather than guess. */
    uint32_t view_origin, player_rec;
    /* Probable luigiAiTest, opt-in only. Zero where it was never identified. */
    uint32_t luigi_test;
    unsigned char writer_sig[10];
} StatmindBuild;

static const StatmindBuild statmind_builds[] = {
    /* Beta 17.1, 9,347,072 bytes, PE timestamp 2026-08-25. */
    { 0x6A8CFC58, 0x940000,
      0x34C00, 0x74B90, 0x74BD0, 0x7E920, 0x7F43D, 0x3D640B, 0x30E358,
      0x5CF7D0, 0x84CD7,
      0x00CEFB3E, 0x00CEBFFC, 0x00CFD44C, 0x00D2C658,
      0x00CD8FA4, 0x00D2D338,
      0x00CEFB36,
      { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xBA, 0x26, 0xAE, 0x00 } },
    /* Beta 17.1 patch 260906, 9,347,584 bytes, PE timestamp 2026-09-06. */
    { 0x6A9CBFDF, 0x940000,
      0x34CD0, 0x74A20, 0x74A60, 0x7E7B0, 0x7F2CD, 0x3D66BB, 0x30E338,
      0x5CEDA0, 0x84B67,
      0x00CEFB3E, 0x00CEBFFC, 0x00CFD44C, 0x00D2C658,
      0x00CD8FA4, 0x00D2D338,
      0x00CEFB36,
      { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x7A, 0x29, 0xAE, 0x00 } },
    /* Steam, Beta 17.1 patch 260906, 9,357,312 bytes, PE timestamp 2026-09-06
     * -- built 77 seconds after the one above, from the same source.
     * player_rec is 0 because it has never been read on this build. */
    { 0x6A9CC02C, 0x941000,
      0x34E40, 0x74D60, 0x74DA0, 0x7EAF0, 0x7F60D, 0x3D790B, 0x30F3F8,
      0x5D1260, 0x84ED7,
      0x00CF0C0B, 0x00CED0CC, 0x00CFE528, 0x00D2D738,
      0x00CDA074, 0x00000000,
      0x00000000,
      { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xAA, 0x43, 0xAE, 0x00 } }
};

static uint32_t Statmind_BuildU32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* base is a loaded module (or a section-mapped image in the offline test).
 * Only fixed-base PE32 images are supported; every read below lands in .text. */
static const StatmindBuild *Statmind_FindBuild(const unsigned char *base)
{
    uint32_t pe, stamp;
    unsigned int i;
    const StatmindBuild *b;
    const unsigned char *cs;
    if (!base || base[0] != 'M' || base[1] != 'Z') return NULL;
    pe = Statmind_BuildU32(base + 0x3C);
    if (pe > 0x1000 || memcmp(base + pe, "PE\0\0\x4C\x01", 6)) return NULL;
    if (base[pe + 24] != 0x0B || base[pe + 25] != 0x01 ||
        Statmind_BuildU32(base + pe + 24 + 28) != 0x400000 ||
        (base[pe + 24 + 70] & 0x40)) return NULL;
    stamp = Statmind_BuildU32(base + pe + 8);
    for (i = 0; i < sizeof(statmind_builds) / sizeof(statmind_builds[0]); ++i) {
        b = &statmind_builds[i];
        if (stamp != b->timestamp) continue;
        if (Statmind_BuildU32(base + pe + 24 + 56) != b->image_size) return NULL;
        if (memcmp(base + b->init + 10, "\xC7\x00\x4C\xFA\xAD\x64", 6) ||
            memcmp(base + b->init + 19, "\xC7\x41\x04\xD9\x3E\x53\x79", 7) ||
            memcmp(base + b->writer, b->writer_sig, 10) ||
            memcmp(base + b->dump_bool, "\x0F\xB6\x45\x0C\x85\xC0\x0F\x85", 8) ||
            memcmp(base + b->history_guard, "\x0F\xB6\x4D\x0C\x85\xC9\x75\x0B", 8) ||
            memcmp(base + b->epilogue, "\x8B\xE5\x5D\xC2\x08\x00", 6)) return NULL;
        /* The map-entry gate encodes both the active byte and the LuigiAi
         * instance, so one match confirms two of the table's addresses:
         *   movzx eax,[active]; test eax,eax; jz +10; mov ecx,<luigi> */
        cs = base + b->luigi_gate;
        if (memcmp(cs, "\x0F\xB6\x05", 3) ||
            Statmind_BuildU32(cs + 3) != b->active ||
            memcmp(cs + 7, "\x85\xC0\x74\x0A\xB9", 5) ||
            Statmind_BuildU32(cs + 12) != b->luigi) return NULL;
        /* cellAt pins the map object's field layout, and one of its call sites
         * pins the singleton's address. Nothing in this shim reads the cell
         * table -- the out-of-process reader does, at an address it has no way
         * to fingerprint from there -- so it is checked here, where a mismatch
         * still stops the gate byte being written. */
        if (memcmp(base + b->cell_at,
                   "\x55\x8B\xEC\x51\x89\x4D\xFC\x8B\x45\xFC\x8B\x4D\x08\x0F\xAF\x48"
                   "\x04\x03\x4D\x0C\x8B\x55\xFC\x8B\x42\x08\x8D\x04\x88\x8B\xE5\x5D"
                   "\xC2\x08\x00", 35)) return NULL;
        cs = base + b->map_callsite;
        if (cs[0] != 0xB9 || Statmind_BuildU32(cs + 1) != b->map_object ||
            cs[5] != 0xE8 ||
            b->map_callsite + 10 + Statmind_BuildU32(cs + 6) != b->cell_at) return NULL;
        /* The Scorekeeper pointer comes from the game's own call site rather
         * than a literal, and the relative call must land on the function just
         * fingerprinted. That cross-check is what makes `this` trustworthy. */
        cs = base + b->callsite;
        if (memcmp(cs, "\x6A\x01\x8D\x45\xD4\x50\xB9", 7) ||
            cs[11] != 0xE8 ||
            b->callsite + 16 + Statmind_BuildU32(cs + 12) != b->writer ||
            Statmind_BuildU32(cs + 7) != b->scorekeeper) return NULL;
        return b;
    }
    return NULL;
}

#endif
