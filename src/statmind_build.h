#ifndef STATMIND_BUILD_H
#define STATMIND_BUILD_H

#include <stdint.h>
#include <string.h>

/* Two distinct Beta 17.1 executables. RVAs are not interchangeable.
 * SHA256s and disassembly evidence: harness/notes/retail-17.1.md.
 * Match metadata AND instructions before enabling writes or game calls.
 *
 * Every RVA here is fingerprinted against immutable bytes -- .text only.
 * Live .data is deliberately never compared: it reads as the linker left it
 * at SDL_Init and as the game left it a moment later, so such a check would
 * pass or fail depending on when it ran. The fixed .data addresses the
 * out-of-process reader uses are verified from the file on disk instead, by
 * harness/verify_retail.py. */
typedef struct {
    uint32_t timestamp;
    uint32_t init, writer, dump_bool, history_guard, epilogue, callsite, luigi_gate;
    uint32_t cell_at, map_callsite;
    unsigned char writer_sig[10];
} StatmindBuild;

static const StatmindBuild statmind_builds[] = {
    { 0x6A8CFC58, 0x34C00, 0x74B90, 0x74BD0, 0x7E920, 0x7F43D, 0x3D640B, 0x30E358,
      0x5CF7D0, 0x84CD7,
      { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xBA, 0x26, 0xAE, 0x00 } },
    { 0x6A9CBFDF, 0x34CD0, 0x74A20, 0x74A60, 0x7E7B0, 0x7F2CD, 0x3D66BB, 0x30E338,
      0x5CEDA0, 0x84B67,
      { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x7A, 0x29, 0xAE, 0x00 } }
};

static uint32_t Statmind_BuildU32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* base is a loaded module (or a section-mapped image in the offline test).
 * Only these fixed-base PE32 images are supported. Their mapped size is
 * 0x940000; all fingerprint reads below fall within their .text section. */
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
        Statmind_BuildU32(base + pe + 24 + 56) != 0x940000 ||
        (base[pe + 24 + 70] & 0x40)) return NULL;
    stamp = Statmind_BuildU32(base + pe + 8);
    for (i = 0; i < sizeof(statmind_builds) / sizeof(statmind_builds[0]); ++i) {
        b = &statmind_builds[i];
        if (stamp != b->timestamp) continue;
        if (memcmp(base + b->init + 10, "\xC7\x00\x4C\xFA\xAD\x64", 6) ||
            memcmp(base + b->init + 19, "\xC7\x41\x04\xD9\x3E\x53\x79", 7) ||
            memcmp(base + b->writer, b->writer_sig, 10) ||
            memcmp(base + b->dump_bool, "\x0F\xB6\x45\x0C\x85\xC0\x0F\x85", 8) ||
            memcmp(base + b->history_guard, "\x0F\xB6\x4D\x0C\x85\xC9\x75\x0B", 8) ||
            memcmp(base + b->epilogue, "\x8B\xE5\x5D\xC2\x08\x00", 6)) return NULL;
        /* The map-entry gate pins the shared active byte and LuigiAi object. */
        if (memcmp(base + b->luigi_gate,
                   "\x0F\xB6\x05\x3E\xFB\xCE\x00\x85\xC0\x74\x0A\xB9\xFC\xBF\xCE\x00", 16)) return NULL;
        /* cellAt pins the map object's field layout, and one of its 1736 call
         * sites pins the singleton's address. Nothing in this shim reads the
         * cell table -- the out-of-process reader does, at a fixed VA it has
         * no way to fingerprint itself -- so it is checked here, where a
         * mismatch stops the gate byte from ever being written. */
        if (memcmp(base + b->cell_at,
                   "\x55\x8B\xEC\x51\x89\x4D\xFC\x8B\x45\xFC\x8B\x4D\x08\x0F\xAF\x48"
                   "\x04\x03\x4D\x0C\x8B\x55\xFC\x8B\x42\x08\x8D\x04\x88\x8B\xE5\x5D"
                   "\xC2\x08\x00", 35)) return NULL;
        cs = base + b->map_callsite;
        if (cs[0] != 0xB9 || Statmind_BuildU32(cs + 1) != 0xCFD44C ||
            cs[5] != 0xE8 ||
            b->map_callsite + 10 + Statmind_BuildU32(cs + 6) != b->cell_at) return NULL;
        cs = base + b->callsite;
        if (memcmp(cs, "\x6A\x01\x8D\x45\xD4\x50\xB9", 7) ||
            cs[11] != 0xE8 ||
            b->callsite + 16 + Statmind_BuildU32(cs + 12) != b->writer ||
            Statmind_BuildU32(cs + 7) != 0xD2C658) return NULL;
        return b;
    }
    return NULL;
}

#endif
