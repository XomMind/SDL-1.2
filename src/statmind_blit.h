/*
 * Statmind blit sniffer -- declarations only.
 *
 * Cogmind re-composites the whole screen every frame rather than tracking dirty
 * rectangles, which means every visible tile produces a blit call on every frame.
 * That inefficiency is a gift: the set of blit destinations *is* the player's
 * field of view, and the source rectangle within the font atlas identifies which
 * glyph was drawn. So instead of hunting for FOV state in memory, we record what
 * actually gets drawn.
 *
 * Definitions live in statmind_ipc.h (included once, by SDL.c). This header is
 * what the blit and flip paths include.
 */
#ifndef STATMIND_BLIT_H
#define STATMIND_BLIT_H

/* Call-site census indices. See g_statmind_calls. */
#define SMC_UPPER_BLIT     0
#define SMC_LOWER_BLIT     1
#define SMC_FILL_RECT      2
#define SMC_LOCK_SURFACE   3
#define SMC_UNLOCK_SURFACE 4
#define SMC_SOFT_STRETCH   5
#define SMC_UPDATE_RECT    6
#define SMC_UPDATE_RECTS   7
#define SMC_FLIP           8
#define SMC_GL_SWAP        9
#define SMC_SET_VIDEOMODE 10
#define SMC_MAX           16

extern void Statmind_Count(int which);

#define SM_DRAW_BLIT 0
#define SM_DRAW_FILL 1

extern void Statmind_RecordBlit(void *src, int sx, int sy,
                                int dx, int dy, int w, int h);
extern void Statmind_RecordFill(int dx, int dy, int w, int h, unsigned int color);
extern void Statmind_PublishFrame(void);

#endif /* STATMIND_BLIT_H */
