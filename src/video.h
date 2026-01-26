#ifndef VIDEO_H
#define VIDEO_H

#include <stdint.h>
#include <efi.h>
#include <csmwrap.h>

extern void *vbios_loc;
extern uintptr_t vbios_size;

EFI_STATUS csmwrap_video_init(struct csmwrap_priv *priv);
EFI_STATUS csmwrap_video_prepare_exitbs(struct csmwrap_priv *priv);

void csmwrap_video_early_init(struct csmwrap_priv *priv);

#endif
