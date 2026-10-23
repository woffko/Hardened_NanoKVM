#pragma once
#include <cstdint>

typedef struct {
    int type;
    int w;
    int h;
    int fmt;
    int jpg_quality;
    int gop;
    int intput_fps;
    int output_fps;
    int bitrate;
} mmf_venc_cfg_t;

typedef struct {
    int count;
    uint8_t *data[8];
    int data_size[8];
} mmf_stream_t;

int mmf_add_venc_channel(int channel, mmf_venc_cfg_t *cfg);
int mmf_del_venc_channel(int channel);
int mmf_invert_format_to_mmf(int format);
int mmf_venc_push(int channel, uint8_t *data, int width, int height, int format);
int mmf_venc_pop(int channel, mmf_stream_t *stream);
int mmf_venc_free(int channel);
int mmf_enc_jpg_deinit(int channel);
int mmf_try_deinit(bool force);
