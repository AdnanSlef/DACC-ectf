#ifndef SRC_CONSTANTS_H_
#define SRC_CONSTANTS_H_

#include "xil_printf.h"

// shared DDR address
#define SHARED_DDR_BASE (0x20000000 + 0x1CC00000)

// memory constants
#define CHUNK_SZ 16000
#define FIFO_CAP 4096*4

// number of seconds to record/playback
#define PREVIEW_TIME_SEC 30

// ADC/DAC sampling rate in Hz
#define AUDIO_SAMPLING_RATE 48000
#define BYTES_PER_SAMP 2
#define PREVIEW_SZ (PREVIEW_TIME_SEC * AUDIO_SAMPLING_RATE * BYTES_PER_SAMP)

// printing utility
#define MB_PROMPT "\r\nMB> "
#define mb_printf(...) xil_printf(MB_PROMPT __VA_ARGS__)

// protocol constants
#define MAX_REGIONS 32
#define REGION_NAME_SZ 64
#define MAX_USERS 64
#define USERNAME_SZ 16
#define MAX_PIN_SZ 64
#define MAX_SONG_SZ (1<<25)
#define MD_SIZE 152


// LED colors and controller
struct color {
    u32 r;
    u32 g;
    u32 b;
};


// struct to interpret shared buffer as a query
typedef struct {
    int num_regions;
    int num_users;
    char owner[USERNAME_SZ];
    char regions[MAX_REGIONS * REGION_NAME_SZ];
    char users[MAX_USERS * USERNAME_SZ];
} query;

// simulate array of 64B names without pointer indirection
#define q_region_lookup(q, i) (q.regions + (i * REGION_NAME_SZ))
#define q_user_lookup(q, i) (q.users + (i * USERNAME_SZ))


// struct to interpret drm metadata
typedef struct __attribute__((__packed__)) {
    char owner_id;
    char num_regions;
    char num_users;
    char rids[MAX_REGIONS];
    char uids[MAX_USERS];
    char extra;
    char iv[16];
    int ct_len;
} drm_md;


// struct to interpret shared buffer as a WAV song file
// packing values skip over non-relevant WAV metadata
typedef struct __attribute__((__packed__)) {
    char packing1[4];
    u32 file_size;
    char packing2[32];
    u32 wav_size;
    char buf[];
} wav;


// struct to interpret shared buffer as a drm song file
typedef struct __attribute__((__packed__)) {
    char mac[32];
    drm_md md;
    char ct[];
} drm;

// shared buffer values
enum commands { QUERY_PLAYER, QUERY_SONG, LOGIN, LOGOUT, SHARE, PLAY, STOP, DIGITAL_OUT, PAUSE, RESTART, FF, RW };
enum states   { STOPPED, WORKING, PLAYING, PAUSED };


// struct to interpret shared command channel
typedef volatile struct __attribute__((__packed__)) {
    char cmd;                   // from commands enum
    char drm_state;             // from states enum
    char login_status;          // 0 = logged off, 1 = logged on
    char padding;               // not used
    char username[USERNAME_SZ]; // stores logged in or attempted username
    char pin[MAX_PIN_SZ];       // stores logged in or attempted pin

    // shared buffer is either a drm song or a wav song or a query
    union {
        drm drm;
        query query;
    	wav wav;
    };
} cmd_channel;


// local store for drm metadata
typedef struct {
    u8 owner_id;
    u8 num_regions;
    u8 num_users;
    u8 rids[MAX_REGIONS];
    u8 uids[MAX_USERS];
    u8 extra;
    u8 iv[16];
    int ct_len;
} song_md;


// store of internal state
typedef struct {
    char logged_in;             // whether or not a user is logged on
    u8 uid;                     // logged on user id
    char username[USERNAME_SZ]; // logged on username
    song_md song_md;            // current song metadata
} internal_state;


#endif /* SRC_CONSTANTS_H_ */
