/*
 * eCTF Collegiate 2020 MicroBlaze Example Code
 * Audio Digital Rights Management
 */

#include <stdio.h>
#include "platform.h"
#include "xparameters.h"
#include "xil_exception.h"
#include "xstatus.h"
#include "xaxidma.h"
#include "xil_mem.h"
#include "util.h"
#include "secrets.h"
#include "xintc.h"
#include "constants.h"
#include "sleep.h"


//////////////////////// GLOBALS ////////////////////////

// audio DMA access
static XAxiDma sAxiDma;

// LED colors and controller
u32 *led = (u32*) XPAR_RGB_PWM_0_PWM_AXI_BASEADDR;
const struct color RED =    {0x01ff, 0x0000, 0x0000};
const struct color YELLOW = {0x01ff, 0x01ff, 0x0000};
const struct color GREEN =  {0x0000, 0x01ff, 0x0000};
const struct color BLUE =   {0x0000, 0x0000, 0x01ff};

// change states
#define change_state(state, color) c->drm_state = state; setLED(led, color);
#define set_stopped() change_state(STOPPED, RED)
#define set_working() change_state(WORKING, YELLOW)
#define set_playing() change_state(PLAYING, GREEN)
#define set_paused()  change_state(PAUSED, BLUE)

// shared command channel -- read/write for both PS and PL
volatile cmd_channel *c = (cmd_channel*)SHARED_DDR_BASE;

// internal state store
internal_state s;


//////////////////////// INTERRUPT HANDLING ////////////////////////

// shared variable between main thread and interrupt processing thread
volatile static int InterruptProcessed = FALSE;
static XIntc InterruptController;

void myISR(void) {
    InterruptProcessed = TRUE;
}


///////////////////////// B-Con Crypto ////////////////////////////

/****************************** MACROS ******************************/
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;

/**************************** VARIABLES *****************************/
static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/
void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
	WORD i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX *ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}


///////////////////////////// NSA Speck  //////////////////////////////

/****************************** MACROS *************(*****************/
#define ROTL64(x,r) (((x)<<(r)) | (x>>(64-(r))))
#define ROTR64(x,r) (((x)>>(r)) | ((x)<<(64-(r))))
#define ER64(x,y,k) (x=ROTR64(x,8), x+=y, x^=k, y=ROTL64(y,3), y^=x)
#define DR64(x,y,k) (y^=x, y=ROTR64(y,3), x^=k, x-=y, x=ROTL64(x,8))

/*********************** FUNCTION DEFINITIONS ************************/
void Words64ToBytes(u64 words[],u8 bytes[],int numwords) {
  int i,j=0;
  for(i=0;i<numwords;i++) {
    bytes[j]=(u8)words[i];
    bytes[j+1]=(u8)(words[i]>>8);
    bytes[j+2]=(u8)(words[i]>>16);
    bytes[j+3]=(u8)(words[i]>>24);
    bytes[j+4]=(u8)(words[i]>>32);
    bytes[j+5]=(u8)(words[i]>>40);
    bytes[j+6]=(u8)(words[i]>>48);
    bytes[j+7]=(u8)(words[i]>>56);
    j+=8;
  }
}

void BytesToWords64(u8 bytes[],u64 words[],int numbytes) {
  int i,j=0;
  for(i=0;i<numbytes/8;i++) {
    words[i]=(u64)bytes[j] | ((u64)bytes[j+1]<<8) | ((u64)bytes[j+2]<<16) | ((u64)bytes[j+3]<<24) | ((u64)bytes[j+4]<<32) | ((u64)bytes[j+5]<<40) | ((u64)bytes[j+6]<<48) | ((u64)bytes[j+7]<<56);
    j+=8;
  }
}

void Speck128256KeySchedule(u64 K[],u64 rk[]) {
  u64 i,D=K[3],C=K[2],B=K[1],A=K[0];
  for(i=0;i<33;) {
    rk[i]=A; ER64(B,A,i++);
    rk[i]=A; ER64(C,A,i++);
    rk[i]=A; ER64(D,A,i++);
  }
  rk[i]=A;
}

void Speck128256Encrypt(u64 Pt[],u64 Ct[],u64 rk[]) {
  u64 i;
  Ct[0]=Pt[0]; Ct[1]=Pt[1];
  for(i=0;i<34;) ER64(Ct[1],Ct[0],rk[i++]);
}

void Speck128256Decrypt(u64 Pt[],u64 Ct[],u64 rk[]) {
  int i;
  Pt[0]=Ct[0]; Pt[1]=Ct[1];
  for(i=33;i>=0;) DR64(Pt[1],Pt[0],rk[i--]);
}

u8 speck_test(int i) {
  u8 pt[] = {0x70,0x6f,0x6f,0x6e,0x65,0x72,0x2e,0x20,0x49,0x6e,0x20,0x74,0x68,0x6f,0x73,0x65};
  u8 k[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
  u8 ct[16];
  u64 Pt[2], K[4], rk[34], Ct[2];
  BytesToWords64(pt,Pt,16);
  if ((Pt[0]!=(u64)0x202e72656e6f6f70) || (Pt[1]!=(u64)0x65736f6874206e49)) return 0;
  BytesToWords64(k,K,32);
  if ((K[0]!=(u64)0x0706050403020100) || (K[1]!=(u64)0x0f0e0d0c0b0a0908) || (K[2]!=(u64)0x1716151413121110) || (K[3]!=(u64)0x1f1e1d1c1b1a1918)) return 0;
  Speck128256KeySchedule(K,rk);
  //check rk
  Speck128256Encrypt(Pt,Ct,rk);
  //check Pt
  //check Ct
  Words64ToBytes(Ct,ct,2);
  return ct[i]; //manually check ct
}

u64 round_key[34];
int key_rounded = 0;
void speck_block_CTR(u8 true_counter[16], u8 true_ciphertext[16], u8 output[16]) {
    u64 Pt[2], Ct[2], K[4];
    u8 ct[16];
    if(!key_rounded) {
        BytesToWords64(KEY1,K,32);
	    Speck128256KeySchedule(K,round_key);
	    key_rounded = 1;
    }
    
    BytesToWords64(true_counter,Pt,16);
    Speck128256Encrypt(Pt,Ct,round_key);
    Words64ToBytes(Ct,ct,2); //ct is now in reverse
    for(int i=0; i<16; i++) {
    	output[i] = true_ciphertext[i] ^ ct[i];
    }
}


//////////////////////// UTILITY FUNCTIONS ////////////////////////

// returns whether an rid has been provisioned
int is_provisioned_rid(char rid) {
    for (int i = 0; i < NUM_PROVISIONED_REGIONS; i++) {
        if (rid == PROVISIONED_RIDS[i]) {
            return TRUE;
        }
    }
    return FALSE;
}

// looks up the region name corresponding to the rid
int rid_to_region_name(char rid, char **region_name, int provisioned_only) {
    for (int i = 0; i < NUM_REGIONS; i++) {
        if (rid == REGION_IDS[i] &&
            (!provisioned_only || is_provisioned_rid(rid))) {
            *region_name = (char *)REGION_NAMES[i];
            return TRUE;
        }
    }

    mb_printf("Could not find region ID '%d'\r\n", rid);
    *region_name = "<unknown region>";
    return FALSE;
}


// looks up the rid corresponding to the region name
int region_name_to_rid(char *region_name, char *rid, int provisioned_only) {
    for (int i = 0; i < NUM_REGIONS; i++) {
        if (!strcmp(region_name, REGION_NAMES[i]) &&
            (!provisioned_only || is_provisioned_rid(REGION_IDS[i]))) {
            *rid = REGION_IDS[i];
            return TRUE;
        }
    }

    mb_printf("Could not find region name '%s'\r\n", region_name);
    *rid = -1;
    return FALSE;
}


// returns whether a uid has been provisioned
int is_provisioned_uid(char uid) {
    for (int i = 0; i < NUM_PROVISIONED_USERS; i++) {
        if (uid == PROVISIONED_UIDS[i]) {
            return TRUE;
        }
    }
    return FALSE;
}


// looks up the username corresponding to the uid
int uid_to_username(char uid, char **username, int provisioned_only) {
    for (int i = 0; i < NUM_USERS; i++) {
        if (uid == USER_IDS[i] &&
            (!provisioned_only || is_provisioned_uid(uid))) {
            *username = (char *)USERNAMES[i];
            return TRUE;
        }
    }

    mb_printf("Could not find uid '%d'\r\n", uid);
    *username = "<unknown user>";
    return FALSE;
}


// looks up the uid corresponding to the username
int username_to_uid(char *username, char *uid, int provisioned_only) {
    for (int i = 0; i < NUM_USERS; i++) {
        if (!strcmp(username, USERNAMES[i]) &&
            (!provisioned_only || is_provisioned_uid(USER_IDS[i]))) {
            *uid = USER_IDS[i];
            return TRUE;
        }
    }

    mb_printf("Could not find username '%s'\r\n", username);
    *uid = -1;
    return FALSE;
}


// loads the song metadata in the shared buffer into the local struct
int load_song_md() {
    BYTE md_buf[120];
    BYTE mac[SHA256_BLOCK_SIZE];
    BYTE tag[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    
    //load data from command channels into local buffers
    memcpy(tag, c->drm.mac, SHA256_BLOCK_SIZE);
    memcpy(md_buf, (void *)&c->drm.md, 120);
    
    //verify the authenticity of the metadata
    sha256_init(&ctx);
    sha256_update(&ctx, md_buf, 120);
    sha256_update(&ctx, KEY2, 32);
    sha256_final(&ctx, mac);
    if(memcmp(tag, mac, SHA256_BLOCK_SIZE)) {
        return FALSE;
    }
    
    //load verified metadata into internal state
    memcpy((void*)&s.song_md, md_buf, 120);
    return TRUE;
}


// checks if the song loaded into the shared buffer is locked for the current user
int is_locked() {//TODO finish, why don't mb_printf calls have \r\n
    int locked = TRUE;

    // check for authorized user
    if (!s.logged_in) {
        mb_printf("No user logged in");
    } else {
        if(!load_song_md()) {
            mb_printf("Tampering detected. Song locked.");
            return FALSE; //TODO does the caller need to know more than 1 bit?
        };

        // check if user is authorized to play song
        if (s.uid == s.song_md.owner_id) {
            locked = FALSE;
        } else {
            for (int i = 0; (i < s.song_md.num_users) && locked; i++) {
                if (s.uid == s.song_md.uids[i]) {
                    locked = FALSE;
                }
            }
        }

        if (locked) {
            mb_printf("User '%s' does not have access to this song", s.username);
            return locked;
        }
        mb_printf("User '%s' has access to this song", s.username);
        locked = TRUE; // reset lock for region check

        // search for region match
        for (int i = 0; i < s.song_md.num_regions; i++) {
            for (int j = 0; j < (u8)NUM_PROVISIONED_REGIONS; j++) {
                if (PROVISIONED_RIDS[j] == s.song_md.rids[i]) {
                    locked = FALSE;
                }
            }
        }

        if (!locked) {
            mb_printf("Region Match. Full Song can be played. Unlocking...");
        } else {
            mb_printf("Invalid region");
        }
    }
    return locked;
}


//////////////////////// COMMAND FUNCTIONS ////////////////////////

// attempt to log in to the credentials in the shared buffer
void login() {
    char *name;
    
    if (s.logged_in) {
        mb_printf("Already logged in. Please log out first.\r\n");
        memcpy((void*)c->username, s.username, USERNAME_SZ);
    } else {
        for (int i = 0; i < NUM_PROVISIONED_USERS; i++) {
            // search for matching username
            for (int j = 0; j < NUM_USERS; j++) {
                if (PROVISIONED_UIDS[i] == USER_IDS[j]) {
                    name = USERNAMES[j];
                }
            }
            if (!strcmp((void*)c->username, name)) {
                // check if pin matches
                if (!strcmp((void*)c->pin, PROVISIONED_PINS[i])) {
                    //update states
                    s.logged_in = 1;
                    c->login_status = 1;
                    memcpy(s.username, (void*)c->username, USERNAME_SZ);
                    s.uid = PROVISIONED_UIDS[i];
                    mb_printf("Logged in for user '%s'\r\n", c->username);
                    return;
                } else {
                    //print error messages
                    mb_printf("Incorrect pin for user '%s'\r\n",c->username);
                    mb_printf("Please do not attempt hacking.\r\n");
                    mb_printf("Wait 4 seconds before next login attempt.\r\n");
                    
                    //delay about 3.6 seconds to prevent brute force
                    for(int i=0;i<1000000;i++) {
                        if(i%(1000000/4)==0) {
                            //nop
                        }
                    }
                    
                    // reject login attempt
                    memset((void*)c->username, 0, USERNAME_SZ);
                    memset((void*)c->pin, 0, MAX_PIN_SZ);
                    return;
                }
            }
        }

        // reject login attempt
        mb_printf("User not found or attack detected\r\n");
        memset((void*)c->username, 0, USERNAME_SZ);
        memset((void*)c->pin, 0, MAX_PIN_SZ);
    }
}


// attempt to log out
void logout() {
    if (s.logged_in) {
        mb_printf("Logging out...\r\n");
        s.logged_in = 0;
        c->login_status = 0;
        memset((void*)c->username, 0, USERNAME_SZ);
        memset((void*)c->pin, 0, MAX_PIN_SZ);
        s.uid = 0;
    } else {
        mb_printf("Not logged in\r\n");
    }
}


// handles a request to query the player's metadata
void query_player() {
    char *name;
    
    c->query.num_regions = NUM_PROVISIONED_REGIONS;
    c->query.num_users = NUM_PROVISIONED_USERS;

    for (int i = 0; i < NUM_PROVISIONED_REGIONS; i++) {
        for (int j = 0; j < NUM_REGIONS; j++) {
            if (PROVISIONED_RIDS[i] == REGION_IDS[j]) {
                name = REGION_NAMES[j];
            }
        }
        strcpy((char *)q_region_lookup(c->query, i), REGION_NAMES[PROVISIONED_RIDS[i]]);
    }

    for (int i = 0; i < NUM_PROVISIONED_USERS; i++) {
        for (int j = 0; j < NUM_USERS; j++) {
            if (PROVISIONED_UIDS[i] == USER_IDS[j]) {
                name = USERNAMES[j];
            }
        }
        strcpy((char *)q_user_lookup(c->query, i), name);
    }

    mb_printf("Queried player (%d regions, %d users)\r\n", c->query.num_regions, c->query.num_users);
}


// handles a request to query song metadata
void query_song() {
    char *name;

    // load song
    if(!load_song_md()) {
	mb_printf("Tampering detected. Song cannot be queried\r\n");
	c->query.num_regions = 99;//communicate failure
	return;
    }
    memset((void *)&c->query, 0, sizeof(query));

    c->query.num_regions = s.song_md.num_regions;
    c->query.num_users = s.song_md.num_users;

    // copy owner name
    uid_to_username(s.song_md.owner_id, &name, FALSE);
    strcpy((char *)c->query.owner, name);

    // copy region names
    for (int i = 0; i < s.song_md.num_regions; i++) {
        rid_to_region_name(s.song_md.rids[i], &name, FALSE);
        strcpy((char *)q_region_lookup(c->query, i), name);
    }

    // copy authorized uid names
    for (int i = 0; i < s.song_md.num_users; i++) {
        uid_to_username(s.song_md.uids[i], &name, FALSE);
        strcpy((char *)q_user_lookup(c->query, i), name);
    }

    mb_printf("Queried song (%d regions, %d users)\r\n", c->query.num_regions, c->query.num_users);
}


// add a user to the song's list of users
void share_song() {
    char md_buf[120], uid;
    SHA256_CTX ctx;
    
    // reject non-owner attempts to share
    if(!load_song_md()) {
        mb_printf("Tampering detected. Song will not be shared\r\n");
        c->drm.md.num_regions=99; // communicate failure
        return;
    }
    if (!s.logged_in) {
        mb_printf("No user is logged in. Cannot share song\r\n");
        c->drm.md.num_regions=99; // communicate failure
        return;
    } else if (s.uid != s.song_md.owner_id) {
        mb_printf("User '%s' is not song's owner. Cannot share song\r\n", s.username);
        c->drm.md.num_regions=99; // communicate failure
        return;
    } else if (!username_to_uid((char *)c->username, &uid, TRUE)) {
        mb_printf("Username not found\r\n");
        c->drm.md.num_regions=99; // communicate failure
        return;
    }
    
    // do not re-share a song
    for(int i=0; i<s.song_md.num_users; i++) {
        if(s.song_md.uids[i]==uid) {
            mb_printf("Song already shared with user\r\n");
            c->drm.md.num_regions=99; // communicate failure
            return;
        }
    }

    // generate new song metadata
    s.song_md.uids[s.song_md.num_users++] = uid;
    c->drm.md.uids[c->drm.md.num_users++] = uid;
    
    // load new song metadata into buffer
    memcpy(md_buf, (void *)&s.song_md, 120);
    
    // sign new song metadata
    sha256_init(&ctx);
    sha256_update(&ctx, md_buf, 120);
    sha256_update(&ctx, KEY2, 32);
    sha256_final(&ctx, c->drm.mac);
    
    mb_printf("Shared song with '%s'\r\n", c->username);
}


// plays a song and looks for play-time commands
void play_song() {//TODO finish
    u32 counter = 0, rem, cp_num, cp_xfil_cnt, offset, dma_cnt, length, *fifo_fill;

    mb_printf("Reading Audio File...");
    load_song_md();
    
    //decrypt here, probably

    // get WAV length
    length = c->wav.wav_size;//this must come after decryption
    mb_printf("Song length = %dB", length);

    // truncate song if locked
    if (length > PREVIEW_SZ && is_locked()) {//TODO how to preview
        length = PREVIEW_SZ;
        mb_printf("Song is locked.  Playing only %ds = %dB\r\n",
                   PREVIEW_TIME_SEC, PREVIEW_SZ);
    } else {
        mb_printf("Song is unlocked. Playing full song\r\n");
    }

    rem = length;
    fifo_fill = (u32 *)XPAR_FIFO_COUNT_AXI_GPIO_0_BASEADDR;

    // write entire file to two-block codec fifo
    // writes to one block while the other is being played
    set_playing();
    while(rem > 0) {
        // check for interrupt to stop playback
        while (InterruptProcessed) {
            InterruptProcessed = FALSE;

            switch (c->cmd) {
            case PAUSE:
                mb_printf("Pausing... \r\n");
                set_paused();
                while (!InterruptProcessed) continue; // wait for interrupt
                break;
            case PLAY:
                mb_printf("Resuming... \r\n");
                set_playing();
                break;
            case STOP:
                mb_printf("Stopping playback...");//TODO why no \r\n
                return;
            case RESTART:
                mb_printf("Restarting song... \r\n");
                rem = length; // reset song counter
                set_playing();
            default:
                break;
            }
        }

        // calculate write size and offset
        cp_num = (rem > CHUNK_SZ) ? CHUNK_SZ : rem;
        offset = (counter++ % 2 == 0) ? 0 : CHUNK_SZ;

        // do first mem cpy here into DMA BRAM
        Xil_MemCpy((void *)(XPAR_MB_DMA_AXI_BRAM_CTRL_0_S_AXI_BASEADDR + offset),
                   (void *)(c->wav.buf + length - rem),
                   (u32)(cp_num));

        cp_xfil_cnt = cp_num;

        while (cp_xfil_cnt > 0) {

            // polling while loop to wait for DMA to be ready
            // DMA must run first for this to yield the proper state
            // rem != length checks for first run
            while (XAxiDma_Busy(&sAxiDma, XAXIDMA_DMA_TO_DEVICE)
                   && rem != length && *fifo_fill < (FIFO_CAP - 32));

            // do DMA
            dma_cnt = (FIFO_CAP - *fifo_fill > cp_xfil_cnt)
                      ? FIFO_CAP - *fifo_fill
                      : cp_xfil_cnt;
            fnAudioPlay(sAxiDma, offset, dma_cnt);
            cp_xfil_cnt -= dma_cnt;
        }

        rem -= cp_num;
    }
}


// removes DRM data from song for digital out
void digital_out() {//TODO finish
    u32 rem, length;
    u8 counter[16], len, plaintext[16], i;
	
    if(!load_song_md()) {
	    mb_printf("Tampering detected. Song will not be played\r\n");
	    return;
    }
	
    length = s.song_md.ct_len;
    
    //truncate song if locked
    if (length > PREVIEW_SZ && is_locked()) {
        mb_printf("Song is locked. Only playing 30 seconds\r\n");
        length = PREVIEW_SZ;
    } else {
        mb_printf("Song is unlocked. Playing full song\r\n");
    }
    
    rem = length;
    
    memcpy(counter, s.song_md.iv, 16);
    
    while(rem>0) {
        speck_block_CTR(counter, &c->drm.ct[length-rem], plaintext);
        len = (rem<16)? rem:16;
        
        //memcpy(outputplace[length-rem], plaintext, len); //TODO where is outputplace?
        
        rem -= len;
        for(i=15; i>=0; i--) {
            counter[i]++;
            if(counter[i]) break;
        }
    }

    mb_printf("Song dump finished\r\n");
}


//////////////////////// MAIN ////////////////////////

int main() {
    u32 status;

    init_platform();
    microblaze_register_handler((XInterruptHandler)myISR, (void *)0);
    microblaze_enable_interrupts();

    // Initialize the interrupt controller driver so that it is ready to use.
    status = XIntc_Initialize(&InterruptController, XPAR_INTC_0_DEVICE_ID);
    if (status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    // Set up the Interrupt System.
    status = SetUpInterruptSystem(&InterruptController, (XInterruptHandler)myISR);
    if (status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    // Congigure the DMA
    status = fnConfigDma(&sAxiDma);
    if(status != XST_SUCCESS) {
        mb_printf("DMA configuration ERROR\r\n");
        return XST_FAILURE;
    }

    // Start the LED
    enableLED(led);
    set_stopped();

    // clear command channel
    memset((void*)c, 0, sizeof(cmd_channel));

    mb_printf("Audio DRM Module has Booted\n\r");

    // Handle commands forever
    while(1) {
        // wait for interrupt to start
        if (InterruptProcessed) {
            InterruptProcessed = FALSE;
            set_working();

            // c->cmd is set by the miPod player
            switch (c->cmd) {
            case LOGIN:
                login();
                break;
            case LOGOUT:
                logout();
                break;
            case QUERY_PLAYER:
                query_player();
                break;
            case QUERY_SONG:
                query_song();
                break;
            case SHARE:
                share_song();
                break;
            case PLAY:
                play_song();
                mb_printf("Done Playing Song\r\n");
                break;
            case DIGITAL_OUT:
                digital_out();
                break;
            default:
                break;
            }

            // reset statuses and sleep to allow player to recognize WORKING state
            strcpy((char *)c->username, s.username);
            c->login_status = s.logged_in;
            usleep(500);
            set_stopped();
        }
    }

    cleanup_platform();
    return 0;
}
