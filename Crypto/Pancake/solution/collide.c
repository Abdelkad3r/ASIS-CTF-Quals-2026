/* Find every 96-bit y with upper96(AES_k1(y<<drop)) == upper96(AES_k1(n2<<drop)),
 * i.e. AES_k1^{-1}(base | sep) whose low `drop` bits are zero, for base=target<<drop.
 * Prints "RESULT:<16-byte plaintext hex>" per collision.
 * Usage: ./collide <key32hex> <base16hex> <drop>
 * Build (mac):   clang -O3 collide.c -o collide
 * Build (linux): gcc  -O3 collide.c -o collide -lcrypto
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#if defined(__APPLE__)
#include <CommonCrypto/CommonCryptor.h>
#else
#include <openssl/aes.h>
#endif
static uint8_t key[32], base[16];
static uint32_t DROP;
enum { NT = 8 };
static pthread_mutex_t mtx=PTHREAD_MUTEX_INITIALIZER;
typedef struct { uint64_t start, end; } rng_t;
static void emit(const uint8_t* b){
    pthread_mutex_lock(&mtx);
    printf("RESULT:"); for(int k=0;k<16;k++) printf("%02x",b[k]); printf("\n"); fflush(stdout);
    pthread_mutex_unlock(&mtx);
}
void* work(void* a){
    rng_t* r=(rng_t*)a; uint64_t cur=r->start;
#if defined(__APPLE__)
    CCCryptorRef cr; CCCryptorCreate(kCCDecrypt,kCCAlgorithmAES,kCCOptionECBMode,key,32,NULL,&cr);
    enum{ B=4096 }; uint8_t in[16*B], out[16*B]; size_t moved;
    for(int i=0;i<B;i++) memcpy(&in[i*16],base,16);
    while(cur<r->end){
        uint32_t cnt=(r->end-cur>B)?B:(uint32_t)(r->end-cur);
        for(uint32_t i=0;i<cnt;i++){ uint32_t sep=(uint32_t)(cur+i);
            in[i*16+12]=(sep>>24)&0xff; in[i*16+13]=(sep>>16)&0xff; in[i*16+14]=(sep>>8)&0xff; in[i*16+15]=sep&0xff; }
        CCCryptorUpdate(cr,in,cnt*16,out,sizeof(out),&moved);
        for(uint32_t i=0;i<cnt;i++){ uint8_t*b=&out[i*16];
            if(b[12]==0&&b[13]==0&&b[14]==0&&b[15]==0) emit(b); }
        cur+=cnt;
    }
    CCCryptorRelease(cr);
#else
    AES_KEY dk; AES_set_decrypt_key(key,256,&dk);
    uint8_t in[16], out[16]; memcpy(in,base,16);
    while(cur<r->end){ uint32_t sep=(uint32_t)cur;
        in[12]=(sep>>24)&0xff; in[13]=(sep>>16)&0xff; in[14]=(sep>>8)&0xff; in[15]=sep&0xff;
        AES_ecb_encrypt(in,out,&dk,AES_DECRYPT);
        if(out[12]==0&&out[13]==0&&out[14]==0&&out[15]==0) emit(out);
        cur++;
    }
#endif
    return NULL;
}
int main(int argc,char**argv){
    if(argc<4){fprintf(stderr,"usage: %s <key32hex> <base16hex> <drop>\n",argv[0]);return 1;}
    for(int i=0;i<32;i++) sscanf(&argv[1][i*2],"%02hhx",&key[i]);
    for(int i=0;i<16;i++) sscanf(&argv[2][i*2],"%02hhx",&base[i]);
    DROP=(uint32_t)atoi(argv[3]);
    uint64_t total=1ULL<<DROP, chunk=total/NT;
    pthread_t th[NT]; rng_t rg[NT];
    for(int i=0;i<NT;i++){rg[i].start=(uint64_t)i*chunk; rg[i].end=(i==NT-1)?total:(uint64_t)(i+1)*chunk; pthread_create(&th[i],NULL,work,&rg[i]);}
    for(int i=0;i<NT;i++) pthread_join(th[i],NULL);
    printf("DONE\n"); return 0;
}
