/* Recover the 32-bit K1 seed from the published hint:
 *   hint = SHA256("K1-SEED-HINT" || be32(seed))
 * Usage: ./seedbrute <hint_hex_64>   ->  prints "SEED:xxxxxxxx"
 * Build (mac):   clang -O3 seedbrute.c -o seedbrute
 * Build (linux): gcc  -O3 seedbrute.c -o seedbrute -lcrypto
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#define SHA256_BUF(in,len,out) CC_SHA256((in),(len),(out))
#else
#include <openssl/sha.h>
#define SHA256_BUF(in,len,out) SHA256((in),(len),(out))
#endif
static uint8_t target[32];
static volatile long found=-1;
enum { NT = 8 };
typedef struct { uint64_t start, end; } rng_t;
void* work(void* a){
    rng_t* r=(rng_t*)a;
    uint8_t buf[16]; memcpy(buf,"K1-SEED-HINT",12);
    uint8_t dg[32];
    for(uint64_t s=r->start; s<r->end && found<0; s++){
        buf[12]=(s>>24)&0xff; buf[13]=(s>>16)&0xff; buf[14]=(s>>8)&0xff; buf[15]=s&0xff;
        SHA256_BUF(buf,16,dg);
        if(dg[0]==target[0]&&dg[1]==target[1]&&dg[2]==target[2]&&dg[3]==target[3]
           && memcmp(dg,target,32)==0){ found=(long)s; return NULL; }
    }
    return NULL;
}
int main(int argc,char**argv){
    if(argc<2){fprintf(stderr,"usage: %s <hint_hex>\n",argv[0]);return 1;}
    for(int i=0;i<32;i++) sscanf(&argv[1][i*2],"%02hhx",&target[i]);
    pthread_t th[NT]; rng_t rg[NT];
    uint64_t total=1ULL<<32, chunk=total/NT;
    for(int i=0;i<NT;i++){rg[i].start=(uint64_t)i*chunk; rg[i].end=(i==NT-1)?total:(uint64_t)(i+1)*chunk; pthread_create(&th[i],NULL,work,&rg[i]);}
    for(int i=0;i<NT;i++) pthread_join(th[i],NULL);
    if(found>=0) printf("SEED:%08lx\n",found); else printf("NOTFOUND\n");
    return 0;
}
