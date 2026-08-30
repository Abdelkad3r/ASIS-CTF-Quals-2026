/* Exhaustive MinRank over each Linchan box.
 *
 * Every box is a basis of an m-dimensional subspace of M_32(F_2). The real
 * boxes contain two planted matrices of rank 25; a uniform 32x32 matrix over
 * F_2 has rank <= 25 with probability ~2^-47, so the low-rank elements are a
 * perfect marker. m <= 18, so the subspace is small enough to enumerate whole:
 * walk it in Gray-code order (one XOR of 32 words per step) and rank each
 * element.
 *
 * Usage:  minrank <boxes.bin> [threshold]
 *
 * boxes.bin: u32 box_count, then per box u32 m and m * 32 u32 rows.
 * Output:    one "box_index coefficient_mask rank" line per hit.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static inline int rank32(const uint32_t *rows) {
    uint32_t pivot[32] = {0};
    int r = 0;
    for (int i = 0; i < 32; i++) {
        uint32_t x = rows[i];
        while (x) {
            int b = 31 - __builtin_clz(x);
            if (pivot[b]) x ^= pivot[b];
            else { pivot[b] = x; r++; break; }
        }
    }
    return r;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <boxes.bin> [threshold]\n", argv[0]); return 2; }
    int threshold = argc > 2 ? atoi(argv[2]) : 26;

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 2; }

    uint32_t nboxes;
    if (fread(&nboxes, 4, 1, f) != 1) return 2;
    for (uint32_t bi = 0; bi < nboxes; bi++) {
        uint32_t m;
        if (fread(&m, 4, 1, f) != 1) return 2;
        uint32_t *basis = malloc((size_t)m * 32 * 4);
        if (!basis || fread(basis, 4, (size_t)m * 32, f) != (size_t)m * 32) return 2;

        uint32_t cur[32] = {0};
        uint64_t total = 1ULL << m;
        for (uint64_t i = 1; i < total; i++) {
            const uint32_t *b = basis + 32 * __builtin_ctzll(i);
            for (int k = 0; k < 32; k++) cur[k] ^= b[k];
            int r = rank32(cur);
            if (r <= threshold)
                printf("%u %llu %d\n", bi, (unsigned long long)(i ^ (i >> 1)), r);
        }
        free(basis);
    }
    return 0;
}
