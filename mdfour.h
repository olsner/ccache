#ifndef MDFOUR_H
#define MDFOUR_H

#include <stddef.h>
#include <inttypes.h>

#include <openssl/md4.h>

struct mdfour {
	MD4_CTX ctx;
	size_t totalN;
};

inline static void mdfour_begin(struct mdfour *md) {
	MD4_Init(&md->ctx);
	md->totalN = 0;
}
inline static void mdfour_update(struct mdfour *md, const unsigned char *in, size_t n) {
	MD4_Update(&md->ctx, in, n);
	md->totalN += n;
}
inline static void mdfour_result(struct mdfour *md, unsigned char *out) {
	MD4_Final(out, &md->ctx);
}

#endif
