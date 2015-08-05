/* crypto/ct/ct_locl.h */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2015.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */


/* All hashes are currently SHA256 */
#define SCT_V1_HASHLEN  32
/* Minimum RSA key size, from RFC6962 */
#define SCT_MIN_RSA_BITS 2048

/*
 * From RFC6962: opaque SerializedSCT<1..2^16-1>; struct { SerializedSCT
 * sct_list <1..2^16-1>; } SignedCertificateTimestampList;
 */

#define MAX_SCT_SIZE            65535
#define MAX_SCT_LIST_SIZE      MAX_SCT_SIZE

struct sct_st {
    int version;
    /* If version is not 0 this contains the encoded SCT */
    unsigned char *sct;
    size_t sctlen;
    /*
     * If version is 0 fields below contain components of the SCT. "logid",
     * "ext" and "sig" point to buffers allocated with OPENSSL_malloc().
     */
    unsigned char *logid;
    size_t logidlen;
    uint64_t timestamp;
    unsigned char *ext;
    size_t extlen;
    unsigned char hash_alg;
    unsigned char sig_alg;
    unsigned char *sig;
    size_t siglen;
    /* Log entry type */
    log_entry_type_t entry_type;
};

/* The following parameters are used during SCT verification */
struct sct_ctx_st {
    EVP_PKEY *pkey;
    /* Hash of public key */
    unsigned char *pkeyhash;
    size_t pkeyhashlen;
    /* For precertificate, issuer public key hash */
    unsigned char *ihash;
    size_t ihashlen;
    /* certificate encoding */
    unsigned char *certder;
    size_t certderlen;
    /* precertificate encoding */
    unsigned char *preder;
    size_t prederlen;
};

int sct_check_format(const SCT *sct);
void sct_free_internal(SCT *sct);
EVP_PKEY *sct_key_dup(EVP_PKEY *pkey);
