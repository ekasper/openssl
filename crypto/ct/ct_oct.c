/*
 * Written by Rob Stradling (rob@comodo.com) and Stephen Henson
 * (steve@openssl.org) for the OpenSSL project 2014.
 */
/* ====================================================================
 * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
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
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <limits.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ct.h>
#include "ct_locl.h"

#define n2s(c,s)        ((s=(((unsigned int)(c[0]))<< 8)| \
                            (((unsigned int)(c[1]))    )),c+=2)

# define s2n(s,c)        ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
                          c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

#define n2l8(c,l)       (l =((uint64_t)(*((c)++)))<<56, \
                         l|=((uint64_t)(*((c)++)))<<48, \
                         l|=((uint64_t)(*((c)++)))<<40, \
                         l|=((uint64_t)(*((c)++)))<<32, \
                         l|=((uint64_t)(*((c)++)))<<24, \
                         l|=((uint64_t)(*((c)++)))<<16, \
                         l|=((uint64_t)(*((c)++)))<< 8, \
                         l|=((uint64_t)(*((c)++))))

# define l2n8(l,c)       (*((c)++)=(unsigned char)(((l)>>56)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>48)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>40)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>32)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>24)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)    )&0xff))

static STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a,
                                   const unsigned char **pp, int len);
static int i2d_SCT_LIST(STACK_OF(SCT) *a, unsigned char **pp);
static int i2r_SCT_LIST(X509V3_EXT_METHOD *method, STACK_OF(SCT) *sct_list,
                        BIO *out, int indent);

static char *i2s_poison(const X509V3_EXT_METHOD *method, void *val)
{
    return OPENSSL_strdup("NULL");
}

const X509V3_EXT_METHOD v3_ct_scts[] = {
    {NID_ct_precert_scts, 0, NULL,
     0, (X509V3_EXT_FREE)SCT_LIST_free,
     (X509V3_EXT_D2I)d2i_SCT_LIST, (X509V3_EXT_I2D)i2d_SCT_LIST,
     0, 0, 0, 0,
     (X509V3_EXT_I2R)i2r_SCT_LIST, 0,
     NULL},

    {NID_ct_precert_poison, 0, ASN1_ITEM_rptr(ASN1_NULL),
     0, 0, 0, 0, i2s_poison, 0,
     0, 0, 0, 0, NULL},

    {NID_ct_cert_scts, 0, NULL,
     0, (X509V3_EXT_FREE)SCT_LIST_free,
     (X509V3_EXT_D2I)d2i_SCT_LIST, (X509V3_EXT_I2D)i2d_SCT_LIST,
     0, 0, 0, 0,
     (X509V3_EXT_I2R)i2r_SCT_LIST, 0,
     NULL},
};

SCT *o2i_SCT(SCT **psct, const unsigned char **in, size_t len)
{
    SCT *sct = NULL;
    const unsigned char *p;

    if (!in || !(*in)) {
        CTerr(CT_F_O2I_SCT, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    } else if (len > MAX_SCT_SIZE || len == 0) {
        CTerr(CT_F_O2I_SCT, CT_R_SCT_INVALID);
        goto err;
    }

    if ((sct = SCT_new()) == NULL)
        goto err;

    p = *in;

    sct->version = *p;
    if (sct->version == 0) {    /* SCT v1 */
        size_t len2;
        /*
         * Fixed-length header: struct { (1 byte) Version sct_version; (32
         * bytes) LogID id; (8 bytes) uint64 timestamp; (2 bytes + ?)
         * CtExtensions extensions;
         */
        if (len < 43)
            goto err;
        len -= 43;
        p++;
        sct->logid = BUF_memdup(p, SCT_V1_HASHLEN);
        if (sct->logid == NULL)
            goto err;
        sct->logidlen = SCT_V1_HASHLEN;
        p += SCT_V1_HASHLEN;

        n2l8(p, sct->timestamp);

        n2s(p, len2);
        if (len < len2)
            return 0;
        if (len2) {
            sct->ext = BUF_memdup(p, len2);
            if (sct->ext == NULL)
                goto err;
        }
        sct->extlen = len2;
        p += len2;
        len -= len2;

        /*
         * digitally-signed struct header: (1 byte) Hash algorithm (1 byte)
         * Signature algorithm (2 bytes + ?) Signature
         */
        if (len < 4)
            return 0;
        len -= 4;

        sct->hash_alg = *p++;
        sct->sig_alg = *p++;
        n2s(p, len2);
        if (len2 == 0 || len != len2)
            return 0;
        sct->sig = BUF_memdup(p, len2);
        if (sct->sig == NULL)
            goto err;
        sct->siglen = len2;
        *in = p + len;
    } else {
        /* If not V1 just cache encoding */
        sct->sct = BUF_memdup(p, len);
        if (!sct->sct)
            goto err;
        sct->sctlen = len;
        *in = p + len;
    }

    if (psct) {
        if (*psct) {
            if (*psct)
                sct_free_internal(*psct);
            memcpy(*psct, sct, sizeof(SCT));
            OPENSSL_free(sct);
            sct = *psct;
        } else
            *psct = sct;
    }

    return sct;

 err:
    SCT_free(sct);
    return NULL;
}

int i2o_SCT(const SCT *sct, unsigned char **out)
{
    int len;
    unsigned char *p;
    if (!sct) {
        CTerr(CT_F_I2O_SCT, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }
    if (!sct_check_format(sct)) {
        CTerr(CT_F_I2O_SCT, CT_R_SCT_NOT_SET);
        return -1;
    }
    /*
     * Fixed-length header: struct { (1 byte) Version sct_version; (32 bytes)
     * LogID id; (8 bytes) uint64 timestamp; (2 bytes + ?) CtExtensions
     * extensions; (1 byte) Hash algorithm (1 byte) Signature algorithm (2
     * bytes + ?) Signature
     */
    if (sct->version == 0)
        len = 43 + sct->extlen + 4 + sct->siglen;
    else
        len = sct->sctlen;
    if (out) {
        if (*out) {
            p = *out;
            *out += len;
        } else {
            p = OPENSSL_malloc(len);
            if (!p) {
                CTerr(CT_F_I2O_SCT, ERR_R_MALLOC_FAILURE);
                return -1;
            }
            *out = p;
        }
        if (sct->version == 0) {
            *p++ = sct->version;
            memcpy(p, sct->logid, SCT_V1_HASHLEN);
            p += SCT_V1_HASHLEN;
            l2n8(sct->timestamp, p);
            s2n(sct->extlen, p);
            if (sct->extlen) {
                memcpy(p, sct->ext, sct->extlen);
                p += sct->extlen;
            }
            *p++ = sct->hash_alg;
            *p++ = sct->sig_alg;
            s2n(sct->siglen, p);
            memcpy(p, sct->sig, sct->siglen);
        } else
            memcpy(p, sct->sct, sct->sctlen);

    }
    return len;
}

void SCT_LIST_free(STACK_OF(SCT) *a)
{
    sk_SCT_pop_free(a, SCT_free);
}

STACK_OF(SCT) *o2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp,
                            size_t len)
{
    STACK_OF(SCT) *sk = NULL;
    SCT *sct;
    size_t listlen, sctlen;

    if (!pp || !(*pp)) {
        CTerr(CT_F_O2I_SCT_LIST, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    } else if ((len < 2) || (len > MAX_SCT_LIST_SIZE)) {
        CTerr(CT_F_O2I_SCT_LIST, CT_R_SCT_LIST_INVALID);
        return NULL;
    }

    n2s((*pp), listlen);
    if (listlen != len - 2)
        return NULL;

    if (a && *a) {
        sk = *a;
        while ((sct = sk_SCT_pop(sk)) != NULL)
            SCT_free(sct);
    } else if ((sk = sk_SCT_new_null()) == NULL)
        return NULL;

    while (listlen > 0) {
        if (listlen < 2)
            goto err;
        n2s((*pp), sctlen);
        listlen -= 2;

        if ((sctlen < 1) || (sctlen > listlen))
            goto err;
        listlen -= sctlen;

        if ((sct = o2i_SCT(NULL, pp, sctlen)) == NULL)
            goto err;
        if (!sk_SCT_push(sk, sct)) {
            SCT_free(sct);
            goto err;
        }
    }

    if (a && !(*a))
        *a = sk;
    return sk;

 err:
    if (!(a && *a))
        SCT_LIST_free(sk);
    return NULL;
}

int i2o_SCT_LIST(STACK_OF(SCT) *a, unsigned char **pp)
{
    int len, sctlen, i, newpp = 0;
    size_t len2;
    unsigned char *p = NULL, *p2;

    if (!a) {
        CTerr(CT_F_I2O_SCT_LIST, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    if (pp) {
        if (*pp == NULL) {
            if ((len = i2o_SCT_LIST(a, NULL)) == -1) {
                CTerr(CT_F_I2O_SCT_LIST, CT_R_SCT_LIST_INVALID);
                return -1;
            }
            if ((*pp = OPENSSL_malloc(len)) == NULL) {
                CTerr(CT_F_I2O_SCT_LIST, ERR_R_MALLOC_FAILURE);
                return -1;
            }
            newpp = 1;
        }
        p = (*pp) + 2;
    }

    len2 = 2;
    for (i = 0; i < sk_SCT_num(a); i++) {
        if (pp) {
            p2 = p;
            p += 2;
            if ((sctlen = i2o_SCT(sk_SCT_value(a, i), &p)) == -1)
                goto err;
            s2n(sctlen, p2);
        } else {
          if ((sctlen = i2o_SCT(sk_SCT_value(a, i), NULL)) == -1)
              goto err;
        }
        len2 += 2 + sctlen;
    }

    if (len2 > MAX_SCT_LIST_SIZE)
        goto err;

    if (pp) {
        p = *pp;
        s2n((len2 - 2), p);
    }
    if (!newpp)
        pp = pp + len2;
    return len2;

 err:
    if (newpp) {
        OPENSSL_free(*pp);
        *pp = NULL;
    }
    return -1;
}

static STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a,
                                   const unsigned char **pp, int len)
{
    ASN1_OCTET_STRING *oct = NULL;
    STACK_OF(SCT) *sk = NULL;
    const unsigned char *p;

    if (!pp || !(*pp)) {
        CTerr(CT_F_D2I_SCT_LIST, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    p = *pp;
    if (d2i_ASN1_OCTET_STRING(&oct, &p, len) == NULL)
        return NULL;

    p = oct->data;
    if ((sk = o2i_SCT_LIST(a, &p, oct->length)) != NULL)
        *pp += len;

    ASN1_OCTET_STRING_free(oct);
    return sk;
}

static int i2d_SCT_LIST(STACK_OF(SCT) *a, unsigned char **out)
{
    ASN1_OCTET_STRING oct;
    int len;

    if (!a) {
        CTerr(CT_F_I2D_SCT_LIST, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    oct.data = NULL;
    if ((oct.length = i2o_SCT_LIST(a, &(oct.data))) == -1)
        return -1;

    len = i2d_ASN1_OCTET_STRING(&oct, out);
    OPENSSL_free(oct.data);
    return len;
}

static int i2r_SCT_LIST(X509V3_EXT_METHOD *method, STACK_OF(SCT) *sct_list,
                        BIO *out, int indent)
{
    SCT *sct;
    int i;

    for (i = 0; i < sk_SCT_num(sct_list);) {
        sct = sk_SCT_value(sct_list, i);
        SCT_print(sct, out, indent);
        if (++i < sk_SCT_num(sct_list))
            BIO_printf(out, "\n");
    }

    return 1;
}
