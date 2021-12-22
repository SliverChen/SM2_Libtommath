/*
    sm2 implimentation 
*/

//curve params

#define SM2_P "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
#define SM2_A "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
#define SM2_B "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
#define SM2_N "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
#define SM2_G_X "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
#define SM2_G_Y "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"

#if 0 //def _DEBUG
const char * param_a= "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
const char * param_b= "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
const char * param_n= "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
const char * param_p= "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
const char * Xg     = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
const char * Yg     = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
#else
const char *param_a = SM2_A;
const char *param_b = SM2_B;
const char *param_n = SM2_N;
const char *param_p = SM2_P;
const char *Xg = SM2_G_X;
const char *Yg = SM2_G_Y;
#endif //_DEBUG

#include "../include/sm2.h"
#include "../include/sm3.h"
#include "../include/tommath.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"
#include "../include/GM_define.h"

int myrng(unsigned char *dst, int len, void *dat)
{
    int x;
    for (x = 0; x < len; ++x)
        dst[x] = rand() & 0xFF;
    return len;
}

int MP_printf(mp_int *mp_num)
{
    char buff[1000] = {0};
    mp_toradix(mp_num, buff, 16);
    int i = 0;
    for (; i < strlen(buff); ++i)
    {
        if (0 == i % 8)
        {
            printf(" ");
        }
        printf("%c", buff[i]);
    }
    printf("\n");
    return 0;
}

void BYTE_print(unsigned char *tar, unsigned long l)
{
    for (int i = 0; i < l; ++i)
    {
        if (i % 4 == 0)
        {
            printf(" ");
        }
        printf("%02x", tar[i]);
    }
    printf("\n");
}

/************实现部分**************/
int GetPrime(mp_int *m, int lon)
{
    int ret = 0;
    ret = mp_prime_random_ex(m, 10, lon,
                             (rand() & 1) ? LTM_PRIME_2MSB_OFF : LTM_PRIME_2MSB_ON, myrng, NULL);
    return ret;
}

int GM_GenSM2keypair(unsigned char *prikey, unsigned long *pulPriLen,
                     unsigned char pubkey_XY[64])
{
    if (NULL == prikey || *pulPriLen < 32)
    {
        return ERR_PARAM;
    }

    int ret = 0;
    mp_int mp_a, mp_b, mp_n, mp_p, mp_Xg, mp_Yg, mp_pri_dA, mp_XA, mp_YA;
    mp_init_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_Xg, &mp_Yg, &mp_pri_dA, &mp_XA, &mp_YA, NULL);
    unsigned char X[100] = {0};
    unsigned long X_len = 100;
    unsigned char Y[100] = {0};
    unsigned long Y_len = 100;
    ret = mp_read_radix(&mp_a, (char *)param_a, 16);
    CHECK_RET(ret);
    ret = mp_read_radix(&mp_b, (char *)param_b, 16);
    CHECK_RET(ret);
    ret = mp_read_radix(&mp_n, (char *)param_n, 16);
    CHECK_RET(ret);
    ret = mp_read_radix(&mp_p, (char *)param_p, 16);
    CHECK_RET(ret);
    ret = mp_read_radix(&mp_Xg, (char *)Xg, 16);
    CHECK_RET(ret);
    ret = mp_read_radix(&mp_Yg, (char *)Yg, 16);
    CHECK_RET(ret);

    ret = Ecc_sm2_genKeypair(&mp_pri_dA, &mp_XA, &mp_YA, &mp_Xg, &mp_Yg, &mp_a, &mp_b, &mp_n, &mp_p);
    CHECK_RET(ret);

    ret = Mp_Int2Byte(prikey, pulPriLen, &mp_pri_dA);
    CHECK_RET(ret);

    ret = Mp_Int2Byte(X, &X_len, &mp_XA);
    CHECK_RET(ret);

    ret = Mp_Int2Byte(Y, &Y_len, &mp_YA);
    CHECK_RET(ret);

    if (X_len + Y_len != 64)
    {
        ret = ERR_UNKNOWN;
        goto END;
    }

    memcpy(pubkey_XY, X, 32);
    memcpy(pubkey_XY + 32, Y, 32);

END:
    mp_clear_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_Xg, &mp_Yg, &mp_pri_dA, &mp_XA, &mp_YA, NULL);
    return ret;
}

int Ecc_sm2_genKeypair(mp_int *mp_pridA,
                       mp_int *mp_XA, mp_int *mp_YA,
                       mp_int *mp_Xg, mp_int *mp_Yg,
                       mp_int *mp_a, mp_int *mp_b, mp_int *mp_n, mp_int *mp_p)
{
}

int Ecc_point_mul(mp_int *result_x, mp_int *result_y,
                  mp_int *px, mp_int *py,
                  mp_int *d,
                  mp_int *param_a, mp_int *param_p)
{
    int ret = 0;
    mp_int mp_A, mp_P;
    mp_int mp_Qx, mp_Qy;
    mp_int tmp_Qx, tmp_Qy;

    char Bt_array[800] = {0};
    int i;
    int Bt_array_len = 0;

    //init parameter A and P
    ret = mp_init_copy(&mp_A, param_a);
    CHECK_RET(ret);
    ret = mp_init_copy(&mp_P, param_p);
    CHECK_RET(ret);

    //set Q(x,y) equals infinity point
    ret = mp_init_set(&mp_Qx, 0);
    CHECK_RET(ret);
    ret = mp_init_set(&mp_Qy, 0);
    CHECK_RET(ret);

    //set Q_tmp(x,y) equals infinity point
    ret = mp_init_set(&tmp_Qx, 0);
    CHECK_RET(ret);
    ret = mp_init_set(&tmp_Qy, 0);
    CHECK_RET(ret);

    //set the number into binary presentation
    ret = mp_toradix(d, Bt_array, 2);
    CHECK_RET(ret);
    Bt_array_len = strlen(Bt_array);

    for (i = 0; i <= Bt_array_len - 1; ++i)
    {
        ret = Ecc_point_add(&tmp_Qx, &tmp_Qy,
                            &mp_Qx, &mp_Qy, &mp_Qx, &mp_Qy, &mp_A, &mp_P);
        CHECK_RET(ret);

        if ('1' == Bt_array[i])
        {
            ret = Ecc_point_add(&mp_Qx, &mp_Qy,
                                &tmp_Qx, &tmp_Qy, px, py, &mp_A, &mp_P);
            CHECK_RET(ret);

            ret = mp_copy(&mp_Qx, &tmp_Qx);
            CHECK_RET(ret);

            ret = mp_copy(&mp_Qy, &tmp_Qy);
            CHECK_RET(ret);
        }
        ret = mp_copy(&tmp_Qx, &mp_Qx);
        CHECK_RET(ret);

        ret = mp_copy(&tmp_Qy, &mp_Qy);
        CHECK_RET(ret);
    }

    ret = mp_copy(&tmp_Qx, result_x);
    CHECK_RET(ret);

    ret = mp_copy(&tmp_Qy, result_y);
    CHECK_RET(ret);

END:
    mp_clear_multi(&mp_A, &mp_P, &mp_Qx, &mp_Qy, &tmp_Qx, &tmp_Qy, NULL);
    return ret;
}

int Ecc_point_add(mp_int *result_x, mp_int *result_y,
                  mp_int *x1, mp_int *y1, mp_int *x2, mp_int *y2,
                  mp_int *param_a, mp_int *param_p)
{
    mp_int mp_tmp_r;
    mp_int tmp1, tmp2;
    mp_int Lambda;
    mp_int top, bottom;

    int ret = 0;
    if ((MP_EQ == mp_cmp_d(x1, 0) && MP_EQ == mp_cmp_d(y1, 0)) &&
        (MP_EQ == mp_cmp_d(x2, 0) && MP_EQ == mp_cmp_d(y2, 0)))
    {
        mp_zero(result_x);
        mp_zero(result_y);
        return SUCCESS;
    }

    if (MP_EQ == mp_cmp_d(x1, 0) && MP_EQ == mp_cmp_d(y1, 0))
    {
        ret = mp_copy(x2, result_x);
        CHECK_RET(ret);

        ret = mp_copy(y2, result_y);
        CHECK_RET(ret);
        return SUCCESS;
    }

    if (MP_EQ == mp_cmp_d(x2, 0) && MP_EQ == mp_cmp_d(y2, 0))
    {
        ret = mp_copy(x1, result_x);
        CHECK_RET(ret);

        ret = mp_copy(y1, result_y);
        CHECK_RET(ret);

        return SUCCESS;
    }

    //P(x,y), Q(x,-y) ==> P+Q == 0
    ret = mp_init_set(&mp_tmp_r, 0);
    CHECK_RET(ret);

    ret = mp_add(y1, y2, &mp_tmp_r);
    CHECK_RET(ret);

    if ((MP_EQ == mp_cmp(x1, x2)) && (MP_EQ == mp_cmp_d(&mp_tmp_r, 0)))
    {
        mp_zero(result_x);
        mp_zero(result_y);
        return SUCCESS;
    }

    ret = mp_init_set(&tmp1, 0);
    CHECK_RET(ret);

    ret = mp_init_set(&tmp2, 0);
    CHECK_RET(ret);

    //P+Q != 0 -->compute Lambda
    ret = mp_init_set(&Lambda, 0);
    CHECK_RET(ret);

    {
        ret = mp_init_set(&top, 0);
        CHECK_RET(ret);
        ret = mp_init_set(&bottom, 0);
        CHECK_RET(ret);

        //x1==x2 && P+Q != 0
        //lambda = (3x1^2+a)/2y1
        if (MP_EQ == mp_cmp(x1, x2))
        {
            //x1^2
            ret = mp_sqr(x1, &tmp1);
            CHECK_RET(ret);

            //3 * x1^2
            ret = mp_mul_d(&tmp1, 3, &tmp2);
            CHECK_RET(ret);

            //(3 * x1^2 + a) mod p
            ret = mp_addmod(&tmp2, param_a, param_p, &top);
            CHECK_RET(ret);

            // 2y1
            ret = mp_mul_d(y1, 2, &tmp1);
            CHECK_RET(ret);

            // 1/2y1
            ret = mp_invmod(&tmp1, param_p, &bottom);
            CHECK_RET(ret);

            // [(3*x1^2+a) * 1/2y1] mod p
            ret = mp_mulmod(&top, &bottom, param_p, &Lambda);
            CHECK_RET(ret);
        }
        else //x1 != x2 ==> lambda = (y2-y1)/(x2-x1)
        {
            //y2-y1 mod p
            ret = mp_submod(y2, y1, param_p, &top);
            CHECK_RET(ret);

            //x2-x1 mod p
            ret = mp_submod(x2, x1, param_p, &tmp1);
            CHECK_RET(ret);

            //1/(x2-x1) mod p
            ret = mp_invmod(&tmp1, param_p, &bottom);
            CHECK_RET(ret);

            //[(y2-y1) * 1/(x2-x1)] mod p
            ret = mp_mulmod(&top, &bottom, param_p, &Lambda);
            CHECK_RET(ret);
        }
        mp_clear(&top);
        mp_clear(&bottom);
    }

    //x3 = lambda^2 - x1 - x2
    ret = mp_sqrmod(&Lambda, param_p, &tmp1); //这里原文不用mod
    CHECK_RET(ret);
    ret = mp_submod(&tmp1, x1, param_p, &tmp2); //这里原文不用mod
    CHECK_RET(ret);
    ret = mp_submod(&tmp2, x2, param_p, result_x);
    CHECK_RET(ret);

    //y3 = lambda * (x1-x3) - y1
    ret = mp_sub(x1, result_x, &tmp1);
    CHECK_RET(ret);
    ret = mp_mul(&Lambda, &tmp1, &tmp2);
    CHECK_RET(ret);
    ret = mp_submod(&tmp2, y1, param_p, result_y);
    CHECK_RET(ret);

END:
    mp_clear_multi(&tmp1, &tmp2, &Lambda, &mp_tmp_r, NULL);
    return ret;
}

int Sm3WithPreprocess(unsigned char *dgst, unsigned long *LenDgst,
                      unsigned char *Src, unsigned long lenSrc,
                      unsigned char *UserID, unsigned long lenUID,
                      mp_int *mp_a, mp_int *mp_b,
                      mp_int *mp_Xg, mp_int *mp_Yg,
                      mp_int *mp_XA, mp_int *mp_YA)
{
}

int Ecc_point_is_on_curve(mp_int *mp_X, mp_int *mp_Y,
                          mp_int *mp_a, mp_int *mp_b, mp_int *mp_p)
{
    //(x,y) ?= (0,0)
    if (MP_EQ == mp_cmp_d(mp_X, 0) && MP_EQ == mp_cmp_d(mp_Y, 0))
    {
        return ERR_INFINITE_POINT;
    }

    if (!(((MP_GT == mp_cmp_d(mp_X, 0) || MP_EQ == mp_cmp_d(mp_X, 0)) && MP_LT == mp_cmp(mp_X, mp_p)) &&
          ((MP_GT == mp_cmp_d(mp_Y, 0) || MP_EQ == mp_cmp_d(mp_Y, 0)) && MP_LT == mp_cmp(mp_Y, mp_p))))
    {
        return ERR_POINT_NOT_ON_CURVE;
    }

    mp_int left, right, mp_tmp, mp_tmp2;
    int ret = 0;
    ret = mp_init_multi(&left, &right, &mp_tmp, &mp_tmp2, NULL);
    CHECK_RET(ret);

    ret = mp_sqrmod(mp_Y, mp_p, &left); // y^2
    CHECK_RET(ret);

    ret = mp_sqr(mp_X, &mp_tmp);
    CHECK_RET(ret);

    ret = mp_mul(mp_X, &mp_tmp, &mp_tmp); // x^3
    CHECK_RET(ret);

    ret = mp_mul(mp_X, mp_a, &mp_tmp2); // a*x
    CHECK_RET(ret);

    ret = mp_add(&mp_tmp, &mp_tmp2, &mp_tmp);
    CHECK_RET(ret);

    ret = mp_addmod(&mp_tmp, mp_b, mp_p, &right); // x^3 + a*x + b (mod p)
    CHECK_RET(ret);

    if (MP_EQ == mp_cmp(&left, &right))
    {
        ret = 0;
    }
    else
    {
        ret = ERR_POINT_NOT_ON_CURVE;
    }

END:
    mp_clear_multi(&left, &right, &mp_tmp, &mp_tmp2, NULL);
    return ret;
}

int genRand_k(mp_int *rand_k, mp_int *mp_n)
{
    int ret = 0;
    srand((unsigned)time(NULL));
    mp_set(rand_k, 1);

    ret = mp_mul_d(rand_k, rand(), rand_k);
    CHECK_RET(ret);

    ret = mp_mul_d(rand_k, rand(), rand_k);
    CHECK_RET(ret);

    ret = mp_mul_d(rand_k, rand(), rand_k);
    CHECK_RET(ret);

    ret = mp_submod(rand_k, mp_n, mp_n, rand_k);
    CHECK_RET(ret);

END:
    return ret;
}

int KDF(unsigned char *kdfOutBuff, unsigned char *Z_in, unsigned long ulZlen, unsigned long klen)
{
    int ret = 0;
    if (NULL == Z_in || 0 == ulZlen || 0 == klen)
    {
        return ERR_PARAM;
    }

    unsigned char *pZandCt = new unsigned char[ulZlen + 4 + 10];
    if (NULL == pZandCt)
    {
        return ERR_MEM_ALLOC;
    }
    unsigned char *pZ = pZandCt;
    memset(pZ, 0x00, ulZlen + 4 + 10);

    unsigned long ct = 1;
    unsigned long mod = (klen) % 32; // 32 = output byte length of sm3
    int max_iter = (klen) / 32;

    char ct_str[10] = {0};
    int ct_len = 0;
    unsigned char ct_un_buff[10] = {0};
    unsigned long len_ct_unbuff = 0;
    unsigned char tmp_buff[32];

    for (ct = 1; ct <= max_iter; ct++)
    {
        sprintf(ct_str, "%8x", ct);
        ct_len = strlen(ct_str);
        ret = hexStr2unsignedStr(ct_str, ct_len, 0, ct_un_buff, &len_ct_unbuff);
        if (ret)
        {
            if (NULL != pZandCt)
            {
                delete[] pZandCt;
            }
            return ret;
        }
        pZ = pZandCt;
        memset(pZ, 0x00, ulZlen + 4 + 10);
        memcpy(pZ, Z_in, ulZlen);
        memcpy(pZ + ulZlen, ct_un_buff, len_ct_unbuff);
        sm3(pZ, ulZlen + 4, kdfOutBuff + (ct - 1) * 32);
    }
    sprintf(ct_str, "%8x", ct);
    ct_len = strlen(ct_str);
    ret = hexStr2unsignedStr(ct_str, ct_len, 0, ct_un_buff, &len_ct_unbuff);
    if (ret)
    {
        if (NULL != pZandCt)
        {
            delete[] pZandCt;
        }
        return ret;
    }
    pZ = pZandCt;
    memset(pZ, 0x00, ulZlen + 4 + 10); //??
    memcpy(pZ, Z_in, ulZlen);
    memcpy(pZ + ulZlen, ct_un_buff, len_ct_unbuff);
    sm3(pZ, ulZlen + 4, tmp_buff);
    memcpy(kdfOutBuff + (ct - 1) * 32, tmp_buff, mod);
    ret = 0;

    if (NULL != pZandCt)
    {
        delete[] pZandCt;
    }

    return ret;
}

int BYTE_POINT_is_on_curve(unsigned char *pubkey_XY, unsigned long ulPubXYLen)
{
    if (NULL == pubkey_XY || 64 != ulPubXYLen)
    {
        return ERR_PARAM;
    }

    mp_int mp_a, mp_b, mp_n, mp_p, mp_x, mp_y;
    mp_init_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_x, &mp_y, NULL);
    unsigned char X[32] = {0};
    unsigned char Y[32] = {0};

    int ret = 0;
    ret = mp_read_radix(&mp_a, (char *)param_a, 16);
    CHECK_RET(ret);
    ret = mp_read_radix(&mp_b, (char *)param_b, 16);
    CHECK_RET(ret);
    ret = mp_read_radix(&mp_n, (char *)param_n, 16);
    CHECK_RET(ret);
    ret = mp_read_radix(&mp_p, (char *)param_p, 16);
    CHECK_RET(ret);

    memcpy(X, pubkey_XY, 32);
    memcpy(Y, pubkey_XY + 32, 32);
    ret = Byte2Mp_Int(&mp_x, X, 32);
    CHECK_RET(ret);
    ret = Byte2Mp_Int(&mp_y, Y, 32);
    CHECK_RET(ret);

#ifdef _DEBUG
    MP_print_Space;
    MP_print(&mp_x);
    MP_print(&mp_y);
#endif

    ret = Ecc_point_is_on_curve(&mp_x, &mp_y, &mp_a, &mp_b, &mp_p);

END:
    mp_clear_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_x, &mp_y, NULL);
    return ret;
}

int BYTE_Point_mul(unsigned char k[32], unsigned char newPoint[64])
{
    int ret = 0;

    unsigned char ret_X[32] = {0};
    unsigned long l_ret_X = 32;
    unsigned char ret_Y[32] = {0};
    unsigned long l_ret_Y = 32;

    mp_int mp_a, mp_p, mp_Xg, mp_Yg, mp_k, mp_ret_x, mp_ret_y;
    mp_init_multi(&mp_a, &mp_p, &mp_Xg, &mp_Yg, &mp_k, &mp_ret_x, &mp_ret_y);

    ret = mp_read_radix(&mp_a, (char *)param_a, 16);
    CHECK_RET(ret);
    ret = mp_read_radix(&mp_p, (char *)param_p, 16);
    CHECK_RET(ret);
    ret = mp_read_radix(&mp_Xg, (char *)Xg, 16);
    CHECK_RET(ret);
    ret = mp_read_radix(&mp_Yg, (char *)Yg, 16);
    CHECK_RET(ret);

    ret = Byte2Mp_Int(&mp_k, k, 32);
    CHECK_RET(ret);

    ret = Ecc_point_mul(&mp_ret_x, &mp_ret_y, &mp_Xg, &mp_Yg, &mp_k, &mp_a, &mp_p);
    CHECK_RET(ret);

    ret = Mp_Int2Byte(ret_X, &l_ret_X, &mp_ret_x);
    CHECK_RET(ret);
    ret = Mp_Int2Byte(ret_Y, &l_ret_Y, &mp_ret_y);
    CHECK_RET(ret);

    memcpy(newPoint, ret_X, 32);
    memcpy(newPoint + 32, ret_Y, 32);

END:
    mp_clear_multi(&mp_a, &mp_p, &mp_Xg, &mp_Yg, &mp_k, &mp_ret_x, &mp_ret_y, NULL);
    return ret;
}