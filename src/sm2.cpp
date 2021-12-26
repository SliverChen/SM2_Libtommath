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

//#if 0 //def _DEBUG
//const char *param_a = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
//const char *param_b = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
//const char *param_n = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
//const char *param_p = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
//const char *Xg = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
//const char *Yg = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
//#else
const char *param_a = SM2_A;
const char *param_b = SM2_B;
const char *param_n = SM2_N;
const char *param_p = SM2_P;
const char *Xg = SM2_G_X;
const char *Yg = SM2_G_Y;
//#endif //_DEBUG

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

int MP_print(mp_int *mp_num)
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

int GM_GenSM2keypair(unsigned char *d1, unsigned char *d2, unsigned long *pulPriLen,
                     unsigned char pubkey_XY[64])
{
    if (NULL == d1 || NULL == d2 || *pulPriLen < 32)
    {
        return ERR_PARAM;
    }

    int ret = 0;
    mp_int mp_a, mp_b, mp_n, mp_p, mp_Xg, mp_Yg,
        mp_pri_d1, mp_pri_d2, mp_XA, mp_YA;
    mp_init_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_Xg, &mp_Yg,
                  &mp_pri_d1, &mp_pri_d2, &mp_XA, &mp_YA, NULL);
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

    ret = Ecc_sm2_genKeypair(&mp_pri_d1, &mp_pri_d2, &mp_XA, &mp_YA, &mp_Xg, &mp_Yg, &mp_a, &mp_b, &mp_n, &mp_p);
    CHECK_RET(ret);

    ret = Mp_Int2Byte(d1, pulPriLen, &mp_pri_d1);
    CHECK_RET(ret);

    ret = Mp_Int2Byte(d2, pulPriLen, &mp_pri_d2);
    CHECK_RET(ret);

    ret = Mp_Int2Byte(X, &X_len, &mp_XA);
    CHECK_RET(ret);

    ret = Mp_Int2Byte(Y, &Y_len, &mp_YA);
    CHECK_RET(ret);

    if (X_len + Y_len != 64)
    {
        ret = ERR_UNKNOWN;
        CHECK_RET(ret);
    }

    memcpy(pubkey_XY, X, 32);
    memcpy(pubkey_XY + 32, Y, 32);

END:
    mp_clear_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_Xg, &mp_Yg,
                   &mp_pri_d1, &mp_pri_d2, &mp_XA, &mp_YA, NULL);
    return ret;
}

int Ecc_sm2_genKeypair(mp_int *mp_pri_d1, mp_int *mp_pri_d2,
                       mp_int *mp_XA, mp_int *mp_YA,
                       mp_int *mp_Xg, mp_int *mp_Yg,
                       mp_int *mp_a, mp_int *mp_b, mp_int *mp_n, mp_int *mp_p)
{
    int ret = 0;
    mp_int mp_rand_k, mp_d1d2_1, mp_d1d2, XA_new, YA_new, one;

    //initialize the mp_int value
    ret = mp_init_multi(&mp_rand_k, &mp_d1d2, &mp_d1d2_1, &one, &XA_new, &YA_new, NULL);
    CHECK_RET(ret);

    //set random k into d1
    ret = genRand_k(&mp_rand_k, mp_n);
    CHECK_RET(ret);
    ret = mp_copy(&mp_rand_k, mp_pri_d1);
    CHECK_RET(ret);

    //set random k into d2
    ret = genRand_k(&mp_rand_k, mp_n);
    CHECK_RET(ret);
    ret = mp_copy(&mp_rand_k, mp_pri_d2);
    CHECK_RET(ret);

    printf("d1 is: ");
    MP_print(mp_pri_d1);

    printf("d2 is: ");
    MP_print(mp_pri_d2);

    //compute the true value of (d1d2-1)
    ret = mp_mulmod(mp_pri_d1, mp_pri_d2, mp_p, &mp_d1d2);
    CHECK_RET(ret);

    mp_set(&one, 1);

    ret = mp_submod(&mp_d1d2, &one, mp_p, &mp_d1d2_1);
    CHECK_RET(ret);

    printf("d1d2-1 is: ");
    MP_print(&mp_d1d2_1);

    //compute public key by using (d1d2-1)G
    ret = Ecc_point_mul(mp_XA, mp_YA, mp_Xg, mp_Yg, &mp_d1d2_1,
                        mp_a, mp_p);
    CHECK_RET(ret);

    //check if public key is on the curve
    ret = Ecc_point_is_on_curve(mp_XA, mp_YA, mp_a, mp_b, mp_p);
    CHECK_RET(ret);

    printf("public Key(using (d1d2-1)G): \n");
    printf("xA: ");
    MP_print(mp_XA);
    printf("yA: ");
    MP_print(mp_YA);

    //compute public key by using d1d2G - G

    //compute d1d2G
    ret = Ecc_point_mul(&XA_new, &YA_new, mp_Xg, mp_Yg, mp_pri_d2,
                        mp_a, mp_p);
    CHECK_RET(ret);
    ret = Ecc_point_mul(&XA_new, &YA_new, &XA_new, &YA_new, mp_pri_d1,
                        mp_a, mp_p);
    CHECK_RET(ret);

    //compute d1d2G - G
    //经过测试发现这种计算方式得到的结果点是不在曲线上的
    //说明这种计算会出现问题
    ret = Ecc_point_sub(&XA_new, &YA_new, &XA_new, &YA_new, mp_Xg, mp_Yg,
                        mp_a, mp_p);
    CHECK_RET(ret);

    printf("\npublic key(using d2Gd1 - G): \n");
    printf("xA: ");
    MP_print(&XA_new);
    printf("yA: ");
    MP_print(&YA_new);

END:
    mp_clear(&mp_rand_k);
    return ret;
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

    for (i = 0; i <= Bt_array_len - 1; i++)
    {
        // Q = [2]Q;
        ret = Ecc_point_add(&tmp_Qx, &tmp_Qy, &mp_Qx, &mp_Qy, &mp_Qx, &mp_Qy, &mp_A, &mp_P);
        CHECK_RET(ret);
        /////////////
        if ('1' == Bt_array[i]) //为什么1的时候额外加一次
        {                       // Q = Q + P
            ret = Ecc_point_add(&mp_Qx, &mp_Qy, &tmp_Qx, &tmp_Qy, px, py, &mp_A, &mp_P);
            CHECK_RET(ret);
            /////////////
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

int Ecc_point_sub(mp_int *result_x, mp_int *result_y,
                  mp_int *x1, mp_int *y1, mp_int *x2, mp_int *y2,
                  mp_int *param_a, mp_int *param_p)
{
    int ret;
    mp_int y2_new;
    ret = mp_init(&y2_new);
    CHECK_RET(ret);

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

    //y2_new = p - y2
    ret = mp_sub(param_p, y2, &y2_new);
    CHECK_RET(ret);

    // cal (x1,y1) + (x2,y2_new)
    ret = Ecc_point_add(result_x, result_y, x1, y1, x2, &y2_new,
                        param_a, param_p);
    CHECK_RET(ret);
END:
    mp_clear(&y2_new);
    return ret;
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

int hexStr2unsignedStr(char *src, unsigned long lsrc, int flag,
                       unsigned char *out, unsigned long *lout)
{
    if ((0 == flag && 0 != lsrc % 2) || (0 != flag && 0 != lsrc % 3) || NULL == src || NULL == out)
    {
        return ERR_HEX2BYTE_PARAM_ERROR; //param err
    }

    int j = 0; //index of out buff
    if (0 == flag)
    {
        for (int i = 0; i < lsrc; i += 2)
        {
            int tmp = 0;
            int HIGH_HALF_BYTE = 0;
            int LOW_HALF_BYTE = 0;
            if (src[i] >= 0x30 && src[i] <= 0x39)
            {
                HIGH_HALF_BYTE = src[i] - 0x30;
            }
            else if (src[i] >= 0x41 && src[i] <= 0x46)
            {
                HIGH_HALF_BYTE = src[i] - 0x37;
            }
            else if (src[i] >= 0x61 && src[i] <= 0x66)
            {
                HIGH_HALF_BYTE = src[i] - 0x57;
            }
            else if (src[i] == 0x20)
            {
                HIGH_HALF_BYTE = 0x00;
            }
            else
            {
                return ERR_HEX2BYTE_INVALID_DATA;
            }

            if (src[i + 1] >= 0x30 && src[i + 1] <= 0x39)
            {
                LOW_HALF_BYTE = src[i + 1] - 0x30;
            }
            else if (src[i + 1] >= 0x41 && src[i + 1] <= 0x46)
            {
                LOW_HALF_BYTE = src[i + 1] - 0x37;
            }
            else if (src[i + 1] >= 0x61 && src[i + 1] <= 0x66)
            {
                LOW_HALF_BYTE = src[i + 1] - 0x57;
            }
            else if (src[i + 1] == 0x20)
            {
                LOW_HALF_BYTE = 0x00;
            }
            else
            {
                return ERR_HEX2BYTE_INVALID_DATA;
            }

            tmp = (HIGH_HALF_BYTE << 4) + LOW_HALF_BYTE;
            out[j] = tmp;
            j++;
        }
    }
    else
    {
        for (int i = 0; i < lsrc; i += 3)
        {
            int tmp = 0;
            int HIGH_HALF_BYTE = 0;
            int LOW_HALF_BYTE = 0;
            if ((i + 2 <= lsrc) && (src[i + 2] != flag))
            {
                return ERR_HEX2BYTE_BEYOND_RANGE;
            }

            if (src[i] >= 0x30 && src[i] <= 0x39)
            {
                HIGH_HALF_BYTE = src[i] - 0x30;
            }
            else if (src[i] >= 0x41 && src[i] <= 0x46)
            {
                HIGH_HALF_BYTE = src[i] - 0x37;
            }
            else if (src[i] >= 0x61 && src[i] <= 0x66)
            {
                HIGH_HALF_BYTE = src[i] - 0x57;
            }
            else
            {
                return ERR_HEX2BYTE_INVALID_DATA;
            }

            if (src[i + 1] >= 0x30 && src[i + 1] <= 0x39)
            {
                LOW_HALF_BYTE = src[i + 1] - 0x30;
            }
            else if (src[i + 1] >= 0x41 && src[i + 1] <= 0x46)
            {
                LOW_HALF_BYTE = src[i + 1] - 0x37;
            }
            else if (src[i + 1] >= 0x61 && src[i + 1] <= 0x66)
            {
                LOW_HALF_BYTE = src[i + 1] - 0x57;
            }
            else
            {
                return ERR_HEX2BYTE_INVALID_DATA;
            }

            tmp = (HIGH_HALF_BYTE << 4) + LOW_HALF_BYTE;
            out[j] = tmp;
            j++;
        }
    }

    *lout = j;
    return 0;
}

int Mp_Int2Byte(unsigned char *tar, unsigned long *lenTar, mp_int *mp_src)
{
    int ret = 0;
    char buff[MAX_STRLEN] = {0};
    char tmp[MAX_STRLEN] = {0};
    int lenBuff = MAX_STRLEN;
    ret = mp_toradix(mp_src, buff, 16);
    CHECK_RET(ret);

    lenBuff = strlen(buff);
    if (0 != lenBuff % 2)
    {
        tmp[0] = 0x30;
        memcpy(tmp + 1, buff, lenBuff);
        memset(buff, 0x00, sizeof(buff));
        memcpy(buff, tmp, lenBuff + 1);
        lenBuff += 1;
    }
    ret = hexStr2unsignedStr(buff, lenBuff, 0, tar, lenTar);

END:
    return ret;
}

int Byte2Mp_Int(mp_int *mp_tar, unsigned char *src_byte, unsigned long lenSrc)
{
    char *src_strbuff = NULL;
    src_strbuff = new char[lenSrc * 2 + MAX_STRLEN];
    if (NULL == src_strbuff)
    {
        return ERR_MEM_ALLOC;
    }
    memset(src_strbuff, 0x00, lenSrc * 2 + MAX_STRLEN);
    int j = 0, ret = 0;
    for (int i = 0; i < lenSrc; i++)
    {
        char tmp = src_byte[i] >> 4;
        if (tmp >= 0 && tmp <= 9)
        {
            src_strbuff[j] = tmp + 0x30;
        }
        else
        {
            src_strbuff[j] = tmp + 0x37;
        }
        tmp = src_byte[i] & 0x0f;
        if (tmp >= 0 && tmp <= 9)
        {
            src_strbuff[j + 1] = tmp + 0x30;
        }
        else
        {
            src_strbuff[j + 1] = tmp + 0x37;
        }
        j += 2;
    }
    src_strbuff[j] = 0;
    ret = mp_read_radix(mp_tar, src_strbuff, 16);

    if (NULL != src_strbuff)
    {
        delete src_strbuff;
    }
    return ret;
}

int genRand_k(mp_int *rand_k, mp_int *mp_n)
{
    int ret = 0;
    BIGNUM *bn_randk = BN_new();
    BIGNUM *bn_curven = BN_new();
    BYTE bin_curven[65];
    BYTE bin_randk[65];
    unsigned long len;

    ret = Mp_Int2Byte(bin_curven, &len, mp_n);
    CHECK_RET(ret);

    BN_bin2bn(bin_curven, len, bn_curven);

    do
    {
        ret = BN_rand_range(bn_randk, bn_curven);

    } while (BN_is_zero(bn_randk));

    BN_bn2bin(bn_randk, bin_randk);

    printf("the random number is: ");
    for (int i = 0; i < 32; ++i)
    {
        printf("%02X", bin_randk[i]);
    }
    printf("\n");

    ret = Byte2Mp_Int(rand_k, bin_randk, len);
    CHECK_RET(ret);

END:
    BN_free(bn_randk);
    BN_free(bn_curven);
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
            CHECK_RET_NOT_GOEND(ret);
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
        CHECK_RET_NOT_GOEND(ret);
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
    CHECK_RET_NOT_GOEND(ret);
    return ret;
}

int Sm3WithPreprocess(unsigned char *dgst, unsigned long *LenDgst,
                      unsigned char *Src, unsigned long lenSrc,
                      unsigned char *UserID, unsigned long lenUID,
                      mp_int *mp_a, mp_int *mp_b,
                      mp_int *mp_Xg, mp_int *mp_Yg,
                      mp_int *mp_XA, mp_int *mp_YA)
{
    int ret = 0;
    if (NULL == Src || 0 == lenSrc || NULL == UserID || 0 == lenUID || 8000 < lenUID)
    {
        ret = ERR_PARAM;
        CHECK_RET_NOT_GOEND(ret);
        return ret;
    }
    if (NULL == dgst)
    {
        *LenDgst = 32;
        ret = ERR_PARAM;
        CHECK_RET_NOT_GOEND(ret);
        return ret;
    }

#ifdef _DEBUG
    MP_print_Space;
    printf("...params are...\n");
    printf("a=");
    MP_print(mp_a);
    printf("b=");
    MP_print(mp_b);
    printf("Xg=");
    MP_print(mp_Xg);
    printf("Yg=");
    MP_print(mp_Yg);
    printf("XA=");
    MP_print(mp_XA);
    printf("YA=");
    MP_print(mp_YA);
#endif
    unsigned char ZA[32] = {0};
    unsigned char *pM_A = NULL;
    unsigned char *ZA_SRC_Buff = NULL;
    unsigned long lenZA_SRC = 0;
    unsigned char ENTL_buf[10] = {0};
    unsigned long Len_ENTL_buf = 0;
    char tmp[10] = {0};
    int tmplen = 0;
    unsigned char uzParam_A[MAX_STRLEN] = {0};
    unsigned long lenParamA = MAX_STRLEN;
    unsigned char uzParam_B[MAX_STRLEN] = {0};
    unsigned long lenParamB = MAX_STRLEN;
    unsigned char uzParam_Xg[MAX_STRLEN] = {0};
    unsigned long lenParamXg = MAX_STRLEN;
    unsigned char uzParam_Yg[MAX_STRLEN] = {0};
    unsigned long lenParamYg = MAX_STRLEN;
    unsigned char uzParam_XA[MAX_STRLEN] = {0};
    unsigned long lenParamXA = MAX_STRLEN;
    unsigned char uzParam_YA[MAX_STRLEN] = {0};
    unsigned long lenParamYA = MAX_STRLEN;

    Mp_Int2Byte(uzParam_A, &lenParamA, mp_a);
    Mp_Int2Byte(uzParam_B, &lenParamB, mp_b);
    Mp_Int2Byte(uzParam_Xg, &lenParamXg, mp_Xg);
    Mp_Int2Byte(uzParam_Yg, &lenParamYg, mp_Yg);
    Mp_Int2Byte(uzParam_XA, &lenParamXA, mp_XA);
    Mp_Int2Byte(uzParam_YA, &lenParamYA, mp_YA);

    sprintf(tmp, "%4x", lenUID * 8);
    tmplen = strlen(tmp);
    ret = hexStr2unsignedStr(tmp, tmplen, 0, ENTL_buf, &Len_ENTL_buf);
    if (ret)
    {
        CHECK_RET(ret);
    }
    lenZA_SRC = Len_ENTL_buf + lenUID + lenParamA + lenParamB + lenParamXg + lenParamYg + lenParamXA + lenParamYA;
    ZA_SRC_Buff = new unsigned char[lenZA_SRC + MAX_STRLEN];
    if (NULL == ZA_SRC_Buff)
    {
        ret = ERR_MEM_ALLOC;
        CHECK_RET(ret);
    }
    memset(ZA_SRC_Buff, 0x00, sizeof(ZA_SRC_Buff));
    memcpy(ZA_SRC_Buff, ENTL_buf, Len_ENTL_buf);
    memcpy(ZA_SRC_Buff + Len_ENTL_buf, UserID, lenUID);
    memcpy(ZA_SRC_Buff + Len_ENTL_buf + lenUID, uzParam_A, lenParamA);
    memcpy(ZA_SRC_Buff + Len_ENTL_buf + lenUID + lenParamA, uzParam_B, lenParamB);
    memcpy(ZA_SRC_Buff + Len_ENTL_buf + lenUID + lenParamA + lenParamB, uzParam_Xg, lenParamXg);
    memcpy(ZA_SRC_Buff + Len_ENTL_buf + lenUID + lenParamA + lenParamB + lenParamXg, uzParam_Yg, lenParamYg);
    memcpy(ZA_SRC_Buff + Len_ENTL_buf + lenUID + lenParamA + lenParamB + lenParamXg + lenParamYg, uzParam_XA, lenParamXA);
    memcpy(ZA_SRC_Buff + Len_ENTL_buf + lenUID + lenParamA + lenParamB + lenParamXg + lenParamYg + lenParamXA, uzParam_YA, lenParamYA);

    sm3(ZA_SRC_Buff, lenZA_SRC, ZA);
    pM_A = new unsigned char[32 + lenSrc + MAX_STRLEN];
    if (NULL == pM_A)
    {
        ret = ERR_MEM_ALLOC;
        CHECK_RET(ret);
    }
#ifdef _DEBUG
    printf("...Z value is:\n");
    BYTE_print(ZA, 32);
#endif
    memset(pM_A, 0x00, 32 + lenSrc + MAX_STRLEN);
    memcpy(pM_A, ZA, 32);
    memcpy(pM_A + 32, Src, lenSrc);
    sm3(pM_A, 32 + lenSrc, dgst);
    *LenDgst = 32;
    ret = 0;
#ifdef _DEBUG
    printf("...M value is:\n");
    BYTE_print(dgst, 32);
#endif

END:
    if (NULL != pM_A)
    {
        delete[] pM_A;
    }
    if (NULL != ZA_SRC_Buff)
    {
        delete[] ZA_SRC_Buff;
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

int GM_SM2Encrypt(unsigned char *encData, unsigned long *ulEncDataLen, unsigned char *plain, unsigned long plainLen,
                  unsigned char *szPubkey_XY, unsigned long ul_PubkXY_len)
{
    if (NULL == plain || 0 == plainLen || NULL == szPubkey_XY || 64 != ul_PubkXY_len)
    {
        return ERR_PARAM;
    }

    //1. initialize the buffer variable
    unsigned char tmpX2Buff[100] = {0};
    unsigned long tmpX2Len = 100;
    unsigned char tmpY2Buff[100] = {0};
    unsigned long tmpY2Len = 100;

    unsigned char *ptmp = NULL;
    unsigned char *t = NULL; //KDF结果

    unsigned char C1[100] = {0};
    unsigned long C1_len = 100;

    unsigned char *C2 = NULL;
    unsigned long C2_len = 100;

    unsigned char C3[32] = {0};

    unsigned char tmpBuff[100] = {0};
    unsigned long ulTmpBuffLen = 100;
    unsigned long ulTmpBuffLen2 = 100;

    //2. initialize the mp_int variable
    mp_int mp_rand_k;
    mp_init_set(&mp_rand_k, 1);

    mp_int mp_a, mp_b, mp_n, mp_p,
        mp_Xg, mp_Yg, mp_XB, mp_YB,
        mp_dgst, mp_x1, mp_y1, mp_x2, mp_y2;

    mp_init_multi(&mp_a, &mp_b, &mp_n, &mp_p,
                  &mp_Xg, &mp_Yg, &mp_XB, &mp_YB,
                  &mp_dgst, &mp_x1, &mp_y1, &mp_x2, &mp_y2, NULL);

    //3.set parameter of the curve
    int ret = 0;
    int iter = 0;

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

    //4.initialize the public key
    ret = Byte2Mp_Int(&mp_XB, szPubkey_XY, 32);
    CHECK_RET(ret);
    ret = Byte2Mp_Int(&mp_YB, szPubkey_XY + 32, 32);
    CHECK_RET(ret);

    do
    {
        //5.generate rand k
        ret = genRand_k(&mp_rand_k, &mp_n);
        CHECK_RET(ret);

        //6. compute C1 = [k]G = (x1,y1)
        ret = Ecc_point_mul(&mp_x1, &mp_y1, &mp_Xg, &mp_Yg, &mp_rand_k,
                            &mp_a, &mp_p);
        CHECK_RET(ret);

        //check if C1 is on the curve
        ret = Ecc_point_is_on_curve(&mp_x1, &mp_y1, &mp_a, &mp_b, &mp_p);
        CHECK_RET(ret);
        printf("In Encryption, the C1 is on the curve\n");

#ifdef _DEBUG
        MP_print_Space;
        printf("x1 = ");
        MP_print(&mp_x1);
        printf("y1 = ");
        MP_print(&mp_y1);
#endif //_DEBUG

        //7. push (x1,y1) into C1
        C1[0] = 0x04; //pay attention to the first position, it's not the part of the (x1,y1)
        Mp_Int2Byte(tmpBuff, &ulTmpBuffLen, &mp_x1);
        memcpy(C1 + 1, tmpBuff, ulTmpBuffLen);
        Mp_Int2Byte(tmpBuff, &ulTmpBuffLen2, &mp_y1);
        memcpy(C1 + ulTmpBuffLen + 1, tmpBuff, ulTmpBuffLen2);
        C1_len = 1 + ulTmpBuffLen + ulTmpBuffLen2;

#ifdef _DEBUG
        MP_print_Space;
        printf("Encrypt: C1 = ");
        BYTE_print(C1, C1_len);
#endif //_DEBUG

        //8. compute [k]PukeyB = [k](XB,YB) = (x2,y2)
        ret = Ecc_point_mul(&mp_x2, &mp_y2, &mp_XB, &mp_YB, &mp_rand_k,
                            &mp_a, &mp_p);
        CHECK_RET(ret);

#ifdef _DEBUG
        MP_print_Space;
        printf("x2 = ");
        MP_print(&mp_x2);
        printf("y2 = ");
        MP_print(&mp_y2);
#endif //_DEBUG

        //9.compute t = KDF(x2 // y2, klen)

        //9.1 transform the mp_int into byte
        ret = Mp_Int2Byte(tmpX2Buff, &tmpX2Len, &mp_x2);
        CHECK_RET(ret);
        ret = Mp_Int2Byte(tmpY2Buff, &tmpY2Len, &mp_y2);
        CHECK_RET(ret);
        ptmp = new unsigned char[tmpX2Len * 3];
        if (NULL == ptmp)
        {
            ret = ERR_MEM_ALLOC;
            CHECK_RET(ret);
        }
        memset(ptmp, 0x00, tmpX2Len * 3);
        memcpy(ptmp, tmpX2Buff, tmpX2Len);
        memcpy(ptmp + tmpX2Len, tmpY2Buff, tmpY2Len);

        //9.2 initialize the output variable
        t = new unsigned char[plainLen + 10];
        if (NULL == t)
        {
            ret = ERR_MEM_ALLOC;
            CHECK_RET(ret);
        }
        memset(t, 0x00, plainLen + 10);

        //9.3 call the function KDF
        ret = KDF(t, ptmp, tmpX2Len + tmpY2Len, plainLen);
        CHECK_RET(ret);

#ifdef _DEBUG
        MP_print_Space;
        printf("KDF t = ");
        BYTE_print(t, plainLen);
#endif //_DEBUG

        //10. check if t == 0
        for (iter = 0; iter < plainLen; ++iter)
        {
            if (t[iter] != 0)
            {
                printf("In encryption, the result of KDF is not zero\n");
                break;
            }
        }
        if (plainLen == iter)
            continue;
        else
        {
            printf("In encryption, the result of KDF is not zero\n");
            break;
        }
    } while (1);

    //11. compute C2 = M ^ t
    C2 = new unsigned char[plainLen + 10];
    if (NULL == C2)
    {
        ret = ERR_MEM_ALLOC;
        CHECK_RET(ret);
    }
    memset(C2, 0x00, plainLen + 10);

    for (iter = 0; iter < plainLen; ++iter)
    {
        C2[iter] = plain[iter] ^ t[iter];
    }
    C2_len = plainLen;

#ifdef _DEBUG
    MP_print_Space;
    printf("C2 = ");
    BYTE_print(C2, C2_len);
#endif // _DEBUG

    //12. compute C3 = HASH(x2 // M // y2)
    if (ptmp)
    {
        delete[] ptmp;
    }
    ptmp = new unsigned char[plainLen + tmpX2Len + tmpY2Len + 100];
    if (NULL == ptmp)
    {
        ret = ERR_MEM_ALLOC;
        CHECK_RET(ret);
    }
    memset(ptmp, 0x00, plainLen + tmpX2Len + tmpY2Len + 100);
    memcpy(ptmp, tmpX2Buff, tmpX2Len);
    memcpy(ptmp + tmpX2Len, plain, plainLen);
    memcpy(ptmp + tmpX2Len + plainLen, tmpY2Buff, tmpY2Len);

    sm3(ptmp, tmpX2Len + plainLen + tmpY2Len, C3);

#ifdef _DEBUG
    MP_print_Space;
    printf("C3 = ");
    BYTE_print(C3, 32);
#endif //_DEBUG

    //set C = C1 // C2 // C3
    if (NULL == encData)
    {
        *ulEncDataLen = 32 + C2_len + C1_len;
        ret = ERR_MEM_ALLOC;
        CHECK_RET(ret);
    }

    if (*ulEncDataLen < 32 + C2_len + C1_len)
    {
        *ulEncDataLen = 32 + C2_len + C1_len;
        ret = ERR_MEM_LOW;
        CHECK_RET(ret);
    }

    memcpy(encData, C1, C1_len);
    memcpy(encData + C1_len, C2, C2_len);
    memcpy(encData + C1_len + C2_len, C3, 32);
    *ulEncDataLen = 32 + C2_len + C1_len;

#ifdef _DEBUG
    MP_print_Space;
    printf("C = ");
    BYTE_print(encData, *ulEncDataLen);
#endif //_DEBUG

    ret = 0;
END:
    if (ptmp)
    {
        delete[] ptmp;
    }
    if (t)
    {
        delete[] t;
    }
    if (C2)
    {
        delete[] C2;
    }
    mp_clear_multi(&mp_a, &mp_b, &mp_n, &mp_p,
                   &mp_Xg, &mp_Yg, &mp_XB, &mp_YB,
                   &mp_dgst, &mp_x1, &mp_y1, &mp_x2, &mp_y2, &mp_rand_k, NULL);
    return ret;
}

int GM_SM2Decrypt(unsigned char *decData, unsigned long *ulDecDataLen, unsigned char *input, unsigned long inlen,
                  unsigned char *pri_dA, unsigned long ulPri_dALen)
{
    int ret = 0;
    //presume that the input data is:
    //[C1->65 Byte][C2->Unknown length][C3->32 Byte]
    if (NULL == input || 98 > inlen || NULL == pri_dA || 0 == ulPri_dALen)
    {
        ret = ERR_PARAM;
        CHECK_RET_NOT_GOEND(ret);
        return ret;
    }

    //1. declare the local variable
    unsigned char C3[32] = {0};
    unsigned char dgstC3[32] = {0};
    unsigned char *pC2 = NULL;
    unsigned char *pout = NULL;
    unsigned char tmpX2Buff[100] = {0};
    unsigned long tmpX2Len = 100;
    unsigned char tmpY2Buff[100] = {0};
    unsigned long tmpY2Len = 100;
    unsigned char *ptmp = NULL;
    unsigned char *p = NULL;
    int C2_len = inlen - 65 - 32;
    int iter = 0;

    //2. declare the mp_int variable
    mp_int mp_pri_dA, mp_x1, mp_y1, mp_x2, mp_y2,
        mp_Xg, mp_Yg, mp_a, mp_b, mp_n, mp_p;

    //3.initialize the local & mp_int variable
    memcpy(C3, input + 65 + C2_len, 32);
    pC2 = new unsigned char[C2_len + 10];
    if (NULL == pC2)
    {
        ret = ERR_MEM_ALLOC;
        CHECK_RET_NOT_GOEND(ret);
        return ret;
    }
    memset(pC2, 0x00, C2_len + 10);

    mp_init_multi(&mp_pri_dA, &mp_x1, &mp_y1, &mp_x2, &mp_y2,
                  &mp_Xg, &mp_Yg, &mp_a, &mp_b, &mp_n, &mp_p, NULL);

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
    ret = Byte2Mp_Int(&mp_pri_dA, pri_dA, ulPri_dALen);
    CHECK_RET(ret);

#ifdef _DEBUG
    MP_print_Space;
    printf("Decrypt: C1 = ");
    BYTE_print(input, 65);
#endif //_DEBUG

    //5. set c1 into (x1,y1)
    ret = Byte2Mp_Int(&mp_x1, input + 1, 32);
    CHECK_RET(ret);
    ret = Byte2Mp_Int(&mp_y1, input + 33, 32);
    CHECK_RET(ret);

#ifdef _DEBUG
    MP_print_Space;
    printf("x1 is: ");
    MP_print(&mp_x1);
    printf("y1 is: ");
    MP_print(&mp_y1);
#endif //_DEBUG

    //4. check c1 if is on the curve
    ret = BYTE_POINT_is_on_curve(input + 1, 64);
    if (ret)
    {
        CHECK_RET_NOT_GOEND(ret);
        return ret;
    }

    //6.cal [dB]C1 = [dB](x2,y2)
    ret = Ecc_point_mul(&mp_x2, &mp_y2, &mp_x1, &mp_y1, &mp_pri_dA,
                        &mp_a, &mp_p);
    CHECK_RET(ret);

    ret = Mp_Int2Byte(tmpX2Buff, &tmpX2Len, &mp_x2);
    CHECK_RET(ret);

    ret = Mp_Int2Byte(tmpY2Buff, &tmpY2Len, &mp_y2);
    CHECK_RET(ret);

#ifdef _DEBUG
    printf("(x2,y2): \n");
    printf("x2 = ");
    BYTE_print(tmpX2Buff, tmpX2Len);
    printf("y2 = ");
    BYTE_print(tmpY2Buff, tmpY2Len);
#endif //_DEBUG

    //7. cal t = KDF(x2//y2,klen)

    //7.1 initialize the kdf string
    ptmp = new unsigned char[tmpX2Len * 3];
    if (NULL == ptmp)
    {
        ret = ERR_MEM_ALLOC;
        CHECK_RET(ret);
    }

    memset(ptmp, 0x00, tmpX2Len * 3);
    memcpy(ptmp, tmpX2Buff, tmpX2Len);
    memcpy(ptmp + tmpX2Len, tmpY2Buff, tmpY2Len);
    pout = new unsigned char[C2_len + 10];
    if (NULL == pout)
    {
        ret = ERR_MEM_ALLOC;
        CHECK_RET(ret);
    }
    memset(pout, 0x00, C2_len + 10);

    //7.2 call the function kdf
    ret = KDF(pout, ptmp, tmpX2Len + tmpY2Len, C2_len);
    CHECK_RET(ret);

#ifdef _DEBUG
    MP_print_Space;
    printf("KDF t = ");
    BYTE_print(pout, C2_len);
#endif // _DEBUG

    //7.3 check if t is zero
    for (iter = 0; iter < C2_len; ++iter)
    {
        if (pout[iter] != 0)
            break;
    }
    if (C2_len == iter)
    {
        ret = ERR_DECRYPTION_FAILED;
        CHECK_RET(ret);
    }

    p = pC2;

    //8. set M = t^C2 to p
    for (iter = 0; iter < C2_len; ++iter)
    {
        *p++ = pout[iter] ^ (*(input + 65 + iter));
    }

#ifdef _DEBUG
    printf("M = ");
    BYTE_print(pC2, C2_len);
#endif //_DEBUG

    //9. compute C3 = hash(x2 // M // y2)
    if (ptmp)
    {
        delete[] ptmp;
    }
    ptmp = new unsigned char[C2_len + tmpX2Len + tmpY2Len + 100];
    if (NULL == ptmp)
    {
        ret = ERR_MEM_ALLOC;
        CHECK_RET(ret);
    }
    memset(ptmp, 0x00, C2_len + tmpX2Len + tmpY2Len + 100);
    memcpy(ptmp, tmpX2Buff, tmpX2Len);
    memcpy(ptmp + tmpX2Len, pC2, C2_len);
    memcpy(ptmp + tmpX2Len + C2_len, tmpY2Buff, tmpY2Len);

    sm3(ptmp, tmpX2Len + C2_len + tmpY2Len, dgstC3);
    if (0 != memcmp(C3, dgstC3, 32))
    {
        ret = ERR_DECRYPTION_FAILED;
        CHECK_RET(ret);
    }

    if (NULL == decData)
    {
        *ulDecDataLen = C2_len;
        ret = ERR_MEM_ALLOC;
        CHECK_RET(ret);
    }

    if (*ulDecDataLen < C2_len)
    {
        *ulDecDataLen = C2_len;
        ret = ERR_MEM_LOW;
        CHECK_RET(ret);
    }

    *ulDecDataLen = C2_len;
    memcpy(decData, pC2, C2_len);
    ret = 0;

#ifdef _DEBUG
    printf("U = ");
    BYTE_print(dgstC3, 32);
#endif //_DEBUG

END:
    if (ptmp)
    {
        delete[] ptmp;
    }
    if (pC2)
    {
        delete[] pC2;
    }
    if (pout)
    {
        delete[] pout;
    }

    mp_clear_multi(&mp_pri_dA, &mp_x1, &mp_y1, &mp_x2, &mp_y2,
                   &mp_Xg, &mp_Yg, &mp_a, &mp_b, &mp_n, &mp_p, NULL);

    return ret;
}