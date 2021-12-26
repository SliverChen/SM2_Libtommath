#ifndef SM2_H
#define SM2_H

#ifndef SM2_DLL_API
#define SM2_DLL_API
#endif // SM2_DLL_API

#include "tommath.h"
#include "../3rdPart/include/openssl/bn.h"
#pragma comment(lib, "libtommath.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

#define SUCCESS 0

//err
#define ERR_PARAM -2
#define ERR_MEM_ALLOC -3
#define ERR_NEED_RAND_REGEN -4
#define ERR_MEM_LOW -5
#define ERR_DECRYPTION_FAILED -6
#define ERR_UNKNOWN -7
#define ERR_GENKEY_FAILED -8

#define ERR_INFINITE_POINT -10
#define ERR_POINT_NOT_ON_CURVE -11

#define ERR_SIG_VER_R_OR_S_LARGER_THAN_N 10
#define ERR_SIG_VER_T_EQUL_ZERO 11
#define ERR_SIG_VER_R_NOT_EQUL 12
#define ERR_HEX2BYTE_PARAM_ERROR 13
#define ERR_HEX2BYTE_INVALID_DATA 14
#define ERR_HEX2BYTE_BEYOND_RANGE 15

extern const char *param_a;
extern const char *param_b;
extern const char *param_n;
extern const char *param_p;
extern const char *Xg;
extern const char *Yg;

#define MAX_STRLEN 256
#define MAX_TRY_TIMES 100
#define MP_print_Space printf("\n")

#define filename(x) strrchr(x, '\\') ? strrchr(x, '\\') + 1 : x

#define CHECK_RET(x)                                                       \
    if (x != MP_OKAY)                                                      \
    {                                                                      \
        ret = x;                                                           \
        fprintf(stderr, "%s(%d):err:%d;desr:%s;\n",                        \
                filename(__FILE__), __LINE__, x, mp_error_to_string(ret)); \
        goto END;                                                          \
    }

#define CHECK_RET_NOT_GOEND(x)                                             \
    if (x != MP_OKAY)                                                      \
    {                                                                      \
        ret = x;                                                           \
        fprintf(stderr, "%s(%d):err:%d;desr:%s;\n",                        \
                filename(__FILE__), __LINE__, x, mp_error_to_string(ret)); \
    }

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

    /*
    GM sm2 生成密钥对
    @param prikey 生成的私钥
    @param pulPriLen 生成私钥的长度
    @param pubkey_XY 生成的公钥（32 byte）
    @returns 0 if success, fail otherwise
*/
    SM2_DLL_API int GM_GenSM2keypair(unsigned char *d1, unsigned char *d2, unsigned long *pulPriLen,
                                     unsigned char pubkey_XY[64]);

    /*
    sm3 kdf
    @param kdfOutBuff KDF计算结果
    @param Z_in 传入的字符串
    @param ulZlen 传入字符串的长度
    @param klen kdf结果长度
    @returns 0 if success, fail otherwise
    */
    SM2_DLL_API int KDF(unsigned char *kdfOutBuff, unsigned char *Z_in, unsigned long ulZlen,
                        unsigned long klen);

    /*
    GM sm2 encryption
    @param encData 密文
    @param ulEncDataLen 密文长度
    @param plain 原文
    @param plainLen 原文长度
    @param szPubkey_XY 公钥
    @param ul_PubXY_len 公钥长度
    @returns 0 if success, fail otherwise
    */
    SM2_DLL_API int GM_SM2Encrypt(unsigned char *encData, unsigned long *ulEncDataLen,
                                  unsigned char *plain, unsigned long plainLen, unsigned char *szPubkey_XY, unsigned long ul_PubXY_len);

    /*
    GM sm2 decryption
    @param decData 解密文
    @param ulDecDataLen 解密文长度
    @param input 密文
    @param inlen 密文长度
    @param pri_dA 私钥
    @param ulPri_dALen 私钥长度
    @returns 0 if success, fail otherwise
    */
    SM2_DLL_API int GM_SM2Decrypt(unsigned char *decData, unsigned long *ul_DecDataLen,
                                  unsigned char *input, unsigned long inlen, unsigned char *pri_dA, unsigned long ulPri_dALen);

    /*
        check if the point is on the curve
        @param point_XY 检验的点
        @param ulpoint_XY_len 点大小
        @returns 0 if on the curve, not on curve otherwise
    */
    SM2_DLL_API int BYTE_POINT_is_on_curve(unsigned char *point_XY, unsigned long ulpoint_XY_len);

    /*
        calculate ecc point multiply
        @param k 标量系数
        @param Point 传入的点，返回更新的点
        @returns 0 if success, fail otherwise
    */
    SM2_DLL_API int BYTE_POINT_mul(unsigned char k[32], unsigned char Point[64]);

    /*
        test for the encryption and decryption
    */
    SM2_DLL_API int test_GM_encryption_and_decryption();

#ifdef __cplusplus
}
#endif //__cplusplus

/********使用libtommath库函数的接口********/

/*
    get a large prime m of length (lon)（获取大素数）
    @param 返回的素数
    @param 素数长度
    @returns 0 if success, fail otherwise
*/
int GetPrime(mp_int *m, int lon);

/*
    sm3 hash数据预处理
    @param dgst 输出的哈希处理后的值
    @param LenDgst 哈希处理的结果长度（一般为32）
    @param Src 需要哈希的字符串
    @param lenSrc 需要哈希的字符串的长度
    @param UserID 用户id
    @param lenUID 用户id长度
    @param mp_a,mp_b 椭圆曲线的参数
    @param mp_Xg,mp_Yg 椭圆曲线的基点坐标
    @param mp_XA,mp_YA 公钥坐标
    @returns 0 if success, fail otherwise
*/
int Sm3WithPreprocess(unsigned char *dgst, unsigned long *LenDgst,
                      unsigned char *Src, unsigned long lenSrc,
                      unsigned char *UserID, unsigned long lenUID,
                      mp_int *mp_a, mp_int *mp_b,
                      mp_int *mp_Xg, mp_int *mp_Yg,
                      mp_int *mp_XA, mp_int *mp_YA);

/*
    sm2 generate key pair
    @param mp_pri_dA 生成的私钥
    @param mp_XA,mp_YA 返回的公钥(Xa,Ya)
    @param mp_a,mp_b 椭圆曲线的参数
    @param mp_n 椭圆曲线的几点的阶
    @param mp_p 椭圆曲线有限域下的模
    @returns 0 if success, fail otherwise
*/
int Ecc_sm2_genKeypair(mp_int *mp_pri_d1, mp_int *mp_pri_d2,
                       mp_int *mp_XA, mp_int *mp_YA,
                       mp_int *mp_Xg, mp_int *mp_Yg,
                       mp_int *mp_a, mp_int *mp_b, mp_int *mp_n, mp_int *mp_p);

/*
    calculate point multiplication
    @param (result_x,result_y) 结果的点坐标
    @param (px,py) 传入的点坐标
    @param d 传入的标量乘系数
    @param param_a 椭圆曲线的参数a
    @param param_p 有限域的模
    @returns 0 if success, fail otherwise
*/
int Ecc_point_mul(mp_int *result_x, mp_int *result_y,
                  mp_int *px, mp_int *py,
                  mp_int *d,
                  mp_int *param_a, mp_int *param_p);

/*
    calculate point addition：C = A + B
    @param (result_x,result_y) 结果C的点坐标
    @param (x1,y1) 点A的坐标
    @param (x2,y2) 点B的坐标
    @param param_a 椭圆曲线的参数a
    @param param_p 有限域的模
    @returns 0 if success, fail otherwise
*/
int Ecc_point_add(mp_int *result_x, mp_int *result_y,
                  mp_int *x1, mp_int *y1, mp_int *x2, mp_int *y2,
                  mp_int *param_a, mp_int *param_p);

/*
    calculate point subtraction: C = A - B
    @param (result_x,result_y) 结果C的点坐标
    @param (x1,y1) 点A的坐标
    @param (x2,y2) 点B的坐标
    @param param_a 椭圆曲线的参数a
    @param param_p 有限域的模
    @returns 0 if success, fail otherwise
*/
int Ecc_point_sub(mp_int *result_x, mp_int *result_y,
                  mp_int *x1, mp_int *y1, mp_int *x2, mp_int *y2,
                  mp_int *param_a, mp_int *param_p);

/*
    check point if is on curve
    @param (mp_X,mp_Y) 需要检验的点坐标
    @param mp_a 椭圆曲线的参数a
    @param mp_b 椭圆曲线的参数b
    @param mp_p 有限域的模
    @returns 0 if is on curve, not on curve otherwise
*/
int Ecc_point_is_on_curve(mp_int *mp_X, mp_int *mp_Y,
                          mp_int *mp_a, mp_int *mp_b, mp_int *mp_p);

/**********内部调用接口（不显式调用）**********/

/*
    随机数生成 k∈[1,n-1]
*/
int genRand_k(mp_int *rand_k, mp_int *mp_n);

/*
    mp_int转换为BYTE类型
    @param tar 返回的BYTE类型数据
    @param lenTar BYTE类型数据长度
    @param mp_src 传入的mp_int类型数据
    @returns 0 if success, fail otherwise
*/
int Mp_Int2Byte(unsigned char *tar, unsigned long *lenTar, mp_int *mp_src);

/*
    BYTE类型转换为mp_int
    @param mp_tar 返回的mp_int类型数据
    @param src_type 传入的BYTE类型数据
    @param lenSrc 传入的BYTE类型数据长度
    @returns 0 if success, fail otherwise
*/
int Byte2Mp_Int(mp_int *mp_tar, unsigned char *src_byte, unsigned long lenSrc);

/*
    按照十六进制格式将字符串转换为BYTE字符串
    举例：1A2B3C4D -> 0x1A2B3C4D
    使用：hexStr2unsignedStr("1A2B3C4D",strlen("1A2B3C4D"),0,buff,&ulBuffLen);
    params:
    src, lsrc 源字符串及其长度
    flag 没有用途
    out, lout 返回的BYTE字符串及其长度
    returns:
    0 if success, fail otherwise
*/
int hexStr2unsignedStr(char *src, unsigned long lsrc, int flag, unsigned char *out, unsigned long *lout);

/*
    print the mp_int value
*/
int MP_printf(mp_int *mp_num);

/*
    print the BYTE value
*/
void BYTE_print(unsigned char *tar, unsigned long l);

#endif //SM2_H