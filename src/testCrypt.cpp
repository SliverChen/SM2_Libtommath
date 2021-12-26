#include "../include/sm2.h"
#include "../include/tommath.h"

int test_GM_encryption_and_decryption()
{
    unsigned char pubkey[64] = {0};
    unsigned long pubkeyLen = 64;
    unsigned char d1[200] = {0};
    unsigned char d2[200] = {0};
    unsigned long priLen = 200;
    int ret = 0;
    char *plain = (char *)"my name is Van, I'm an artist.";
    unsigned char encData[1000] = {0};
    unsigned long encLen = 1000;
    unsigned char decData[1000] = {0};
    unsigned long decLen = 1000;

    printf("plain text is: %s\n", plain);

    //1. generate the private key
    ret = GM_GenSM2keypair(d1, d2, &priLen, pubkey);
    CHECK_RET(ret);

    //2.encrypting
    ret = GM_SM2Encrypt(encData, &encLen, (unsigned char *)plain, strlen(plain),
                        pubkey, pubkeyLen);
    CHECK_RET(ret);

    //3.decrypting
    // ret = GM_SM2Decrypt(decData, &decLen, encData, encLen, prikey, priLen);
    // CHECK_RET(ret);
    // printf("the decrypt is: %s\n", decData);

END:
    return ret;
}

int main()
{
    test_GM_encryption_and_decryption();
    return 0;
}