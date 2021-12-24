#include <tommath.h>
#ifdef BN_ERROR_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is a library that provides multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library was designed directly after the MPI library by
 * Michael Fromberger but has been written from scratch with
 * additional optimizations in place.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

static const struct
{
    int code;
    char *msg;
} msgs[] = {
    {MP_OKAY, "Successful"},
    {MP_MEM, "Out of heap"},
    {MP_VAL, "Value out of range"},
    {ERR_PARAM, "Invalid parameter"},
    {ERR_MEM_ALLOC, "Fail to allocate cache"},
    {ERR_NEED_RAND_REGEN, "Random number need regenerate"},
    {ERR_MEM_LOW, "Memory lower than the standard"},
    {ERR_DECRYPTION_FAILED, "Decryption failed"},
    {ERR_UNKNOWN, "Unknown error"},
    {ERR_GENKEY_FAILED, "Fail to generate key"},
    {ERR_INFINITE_POINT, "The point is infinite"},
    {ERR_POINT_NOT_ON_CURVE, "The point is not on curve"},
    {ERR_SIG_VER_R_OR_S_LARGER_THAN_N, "R or S is out of range N"},
    {ERR_SIG_VER_T_EQUL_ZERO, "T equals zero"},
    {ERR_SIG_VER_R_NOT_EQUL, "R is incorrect"},
    {ERR_HEX2BYTE_PARAM_ERROR, "Invalid parameter"},
    {ERR_HEX2BYTE_INVALID_DATA, "Invalid data"},
    {ERR_HEX2BYTE_BEYOND_RANGE, "Out of range"}

};

/* return a char * string for a given code */
char *mp_error_to_string(int code)
{
    int x;

    /* scan the lookup table for the given message */
    for (x = 0; x < (int)(sizeof(msgs) / sizeof(msgs[0])); x++)
    {
        if (msgs[x].code == code)
        {
            return msgs[x].msg;
        }
    }

    /* generic reply for invalid code */
    return "Invalid error code";
}

#endif

/* $Source$ */
/* $Revision: 0.41 $ */
/* $Date: 2007-04-18 09:58:18 +0000 $ */
