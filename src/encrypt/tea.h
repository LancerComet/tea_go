//
//  Tea.hpp
//  MacTest
//
//  Created by apple on 2019/8/22.
//  Copyright © 2019 apple. All rights reserved.
//

#ifndef Tea_hpp
#define Tea_hpp

typedef unsigned char BYTE;
typedef char BOOL;

#define TRUE 1
#define FALSE 0


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>


#define MD5_DIGEST_LENGTH    16
#define ENCRYPT_PADLEN        18
#define CRYPT_KEY_SIZE        16


/************************************************************************************************
 对称加密底层函数
 ************************************************************************************************/
//pOutBuffer、pInBuffer 均为 8byte, pKey 为 16byte
extern void TeaEncryptECB(const BYTE *pInBuf, const BYTE *pKey, BYTE *pOutBuf);
extern void TeaDecryptECB(const BYTE *pInBuf, const BYTE *pKey, BYTE *pOutBuf);
extern void TeaEncryptECB3(const BYTE *pInBuf, const BYTE *pKey, BYTE *pOutBuf);
extern void TeaDecryptECB3(const BYTE *pInBuf, const BYTE *pKey, BYTE *pOutBuf);



/************************************************************************************************
 QQ 对称加密第一代函数
 ************************************************************************************************/

/*pKey 为 16byte*/
/*
 输入:pInBuf 为需加密的明文部分 (Body),nInBufLen 为 pInBuf 长度；
 输出:pOutBuf 为密文格式，pOutBufLen 为 pOutBuf 的长度是 8byte 的倍数，至少应预留 nInBufLen+17;
 */
/*TEA 加密算法，CBC 模式 */
/* 密文格式：PadLen (1byte)+Padding (var,0-7byte)+Salt (2byte)+Body (var byte)+Zero (7byte)*/
extern void oi_symmetry_encrypt(const BYTE* pInBuf, int nInBufLen, const BYTE* pKey, BYTE* pOutBuf, int *pOutBufLen);

/*pKey 为 16byte*/
/*
 输入:pInBuf 为密文格式，nInBufLen 为 pInBuf 的长度是 8byte 的倍数；*pOutBufLen 为接收缓冲区的长度
 特别注意 * pOutBufLen 应预置接收缓冲区的长度！
 输出:pOutBuf 为明文 (Body),pOutBufLen 为 pOutBuf 的长度，至少应预留 nInBufLen-10;
 返回值：如果格式正确返回 TRUE;
 */
/*TEA 解密算法，CBC 模式 */
/* 密文格式：PadLen (1byte)+Padding (var,0-7byte)+Salt (2byte)+Body (var byte)+Zero (7byte)*/
extern BOOL oi_symmetry_decrypt(const BYTE* pInBuf, int nInBufLen, const BYTE* pKey, BYTE* pOutBuf, int *pOutBufLen);

/************************************************************************************************
 QQ 对称加密第二代函数
 ************************************************************************************************/

/*pKey 为 16byte*/
/*
 输入:nInBufLen 为需加密的明文部分 (Body) 长度；
 输出：返回为加密后的长度 (是 8byte 的倍数);
 */
/*TEA 加密算法，CBC 模式 */
/* 密文格式：PadLen (1byte)+Padding (var,0-7byte)+Salt (2byte)+Body (var byte)+Zero (7byte)*/
extern int oi_symmetry_encrypt2_len(int nInBufLen);


/*pKey 为 16byte*/
/*
 输入:pInBuf 为需加密的明文部分 (Body),nInBufLen 为 pInBuf 长度；
 输出:pOutBuf 为密文格式，pOutBufLen 为 pOutBuf 的长度是 8byte 的倍数，至少应预留 nInBufLen+17;
 */
/*TEA 加密算法，CBC 模式 */
/* 密文格式：PadLen (1byte)+Padding (var,0-7byte)+Salt (2byte)+Body (var byte)+Zero (7byte)*/
extern void oi_symmetry_encrypt2(const BYTE* pInBuf, int nInBufLen, const BYTE* pKey, BYTE* pOutBuf, int *pOutBufLen);


/*pKey 为 16byte*/
/*
 输入:pInBuf 为密文格式，nInBufLen 为 pInBuf 的长度是 8byte 的倍数；*pOutBufLen 为接收缓冲区的长度
 特别注意 * pOutBufLen 应预置接收缓冲区的长度！
 输出:pOutBuf 为明文 (Body),pOutBufLen 为 pOutBuf 的长度，至少应预留 nInBufLen-10;
 返回值：如果格式正确返回 TRUE;
 */
/*TEA 解密算法，CBC 模式 */
/* 密文格式：PadLen (1byte)+Padding (var,0-7byte)+Salt (2byte)+Body (var byte)+Zero (7byte)*/
extern BOOL oi_symmetry_decrypt2(const BYTE* pInBuf, int nInBufLen, const BYTE* pKey, BYTE* pOutBuf, int *pOutBufLen);


#endif /* Tea_hpp */
