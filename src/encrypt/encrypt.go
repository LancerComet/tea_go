package encrypt

//#include "./tea.h"
import "C"
import (
	"unsafe"
)

//void TeaEncryptECB(const BYTE *pInBuf, const BYTE *pKey, BYTE *pOutBuf);
//void TeaDecryptECB(const BYTE *pInBuf, const BYTE *pKey, BYTE *pOutBuf);

func TeaEncryptECB(pInBuf []byte, pKey []byte, pOutBuf []byte) {
	cPInBuf := (*C.uchar)(unsafe.Pointer(&pInBuf[0]))
	cPkey := (*C.uchar)(unsafe.Pointer(&pKey[0]))
	cPOutBuf := (*C.uchar)(unsafe.Pointer(&pOutBuf[0]))
	C.TeaEncryptECB(cPInBuf, cPkey, cPOutBuf)
}

func TeaDecryptECB(pInBuf []byte, pKey []byte, pOutBuf []byte) {
	cPInBuf := (*C.uchar)(unsafe.Pointer(&pInBuf[0]))
	cPkey := (*C.uchar)(unsafe.Pointer(&pKey[0]))
	cPOutBuf := (*C.uchar)(unsafe.Pointer(&pOutBuf[0]))
	C.TeaDecryptECB(cPInBuf, cPkey, cPOutBuf)
}

/*pKey 为 16byte*/
/*
 输入:pInBuf 为需加密的明文部分 (Body),nInBufLen 为 pInBuf 长度；
 输出:pOutBuf 为密文格式，pOutBufLen 为 pOutBuf 的长度是 8byte 的倍数，至少应预留 nInBufLen+17;
*/
/*TEA 加密算法，CBC 模式 */

func OiSymmetryEncrypt(pInBuf []byte, inBufLen int, pKey []byte, pOutBuf []byte, pOutPutLen *int) {
	cPInBuf := (*C.uchar)(unsafe.Pointer(&pInBuf[0]))
	cPkey := (*C.uchar)(unsafe.Pointer(&pKey[0]))
	cPOutBuf := (*C.uchar)(unsafe.Pointer(&pOutBuf[0]))
	cPOutPutLen := (*C.int)(unsafe.Pointer(pOutPutLen))
	C.oi_symmetry_encrypt(cPInBuf, C.int(inBufLen), cPkey, cPOutBuf, cPOutPutLen)
}

func OiSymmetryEncrypt2(pInBuf []byte, inBufLen int, pKey []byte, pOutBuf []byte, pOutPutLen *int) {
	cPInBuf := (*C.uchar)(unsafe.Pointer(&pInBuf[0]))
	cPkey := (*C.uchar)(unsafe.Pointer(&pKey[0]))
	cPOutBuf := (*C.uchar)(unsafe.Pointer(&pOutBuf[0]))
	cPOutPutLen := (*C.int)(unsafe.Pointer(pOutPutLen))
	C.oi_symmetry_encrypt2(cPInBuf, C.int(inBufLen), cPkey, cPOutBuf, cPOutPutLen)
}

/*pKey 为 16byte*/
/*
 输入:pInBuf 为密文格式，nInBufLen 为 pInBuf 的长度是 8byte 的倍数；*pOutBufLen 为接收缓冲区的长度
 特别注意 * pOutBufLen 应预置接收缓冲区的长度！
 输出:pOutBuf 为明文 (Body),pOutBufLen 为 pOutBuf 的长度，至少应预留 nInBufLen-10;
 返回值：如果格式正确返回 TRUE;
*/
func OiSymmetryDecrypt(pInBuf []byte, inBufLen int, pKey []byte, pOutBuf []byte, pOutPutLen *int) bool {
	cPInBuf := (*C.uchar)(unsafe.Pointer(&pInBuf[0]))
	cPkey := (*C.uchar)(unsafe.Pointer(&pKey[0]))
	cPOutBuf := (*C.uchar)(unsafe.Pointer(&pOutBuf[0]))
	cPOutPutLen := (*C.int)(unsafe.Pointer(pOutPutLen))
	cBool := C.oi_symmetry_decrypt(cPInBuf, C.int(inBufLen), cPkey, cPOutBuf, cPOutPutLen)
	return cBool != 0
}
func OiSymmetryDecrypt2(pInBuf []byte, inBufLen int, pKey []byte, pOutBuf []byte, pOutPutLen *int) bool {
	cPInBuf := (*C.uchar)(unsafe.Pointer(&pInBuf[0]))
	cPkey := (*C.uchar)(unsafe.Pointer(&pKey[0]))
	cPOutBuf := (*C.uchar)(unsafe.Pointer(&pOutBuf[0]))
	cPOutPutLen := (*C.int)(unsafe.Pointer(pOutPutLen))
	cBool := C.oi_symmetry_decrypt2(cPInBuf, C.int(inBufLen), cPkey, cPOutBuf, cPOutPutLen)
	return cBool != 0
}
