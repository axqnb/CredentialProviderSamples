/****************************************************************************** 
 * 程序名称: libFPDevICBC.h                                                        *
 * 程序功能: 指纹设备库接口                                               *
 * 程序版本: 1.000                                                            *
 * 开发人员: kf                                                               *
 * 完成日期: 2013.04.15                                                       *
 * 修改人员:                                                                  *
 * 修改日期:                                                                  *
 * 修改内容:                                                                  *
 ******************************************************************************/

#ifndef _LIBFPDEVICBC_H_
#define _LIBFPDEVICBC_H_

#ifndef BYTE
typedef unsigned char BYTE;
#endif


#define FP_ERROR_SUCCESS					(0)
//其中错误代码从-1～-100为系统保留错误代码，用户可以自行定义的错误代码范围为-101～-200。 其他错误号码保留。
#define FP_ERROR_INVALID_PARAMETER			(-1)	//	参数错误。给定函数的参数有错误。
#define FP_ERROR_NOT_ENOUGH_MEMORY			(-2)	//	内存分配失败。没有分配到足够的内存。
#define FP_ERROR_NOT_SUPPORT_FUNCTION		(-3)	//	功能未开放。调用函数的功能没有实现。
#define FP_ERROR_DEVICE_NOT_FOUND			(-4)	//	设备不存在。初始化的时候，检测到设备不存在。
#define FP_ERROR_DEVICE_NOT_INIT			(-5)	//	设备未初始化。
#define FP_ERROR_INVALIDE_CODE				(-6)	//	非法的错误号。
#define FP_ERROR_NO_PRIVILEGE				(-7)	//	没有授权。

//#define -8～-100	系统保留。
#define FP_ERROR_BASE64						(-8)	//	BASE64编解码失败。
#define	FP_ERROR_EXCEPTION					(-9)	//	操作异常
#define FP_ERROR_RESERVE					(-10)	//	系统保留
#define FP_ERROR_MAC						(-11)	//	MAC错误
#define FP_ERROR_ID							(-12)	//	设备ID错误
#define FP_ERROR_IMAGE						(-13)	//	图像错误
#define FP_ERROR_FILE_NO_FOUND				(-14)	//	文件不存在

//#define -101～-200	用户自定义。
#define FP_ERROR_UNSUCCESS					(-100)	//  操作失败
#define FP_ERROR_UNKNOWN					(-101)	//	未知错误
#define FP_ERROR_DEVICECMD					(-102)	//	通讯错误
#define FP_ERROR_TIMEOUT					(-111)	//	操作超时
#define FP_ERROR_CANCEL						(-112)	//	操作取消
#define FP_ERROR_IMAGE_NOTENOUGH			(-115)	//	图像不合格
#define FP_ERROR_IS_BUSY				    (-116)	//	设备正忙

#define FP_ERROR_FINGER_VERIFY				(-201)	 //	指纹比对失败
#define FP_ERROR_FINGER_EXTRACT				(-202)	//	合成特征失败
#define FP_ERROR_FINGER_ENROLL				(-203)	//	合成模板失败
#define FP_ERROR_FINGER_ILLEGAL				(-204)	//	非法指纹数据
#define FP_ERROR_INVALID_TEMPLATE			(-205)	//	模板参数错误
#define FP_ERROR_INVALID_FEATURE			(-206)	//	特征参数错误


#ifdef __cplusplus 
extern "C" { 
#endif
	
	int __declspec(dllexport)  __stdcall FPIDeviceInit();
	int __declspec(dllexport)  __stdcall FPIDeviceClose();

	// -------------------------------------------------- 标准接口整理 --------------------------------------------------------------------
	// 01 检测设备类型
	int __declspec(dllexport)  __stdcall FPIDevDetect();

	// 02 获取固件版本
	int __declspec(dllexport)  __stdcall FPIGetVersion(int nPort, unsigned char *psOutversion, int *lpLength);

	// 03 登记指纹模板
	int __declspec(dllexport)  __stdcall FPITemplate(int nPort, unsigned char *psMB, int *lpLength);

	// 04 采集指纹特征
	int __declspec(dllexport)  __stdcall FPIFeature(int nPort, unsigned char *psTZ, int *lpLength);

	// 05 指纹比对
	int __declspec(dllexport)  __stdcall FPIMatch(unsigned char *psMB, unsigned char *psTZ, int iLevel);

	// 06 采集指纹图像到内存
	int __declspec(dllexport)  __stdcall FPIGetImageData(int nPort, int *lpImageWidth, int *lpImageHeight, unsigned char *psImage);
	
	// 07 采集指纹特征和图像数据
	int __declspec(dllexport)  __stdcall FPIGetFeatureAndImage(int nPortNo, char *pTzData, int *pLength, unsigned char *psImage, int *lpImageWidth, int *lpImageHeight);

	// 08 采集指纹图像到硬盘
	int __declspec(dllexport)  __stdcall FPIImg2Bmp(int nPort, char *psImgPath);

	// 9 检查手指是否按上
	int __declspec(dllexport)  __stdcall FPICheckFinger(int nPort);

	// 10 指纹比对
	int __declspec(dllexport)  __stdcall FPIFpMatch(char *psRegBuf, char *psVerBuf, int iLevel);


	// -------------------------------------------------- 相关辅助接口 --------------------------------------------------------------------
	// 21 接口参数设置
	int __declspec(dllexport)  __stdcall FPISetParam(int nShowImg, int nBaund, int featureTimeOut,int templateTimeOut,int imageTimeOut);

	// 22 取消当前操作 
	int	__declspec(dllexport)  __stdcall FPICancel();


	// 23 指纹图像分析（偏上、偏下、偏左、偏右、太小、偏湿、偏干）
	int __declspec(dllexport)  __stdcall FPIImageAnalyse (unsigned char *psImage, int *pnErrType, unsigned char *psErrMsg, unsigned char *psSuggest);

	// 24 数据BASE54编码/解码（nMode: 0-编码  1-解码） 
	int __declspec(dllexport) __stdcall FPICryptBase64(int nMode, unsigned char *psInput, int nInLen, unsigned char *psOutput, int *pnOutlen);

	// 25 152*200指纹图像BUF保存为BMP图像文件
	int __declspec(dllexport)  __stdcall FPISaveBMP (char* sFileName, unsigned char * psImageBuf, int iX, int iY);

	// 26 从BMP文件中读取152*200原始指纹图像数据
	int __declspec(dllexport)  __stdcall FPIReadBMP (char* sFileName, unsigned char *psImageBuf, int *piX, int *piY);
	
	// 获取序列号
	int __declspec(dllexport) __stdcall FPIGetDeviceID (int nChannel, unsigned char *psDeviceID);

	//00 设置日志信息
	int __declspec(dllexport)  __stdcall FPISetLogFile (int iFlag, char *psLogFile);

	//取密文特征
	int __declspec(dllexport)  __stdcall FPIGetMacFeature (int nChannel, int nTimeOut, unsigned char *psDeviceID, unsigned char* psRandom, unsigned char *psMAC, unsigned char *psFeatureBuf);

	int __declspec(dllexport)  __stdcall FPIGetDevStatus ();

	// 兴业银行接口
	// 获取设备序列号
	int __declspec(dllexport)  __stdcall FPIGetFeature(int nPortNo, char *pTzData, int *pLength, char* lpErrMsg);
	int __declspec(dllexport)  __stdcall FPIGetTemplate(int nPortNo, char *pMbData, int *pLength, char* lpErrMsg);
	int __declspec(dllexport)  __stdcall FPIGetLice (int nPortNo, char *pChData, int *pLength, char* lpErrMsg);

	// 指纹下载并搜搜
	int __declspec(dllexport)  __stdcall FPIClearMBLib ();
	int __declspec(dllexport)  __stdcall FPIGetMBLibCount();
	int __declspec(dllexport)  __stdcall FPIInsertMBLib(int nPos, unsigned char *psUserInfo, int iLenOfUserInfo,  unsigned char *psMB, int iLenOfMB);
	int __declspec(dllexport)  __stdcall FPISearchMBLib(int iStartPos, int iEndPos, int *piPos, unsigned char *psUserInfo, int *piLenOfUserInfo);
	int __declspec(dllexport)  __stdcall FPIDeleteMBLib(int nPos);

	

#ifdef __cplusplus
}
#endif

#endif 