//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//
#include <windows.h>
#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif

#include <unknwn.h>
#include "CSampleCredential.h"
#include "guid.h"
#include "WMRAPI.h"
#include "libFpDriver_WL.h"
#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <curl/curl.h> 
#include <chrono> 
#include <tlhelp32.h>
#include <wincred.h>
#include <lm.h>
#include "WhitelistManager.h" //白名单
#include <SetupAPI.h>
#include <devguid.h>

#ifdef ACCESS_READ
#undef ACCESS_READ
#endif
#ifdef ACCESS_WRITE
#undef ACCESS_WRITE
#endif
#include <opencv2/opencv.hpp>
#include <opencv2/objdetect.hpp>
#include <opencv2/core.hpp>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "NetAPI32.lib")
#pragma comment(lib, "opencv_world4110d.lib")

#define IDCANCEL 1001
#define IDB_BITMAP2 114
#define BUFFER_SIZE 1024
#define SCAN_INTERVAL 5000 // 扫描间隔为 5000 毫秒（5 秒） 

using std::string;
using std::wstring;
using std::vector;
using namespace cv;

wstring username1;                      //宽字节用户名
string password;                        //密码，未启用
Mat faceImage;                          //人脸信息
HINSTANCE hDLL;
HANDLE m_DevHandle = INVALID_HANDLE_VALUE;

//获取注册表存储的智能卡模版数据
WCHAR _wszSavedTemplateData[2048];
bool  _bHasSavedTemplateData;

//检测设备
BOOL DevDetect();

//获取人脸数据
int FaceDective();
int GetFaceData(string username,string SubAccount,int &authType);

//注册人脸数据
int FaceRegister(string username);
INT IsFaceRegister(string username, string SubAccount, MSG msg, int &authType);
int HttpsPostIsRegister(string username, string SubAccount, int &authType);
int HttpsPostWithImageRegister(Mat& faceImage, string& username);

bool RunProcessHidden(const string& command, string& output);

//远程认证无法连接到服务器，进行本地验证
int LocalAuthentication(string fingerstr, string username);

//https获取post数据 
int httpspost(string fingerstr, string username);
int httpsPostWithImage(Mat& faceImage, string& username, string SubAccount);
int SendVerificationCode(string username, string subAccount);
int VerifyVerificationCode(string username, string subAccount, string verificationCode);

//日志存储
void LogMessage(const wstring& message);
BOOL _ReadLogMessageFromRegistry();

//读取摄像头序列号
HRESULT _ReadCameraNumFromRegistry(DWORD* pOutValue);

//特征数据提取等待框 
bool g_returnClicked = false;
HWND _fingerprintPromptWindow = NULL;
HWND _returnButton = NULL;
HRESULT ShowFingerprintPrompt(int iRet,bool timeoutTF, int result, bool localverifi, bool isFaceRegister);
HRESULT HideFingerprintPrompt();

//保存模板数据至本地注册表，阅读本地注册表数据
HRESULT _SavetemplateDataToRegistry(PCWSTR templateData);
HRESULT _ReadSavedtemplateData();

//加解密函数--实现免密登录
HRESULT EncryptPassword(PWSTR pPlainText, PBYTE* ppEncryptedData, DWORD* pcbEncryptedData);
HRESULT DecryptPassword(PBYTE pEncryptedData, DWORD cbEncryptedData, PWSTR* ppPlainText);
HRESULT ReadPasswordFromRegistry(PWSTR* ppPassword);

// 提取 UID 字段  
const char* extract_uid(const char* buffer) {
    const char* uid_prefix = "UID (NFCID1):";
    const char* uid_start = strstr(buffer, uid_prefix);
    if (uid_start) {
        uid_start += strlen(uid_prefix); // 跳过 "UID (NFCID1):"  
        while (*uid_start == ' ') uid_start++; // 跳过空格  

        // 找到 UID 的结束位置（换行符或字符串末尾）  
        const char* uid_end = uid_start;
        while (*uid_end != '\0' && *uid_end != '\n') uid_end++;

        // 将 UID 的结束位置标记为字符串结束符  
        if (*uid_end != '\0') {
            *(const_cast<char*>(uid_end)) = '\0'; // 强制修改为字符串结束符  
        }

        // 返回指向 UID 值的指针  
        return uid_start;
    }
    return NULL; // 如果没有找到 UID，返回 NULL  
}

//进制转换ppsz
void CharStr2HexStr(unsigned char const* pucCharStr, char* pszHexStr, int iSize)
{
    int i = 0;
    unsigned char byte[2];
    pszHexStr[0] = 0;
    for (i = 0; i < iSize; i++)
    {
        byte[0] = pucCharStr[i] >> 4;
        byte[1] = pucCharStr[i] % 16;
        for (int j = 0; j < 2; j++)
        {
            if (byte[j] >= (unsigned char)0 && byte[j] <= (unsigned char)9)
                pszHexStr[i * 2 + j] = '0' + byte[j];
            else
                pszHexStr[i * 2 + j] = 'A' + byte[j] - 10;
        }
    }
}

//回调函数，用于处理curl的响应数据
size_t write_data(void* ptr, size_t size, size_t nmemb, void* stream) {
    string data((char*)ptr, size * nmemb);
    ((std::stringstream*)stream)->str(data);
    return size * nmemb;
}

//宽字节转换为字符串
string WCharToMByte(LPCWSTR lpcwszStr)
{
    string str;
    DWORD dwMinSize = 0;
    LPSTR lpszStr = NULL;
    dwMinSize = WideCharToMultiByte(CP_OEMCP, NULL, lpcwszStr, -1, NULL, 0, NULL, FALSE);
    if (0 == dwMinSize)
    {
        return FALSE;
    }
    lpszStr = new char[dwMinSize];
    WideCharToMultiByte(CP_OEMCP, NULL, lpcwszStr, -1, lpszStr, dwMinSize, NULL, FALSE);
    str = lpszStr;
    delete[] lpszStr;
    return str;
}

//字符串转换为宽字节字符串
wstring stringToWString(const string& str) {
    return wstring(str.begin(), str.end());
}

wstring StringToWide(string& narrowStr) {
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), -1, nullptr, 0);
    if (wideLen == 0) return L"";
    wstring wideStr(wideLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), -1, &wideStr[0], wideLen);
    return wideStr;
}
//清洗字符串，去除空格，换行符
string cleanSmartcard(const string& smartcard) {
    string cleaned;
    // 遍历每个字符  
    for (char ch : smartcard) {
        // 如果是字母或数字，保留  
        if (std::isalnum(ch)) {
            cleaned += ch;
        }
    }
    return cleaned;
}

// CSampleCredential ////////////////////////////////////////////////////////

CSampleCredential::CSampleCredential():
    _cRef(1),
    _pCredProvCredentialEvents(NULL)
{
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
    _bChecked = FALSE;
    _dwComboIndex = 0;
}

CSampleCredential::~CSampleCredential()
{
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }

    DllRelease();
}


// Initializes one credential with the field information passed in.
// Set the value of the SFI_LARGE_TEXT field to pwzUsername.
HRESULT CSampleCredential::Initialize(
    __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    __in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,// 类型，控件的类型及默认显示文字
    __in const FIELD_STATE_PAIR* rgfsp,   // 状态，是否显示、是否是焦点
    __in DWORD dwFlags,
    __in_opt PCWSTR wszUsername,
    __in_opt PCWSTR wszSubAccount
    )
{
    //OutputDebugString(L"CSampleCredential::Initialize");
    HRESULT hr = S_OK;

    _cpus = cpus;
    _dwFlags = dwFlags;
    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String value of all the fields. 
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"人脸识别认证", &_rgFieldStrings[SFI_LARGE_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"人脸识别认证凭据提供程序", &_rgFieldStrings[SFI_SMALL_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        if (wszUsername && wcslen(wszUsername) > 0)
        {
            CoTaskMemFree(_rgFieldStrings[SFI_EDIT_TEXT]);
            SHStrDupW(wszUsername, &_rgFieldStrings[SFI_EDIT_TEXT]);
        }
        else
        {
            hr = SHStrDupW(L"", &_rgFieldStrings[SFI_EDIT_TEXT]);
        }
    }
    if (SUCCEEDED(hr))
    {
        if (wszSubAccount && wcslen(wszSubAccount) > 0)
        {
            CoTaskMemFree(_rgFieldStrings[SFI_SUB_ACCOUNT]);
            SHStrDupW(wszSubAccount, &_rgFieldStrings[SFI_SUB_ACCOUNT]);
        }
        else
        {
            hr = SHStrDupW(L"", &_rgFieldStrings[SFI_SUB_ACCOUNT]);
        }
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]); 
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_NEW_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_CONFIRM_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_VERIFICATION_CODE]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"发送验证码", &_rgFieldStrings[SFI_SEND_CODE_BUTTON]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Checkbox", &_rgFieldStrings[SFI_CHECKBOX]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Combobox", &_rgFieldStrings[SFI_COMBOBOX]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Command Link", &_rgFieldStrings[SFI_COMMAND_LINK]);
    }

    return S_OK;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CSampleCredential::Advise(
    __in ICredentialProviderCredentialEvents* pcpce
    )
{
    //OutputDebugString(L"CSampleCredential::Advise");
    if (_pCredProvCredentialEvents != NULL)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();
    return S_OK;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CSampleCredential::UnAdvise()
{
    //OutputDebugString(L"CSampleCredential::UnAdvise");
    if (_pCredProvCredentialEvents)
    {   
        _SaveChangePasswordToRegistry(FALSE);  //将改密标志标记为“0”
        //OutputDebugString(L"_SaveChangePasswordToRegistry(FALSE)");
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = NULL;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the 
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
//当我们的tile被选中(缩放)时，LogonUI调用这个函数
//如果你只是想根据选择的状态显示/隐藏字段，
//这里不需要做任何事情——你可以在
//字段定义。但如果你想做点什么
//更复杂，如更改字段的内容时，瓷砖
//选中后，在这里执行。
HRESULT CSampleCredential::SetSelected(__out BOOL* pbAutoLogon)  
{
    //OutputDebugString(L"CSampleCredential::SetSelected");
    if (NULL != _pCredProvCredentialEvents)
    {
        // 设置 Combobox、checkbox、 控件为隐藏状态
        _pCredProvCredentialEvents->SetFieldState(this, SFI_COMBOBOX, CPFS_HIDDEN);
        _pCredProvCredentialEvents->SetFieldState(this, SFI_CHECKBOX, CPFS_HIDDEN);
        _pCredProvCredentialEvents->SetFieldState(this, SFI_COMMAND_LINK, CPFS_HIDDEN);
        _pCredProvCredentialEvents->SetFieldState(this, SFI_SMALL_TEXT, CPFS_HIDDEN);
        
        // 判断不同场景显示不同的输入框
        if (_cpus == CPUS_CHANGE_PASSWORD) {
            _pCredProvCredentialEvents->SetFieldState(this, SFI_NEW_PASSWORD, CPFS_DISPLAY_IN_BOTH);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_CONFIRM_PASSWORD, CPFS_DISPLAY_IN_BOTH);
        }
        else {
            _pCredProvCredentialEvents->SetFieldState(this, SFI_NEW_PASSWORD, CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_CONFIRM_PASSWORD, CPFS_HIDDEN);
        }
        // 如果用户名已填充，焦点切到密码框
        if (wcslen(_rgFieldStrings[SFI_EDIT_TEXT]) > 0 )
        {
            _pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_PASSWORD, CPFIS_FOCUSED);
        }
    }

    *pbAutoLogon = FALSE; // wherether auto logon? 是否自动登录
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
//与SetSelected类似，LogonUI在你的tile被选中时调用这个函数
//现在不再是。这里最常见的事情是(我们将在下面做)清除密码字段。
HRESULT CSampleCredential::SetDeselected()
{
    //OutputDebugString(L"CSampleCredential::SetDeselected");
    HRESULT hr = S_OK;
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));

        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
        }
    }

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information 
// to display the tile.
HRESULT CSampleCredential::GetFieldState(
    __in DWORD dwFieldID,
    __out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    __out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
    )
{
    //OutputDebugString(L"CSampleCredential::GetFieldState");
    HRESULT hr;
    
    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)) && pcpfs && pcpfis)
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID

HRESULT CSampleCredential::GetStringValue(
    __in DWORD dwFieldID, 
    __deref_out PWSTR* ppwsz
    )
{
    //OutputDebugString(L"CSampleCredential::GetStringValue");
    HRESULT hr;

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && ppwsz) 
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
HRESULT CSampleCredential::GetBitmapValue(
    __in DWORD dwFieldID, 
    __out HBITMAP* phbmp
    )
{
    //OutputDebugString(L"CSampleCredential::GetBitmapValue");
    HRESULT hr;
    if ((SFI_TILEIMAGE == dwFieldID) && phbmp)
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != NULL)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be 
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
//将pdwAdjacentTo设置为提交按钮所在字段的索引
//与之相邻。我们建议将提交按钮放在最后一个按钮旁边
//用户需要输入信息的字段。可选字段
//应该在提交按钮的下面。
HRESULT CSampleCredential::GetSubmitButtonValue(
    __in DWORD dwFieldID,
    __out DWORD* pdwAdjacentTo
    )
{
    //OutputDebugString(L"CSampleCredential::GetSubmitButtonValue");
    HRESULT hr;

    if (SFI_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to 
        // appear next to.
        // pdwAdjacentTo是一个指向你想要提交按钮的字段的指针
        //出现在…
        if (CPUS_CHANGE_PASSWORD == _cpus) {
            *pdwAdjacentTo = SFI_CONFIRM_PASSWORD;
        }
        else {
            *pdwAdjacentTo = SFI_PASSWORD;
        }
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CSampleCredential::SetStringValue(
    __in DWORD dwFieldID, 
    __in PCWSTR pwz      
    )
{
    //OutputDebugString(L"CSampleCredential::SetStringValue");
    HRESULT hr;
    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft || 
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft)) 
    {
        PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns whether a checkbox is checked or not as well as its label.

HRESULT CSampleCredential::GetCheckboxValue(
    __in DWORD dwFieldID, 
    __in BOOL* pbChecked,
    __deref_out PWSTR* ppwszLabel
    )
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pbChecked = _bChecked;
        hr = SHStrDupW(_rgFieldStrings[SFI_CHECKBOX], ppwszLabel);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets whether the specified checkbox is checked or not.
HRESULT CSampleCredential::SetCheckboxValue(
    __in DWORD dwFieldID, 
    __in BOOL bChecked
    )
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _bChecked = bChecked;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the 
// currently selected item (pdwSelectedItem).
HRESULT CSampleCredential::GetComboBoxValueCount(
    __in DWORD dwFieldID, 
    __out DWORD* pcItems, 
    __out_range(<,*pcItems) DWORD* pdwSelectedItem
    )
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pcItems = ARRAYSIZE(s_rgComboBoxStrings);
        *pdwSelectedItem = 0;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return S_OK;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CSampleCredential::GetComboBoxValueAt(
    __in DWORD dwFieldID, 
    __in DWORD dwItem,
    __deref_out PWSTR* ppwszItem
    )
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        hr = SHStrDupW(s_rgComboBoxStrings[dwItem], ppwszItem);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user changes the selected item in the combobox.
HRESULT CSampleCredential::SetComboBoxSelectedValue(
    __in DWORD dwFieldID,
    __in DWORD dwSelectedItem
    )
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _dwComboIndex = dwSelectedItem;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user clicks a command link.
HRESULT CSampleCredential::CommandLinkClicked(__in DWORD dwFieldID)
{
    HRESULT hr;

    // Validate parameter.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
        (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        HWND hwndOwner = NULL;

        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
        }

        // 处理发送验证码按钮点击
        if (dwFieldID == SFI_SEND_CODE_BUTTON)
        {
            // 获取用户名
            if (_rgFieldStrings[SFI_EDIT_TEXT] && wcslen(_rgFieldStrings[SFI_EDIT_TEXT]) > 0)
            {
                string username = WCharToMByte(_rgFieldStrings[SFI_EDIT_TEXT]);
                string subAccount = WCharToMByte(_rgFieldStrings[SFI_SUB_ACCOUNT]);

                // 调用发送验证码函数
                int result = SendVerificationCode(username, subAccount);

                if (result == 0)
                {
                    ::MessageBox(hwndOwner, L"验证码已发送", L"成功", MB_OK | MB_ICONINFORMATION);
                }
                else
                {
                    ::MessageBox(hwndOwner, L"验证码发送失败", L"错误", MB_OK | MB_ICONERROR);
                }
            }
            else
            {
                ::MessageBox(hwndOwner, L"请先输入用户名", L"提示", MB_OK | MB_ICONWARNING);
            }
        }
        else
        {
            // Pop a messagebox indicating the click.
            ::MessageBox(hwndOwner, L"Command link clicked", L"Click!", 0);
        }
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Collect the username and password into a serialized credential for the correct usage scenario 
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials 
// back to the system to log on.
// 将用户名和密码收集到一个序列化的凭据中，以用于正确的使用场景
//(在这个示例中演示了登录/解锁)。然后LogonUI传递这些凭据
//返回系统进行登录。
//点击登录按钮后出发的函数
HRESULT CSampleCredential::GetSerialization(
    __out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
    __deref_out_opt PWSTR* ppwszOptionalStatusText, 
    __in CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{   
    //OutputDebugString(L"CSampleCredential::GetSerialization");
    HRESULT hr = E_UNEXPECTED;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    //远程登录
    DWORD cb = 0;
    BYTE* rgb = NULL;

    int reiRet = -1;                                                        //指纹判断返回值
    int WhiteUser = 0;

    //获取用户名
    /*
    int size = WideCharToMultiByte(CP_ACP, 0, _rgFieldStrings[SFI_EDIT_TEXT], -1, NULL, 0, NULL, NULL);
    char* buffer = new char[size];                                          //创建一个buffer资源，暂存CHAR型用户名
    WideCharToMultiByte(CP_ACP, 0, _rgFieldStrings[SFI_EDIT_TEXT], -1, buffer, size, NULL, NULL);
    string username(buffer);                                                //字符串用户名
    delete[] buffer;                                                        //清除buffer资源
    */


    if (_rgFieldStrings[SFI_EDIT_TEXT] == nullptr ||
        _rgFieldStrings[SFI_EDIT_TEXT][0] == L'\0') {
        hr = E_INVALIDARG;  
        return hr;
    }

    string username = WCharToMByte(_rgFieldStrings[SFI_EDIT_TEXT]);                 //宽字节用户名转换为字符串用户名
    string SubAccount = WCharToMByte(_rgFieldStrings[SFI_SUB_ACCOUNT]);             //宽字节子账户转换为字符串子账户
    string verificationCode = WCharToMByte(_rgFieldStrings[SFI_VERIFICATION_CODE]); //验证码
    username1 = _rgFieldStrings[SFI_EDIT_TEXT];                                     //宽字节用户名
    int authType = 0;                                                               //认证方式,0为密码+人脸，1为只用人脸

    if (IsUserInWhitelist(username1)) { 
        reiRet = 0;
    }
    else {
        // 验证验证码
        if (verificationCode.empty()) {
            LogMessage(L"Verification code is empty");
            MessageBox(NULL, L"请输入验证码", L"提示", MB_OK | MB_ICONWARNING);
            hr = E_FAIL;
            return hr;
        }

        // 调用验证码验证函数
        int verifyResult = VerifyVerificationCode(username, SubAccount, verificationCode);
        if (verifyResult != 0) {
            LogMessage(L"Verification code verification failed");
            MessageBox(NULL, L"验证码错误或已过期", L"错误", MB_OK | MB_ICONERROR);
            hr = E_FAIL;
            return hr;
        }
        LogMessage(L"Verification code verified successfully");
        reiRet = 0; // 验证码验证成功，设置返回码为0
    }

        WCHAR wsz[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD cch = ARRAYSIZE(wsz);

        if (GetComputerNameW(wsz, &cch) && (reiRet == 0 || reiRet == 999))
        {
            
            PCWSTR wszUsername = _rgFieldStrings[SFI_EDIT_TEXT];
            if (wszUsername && wcslen(wszUsername) > 0)
            {
                // 保存到注册表
                //LogMessage(wszUsername);
                _SaveUsernameToRegistry(L"LastUsername", wszUsername);
                _SaveUsernameToRegistry(L"LastSubAccount", _rgFieldStrings[SFI_SUB_ACCOUNT]);
            }
            if ( _cpus == CPUS_CREDUI && wszUsername && wcslen(wszUsername) > 0)
            {
                // 保存远程调用到注册表
                _SaveRemoteUsernameToRegistry(wszUsername);

            }

            PWSTR pwStrDomainName = _rgFieldStrings[SFI_EDIT_TEXT];
            string strDomainName = WCharToMByte(pwStrDomainName);
            PWSTR pszDomain = wsz;
            PWSTR pszUsername = _rgFieldStrings[SFI_EDIT_TEXT];

            //如果用户使用域登录，判断使用有“\”，若有则进行分割，若无则正常进行本地验证。
            int fIsDomainUser = strDomainName.find("\\");
            if ((fIsDomainUser > 0) && (fIsDomainUser < strDomainName.size())) {
                hr = SplitDomainAndUsername(pwStrDomainName, &pszDomain, &pszUsername);
            }

            //判断登录场景是否是更改密码
            if (CPUS_CHANGE_PASSWORD == _cpus) {
                HWND hwndChangePass = NULL;
                if (_pCredProvCredentialEvents)
                {
                    _pCredProvCredentialEvents->OnCreatingWindow(&hwndChangePass);
                }
                NET_API_STATUS status;

                //匹配两次密码是否一致
                if (wcscmp(_rgFieldStrings[SFI_NEW_PASSWORD], _rgFieldStrings[SFI_CONFIRM_PASSWORD]) == 0) {
                    status = NetUserChangePassword(pszDomain, pszUsername, _rgFieldStrings[SFI_PASSWORD], _rgFieldStrings[SFI_NEW_PASSWORD]);
                    //OutputDebugString(L"NetUserChangePassword(pszDomain, pszUsername, _rgFieldStrings[SFI_PASSWORD], _rgFieldStrings[SFI_NEW_PASSWORD]);");
                    if (status == NERR_Success) {
                        //OutputDebugString(L"Password changed successfully!");
                        ::MessageBox(hwndChangePass, L"密码已修改成功！请“取消”之后重新登录！", L"提示", 0);
                        LogMessage(L"Password changed successfully!");
                        _rgFieldStrings[SFI_PASSWORD] = _rgFieldStrings[SFI_NEW_PASSWORD];
                        //_cpus = CPUS_LOGON;
                    }
                    else {
                        switch (status) {
                        case ERROR_ACCESS_DENIED:
                            //OutputDebugString(L"Error: Access denied (insufficient privileges)");
                            ::MessageBox(hwndChangePass, L"权限不足！", L"提示", 0);
                            break;
                        case NERR_InvalidComputer:
                            //OutputDebugString(L"Error: Invalid computer name");
                            ::MessageBox(hwndChangePass, L"无效的域名！", L"提示", 0);
                            break;
                        case NERR_NotPrimary:
                            //OutputDebugString(L"Error: Operation must be performed on primary domain controller");
                            ::MessageBox(hwndChangePass, L"操作需在主域控制器进行！", L"提示", 0);
                            break;
                        case NERR_UserNotFound:
                            //OutputDebugString(L"Error: User not found");
                            ::MessageBox(hwndChangePass, L"用户不存在！", L"提示", 0);
                            break;
                        case NERR_PasswordTooShort:
                            //OutputDebugString(L"Error: Password is too short");
                            ::MessageBox(hwndChangePass, L"新密码不符合域/本地密码规则策略！", L"提示", 0);
                            break;
                        case ERROR_INVALID_PASSWORD:
                            //OutputDebugString(L"Error: Old password is incorrect");
                            ::MessageBox(hwndChangePass, L"旧密码不正确，请重试！", L"提示", 0);
                            break;
                        default:
                            //OutputDebugString(L"Error: Unknow Error");
                            ::MessageBox(hwndChangePass, L"未知错误！", L"提示", 0);
                        }
                    }
                }
                else {
                    ::MessageBox(hwndChangePass, L"两次密码不一致，请重新输入！", L"提示", 0);
                    return S_FALSE;
                }
            }
            //显示密码
            //LogMessage(_rgFieldStrings[SFI_PASSWORD]);
            //判断服务器选择的认证方式，如果是选择了免密登录且用户是否没有填写密码字段，如果没有填写则读取注册表中的的密码字段，填写了则读取填写的密码字段。
            if (authType == 1 && (_rgFieldStrings[SFI_PASSWORD] == nullptr || _rgFieldStrings[SFI_PASSWORD][0] == L'\0')) {
                PWSTR pStoredPassword = nullptr;
                HRESULT hr = ReadPasswordFromRegistry(&pStoredPassword);
                if (SUCCEEDED(hr) && pStoredPassword != nullptr && pStoredPassword[0]  != L'\0')
                {   
                    size_t len = wcslen(pStoredPassword) + 1;
                    if (_rgFieldStrings[SFI_PASSWORD] == nullptr)
                    {
                        _rgFieldStrings[SFI_PASSWORD] = (PWSTR)CoTaskMemAlloc(len * sizeof(WCHAR));
                    }
                    else
                    {
                        _rgFieldStrings[SFI_PASSWORD] = (PWSTR)CoTaskMemRealloc(_rgFieldStrings[SFI_PASSWORD], len * sizeof(WCHAR));
                    }
                    if (_rgFieldStrings[SFI_PASSWORD] != nullptr)
                    {
                        wcscpy_s(_rgFieldStrings[SFI_PASSWORD], len, pStoredPassword);
                    }
                    SecureZeroMemory(pStoredPassword, wcslen(pStoredPassword) * sizeof(WCHAR));
                    //LogMessage(_rgFieldStrings[SFI_PASSWORD]);
                    CoTaskMemFree(pStoredPassword);
                }
            }
            else {
                // 在保存到注册表前加密
                PBYTE pEncryptedPassword = NULL;
                DWORD cbEncryptedPassword = 0;
                hr = EncryptPassword(_rgFieldStrings[SFI_PASSWORD], &pEncryptedPassword, &cbEncryptedPassword);

                if (SUCCEEDED(hr))
                {
                    // 保存加密后的数据到注册表
                    HKEY hKey;
                    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,       // 根键
                        L"SOFTWARE\\Softdomain\\LoginWhitelist", // 子键路径
                        0,                                      // 保留参数
                        NULL,                                   // 类名（无需指定）
                        0,                
                        KEY_WRITE | KEY_QUERY_VALUE,            // 权限：写入 + 查询
                        NULL,                                   // 安全属性（默认）
                        &hKey,                                  // 接收打开的键句柄
                        NULL                                    // 是否新建（无需返回）
                        ) == ERROR_SUCCESS)
                    {
                        RegSetValueExW(hKey, L"UIDPW", 0, REG_BINARY, pEncryptedPassword, cbEncryptedPassword);
                        RegCloseKey(hKey);
                    }
                    LocalFree(pEncryptedPassword);
                }
            }

            PWSTR pwzProtectedPassword;
            
            hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);

            //远程登录调用
            if (CPUS_CREDUI == _cpus) 
            {
                if (SUCCEEDED(hr))
                {
                    PWSTR pwzDomainUsername = NULL;
                    hr = DomainUsernameStringAlloc(wsz, _rgFieldStrings[SFI_EDIT_TEXT], &pwzDomainUsername);
                    if (SUCCEEDED(hr))
                    {
                        // We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
                        // KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
                        // as necessary.
                        if (!CredPackAuthenticationBufferW((CREDUIWIN_PACK_32_WOW & _dwFlags) ? CRED_PACK_WOW_BUFFER : 0, pwzDomainUsername, pwzProtectedPassword, rgb, &cb))
                        {
                            if (ERROR_INSUFFICIENT_BUFFER == GetLastError())
                            {
                                rgb = (BYTE*)HeapAlloc(GetProcessHeap(), 0, cb);
                                if (rgb)
                                {
                                    // If the CREDUIWIN_PACK_32_WOW flag is set we need to return 32 bit buffers to our caller we do this by 
                                    // passing CRED_PACK_WOW_BUFFER to CredPacAuthenticationBufferW.
                                    if (!CredPackAuthenticationBufferW((CREDUIWIN_PACK_32_WOW & _dwFlags) ? CRED_PACK_WOW_BUFFER : 0, pwzDomainUsername, pwzProtectedPassword, rgb, &cb))
                                    {
                                        HeapFree(GetProcessHeap(), 0, rgb);
                                        hr = HRESULT_FROM_WIN32(GetLastError());
                                    }
                                    else
                                    {
                                        hr = S_OK;
                                    }
                                }
                                else
                                {
                                    hr = E_OUTOFMEMORY;
                                }
                            }
                            else
                            {
                                hr = E_FAIL;
                            }
                            HeapFree(GetProcessHeap(), 0, pwzDomainUsername);
                        }
                        else
                        {
                            hr = E_FAIL;
                        }
                    }
                    CoTaskMemFree(pwzProtectedPassword);
                }
            }
            else
            {
                KERB_INTERACTIVE_UNLOCK_LOGON kiul;

                hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, pwzProtectedPassword, _cpus, &kiul);
                if (SUCCEEDED(hr))
                {

                    // We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
                    // KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
                    // as necessary.
                    //我们在解锁和登录场景中都使用KERB_INTERACTIVE_UNLOCK_LOGON。它包含一个
                    // KERB_INTERACTIVE_LOGON保存信用加上一个由Winlogon为我们填写的LUID
                    //根据需要。
                    hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
                }
            }
                
            if (SUCCEEDED(hr))
            {

                ULONG ulAuthPackage;
                hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                if (SUCCEEDED(hr))
                {

                    pcpcs->ulAuthenticationPackage = ulAuthPackage;
                    pcpcs->clsidCredentialProvider = CLSID_CSample;

                    // In CredUI scenarios, we must pass back the buffer constructed with CredPackAuthenticationBuffer.
                    if (CPUS_CREDUI == _cpus)
                    {
                        pcpcs->rgbSerialization = rgb;
                        pcpcs->cbSerialization = cb;
                    }

                    // At this point the credential has created the serialized credential used for logon
                    // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                    // that we have all the information we need and it should attempt to submit the 
                    // serialized credential.
                    //此时，凭据已经创建了用于登录的序列化凭据
                    //通过设置CPGSR_RETURN_CREDENTIAL_FINISHED，我们让logonUI知道
                    //我们有我们需要的所有信息，它应该尝试提交序列化凭证。
                    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                }
                else
                {
                    HeapFree(GetProcessHeap(), 0, rgb);
                }
            }
        }
        else
        {
            DWORD dwErr = GetLastError();
            hr = HRESULT_FROM_WIN32(dwErr);
        }
        return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"账户名或密码不正确", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"此账户已被禁用", CPSI_WARNING },
    { STATUS_PASSWORD_MUST_CHANGE, STATUS_SUCCESS,L"在登录之前，必须修改用户的密码", CPSI_WARNING },
    { STATUS_PASSWORD_EXPIRED, STATUS_PASSWORD_EXPIRED,L"密码已过期，需要更改", CPSI_WARNING },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_PASSWORD_EXPIRED,L"此账户的密码已过期，必须更改", CPSI_WARNING}
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to 
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
// ReportResult是完全可选的。其目的是允许凭据自定义字符串
//登录失败时显示的图标。例如，我们选择
//自定义错误的情况下显示是错误的用户名/密码和帐户的情况
//被禁用。
HRESULT CSampleCredential::ReportResult(
    __in NTSTATUS ntsStatus, 
    __in NTSTATUS ntsSubstatus,
    __deref_out_opt PWSTR* ppwszOptionalStatusText, 
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    //OutputDebugString(L"CSampleCredential::ReportResult");
    //wchar_t debugMsg[256];
    //swprintf_s(debugMsg, L"ReportResult: ntsStatus=0x%X, ntsSubstatus=0x%X", ntsStatus, ntsSubstatus);
    //OutputDebugString(debugMsg);

    *ppwszOptionalStatusText = NULL;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    // 检测密码过期状态，密码过期或需要强制更改，修改登录场景并保存标签到注册表
    if (ntsStatus == STATUS_PASSWORD_MUST_CHANGE || ntsSubstatus == STATUS_PASSWORD_EXPIRED) {
        _cpus = CPUS_CHANGE_PASSWORD;
        _SaveChangePasswordToRegistry(TRUE);
        //OutputDebugString(L"_SaveChangePasswordToRegistry(TRUE)");
    }
    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    // If we failed the logon, try to erase the password field.
    //如果登录失败且不是改密操作，尝试擦除密码字段
    if (!SUCCEEDED(HRESULT_FROM_NT(ntsStatus)) && ntsStatus != STATUS_PASSWORD_MUST_CHANGE && ntsSubstatus != STATUS_PASSWORD_EXPIRED)
    {
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
        }
    }

    // Since NULL is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

//日志存储
void LogMessage(const wstring& message) {
    // 检查是否允许记录日志
    if (!_ReadLogMessageFromRegistry()) return;

    try {
        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);

        struct tm localTime;
        localtime_s(&localTime, &time);

        char timeStr[100];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &localTime);

        std::wofstream logfile("C:\\Program Files (x86)\\sdface\\log.txt", std::ios_base::app);
        if (logfile.is_open()) {
            logfile << timeStr << L"--" << username1 << L"--" << message << std::endl;
        }
        // 自动调用析构函数关闭文件
    }
    catch (const std::exception& e) {
    }
}

//调用nfc-list.exe--登录使用
bool RunProcessHidden(const string& command, string& output) {
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return false;
    }

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE; // 隐藏窗口  

    if (!CreateProcessA(NULL, (LPSTR)command.c_str(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return false;
    }

    CloseHandle(hWritePipe);

    char buffer[4096];
    DWORD bytesRead;
    output.clear();
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }

    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}

// 检查目标进程是否在运行   
bool IsProcessRunning(LPCWSTR processName) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // 获取系统中的进程快照  
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return false; // 捕捉快照失败  
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 遍历进程列表  
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return false; // 无法取得第一个进程  
    }

    do {
        // 检查进程名以确定其是否存在  
        if (wcscmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hProcessSnap); // 找到进程，关闭快照句柄  
            return true; // 找到了目标进程  
        }
    } while (Process32Next(hProcessSnap, &pe32)); // 继续查找下一个进程

    CloseHandle(hProcessSnap); // 关闭快照句柄  
    return false; // 未找到进程  
}

//后台调用SDSmartCardLock.exe--登录成功后执行
void StartBackgroundProcessL() {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // 隐藏窗口，运行为后台进程  
    ZeroMemory(&pi, sizeof(pi));

    LPCWSTR exePath = L"SDSmartCardLock.exe"; // 替换为实际路径  
    if (!CreateProcess(
        exePath,    // 可执行文件路径  
        NULL,       // 默认参数  
        NULL,       // 默认进程安全属性  
        NULL,       // 默认线程安全属性  
        FALSE,      // 不继承句柄  
        CREATE_NO_WINDOW, // 不显示窗口  
        NULL,       // 默认环境变量  
        NULL,       // 默认工作目录  
        &si,        // 启动信息  
        &pi         // 进程信息  
    )) {
        // 错误处理  
        DWORD error = GetLastError();
        LogMessage(L"Error starting background processL:" + std::to_wstring(error));
    }
}

//后台调用SDSmartCardMonitor.exe--监控程序
void StartBackgroundProcessM() {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // 隐藏窗口，运行为后台进程  
    ZeroMemory(&pi, sizeof(pi));

    LPCWSTR exePath = L"SDSmartCardMonitor.exe"; // 替换为实际路径  
    if (!CreateProcess(
        exePath,    // 可执行文件路径  
        NULL,       // 默认参数  
        NULL,       // 默认进程安全属性  
        NULL,       // 默认线程安全属性  
        FALSE,      // 不继承句柄  
        CREATE_NO_WINDOW, // 不显示窗口  
        NULL,       // 默认环境变量  
        NULL,       // 默认工作目录  
        &si,        // 启动信息  
        &pi         // 进程信息  
    )) {
        // 错误处理  
        DWORD error = GetLastError();
        LogMessage(L"Error starting background processM:" + std::to_wstring(error));
    }
}

//终止程序
void StopProcessByName(LPCWSTR processName) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // 获取系统中的进程快照  
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return; // 捕捉快照失败  
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 遍历进程列表  
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return; // 无法取得第一个进程  
    }

    do {
        // 检查进程名以确定其是否存在  
        if (wcscmp(pe32.szExeFile, processName) == 0) {
            // 找到目标进程，打开它以获取句柄  
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                // 尝试终止进程  
                if (TerminateProcess(hProcess, 0)) {
                    CloseHandle(hProcess);
                    CloseHandle(hProcessSnap);
                    return; // 成功终止进程  
                }
                CloseHandle(hProcess);
            }
        }
    } while (Process32Next(hProcessSnap, &pe32)); // 继续查找下一个进程  

    CloseHandle(hProcessSnap); // 关闭快照句柄  
}  

//总的调用，是否执行exe程序
void StartProcesses() {
    LPCWSTR exePathL = L"SDSmartCardLock.exe";
    LPCWSTR exePathM = L"SDSmartCardMonitor.exe";

    if (!IsProcessRunning(exePathL)) {
        StartBackgroundProcessL();
    }
    if (!IsProcessRunning(exePathM)) {
        StartBackgroundProcessM();
    }
}

//总的调用，是否终止exe程序
void StopProcesses() {
    LPCWSTR exePathL = L"SDSmartCardLock.exe";
    LPCWSTR exePathM = L"SDSmartCardMonitor.exe";

    if (IsProcessRunning(exePathL)) {
        StopProcessByName(exePathL);
    }
    if (IsProcessRunning(exePathM)) {
        StopProcessByName(exePathM);
    }
}

//检测设备
BOOL DevDetect() {
    GUID classGuids[] = {
        GUID_DEVCLASS_CAMERA,
        GUID_DEVCLASS_IMAGE
    };

    for (int i = 0; i < 2; i++) {
        HDEVINFO hDevInfo = SetupDiGetClassDevs(&classGuids[i], NULL, NULL, DIGCF_PRESENT);
        if (hDevInfo != INVALID_HANDLE_VALUE) {
            SP_DEVINFO_DATA DeviceInfoData = { sizeof(SP_DEVINFO_DATA) };
            if (SetupDiEnumDeviceInfo(hDevInfo, 0, &DeviceInfoData)) {
                SetupDiDestroyDeviceInfoList(hDevInfo);
                return TRUE;
            }
            SetupDiDestroyDeviceInfoList(hDevInfo);
        }
    }
    return FALSE;
}

// 采集人脸数据
int GetFaceData(string username,string SubAccount,int &authType) {
    
    const char* uid;
    int revalue = -1;
    char buffer[BUFFER_SIZE];
    int uid_found = 0;
    int iRet = -1;
   
    bool timeoutTF = false;            //是否超时
    DWORD startTime = GetTickCount();  //获取当前时间
    const DWORD timeout = 60000;        //超时时间  
    MSG msg;

    bool localverifi = false;           //是否是本地验证
    int recode = IsFaceRegister(username, SubAccount, msg, authType);

    //服务器白名单，放行
    if (recode == 999) {
        LogMessage(L"White user,pass!");
        return recode;
    }
    if (recode < 0) {
        LogMessage(L"IsFaceRegister failed,can't verifi,please check Network");
    }

    LogMessage(L"Face collection begins");
    g_returnClicked = false;          
    ShowFingerprintPrompt(iRet, timeoutTF, revalue, false, false);       //展示指纹提取提示框
    while (iRet != 0 && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);           //获取窗口信息
        DispatchMessage(&msg);

        if (g_returnClicked)
        {
            HideFingerprintPrompt();
            LogMessage(L"Close camera");
            return revalue;
        }

        iRet = FaceDective();

        if (GetTickCount() - startTime > timeout) {
            timeoutTF = true;
            LogMessage(L"Get face data tinmeout!");
            HideFingerprintPrompt();
            ShowFingerprintPrompt(iRet, timeoutTF, revalue, false, false);
            Sleep(1000);
            HideFingerprintPrompt();
            return revalue;
        }
    }
    HideFingerprintPrompt();

    revalue = httpsPostWithImage(faceImage,username,SubAccount);

    //本地验证模式
    if (revalue == 3) {
        LogMessage(L"local_authentication");
        localverifi = true;
        //revalue = LocalAuthentication(faceImage, username);
    }

    ShowFingerprintPrompt(iRet, timeoutTF, revalue, localverifi, false);
    Sleep(1000);
    HideFingerprintPrompt();
    return revalue;
}

//判断人脸是否注册
int HttpsPostIsRegister(string username, string SubAccount, int &authType) {
    CURL* curl = curl_easy_init();
    int responseCode = -1;
    std::stringstream responseStream;

    if (!curl) {
        LogMessage(L"Failed to initialize CURL");
        return responseCode;
    }

    // 准备multipart/form-data
    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part;

    // 添加用户名字段
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "username");
    curl_mime_data(part, username.c_str(), CURL_ZERO_TERMINATED);

    // 添加子账号字段（新增）
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "sub_account");
    curl_mime_data(part, SubAccount.c_str(), CURL_ZERO_TERMINATED);

    // 设置CURL选项
    wstring urlW = GetRegistryValue(L"RequestRegisterURL");
    if (urlW.empty()) {
        LogMessage(L"404--Not found url");
        MessageBox(NULL, L"人脸注册服务器错误！", L"失败", MB_OK | MB_ICONERROR);
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return -1;
    }

    string url(urlW.begin(), urlW.end());
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseStream);

    // 保持原有设置
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

    // 4. 执行请求
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        // 处理响应数据 (保持原有逻辑)
        string response = responseStream.str();

        // 分割字符串 "1:0"
        size_t colonPos = response.find(':');
        if (colonPos != string::npos) {
            // 转换为整数
            responseCode = std::stoi(response.substr(0, colonPos));
            authType = std::stoi(response.substr(colonPos + 1));
        }
        else { responseCode = std::stoi(response); }
    }
    else {
        string errorMsg = "curl_easy_perform() failed: " + string(curl_easy_strerror(res));
        LogMessage(wstring(errorMsg.begin(), errorMsg.end()));
        responseCode = 3; //保持与原代码一致的错误码
    }

    //清理资源
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return responseCode;
}

int HttpsPostWithImageRegister(Mat& faceImage, string& username) {

    CURL* curl = curl_easy_init();
    int responseCode = -1;
    std::stringstream responseStream;

    if (!curl) {
        LogMessage(L"Failed to initialize CURL");
        return responseCode;
    }

    // 1. 将Mat图像编码为JPEG格式的内存缓冲区
    vector<uchar> imageBuffer;
    cv::imencode(".jpg", faceImage, imageBuffer, { cv::IMWRITE_JPEG_QUALITY, 85 });

    // 2. 准备multipart/form-data
    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part;

    // 添加用户名字段
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "username");
    curl_mime_data(part, username.c_str(), CURL_ZERO_TERMINATED);

    // 添加人脸图像字段
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "face_image");
    curl_mime_filename(part, "face.jpg");
    curl_mime_type(part, "image/jpeg");
    curl_mime_data(part, reinterpret_cast<const char*>(imageBuffer.data()), imageBuffer.size());

    // 3. 设置CURL选项
    wstring urlW = GetRegistryValue(L"RequestRegisterURL");
    if (urlW.empty()) {
        LogMessage(L"404--Not found url");
        MessageBox(NULL, L"人脸注册服务器错误！", L"失败", MB_OK | MB_ICONERROR);
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return -1;
    }

    string url(urlW.begin(), urlW.end());
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseStream);

    // 保持原有设置
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

    // 4. 执行请求
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        // 处理响应数据 (保持原有逻辑)
        string response = responseStream.str();
        responseCode = std::stoi(response);

        // 记录响应状态
        switch (responseCode) {
        case 0: LogMessage(L"0--Fcae data exits."); break;
        case 1: LogMessage(L"1--No face data found or no user."); break;
        case 101:LogMessage(L"101--Send first face success"); break;
        case 102:LogMessage(L"102--Send second face success"); break;
        case 103:LogMessage(L"103--Send third face success"); break;
        default: LogMessage(L"?--Unknown response111."); break;
        }
    }
    else {
        string errorMsg = "curl_easy_perform() failed: " + string(curl_easy_strerror(res));
        LogMessage(wstring(errorMsg.begin(), errorMsg.end()));
        responseCode = 3; // 保持与原代码一致的错误码
    }

    // 5. 清理资源
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return responseCode;
}

//https发送post数据--axq
int httpspost(string fingerstr, string username) {
    // 使用string的构造函数进行转换 
    //string fingerstr(reinterpret_cast<char*>(szFpData),dataSize);
    // 现在可以将转换后的string赋值给需要的变量
    username.append(":");
    username.append(fingerstr);
    int value = -1;
    
    CURL* curl = curl_easy_init();
    if (curl) {
        // 设置请求URL
        wstring urlW = GetRegistryValue(L"RequestURL");
        string url(urlW.begin(), urlW.end());

        // 如果注册表中没有 URL报错
        if (url.empty()) {
            LogMessage(L"404--Not found url");
            MessageBox(NULL, L"智能卡验证服务器错误！", L"失败", MB_OK | MB_ICONERROR);
            return value;
        }
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        // 设置请求方法为POST
        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        // 设置POST数据
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, username.c_str());

        // 设置回调函数，用于处理响应数据
        std::stringstream responseStream;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseStream);

        // 设置SSL验证
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // 设置超时时间
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);       // 整个请求超时时间为 10 秒
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L); // 连接超时时间为 5 秒

        // 执行请求
        CURLcode res = curl_easy_perform(curl);

        // 检查请求结果
        if (res != CURLE_OK) {
            string errorMessage = "curl_easy_perform() failed: " + string(curl_easy_strerror(res));
            wstring errorMessageW(errorMessage.begin(), errorMessage.end());
            //MessageBox(NULL, L"认证服务器超时！", L"error", MB_OK | MB_ICONERROR);
            LogMessage(errorMessageW);
            value = 3;
        }
        else {

            // 打印响应数据
            /*string resMessage = "Response:" + string(responseStream.str());
            wstring resMessageW(resMessage.begin(), resMessage.end());
            MessageBox(NULL, resMessageW.c_str(), L"response", MB_OK);*/

            //如果采用密码管理方式，根据服务器响应数据进行裁剪
            //string response = responseStream.str();
            //// 查找第一个分隔符的位置  
            //size_t delimiterPos = response.find(':');
            //// 处理分隔符位置是否存在  
            //if (delimiterPos != string::npos) { 
            //    string valueStr = response.substr(0, delimiterPos);
            //    value = std::stoi(valueStr);                      // 将字符串转换为整数
            //    password = response.substr(delimiterPos + 1);
            //    if (!password.empty()) {
            //        LogMessage(wstring(password.begin(), password.end()));
            //    }
            //}

            string response = responseStream.str();
            // 查找冒号的位置
            size_t delimiterPos = response.find(':');
            // 检查冒号是否存在
            if (delimiterPos != string::npos) {
                // 提取冒号前的部分并转换为整数
                string valueStr = response.substr(0, delimiterPos);
                value = std::stoi(valueStr);

                // 提取冒号后的部分
                string templateDataHex = response.substr(delimiterPos + 1);
                wstring templateData = StringToWide(templateDataHex);
                _SavetemplateDataToRegistry(templateData.c_str());
            }
            else {
                value = std::stoi(response);
            }
            // 使用switch语句判断响应数据
            switch (value) {
            case 0:
                LogMessage(L"0--UID identification successful!");
                //MessageBox(NULL, L"识别成功", L"成功", MB_OK);
                break;
            case 1:
                LogMessage(L"1--No UID found. No entry.");
                //MessageBox(NULL, L"没有找到指纹信息，没有录入", L"失败", MB_OK | MB_ICONERROR);
                break;
            case 2:
                LogMessage(L"2---Comparison failure.");
                //MessageBox(NULL, L"比对失败", L"失败", MB_OK | MB_ICONERROR);
                break;
            default:
                LogMessage(L"?--Unknown response.");
                //MessageBox(NULL, L"未知响应", L"未知", MB_OK | MB_ICONERROR);
                break;
            }
        }
        // 清理curl资源
        curl_easy_cleanup(curl);
    }
    return value;
}

int httpsPostWithImage(Mat& faceImage, string& username, string SubAccount) {

    CURL* curl = curl_easy_init();
    int responseCode = -1;
    std::stringstream responseStream;

    if (!curl) {
        LogMessage(L"Failed to initialize CURL");
        return responseCode;
    }

    // 1. 将Mat图像编码为JPEG格式的内存缓冲区
    vector<uchar> imageBuffer;
    cv::imencode(".jpg", faceImage, imageBuffer, { cv::IMWRITE_JPEG_QUALITY, 85 });

    // 2. 准备multipart/form-data
    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part;

    // 添加用户名字段
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "username");
    curl_mime_data(part, username.c_str(), CURL_ZERO_TERMINATED);

    // 添加子账号字段（新增）
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "sub_account");
    curl_mime_data(part, SubAccount.c_str(), CURL_ZERO_TERMINATED);

    // 添加人脸图像字段
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "face_image");
    curl_mime_filename(part, "face.jpg");
    curl_mime_type(part, "image/jpeg");
    curl_mime_data(part, reinterpret_cast<const char*>(imageBuffer.data()), imageBuffer.size());

    // 3. 设置CURL选项
    wstring urlW = GetRegistryValue(L"RequestURL");
    if (urlW.empty()) {
        LogMessage(L"404--Not found url");
        MessageBox(NULL, L"人脸识别验证服务器错误！", L"失败", MB_OK | MB_ICONERROR);
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return -1;
    }

    string url(urlW.begin(), urlW.end());
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseStream);

    // 保持原有设置
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

    // 4. 执行请求
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        // 处理响应数据 (保持原有逻辑)
        string response = responseStream.str();
        size_t delimiterPos = response.find(':');
        if (delimiterPos != string::npos) {
            string valueStr = response.substr(0, delimiterPos);
            responseCode = std::stoi(valueStr);
        }
        else {
            responseCode = std::stoi(response);
        }

        // 记录响应状态
        switch (responseCode) {
        case 0: LogMessage(L"0--UID identification successful!"); break;
        case 1: LogMessage(L"1--No UID found. No entry."); break;
        case 2: LogMessage(L"2---Comparison failure."); break;
        default: LogMessage(L"?--Unknown response."); break;
        }
    }
    else {
        string errorMsg = "curl_easy_perform() failed: " + string(curl_easy_strerror(res));
        LogMessage(wstring(errorMsg.begin(), errorMsg.end()));
        responseCode = 3; // 保持与原代码一致的错误码
    }

    // 5. 清理资源
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return responseCode;
}

//发送验证码函数
int SendVerificationCode(string username, string subAccount) {
    int value = -1;

    CURL* curl = curl_easy_init();
    if (curl) {
        // 准备multipart/form-data
        curl_mime* mime = curl_mime_init(curl);
        curl_mimepart* part;

        // 添加用户名字段
        part = curl_mime_addpart(mime);
        curl_mime_name(part, "username");
        curl_mime_data(part, username.c_str(), CURL_ZERO_TERMINATED);

        // 添加子账号字段
        part = curl_mime_addpart(mime);
        curl_mime_name(part, "sub_account");
        curl_mime_data(part, subAccount.c_str(), CURL_ZERO_TERMINATED);

        // 设置请求URL
        wstring urlW = GetRegistryValue(L"RequestVerificationCodeURL");
        string url(urlW.begin(), urlW.end());

        // 如果注册表中没有验证码URL报错
        if (url.empty()) {
            LogMessage(L"404--Not found verification code url");
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            return -1;
        }

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        // 设置回调函数，用于处理响应数据
        std::stringstream responseStream;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseStream);

        // 设置SSL验证
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // 设置超时时间
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);       // 整个请求超时时间为 10 秒
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L); // 连接超时时间为 5 秒

        // 执行请求
        CURLcode res = curl_easy_perform(curl);

        // 检查请求结果
        if (res != CURLE_OK) {
            string errorMessage = "curl_easy_perform() failed: " + string(curl_easy_strerror(res));
            wstring errorMessageW(errorMessage.begin(), errorMessage.end());
            LogMessage(errorMessageW);
            value = -1;
        }
        else {
            // 解析响应数据
            string response = responseStream.str();
            LogMessage(stringToWString(response));

            // 假设服务器返回简单的成功/失败标识
            if (response.find("success") != string::npos || response.find("0") != string::npos) {
                value = 0; // 成功
            }
            else {
                value = -1; // 失败
            }
        }

        // 清理资源
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
    }
    return value;
}

//验证验证码函数
int VerifyVerificationCode(string username, string subAccount, string verificationCode) {
    int value = -1;

    CURL* curl = curl_easy_init();
    if (curl) {
        // 准备multipart/form-data
        curl_mime* mime = curl_mime_init(curl);
        curl_mimepart* part;

        // 添加用户名字段
        part = curl_mime_addpart(mime);
        curl_mime_name(part, "username");
        curl_mime_data(part, username.c_str(), CURL_ZERO_TERMINATED);

        // 添加子账号字段
        part = curl_mime_addpart(mime);
        curl_mime_name(part, "sub_account");
        curl_mime_data(part, subAccount.c_str(), CURL_ZERO_TERMINATED);

        // 添加验证码字段
        part = curl_mime_addpart(mime);
        curl_mime_name(part, "verification_code");
        curl_mime_data(part, verificationCode.c_str(), CURL_ZERO_TERMINATED);

        // 设置请求URL
        wstring urlW = GetRegistryValue(L"RequestVerifyCodeURL");
        string url(urlW.begin(), urlW.end());

        // 如果注册表中没有验证码URL报错
        if (url.empty()) {
            LogMessage(L"404--Not found verify code url");
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            return -1;
        }

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        // 设置回调函数，用于处理响应数据
        std::stringstream responseStream;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseStream);

        // 设置SSL验证
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // 设置超时时间
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);       // 整个请求超时时间为 10 秒
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L); // 连接超时时间为 5 秒

        // 执行请求
        CURLcode res = curl_easy_perform(curl);

        // 检查请求结果
        if (res != CURLE_OK) {
            string errorMessage = "curl_easy_perform() failed: " + string(curl_easy_strerror(res));
            wstring errorMessageW(errorMessage.begin(), errorMessage.end());
            LogMessage(errorMessageW);
            value = -1;
        }
        else {
            // 解析响应数据
            string response = responseStream.str();
            LogMessage(stringToWString(response));

            // 假设服务器返回简单的成功/失败标识
            if (response.find("success") != string::npos || response.find("0") != string::npos) {
                value = 0; // 成功
            }
            else {
                value = -1; // 失败
            }
        }

        // 清理资源
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
    }
    return value;
}

//本地认证模式
int LocalAuthentication(string smartcard, string username) {
    _ReadSavedtemplateData();
    if (!_bHasSavedTemplateData) {
        LogMessage(L"get templatedate failed!");
    }
    PCWSTR pcwtemplateData = _bHasSavedTemplateData ? _wszSavedTemplateData : L"";
    string templateData = WCharToMByte(pcwtemplateData);

    /*
    int size_needed2 = MultiByteToWideChar(CP_UTF8, 0, templateData.c_str(), static_cast<int>(templateData.size()), NULL, 0);
    wchar_t* w_message2 = new wchar_t[size_needed2];
    MultiByteToWideChar(CP_UTF8, 0, templateData.c_str(), static_cast<int>(templateData.size()), w_message2, size_needed2);
    MessageBoxW(NULL, w_message2, L"模版指纹数据", MB_OK | MB_ICONINFORMATION);
    delete[] w_message2;

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, smartcard.c_str(), static_cast<int>(smartcard.size()), NULL, 0);
    wchar_t* w_message = new wchar_t[size_needed];
    MultiByteToWideChar(CP_UTF8, 0, smartcard.c_str(), static_cast<int>(smartcard.size()), w_message, size_needed);
    MessageBoxW(NULL, w_message, L"特征指纹数据", MB_OK | MB_ICONINFORMATION);
    delete[] w_message;
    */

    // 输出比对结果
    if (smartcard == templateData) {
        LogMessage(L"local--Fingerprint identification successful!");
        return 0;
    }
    else {
        LogMessage(L"local--Fingerprint identification failed!");
        return 2;               //比对失败
    }
}

//点击返回按钮  ---未启用
void HandleReturnButtonClick() {
    int iRet = -1;
    typedef int(__stdcall* FunctionPtr)(HANDLE);
    FunctionPtr func = (FunctionPtr)GetProcAddress(hDLL, "WM_CloseDevice");
    if (func == NULL) {
        LogMessage(L"error function");
        MessageBox(NULL, L"指纹驱动加载失败！", L"error2", MB_OK | MB_ICONERROR);
    }
    iRet = func(m_DevHandle);
}

//人脸检测
int FaceDective() {
    CascadeClassifier faceCascade, eyeCascade;
    if (!faceCascade.load("haarcascade_frontalface_default.xml") ||
        !eyeCascade.load("haarcascade_eye.xml"))
    {
        OutputDebugString(L"load model failed!");
        return -1;
    }
    DWORD dwCameraNum = 0;
    _ReadCameraNumFromRegistry(&dwCameraNum);
    VideoCapture cap(dwCameraNum, cv::CAP_DSHOW);
    if (!cap.isOpened())
    {
        OutputDebugString(L"failed open camera");
        return -1;
    }
    Mat frame;
    bool faceDetected = false;
    int framesWithoutFace = 0;
    const int maxFramesWithoutFace = 10;        // 连续多少帧未检测到人脸后重置
    const float minFrontalAspectRatio = 0.7;    // 最小正面宽高比
    const float maxFrontalAspectRatio = 1.3;    // 最大正面宽高比
    const int minFaceSize = 90;                // 最小人脸尺寸(像素)
    const float maxEyeAngleDeviation = 17.0;    // 最大眼睛角度偏差（度）
    MSG msg;

    DWORD startTime = GetTickCount();   //获取当前时间
    DWORD timeout = 60000;              //超时时间

    while (true && GetMessage(&msg, NULL, 0, 0))
    {   
        if (GetTickCount() - startTime > timeout) {
            LogMessage(L"Timeout: No face detected in 9 seconds!");
            cap.release();
            cv::destroyWindow("Face Detection");
            return -1;
        }

        TranslateMessage(&msg);           //获取窗口信息
        DispatchMessage(&msg);

        if (g_returnClicked)
        {
            LogMessage(L"Close camera");
            cap.release();
            cv::destroyWindow("Face Detection");
            return -1;
        }

        cap >> frame;
        if (frame.empty()) break;

        // 转换为灰度图像(人脸检测更快)
        Mat gray;
        cv::cvtColor(frame, gray, cv::COLOR_BGR2GRAY);
        cv::equalizeHist(gray, gray); // 增强对比度

        // 检测人脸
        vector<cv::Rect> faces;
        faceCascade.detectMultiScale(gray, faces, 1.1, 3, 0, cv::Size(minFaceSize, minFaceSize));

        // 在检测到的人脸周围画矩形
        for (const auto& face : faces)
        {
            if (GetTickCount() - startTime > timeout) {
                LogMessage(L"Timeout: No face detected in 9 seconds!");
                cap.release();
                cv::destroyWindow("Face Detection");
                return -1;
            }
            Mat cleanFaceImage = frame(face).clone();

            // 计算人脸中心位置(用于判断是否面向摄像头)
            cv::Point faceCenter(face.x + face.width / 2, face.y + face.height / 2);
            float aspectRatio = (float)face.width / face.height;

            // 检测眼睛（仅在人脸ROI内检测）
            Mat faceROI = gray(face);
            vector<cv::Rect> eyes;
            eyeCascade.detectMultiScale(faceROI, eyes, 1.1, 2, 0, cv::Size(30, 30));

            // 确保检测到两只眼睛
            bool hasTwoEyes = (eyes.size() >= 2);

            // 计算双眼连线的角度（判断是否水平）
            float eyeAngle = 0.0;
            if (hasTwoEyes)
            {
                cv::Point eye1(face.x + eyes[0].x + eyes[0].width / 2, face.y + eyes[0].y + eyes[0].height / 2);
                cv::Point eye2(face.x + eyes[1].x + eyes[1].width / 2, face.y + eyes[1].y + eyes[1].height / 2);
                eyeAngle = atan2(eye2.y - eye1.y, eye2.x - eye1.x) * (180.0 / CV_PI);
            }

            // 判断是否为正脸且双眼水平
            bool isFrontal = aspectRatio > minFrontalAspectRatio &&
                aspectRatio < maxFrontalAspectRatio&&
                abs(faceCenter.x - frame.cols / 2) < frame.cols / 4 &&  // 人脸位于画面中央
                hasTwoEyes &&
                abs(eyeAngle) < maxEyeAngleDeviation;  // 双眼水平

            //绘画出人脸框
            Scalar faceColor = isFrontal ? Scalar(0, 255, 0) : Scalar(0, 0, 255);
            rectangle(frame, face, faceColor, 2);

            if (isFrontal && !faceDetected)
            {

                // 当检测到正脸时，保存图像
                faceImage = cleanFaceImage;
                framesWithoutFace = 0;
                faceDetected = true;
                cap.release();
                cv::destroyWindow("Face Detection");
                return 0;
            }
        }
        if (faces.empty())
        {
            framesWithoutFace++;
            if (framesWithoutFace > maxFramesWithoutFace)
            {
                faceDetected = false;
            }
        }
        //展示摄像头预览，不过只能在注销时显示
        imshow("Face Detection", frame);
    }
    cap.release();
    cv::destroyWindow("Face Detection");
    return -1;
}

//人脸注册
int FaceRegister(string username) {
    LogMessage(L"FaceRegister");
    CascadeClassifier faceCascade, eyeCascade;
    if (!faceCascade.load("haarcascade_frontalface_default.xml") ||
        !eyeCascade.load("haarcascade_eye.xml"))
    {
        return -1;
    }
    DWORD dwCameraNum = 0;
    _ReadCameraNumFromRegistry(&dwCameraNum);
    VideoCapture cap(dwCameraNum, cv::CAP_DSHOW);
    if (!cap.isOpened())
    {
        return -1;
    }
    Mat frame;
    bool faceDetected = false;
    int framesWithoutFace = 0;
    int frameCount = 0;
    int maxFrameCount = 3;
    const int maxFramesWithoutFace = 10;        // 连续多少帧未检测到人脸后重置
    const float minFrontalAspectRatio = 0.8;    // 最小正面宽高比
    const float maxFrontalAspectRatio = 1.2;    // 最大正面宽高比
    const int minFaceSize = 150;                // 最小人脸尺寸(像素)
    const float maxEyeAngleDeviation = 15.0;    // 最大眼睛角度偏差（度）
    int iRet = -1;
    MSG msg;

    DWORD startTime = GetTickCount();   //获取当前时间
    DWORD timeout = 10000;              //超时时间

    while (true && GetMessage(&msg, NULL, 0, 0))
    {   

        if (GetTickCount() - startTime > timeout) {
            LogMessage(L"Timeout: No face detected in 9 seconds!");
            cap.release();
            cv::destroyWindow("Face Detection");
            return -1;
        }

        TranslateMessage(&msg);           //获取窗口信息
        DispatchMessage(&msg);

        if (g_returnClicked)
        {
            LogMessage(L"Close camera");
            cap.release();
            cv::destroyWindow("Face Detection");
            return -1;
        }

        cap >> frame;
        if (frame.empty()) break;

        // 转换为灰度图像(人脸检测更快)
        Mat gray;
        cv::cvtColor(frame, gray, cv::COLOR_BGR2GRAY);
        cv::equalizeHist(gray, gray); // 增强对比度

        // 检测人脸
        vector<cv::Rect> faces;
        faceCascade.detectMultiScale(gray, faces, 1.1, 3, 0, cv::Size(minFaceSize, minFaceSize));

        // 在检测到的人脸周围画矩形
        for (const auto& face : faces)
        {   
            if (GetTickCount() - startTime > timeout) {
                LogMessage(L"Timeout: No face detected in 9 seconds!");
                cap.release();
                cv::destroyWindow("Face Detection");
                return -1;
            }
            Mat cleanFaceImage = frame(face).clone();

            // 计算人脸中心位置(用于判断是否面向摄像头)
            cv::Point faceCenter(face.x + face.width / 2, face.y + face.height / 2);
            float aspectRatio = (float)face.width / face.height;

            // 检测眼睛（仅在人脸ROI内检测）
            Mat faceROI = gray(face);
            vector<cv::Rect> eyes;
            eyeCascade.detectMultiScale(faceROI, eyes, 1.1, 2, 0, cv::Size(30, 30));

            // 确保检测到两只眼睛
            bool hasTwoEyes = (eyes.size() >= 2);

            // 计算双眼连线的角度（判断是否水平）
            float eyeAngle = 0.0;
            if (hasTwoEyes)
            {
                cv::Point eye1(face.x + eyes[0].x + eyes[0].width / 2, face.y + eyes[0].y + eyes[0].height / 2);
                cv::Point eye2(face.x + eyes[1].x + eyes[1].width / 2, face.y + eyes[1].y + eyes[1].height / 2);
                eyeAngle = atan2(eye2.y - eye1.y, eye2.x - eye1.x) * (180.0 / CV_PI);
            }

            // 判断是否为正脸且双眼水平
            bool isFrontal = aspectRatio > minFrontalAspectRatio &&
                aspectRatio < maxFrontalAspectRatio&&
                abs(faceCenter.x - frame.cols / 2) < frame.cols / 4 &&  // 人脸位于画面中央
                hasTwoEyes &&
                abs(eyeAngle) < maxEyeAngleDeviation;  // 双眼水平

            Scalar faceColor = isFrontal ? Scalar(0, 255, 0) : Scalar(0, 0, 255);
            rectangle(frame, face, faceColor, 2);

            if (isFrontal && !faceDetected)
            {

                // 当检测到正脸时，保存图像
                cleanFaceImage;
                framesWithoutFace = 0;
                faceDetected = true;
                iRet = HttpsPostWithImageRegister(cleanFaceImage, username);  
                if (iRet == 0 || iRet == 103)
                {
                    cap.release();
                    cv::destroyWindow("Face Detection");
                    return 0;
                }
                if (iRet == 1) { 
                    cap.release();
                    cv::destroyWindow("Face Detection");
                    return -1;
                }
            }
        }
        if (faces.empty())
        {
            framesWithoutFace++;
            if (framesWithoutFace > maxFramesWithoutFace)
            {
                faceDetected = false;
            }
        }
        imshow("Face Detection", frame);
    }
    cap.release();
    cv::destroyWindow("Face Detection");
    return -1;
}

INT IsFaceRegister(string username, string SubAccount, MSG msg, int &authType) {
    int revalue = -1;
    int iRet = -1;
    g_returnClicked = false;
    revalue = HttpsPostIsRegister(username, SubAccount, authType);
    LogMessage(L"HttpPostIsRegister respose code:"+stringToWString(std::to_string(revalue)));
    //用户白名单，直接放行
    /*
    if (revalue == 999) { 
        return revalue; 
    }
    if (revalue == 0) {
        return 1;
    }
    if (revalue == 3) {
        return 3;
    }
    else {

        ShowFingerprintPrompt(iRet, false, revalue, false, true);       //展示指纹提取提示框
        while (revalue != 0 && GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);           //获取窗口信息
            DispatchMessage(&msg);

            if (g_returnClicked)
            {
                HideFingerprintPrompt();
                LogMessage(L"Close face register");
                return revalue;
            }
            LogMessage(L"Start face register");
            revalue = FaceRegister(username);

            if (revalue == 0) {
                HideFingerprintPrompt();
                iRet = 0;
                ShowFingerprintPrompt(iRet, false, revalue, false, true);
                Sleep(1000);
                HideFingerprintPrompt();
                return 1111;
            }
            else {
                revalue = 0;
            }
        }
        HideFingerprintPrompt();
    }
    LogMessage(L"Face register failed,return -1");
    */
    return revalue;
}

//窗口过程
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_COMMAND:
        if (LOWORD(wParam) == IDCANCEL) // 返回按钮的ID
        {
            //HandleReturnButtonClick();
            g_returnClicked = true;
            DestroyWindow(hwnd);
            _fingerprintPromptWindow = NULL;
        }
        break;
    case WM_DESTROY:
        _fingerprintPromptWindow = NULL;
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

//加载图标
HBITMAP LoadBitmapFromFile(const wchar_t* filePath)
{
    return (HBITMAP)LoadImage(NULL, filePath, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
}

// 创建提示文本的函数
HWND CreatePromptText(HWND hwndParent, int x, int y, int width, int height, const wchar_t* text)
{
    return CreateWindowEx(0, L"STATIC", text,
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        x, y, width, height, hwndParent, NULL, GetModuleHandle(NULL), NULL);
}

// 创建位图控件的函数
HWND CreateBitmapControl(HWND hwndParent, int x, int y, int width, int height, HBITMAP hBitmap)
{
    HWND hBitmapStatic = CreateWindowEx(0, L"STATIC", NULL,
        WS_CHILD | WS_VISIBLE | SS_BITMAP,
        x, y, width, height, hwndParent, NULL, GetModuleHandle(NULL), NULL);
    if (hBitmapStatic && hBitmap)
    {
        SendMessage(hBitmapStatic, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)hBitmap);
    }
    return hBitmapStatic;
}

//展示显示框
HRESULT ShowFingerprintPrompt(int iRet, bool timeoutTF, int result, bool localverifi, bool isFaceRegister)
{
    if (_fingerprintPromptWindow == NULL)
    {
        // 初始化通用控件
        INITCOMMONCONTROLSEX icex;
        icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
        icex.dwICC = ICC_STANDARD_CLASSES;
        InitCommonControlsEx(&icex);

        // 注册窗口类
        WNDCLASSEX wc = { 0 };
        wc.cbSize = sizeof(WNDCLASSEX);
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"FaceVerifiPromptClass";
        RegisterClassEx(&wc);

        // 获取屏幕尺寸
        int screenWidth = GetSystemMetrics(SM_CXSCREEN);
        int screenHeight = GetSystemMetrics(SM_CYSCREEN);

        // 设置窗口尺寸和位置
        int windowWidth = 330;
        int windowHeight = 280;
        int windowX = (screenWidth - windowWidth) / 2;
        int windowY = (screenHeight - windowHeight) / 2;

        // 创建窗口
        _fingerprintPromptWindow = CreateWindowEx(
            WS_EX_TOPMOST,
            L"FaceVerifiPromptClass",
            L"人脸识别验证",
            WS_POPUP | WS_BORDER | WS_CAPTION,
            windowX, windowY, windowWidth, windowHeight,
            NULL, NULL, GetModuleHandle(NULL), NULL
        );

        if (_fingerprintPromptWindow == NULL)
        {
            return E_FAIL;
        }

        // 计算居中的 X 坐标  
        int centerX = (windowWidth - 280) / 2; // 提示文本的宽度   
        HBITMAP hBitmap = nullptr;

        // 创建提示文本
        CreatePromptText(_fingerprintPromptWindow, centerX, 20, 280, 30, L"请面向摄像头...");

        //超时展示框
        if (timeoutTF) {
            hBitmap = LoadBitmapFromFile(L"C:\\Windows\\System32\\timeout.bmp"); // 请替换成实际文件路径  
            if (hBitmap != NULL)
            {
                CreateBitmapControl(_fingerprintPromptWindow, (windowWidth - 100) / 2, 70, 100, 100, hBitmap);
            }
            else {
                MessageBox(_fingerprintPromptWindow, L"无法加载位图!", L"错误", MB_OK | MB_ICONERROR);
            }

            // 创建返回按钮
            CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"人脸检测超时，请重试。");
        }

        //人脸数据获取框
        if (iRet != 0 && timeoutTF == false && !isFaceRegister) {
            hBitmap = LoadBitmapFromFile(L"C:\\Windows\\System32\\facedetect.bmp"); // 请替换成实际文件路径  
            if (hBitmap != NULL)
            {
                CreateBitmapControl(_fingerprintPromptWindow, (windowWidth - 100) / 2, 70, 100, 100, hBitmap);
            }
            else {
                MessageBox(_fingerprintPromptWindow, L"无法加载位图!", L"错误", MB_OK | MB_ICONERROR);
            }

            // 创建返回按钮
            _returnButton = CreateWindowEx(0, L"BUTTON", L"返回",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                (windowWidth - 80) / 2, windowHeight - 90, 80, 30, _fingerprintPromptWindow, (HMENU)IDCANCEL, GetModuleHandle(NULL), NULL);
        }

        //人脸模版注册获取框
        if (iRet != 0 && timeoutTF == false && isFaceRegister) {
            CreatePromptText(_fingerprintPromptWindow, centerX, 20, 280, 30, L"首次登录,请眨眼并轻微摇头以录入人脸");
            hBitmap = LoadBitmapFromFile(L"C:\\Windows\\System32\\faceregister.bmp"); // 请替换成实际文件路径  
            if (hBitmap != NULL)
            {
                CreateBitmapControl(_fingerprintPromptWindow, (windowWidth - 100) / 2, 70, 100, 100, hBitmap);
            }
            else {
                MessageBox(_fingerprintPromptWindow, L"无法加载位图!", L"错误", MB_OK | MB_ICONERROR);
            }

            // 创建返回按钮
            _returnButton = CreateWindowEx(0, L"BUTTON", L"返回",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                (windowWidth - 80) / 2, windowHeight - 90, 80, 30, _fingerprintPromptWindow, (HMENU)IDCANCEL, GetModuleHandle(NULL), NULL);
        }

        if (iRet == 0 && timeoutTF == false && isFaceRegister) {
                hBitmap = LoadBitmapFromFile(L"C:\\Windows\\System32\\successregister.bmp"); // 请替换成实际文件路径  
                if (hBitmap != NULL)
                {
                    CreateBitmapControl(_fingerprintPromptWindow, (windowWidth - 100) / 2, 70, 100, 100, hBitmap);
                }
                else {
                    MessageBox(_fingerprintPromptWindow, L"无法加载位图!", L"错误", MB_OK | MB_ICONERROR);
                }
                CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"人脸录入成功！");
        }

        //人脸数据获取成功，展示对比结果框
        if (iRet == 0 && timeoutTF == false && !isFaceRegister) {
            switch (result) {
            case 0: {
                hBitmap = LoadBitmapFromFile(L"C:\\Windows\\System32\\success.bmp"); // 请替换成实际文件路径  
                if (hBitmap != NULL)
                {
                    CreateBitmapControl(_fingerprintPromptWindow, (windowWidth - 100) / 2, 70, 100, 100, hBitmap);
                }
                else {
                    MessageBox(_fingerprintPromptWindow, L"无法加载位图!", L"错误", MB_OK | MB_ICONERROR);
                }
                if (localverifi) {
                    CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"本地人脸验证通过！");
                }
                else {
                    CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"人脸验证通过！");
                }
                break;
            }
            case 1: {
                hBitmap = LoadBitmapFromFile(L"C:\\Windows\\System32\\noFPdata.bmp"); // 请替换成实际文件路径  
                if (hBitmap != NULL)
                {
                    CreateBitmapControl(_fingerprintPromptWindow, (windowWidth - 100) / 2, 70, 100, 100, hBitmap);
                }
                else {
                    MessageBox(_fingerprintPromptWindow, L"无法加载位图!", L"错误", MB_OK | MB_ICONERROR);
                }
                CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"未找到相应用户信息！");
                break;
            }
            case 2: {
                hBitmap = LoadBitmapFromFile(L"C:\\Windows\\System32\\failed.bmp"); // 请替换成实际文件路径  
                if (hBitmap != NULL)
                {
                    CreateBitmapControl(_fingerprintPromptWindow, (windowWidth - 100) / 2, 70, 100, 100, hBitmap);
                }
                else {
                    MessageBox(_fingerprintPromptWindow, L"无法加载位图!", L"错误", MB_OK | MB_ICONERROR);
                }
                if (localverifi) {
                    CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"本地人脸识别不通过！");
                }
                else {
                    CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"人脸识别不通过！");
                }
                break;
            }
            default: {
                hBitmap = LoadBitmapFromFile(L"C:\\Windows\\System32\\unknowerror.bmp"); // 请替换成实际文件路径  
                if (hBitmap != NULL)
                {
                    CreateBitmapControl(_fingerprintPromptWindow, (windowWidth - 100) / 2, 70, 100, 100, hBitmap);
                }
                else {
                    MessageBox(_fingerprintPromptWindow, L"无法加载位图!", L"错误", MB_OK | MB_ICONERROR);
                }
                CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"未知错误，请检测网络！");
                break;
            }
            }
        }
        // 显示窗口
        ShowWindow(_fingerprintPromptWindow, SW_SHOW);
        UpdateWindow(_fingerprintPromptWindow);
    }
    return S_OK;
}

//隐藏等待框
HRESULT HideFingerprintPrompt()
{
    if (_fingerprintPromptWindow != NULL)
    {
        DestroyWindow(_fingerprintPromptWindow);
        _fingerprintPromptWindow = NULL;
    }

    return S_OK;
}

// 保存用户名到注册表
HRESULT CSampleCredential::_SaveUsernameToRegistry(__in PCWSTR wszKeyName, __in PCWSTR wszUsername)
{
    HKEY hKey;
    LSTATUS status;

    // 1. 打开或创建注册表项
    status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,                    // 根键
        L"SOFTWARE\\Softdomain\\LoginWhitelist", // 子键路径
        0,                                      // 保留参数
        NULL,                                   // 类名（无需指定）
        REG_OPTION_NON_VOLATILE,                // 非临时键
        KEY_WRITE | KEY_QUERY_VALUE,            // 权限：写入 + 查询
        NULL,                                   // 安全属性（默认）
        &hKey,                                  // 接收打开的键句柄
        NULL                                    // 是否新建（无需返回）
    );

    if (status != ERROR_SUCCESS)
    {
        // 获取错误代码
        DWORD dwErr = GetLastError();
        return HRESULT_FROM_WIN32(dwErr);
    }

    // 2. 写入用户名值
    status = RegSetValueExW(
        hKey,                                   // 键句柄
        wszKeyName,                        // 键名
        0,                                      // 保留参数
        REG_SZ,                                 // 数据类型：字符串
        (const BYTE*)wszUsername,               // 数据指针
        (wcslen(wszUsername) + 1) * sizeof(WCHAR) // 数据长度（含终止符）
    );

    RegCloseKey(hKey); // 关闭键句柄

    if (status != ERROR_SUCCESS)
    {
        DWORD dwErr = GetLastError();
        return HRESULT_FROM_WIN32(dwErr);
    }

    return S_OK;
}

// 保存远程用户名到注册表
HRESULT CSampleCredential::_SaveRemoteUsernameToRegistry(__in PCWSTR wszUsername)
{
    HKEY hKey;
    LSTATUS status;

    // 1. 打开或创建注册表项
    status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,                    // 根键
        L"SOFTWARE\\Softdomain\\LoginWhitelist", // 子键路径
        0,                                      // 保留参数
        NULL,                                   // 类名（无需指定）
        REG_OPTION_NON_VOLATILE,                // 非临时键
        KEY_WRITE | KEY_QUERY_VALUE,            // 权限：写入 + 查询
        NULL,                                   // 安全属性（默认）
        &hKey,                                  // 接收打开的键句柄
        NULL                                    // 是否新建（无需返回）
    );

    if (status != ERROR_SUCCESS)
    {
        // 获取错误代码
        DWORD dwErr = GetLastError();
        return HRESULT_FROM_WIN32(dwErr);
    }

    // 2. 写入用户名值
    status = RegSetValueExW(
        hKey,                                   // 键句柄
        L"LastRemoteUsername",                  // 键名
        0,                                      // 保留参数
        REG_SZ,                                 // 数据类型：字符串
        (const BYTE*)wszUsername,               // 数据指针
        (wcslen(wszUsername) + 1) * sizeof(WCHAR) // 数据长度（含终止符）
    );

    RegCloseKey(hKey); // 关闭键句柄

    if (status != ERROR_SUCCESS)
    {
        DWORD dwErr = GetLastError();
        return HRESULT_FROM_WIN32(dwErr);
    }

    return S_OK;
}

// 保存模版数据到注册表
HRESULT _SavetemplateDataToRegistry(__in PCWSTR templateData)
{
    HKEY hKey;
    LSTATUS status;

    // 1. 打开或创建注册表项
    status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,                    // 根键
        L"SOFTWARE\\Softdomain\\LoginWhitelist", // 子键路径
        0,                                      // 保留参数
        NULL,                                   // 类名（无需指定）
        REG_OPTION_NON_VOLATILE,                // 非临时键
        KEY_WRITE | KEY_QUERY_VALUE,            // 权限：写入 + 查询
        NULL,                                   // 安全属性（默认）
        &hKey,                                  // 接收打开的键句柄
        NULL                                    // 是否新建（无需返回）
    );

    if (status != ERROR_SUCCESS)
    {
        // 获取错误代码
        DWORD dwErr = GetLastError();
        return HRESULT_FROM_WIN32(dwErr);
    }

    // 2. 写入用户名值
    status = RegSetValueExW(
        hKey,                                   // 键句柄
        L"LastTemplateData",                        // 键名
        0,                                      // 保留参数
        REG_SZ,                                 // 数据类型：字符串
        (const BYTE*)templateData,               // 数据指针
        (wcslen(templateData) + 1) * sizeof(WCHAR) // 数据长度（含终止符）
    );

    RegCloseKey(hKey); // 关闭键句柄

    if (status != ERROR_SUCCESS)
    {
        DWORD dwErr = GetLastError();
        return HRESULT_FROM_WIN32(dwErr);
    }

    return S_OK;
}

// 保存更改密码标签到注册表（使用 REG_DWORD 存储 1 或 0）
HRESULT CSampleCredential::_SaveChangePasswordToRegistry(__in BOOL isChangePassword)
{
    HKEY hKey;
    LSTATUS status;

    // 1. 打开或创建注册表项
    status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,                    // 根键
        L"SOFTWARE\\Softdomain\\LoginWhitelist", // 子键路径
        0,                                      // 保留参数
        NULL,                                   // 类名（无需指定）
        REG_OPTION_NON_VOLATILE,                // 非临时键
        KEY_WRITE | KEY_QUERY_VALUE,            // 权限：写入 + 查询
        NULL,                                   // 安全属性（默认）
        &hKey,                                  // 接收打开的键句柄
        NULL                                    // 是否新建（无需返回）
    );

    if (status != ERROR_SUCCESS)
    {
        DWORD dwErr = GetLastError();
        return HRESULT_FROM_WIN32(dwErr);
    }

    // 2. 写入 DWORD 值（1 或 0）
    DWORD dwValue = isChangePassword ? 1 : 0;  // 转换为 DWORD
    status = RegSetValueExW(
        hKey,                                   // 键句柄
        L"ChangePassword",                       // 键名
        0,                                      // 保留参数
        REG_DWORD,                              // 数据类型：DWORD（数字）
        (const BYTE*)&dwValue,                  // 数据指针（取地址）
        sizeof(DWORD)                           // 数据长度（固定 4 字节）
    );

    RegCloseKey(hKey); // 关闭键句柄

    if (status != ERROR_SUCCESS)
    {
        DWORD dwErr = GetLastError();
        return HRESULT_FROM_WIN32(dwErr);
    }

    return S_OK;
}

// 读取注册表中的模版数据
HRESULT _ReadSavedtemplateData()
{
    HKEY hKey;
    DWORD dwType = REG_SZ;
    WCHAR wszTemplateData[2048] = { 0 };
    DWORD cbData = sizeof(wszTemplateData);

    LSTATUS status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Softdomain\\LoginWhitelist",
        0,
        KEY_READ,
        &hKey
    );

    if (status == ERROR_SUCCESS)
    {
        status = RegQueryValueExW(
            hKey,
            L"LastTemplateData",
            NULL,
            &dwType,
            (LPBYTE)wszTemplateData,
            &cbData
        );
        RegCloseKey(hKey);

        if (status == ERROR_SUCCESS)
        {
            StringCchCopyW(_wszSavedTemplateData, ARRAYSIZE(_wszSavedTemplateData), wszTemplateData);
            _bHasSavedTemplateData = true;
            return S_OK;
        }
    }
    _bHasSavedTemplateData = false;
    return S_FALSE;
}

// 从注册表读取 “是否记录日志” 标志（返回 BOOL）
BOOL _ReadLogMessageFromRegistry()
{
    HKEY hKey;
    LSTATUS status;
    DWORD dwValue = 0;
    DWORD dwSize = sizeof(DWORD);

    // 1. 打开注册表项
    status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Softdomain\\LoginWhitelist",
        0,
        KEY_READ,
        &hKey
    );

    if (status != ERROR_SUCCESS)
    {
        return FALSE; // 默认返回 FALSE
    }

    // 2. 读取 DWORD 值
    status = RegQueryValueExW(
        hKey,
        L"LogRecording",
        NULL,
        NULL,
        (LPBYTE)&dwValue,
        &dwSize
    );

    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS)
    {
        return FALSE; 
    }
    return (dwValue == 1); // 返回 TRUE 仅当值为 1
}

// 读取注册表中的相机的DWORD值
HRESULT _ReadCameraNumFromRegistry(DWORD* pOutValue)
{
    if (pOutValue == nullptr) {
        return E_INVALIDARG; // 检查无效指针
    }

    HKEY hKey;
    DWORD dwValue = 0;
    DWORD cbData = sizeof(DWORD);

    // 打开注册表键
    LSTATUS status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Softdomain\\LoginWhitelist",
        0,
        KEY_READ,
        &hKey
    );

    if (status == ERROR_SUCCESS)
    {
        // 查询DWORD值
        status = RegQueryValueExW(
            hKey,
            L"CameraNum", // 替换为实际的DWORD值名称
            NULL,
            NULL,
            (LPBYTE)&dwValue,
            &cbData
        );
        RegCloseKey(hKey);

        if (status == ERROR_SUCCESS)
        {
            *pOutValue = dwValue; // 通过指针参数返回结果
            return S_OK;
        }
    }

    // 失败时设置默认值（可选）
    *pOutValue = 0;
    return HRESULT_FROM_WIN32(status); // 返回错误码
}

// 加密函数
HRESULT EncryptPassword(PWSTR pPlainText, PBYTE* ppEncryptedData, DWORD* pcbEncryptedData)
{
    DATA_BLOB DataIn = { 0 };
    DATA_BLOB DataOut = { 0 };

    DataIn.cbData = (wcslen(pPlainText) + 1) * sizeof(WCHAR);
    DataIn.pbData = (BYTE*)pPlainText;

    if (!CryptProtectData(&DataIn, L"Password", NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &DataOut))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    *ppEncryptedData = DataOut.pbData;
    *pcbEncryptedData = DataOut.cbData;

    return S_OK;
}

// 解密函数
HRESULT DecryptPassword(PBYTE pEncryptedData, DWORD cbEncryptedData, PWSTR* ppPlainText)
{
    DATA_BLOB DataIn = { 0 };
    DATA_BLOB DataOut = { 0 };

    DataIn.pbData = pEncryptedData;
    DataIn.cbData = cbEncryptedData;

    if (!CryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &DataOut))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    *ppPlainText = (PWSTR)DataOut.pbData;

    return S_OK;
}

// 从注册表读取密码并解密
HRESULT ReadPasswordFromRegistry(PWSTR* ppPassword)
{
    HKEY hKey;
    HRESULT hr = E_FAIL;
    DWORD dwType = 0;
    DWORD cbData = 0;
    PBYTE pData = NULL;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Softdomain\\LoginWhitelist", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        if (RegQueryValueExW(hKey, L"UIDPW", NULL, &dwType, NULL, &cbData) == ERROR_SUCCESS)
        {
            pData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbData);
            if (pData)
            {
                if (RegQueryValueExW(hKey, L"UIDPW", NULL, &dwType, pData, &cbData) == ERROR_SUCCESS)
                {
                    hr = DecryptPassword(pData, cbData, ppPassword);
                }
                HeapFree(GetProcessHeap(), 0, pData);
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
        RegCloseKey(hKey);
    }

    return hr;
}
