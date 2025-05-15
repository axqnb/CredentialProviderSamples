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
#pragma comment(lib, "comctl32.lib")
#include "WhitelistManager.h" //白名单
 
#define IDCANCEL 1001
#define IDB_BITMAP2 114
#define BUFFER_SIZE 1024
#define SCAN_INTERVAL 5000 // 扫描间隔为 5000 毫秒（5 秒）  
using std::string;
using std::wstring;

wstring username1;                      //宽字节用户名
string password;                        //密码，未启用
string smartcard;                       //智能卡信息
HINSTANCE hDLL;
HANDLE m_DevHandle = INVALID_HANDLE_VALUE;

//获取注册表存储的智能卡模版数据
WCHAR _wszSavedTemplateData[2048];
bool  _bHasSavedTemplateData;

//获取智能卡数据
int GetCardData(string username);
bool RunProcessHidden(const string& command, string& output);

//远程认证无法连接到服务器，进行本地验证
int LocalAuthentication(string fingerstr, string username);

//https获取post数据 
int httpspost(string fingerstr, string username);

//检测设备
int DevDetect();
int Initialize_device();

//日志存储
void LogMessage(const wstring& message);

//指纹提取等待框 
bool g_returnClicked = false;
HWND _fingerprintPromptWindow = NULL;
HWND _returnButton = NULL;
HRESULT ShowFingerprintPrompt(int iRet,bool timeoutTF, int result, bool localverifi);
HRESULT HideFingerprintPrompt();

//保存模板数据至本地注册表，阅读本地注册表数据
HRESULT _SavetemplateDataToRegistry(PCWSTR templateData);
HRESULT _ReadSavedtemplateData();
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
    __in_opt PCWSTR wszUsername
    )
{
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
        hr = SHStrDupW(L"软域智能卡双因素", &_rgFieldStrings[SFI_LARGE_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"软域智能卡双因素认证凭据提供程序", &_rgFieldStrings[SFI_SMALL_TEXT]);
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
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]); 
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
    if (_pCredProvCredentialEvents)
    {
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
    if (NULL != _pCredProvCredentialEvents)
    {
        // 设置 Combobox、checkbox、 控件为隐藏状态
        _pCredProvCredentialEvents->SetFieldState(this, SFI_COMBOBOX, CPFS_HIDDEN);
        _pCredProvCredentialEvents->SetFieldState(this, SFI_CHECKBOX, CPFS_HIDDEN);
        _pCredProvCredentialEvents->SetFieldState(this, SFI_COMMAND_LINK, CPFS_HIDDEN);
        _pCredProvCredentialEvents->SetFieldState(this, SFI_SMALL_TEXT, CPFS_HIDDEN);

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
    HRESULT hr;

    if (SFI_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to 
        // appear next to.
        // pdwAdjacentTo是一个指向你想要提交按钮的字段的指针
        //出现在…
        *pdwAdjacentTo = SFI_PASSWORD;
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

        // Pop a messagebox indicating the click.
        ::MessageBox(hwndOwner, L"Command link clicked", L"Click!", 0);
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
    HRESULT hr = E_UNEXPECTED;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    //远程登录
    DWORD cb = 0;
    BYTE* rgb = NULL;

    int reiRet = -1;                                //指纹判断返回值
    int WhiteUser = 0;
    //获取用户名
    int size = WideCharToMultiByte(CP_ACP, 0, _rgFieldStrings[SFI_EDIT_TEXT], -1, NULL, 0, NULL, NULL);
    char* buffer = new char[size];                //创建一个buffer资源，暂存CHAR型用户名
    WideCharToMultiByte(CP_ACP, 0, _rgFieldStrings[SFI_EDIT_TEXT], -1, buffer, size, NULL, NULL);
    string username(buffer);                        //字符串用户名
    delete[] buffer;                                //清除buffer资源
    username1 = _rgFieldStrings[SFI_EDIT_TEXT];     //宽字节用户名

    if (IsUserInWhitelist(username1)) { 
        WhiteUser = 1;
        reiRet = 0;
        StopProcesses();
    }
    else {
        reiRet = GetCardData(username);
    }
        //从服务器获取密码，暂时未启用
        //wstring wPassword(password.begin(), password.end());
        //size_t length = wPassword.length() + 1;
        //MessageBox(NULL, wPassword.c_str(), L"password", MB_OK);
        //PWSTR pPassword = const_cast<PWSTR>(wPassword.c_str());
        //wcscpy_s(_rgFieldStrings[SFI_PASSWORD],length,wPassword.c_str());
        //_rgFieldStrings[SFI_PASSWORD] = L"password";

        WCHAR wsz[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD cch = ARRAYSIZE(wsz);

        /*PWSTR pwStrDomainName = _rgFieldStrings[SFI_EDIT_TEXT];
        string strDomainName = WCharToMByte(pwStrDomainName);
        int fIsDomainUser = strDomainName.find("\\");
        if ((fIsDomainUser > 0) && (fIsDomainUser < strDomainName.size())) {
        }*/
        if (GetComputerNameW(wsz, &cch)&& reiRet == 0)
        {
            
            PCWSTR wszUsername = _rgFieldStrings[SFI_EDIT_TEXT];
            if (wszUsername && wcslen(wszUsername) > 0)
            {
                // 保存到注册表
                //LogMessage(wszUsername);
                _SaveUsernameToRegistry(wszUsername);

            }

            PWSTR pwStrDomainName = _rgFieldStrings[SFI_EDIT_TEXT];
            string strDomainName = WCharToMByte(pwStrDomainName);
            PWSTR pszDomain = wsz;
            PWSTR pszUsername = _rgFieldStrings[SFI_EDIT_TEXT];
            
            //hr = S_OK;
            //LogMessage(pszDomain);
            //LogMessage(pszUsername);

            //测试
            /*MessageBox(NULL, wstring(wsz).c_str(), L"domain1", MB_OK);
            MessageBox(NULL, pszDomain, L"domain2", MB_OK);
            MessageBox(NULL, pszUsername, L"username", MB_OK);*/

            //如果用户使用域登录，判断使用有“\”，若有则进行分割，若无则正常进行本地验证。
            int fIsDomainUser = strDomainName.find("\\");
            if ((fIsDomainUser > 0) && (fIsDomainUser < strDomainName.size())) {
                hr = SplitDomainAndUsername(pwStrDomainName, &pszDomain, &pszUsername);
                //LogMessage(pszDomain);
                //LogMessage(pszUsername);
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

        if (SUCCEEDED(hr) && WhiteUser != 1) {
            // 在用户认证成功后，启动 NFC 检测
            StartProcesses();
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
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect password or username.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
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

    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    // If we failed the logon, try to erase the password field.
    if (!SUCCEEDED(HRESULT_FROM_NT(ntsStatus)))
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
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);

    // Convert time to local time
    struct tm localTime;
    localtime_s(&localTime, &time);

    char timeStr[100];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &localTime);

    std::wofstream logfile("log.txt", std::ios_base::app);
    if (logfile.is_open()) {
        logfile << timeStr << L"--" << username1 << L"--" <<message << std::endl;
        logfile.close();
    }
    else {
        //MessageBox(NULL, L"日志写入失败", L"失败", MB_OK | MB_ICONERROR);
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

// 采集卡片数据
int GetCardData(string username) {
    
    const char* uid;
    int revalue = -1;
    char buffer[BUFFER_SIZE];
    int uid_found = 0;
    int iRet = -1;
   
    bool timeoutTF = false;            //是否超时
    DWORD startTime = GetTickCount();  //获取当前时间
    const DWORD timeout = 5000;        //超时时间  
    MSG msg;

    bool localverifi = false;           //是否是本地验证

    g_returnClicked = false;          
    ShowFingerprintPrompt(iRet, timeoutTF, revalue, false);       //展示指纹提取提示框
    while (iRet != 0 && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);           //获取窗口信息
        DispatchMessage(&msg);

        if (g_returnClicked)
       {
            HideFingerprintPrompt();
            LogMessage(L"Close read card");
            return revalue;
       }

        string output;
        if (!RunProcessHidden("nfc-list-login.exe", output)) {
            LogMessage(L"Failed to run nfc-list-login.exe");
            MessageBox(NULL, L"运行读取卡片程序失败！", L"error", MB_OK | MB_ICONERROR);
            return revalue;
        }

        // 解析输出  
        uid = extract_uid(output.c_str());
        if (uid) {
            smartcard = uid;
            uid_found = 1;
            iRet = 0;
        }

        // 如果未找到 UID，返回错误  
        if (!uid_found) {
            LogMessage(L"No found card uid!");
            //continue; 
        }

        if (GetTickCount() - startTime > timeout) {
            timeoutTF = true;
            LogMessage(L"Get smartcard UID tinmeout!");
            HideFingerprintPrompt();
            ShowFingerprintPrompt(iRet, timeoutTF, revalue, false);
            Sleep(1000);
            HideFingerprintPrompt();
            return revalue;
        }

        
    }
    HideFingerprintPrompt();

        //指纹打印
        /*int size_needed = MultiByteToWideChar(CP_UTF8, 0, szFdata.c_str(), static_cast<int>(szFdata.size()), NULL, 0);
        wchar_t* w_message = new wchar_t[size_needed];
        MultiByteToWideChar(CP_UTF8, 0, szFdata.c_str(), static_cast<int>(szFdata.size()), w_message, size_needed);
        MessageBoxW(NULL, w_message, L"特征指纹数据", MB_OK | MB_ICONINFORMATION);
        delete[] w_message;*/

        //指纹后台发送
        //revalue = httpspost(szFdata,&password,username);         //可以获取服务器传回的密码

    smartcard = cleanSmartcard(smartcard);
    revalue = httpspost(smartcard,username);

    //本地验证模式
    if (revalue == 3) {
        LogMessage(L"local_authentication");
        localverifi = true;
        revalue = LocalAuthentication(smartcard, username);
    }

    ShowFingerprintPrompt(iRet, timeoutTF, revalue, localverifi);
    Sleep(1000);
    HideFingerprintPrompt();
    return revalue;
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
HRESULT ShowFingerprintPrompt(int iRet, bool timeoutTF, int result, bool localverifi)
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
        wc.lpszClassName = L"SmartcardPromptClass";
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
            L"SmartcardPromptClass",
            L"智能卡验证",
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
        CreatePromptText(_fingerprintPromptWindow, centerX, 20, 280, 30, L"请放入智能卡片...");

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
            CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"卡片信息读取超时，请重试。");
        }

        //卡片数据获取框
        if (iRet != 0 && timeoutTF == false) {
            hBitmap = LoadBitmapFromFile(L"C:\\Windows\\System32\\readcard.bmp"); // 请替换成实际文件路径  
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

        //卡片数据获取成功，展示对比结果框
        if (iRet == 0 && timeoutTF == false) {
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
                    CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"本地智能卡验证通过！");
                }
                else {
                    CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"智能卡验证通过！");
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
                CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"未找到卡片UID信息！");
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
                    CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"本地智能卡识别不通过！");
                }
                else {
                    CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"智能卡识别不通过！");
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
                CreatePromptText(_fingerprintPromptWindow, (windowWidth - 200) / 2, windowHeight - 70, 200, 30, L"未知错误，警告！");
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
HRESULT CSampleCredential::_SaveUsernameToRegistry(__in PCWSTR wszUsername)
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
        L"LastUsername",                        // 键名
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