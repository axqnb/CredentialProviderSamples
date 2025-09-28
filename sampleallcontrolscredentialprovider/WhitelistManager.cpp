#include <windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <sddl.h>
#include "resource.h"  // 确保这个头文件包含了 WHITELIST_KEY 的定义
#include "WhitelistManager.h"

// 定义您的自定义凭据提供程序的CLSID
const std::wstring YOUR_CREDENTIAL_PROVIDER_CLSID = L"{FF032558-38DA-4472-B969-31A636B7E5C7}";

//使用分隔符分割字符串的辅助函数
std::vector<std::wstring> SplitString(const std::wstring& str, wchar_t delimiter)
{
    std::vector<std::wstring> tokens;
    std::wstringstream ss(str);
    std::wstring token;
    while (std::getline(ss, token, delimiter))
    {
        tokens.push_back(token);
    }
    return tokens;
}

//使用分隔符将字符串向量连接为单个字符串的辅助函数
std::wstring JoinStrings(const std::vector<std::wstring>& tokens, wchar_t delimiter)
{
    std::wstring result;
    for (size_t i = 0; i < tokens.size(); ++i)
    {
        if (i != 0)
        {
            result += delimiter;
        }
        result += tokens[i];
    }
    return result;
}

// 检查用户是否在本地白名单中
bool IsUserInWhitelist(const std::wstring& username)
{
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, WHITELIST_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        return false; // 如果键不存在，返回false
    }

    DWORD type;
    wchar_t data[1024];
    DWORD dataSize = sizeof(data);

    // 查询白名单字符串
    LONG result = RegQueryValueEx(hKey, L"Users", NULL, &type, (LPBYTE)data, &dataSize);
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS && type == REG_SZ)
    {
        std::vector<std::wstring> users = SplitString(data, L',');
        return std::find(users.begin(), users.end(), username) != users.end();
    }

    return false;
}

// 将用户添加到白名单
bool AddUserToWhitelist(const std::wstring& username)
{
    HKEY hKey;
    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, WHITELIST_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, NULL, &hKey, NULL) != ERROR_SUCCESS)
    {
        return false; // 如果无法创建或打开键，返回false
    }

    wchar_t data[1024];
    DWORD dataSize = sizeof(data);
    DWORD type;

    // 查询现有的白名单字符串
    LONG result = RegQueryValueEx(hKey, L"Users", NULL, &type, (LPBYTE)data, &dataSize);
    std::vector<std::wstring> users;
    if (result == ERROR_SUCCESS && type == REG_SZ)
    {
        users = SplitString(data, L',');
    }

    // 添加新用户
    if (std::find(users.begin(), users.end(), username) == users.end())
    {
        users.push_back(username);
        std::wstring newData = JoinStrings(users, L',');
        result = RegSetValueEx(hKey, L"Users", 0, REG_SZ, (const BYTE*)newData.c_str(), (newData.size() + 1) * sizeof(wchar_t));
    }

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

// 从白名单中移除用户
bool RemoveUserFromWhitelist(const std::wstring& username)
{
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, WHITELIST_KEY, 0, KEY_WRITE | KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        return false; // 如果无法打开键，返回false
    }

    wchar_t data[1024];
    DWORD dataSize = sizeof(data);
    DWORD type;

    // 查询现有的白名单字符串
    LONG result = RegQueryValueEx(hKey, L"Users", NULL, &type, (LPBYTE)data, &dataSize);
    std::vector<std::wstring> users;
    if (result == ERROR_SUCCESS && type == REG_SZ)
    {
        users = SplitString(data, L',');
    }

    // 移除用户
    auto it = std::find(users.begin(), users.end(), username);
    if (it != users.end())
    {
        users.erase(it);
        std::wstring newData = JoinStrings(users, L',');
        result = RegSetValueEx(hKey, L"Users", 0, REG_SZ, (const BYTE*)newData.c_str(), (newData.size() + 1) * sizeof(wchar_t));
    }

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

// 设置注册表值(url)
bool SetRegistryValue(const std::wstring& valueName, const std::wstring& data)
{
    HKEY hKey;
    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, WHITELIST_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
    {
        return false;
    }

    LONG result = RegSetValueEx(hKey, valueName.c_str(), 0, REG_SZ, (const BYTE*)data.c_str(), (data.size() + 1) * sizeof(wchar_t));
    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

// 获取注册表值(通用函数)
std::wstring GetRegistryValue(const std::wstring& valueName)
{
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, WHITELIST_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        return L"";
    }

    wchar_t data[1024];
    DWORD dataSize = sizeof(data);
    DWORD type;

    LONG result = RegQueryValueEx(hKey, valueName.c_str(), NULL, &type, (LPBYTE)data, &dataSize);
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS && type == REG_SZ)
    {
        return std::wstring(data);
    }

    return L"";
}

// 设置请求URL
bool SetRequestURL(const std::wstring& url)
{
    return SetRegistryValue(L"RequestURL", url);
}

//设置注册表值（设置所有用户只能使用自定义凭据）
bool SetRegistry(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& data)
{
    HKEY hKey;
    LONG result = RegCreateKeyEx(hKeyRoot, subKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS)
    {
        return false;
    }

    result = RegSetValueEx(hKey, valueName.c_str(), 0, REG_SZ, (BYTE*)data.c_str(), (data.size() + 1) * sizeof(wchar_t));
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS){
    
        return false;
    }

    return true;
}

//修改自定义凭据，写入（设置所有用户只能使用自定义凭据）
bool ConfigureCredentialProviders()
{
    // 设置默认凭据提供程序
    if (!SetRegistry(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers",
        L"DefaultCredentialProvider",
        YOUR_CREDENTIAL_PROVIDER_CLSID))
    {
        return false;
    }

    // 排除其他凭据提供程序
    std::wstring excludedProviders = L"{60b78e88-ead8-445c-9cfd-0b87f74ea6cd},{D6886603-9D2F-4EB2-B667-1971041FA96B},{6f45dc1e-5384-457a-bc13-2cd81b0d28ed},{8FD7E19C-3BF7-489B-A72C-846AB3678C96}";
    if (!SetRegistry(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        L"ExcludedCredentialProviders",
        excludedProviders))
    {
        return false;
    }
    return true;
}

//删除注册表值（删除所有用户只能使用自定义凭据）
bool DeleteRegistry(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& valueName)
{
    HKEY hKey;
    LONG result = RegOpenKeyEx(hKeyRoot, subKey.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS)
    {
        return false;
    }

    result = RegDeleteValue(hKey, valueName.c_str());
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS);
}

//移除凭据提供程序配置(删除所有用户只能使用自定义凭据)
bool RemoveCredentialProvidersConfiguration()
{
    // 删除默认凭据提供程序设置
    if (!DeleteRegistry(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers",
        L"DefaultCredentialProvider"))
    {
        return false;
    }

    // 删除排除的凭据提供程序设置
    if (!DeleteRegistry(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        L"ExcludedCredentialProviders"))
    {
        return false;
    }
    return true;
}

//// 获取用户名对应的SID

//bool GetSidFromUsername(const std::wstring& username, PSID& sid)
//{
//    DWORD sidSize = 0;
//    DWORD domainSize = 0;
//    SID_NAME_USE sidType;
//    LookupAccountName(NULL, username.c_str(), NULL, &sidSize, NULL, &domainSize, &sidType);
//
//    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
//    {
//        return false;
//    }
//
//    sid = (PSID)malloc(sidSize);
//    std::wstring domainName(domainSize, L'\0');
//
//    if (!LookupAccountName(NULL, username.c_str(), sid, &sidSize, &domainName[0], &domainSize, &sidType))
//    {
//        free(sid);
//        return false;
//    }
//
//    return true;
//}

//// 配置特定用户可以使用系统默认凭据提供程序

//bool SetUserSpecificCredentialProvider(const std::wstring& username, bool useDefault)
//{
//    PSID sid;
//    if (!GetSidFromUsername(username, sid))
//    {
//        return false;
//    }
//
//    // 将SID转换为字符串
//    LPWSTR sidString;
//    if (!ConvertSidToStringSid(sid, &sidString))
//    {
//        free(sid);
//        return false;
//    }
//
//    std::wstring subKey = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\") + sidString;
//    std::wstring valueName = L"CredentialProviderFilters";
//    std::wstring data = useDefault ? L"" : YOUR_CREDENTIAL_PROVIDER_CLSID;
//
//    HKEY hKey;
//    LONG result = RegCreateKeyEx(HKEY_USERS, subKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
//    if (result != ERROR_SUCCESS)
//    {
//        LocalFree(sidString);
//        free(sid);
//        return false;
//    }
//
//    if (useDefault)
//    {
//        result = RegDeleteValue(hKey, valueName.c_str());
//    }
//    else
//    {
//        result = RegSetValueEx(hKey, valueName.c_str(), 0, REG_SZ, (BYTE*)data.c_str(), (data.size() + 1) * sizeof(wchar_t));
//    }
//
//    RegCloseKey(hKey);
//    LocalFree(sidString);
//    free(sid);
//
//    return (result == ERROR_SUCCESS);
//}

//// 删除特定用户凭据提供程序

//bool RemoveUserSpecificCredentialProvider(const std::wstring& username)
//{
//    PSID sid;
//    if (!GetSidFromUsername(username, sid))
//    {
//        return false;
//    }
//
//    // 将SID转换为字符串
//    LPWSTR sidString;
//    if (!ConvertSidToStringSid(sid, &sidString))
//    {
//        free(sid);
//        return false;
//    }
//
//    std::wstring subKey = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\") + sidString;
//    std::wstring valueName = L"CredentialProviderFilters";
//
//    HKEY hKey;
//    LONG result = RegOpenKeyEx(HKEY_USERS, subKey.c_str(), 0, KEY_ALL_ACCESS, &hKey);
//    if (result != ERROR_SUCCESS)
//    {
//        LocalFree(sidString);
//        free(sid);
//        return false;
//    }
//
//    // 删除 CredentialProviderFilters 值
//    result = RegDeleteValue(hKey, valueName.c_str());
//
//    // 如果键为空，则删除整个键
//    DWORD subKeys, values;
//    if (RegQueryInfoKey(hKey, NULL, NULL, NULL, &subKeys, NULL, NULL, &values, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
//    {
//        if (subKeys == 0 && values == 0)
//        {
//            RegCloseKey(hKey);
//            RegDeleteKey(HKEY_USERS, subKey.c_str());
//        }
//    }
//
//    RegCloseKey(hKey);
//    LocalFree(sidString);
//    free(sid);
//
//    return (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND);
//}
