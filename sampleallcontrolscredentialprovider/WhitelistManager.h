#pragma once
#include <windows.h>
#include <winreg.h>
#include <string>
// 定义白名单注册表键路径
// 注意：实际使用时，请将 "YourCompany" 替换为您的公司或项目名称
#define WHITELIST_KEY L"SOFTWARE\\Softdomain\\LoginWhitelist"

// 检查用户是否在白名单中
bool IsUserInWhitelist(const std::wstring& username);

// 将用户添加到白名单
bool AddUserToWhitelist(const std::wstring& username);

// 从白名单中移除用户
bool RemoveUserFromWhitelist(const std::wstring& username);

// 设置注册表值(通用函数)
bool SetRegistryValue(const std::wstring& valueName, const std::wstring& data);

// 获取注册表值(通用函数)
std::wstring GetRegistryValue(const std::wstring& valueName);

// 设置请求URL
bool SetRequestURL(const std::wstring& url);

//设置注册表值（设置全部用户使用自定义凭据）
bool SetRegistry(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& data);

//修改自定义凭据，写入（设置所有用户只能使用自定义凭据）
bool ConfigureCredentialProviders();

//删除注册表值（删除所有用户只能使用自定义凭据）
bool DeleteRegistry(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& valueName);

//移除凭据提供程序配置(删除所有用户只能使用自定义凭据)
bool RemoveCredentialProvidersConfiguration();

//// 获取用户名对应的SID
//bool GetSidFromUsername(const std::wstring& username, PSID& sid);
//
//// 配置特定用户的凭据提供程序
//bool SetUserSpecificCredentialProvider(const std::wstring& username, bool useDefault);
//
////删除特定用户的凭据提供程序
//bool RemoveUserSpecificCredentialProvider(const std::wstring& username);
