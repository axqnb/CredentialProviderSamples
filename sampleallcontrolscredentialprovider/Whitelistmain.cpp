// main.cpp
#include <iostream>
#include <string>
#include <regex>
#include "WhitelistManager.h"

// 验证URL格式的函数
//bool isValidURL(const std::wstring& url) {
//    std::wregex urlRegex(L"^(https?:\\/\\/)?([\\da-z\\.-]+)\\.([a-z\\.]{2,6})([\\/\\w \\.-]*)*\\/?$");
//    return std::regex_match(url, urlRegex);
//}

int main()
{
    std::wstring username;
    std::wstring url;
    int choice;

    while (true)
    {
        std::cout << "白名单管理工具\n";
        std::cout << "1. 添加用户到白名单\n";
        std::cout << "2. 从白名单移除用户\n";
        std::cout << "3. 检查用户是否在白名单中\n";
        std::cout << "4. 请输入要添加的URL\n";
        std::cout << "5. 配置全部用户仅使用自定义凭据登录方式\n";
        std::cout << "6. 删除全部用户仅使用自定义凭据登录方式\n";
        //std::cout << "7. 配置特定用户可以使用系统默认凭据提供程序\n";
        //std::cout << "8. 删除特定用户可以使用系统默认凭据登录方式\n";
        std::cout << "0. 退出\n";
        std::cout << "请选择操作: ";
        std::cin >> choice;

        switch (choice)
        {
        case 1:
            std::cout << "输入要添加的用户名: ";
            std::wcin >> username;
            if (AddUserToWhitelist(username))
                std::cout << "用户已添加到白名单\n";
            else
                std::cout << "添加用户失败\n";
            break;
        case 2:
            std::cout << "输入要移除的用户名: ";
            std::wcin >> username;
            if (RemoveUserFromWhitelist(username))
                std::cout << "用户已从白名单移除\n";
            else
                std::cout << "移除用户失败\n";
            break;
        case 3:
            std::cout << "输入要检查的用户名: ";
            std::wcin >> username;
            if (IsUserInWhitelist(username))
                std::cout << "用户在白名单中\n";
            else
                std::cout << "用户不在白名单中\n";
            break;
        case 4:
            std::cout << "输入要设置的URL: ";
            std::wcin >> url;
                if (SetRequestURL(url))
                    std::cout << "URL已成功设置\n";
                else
                    std::cout << "设置URL失败\n";
            break;
        case 5:
            if (ConfigureCredentialProviders())
                std::cout << "成功为所有用户配置自定义凭据提供程序\n";
            else
                std::cout << "操作失败，为所有用户配置自定义凭据提供程序失败。\n";
            break;
        case 6:
            if (RemoveCredentialProvidersConfiguration())
                std::cout << "成功删除所有用户自定义凭据提供程序\n";
            else
                std::cout << "操作失败。\n";
            break;
        /*case 7:
            std::cout << "输入要配置的特定用户名: ";
            std::wcin >> username;
            if (SetUserSpecificCredentialProvider(username, true))
                std::cout << "成功允许特定用户使用系统默认凭据提供程序。\n";
            else
                std::cout << "设置特定用户凭据提供程序失败。\n";
            break;
        case 8:
            std::cout << "输入要删除的特定用户名: ";
            std::wcin >> username;
            if (RemoveUserSpecificCredentialProvider(username))
                std::cout << "成功删除用户 " << username.c_str() << " 的凭据提供程序设置。\n";
            else
                std::cout << "删除用户 " << username.c_str() << " 的凭据提供程序设置失败。\n";
            break;*/
        case 0:
            return 0;
        default:
            std::cout << "无效选择，请重试\n";
        }
        std::cout << L"\n";
    }

    return 0;
}
