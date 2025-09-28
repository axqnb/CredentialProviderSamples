//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

#include <credentialprovider.h>
#include <windows.h>
#include <strsafe.h>
#include "CSampleCredential.h"
#include "helpers.h"

class CSampleProvider : public ICredentialProvider
{
  public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return ++_cRef;
    }
    
    IFACEMETHODIMP_(ULONG) Release()
    {
        LONG cRef = --_cRef;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CSampleProvider, ICredentialProvider), // IID_ICredentialProvider
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

  public:
    IFACEMETHODIMP SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, __in DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(__in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);

    IFACEMETHODIMP Advise(__in ICredentialProviderEvents* pcpe, __in UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP GetFieldDescriptorCount(__out DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(__in DWORD dwIndex,  __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);

    IFACEMETHODIMP GetCredentialCount(__out DWORD* pdwCount,
                                      __out_range(<,*pdwCount) DWORD* pdwDefault,
                                      __out BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(__in DWORD dwIndex, 
                                   __deref_out ICredentialProviderCredential** ppcpc);

    friend HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv);

    // 获取注册表操作函数--0313
    //用户获取上次登录的用户名,已经子账号，改密标志
    HRESULT _ReadSavedUsername();
    HRESULT _ReadSavedRemoteUsername();
    HRESULT _ReadSavedSubAccount();
    BOOL    _ReadChangePasswordFromRegistry();
  protected:
    CSampleProvider();
    __override ~CSampleProvider();
    
  private:
    
private:
    LONG                                    _cRef;            // Used for reference counting.
    CSampleCredential                       *_pCredential;    // Our credential.
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;
    DWORD                                   _dwCredUIFlags;
    KERB_INTERACTIVE_UNLOCK_LOGON*          _pkiulSetSerialization;
    
    //用户保存上次登录的用户名（本地和远程）
    WCHAR _wszSavedUsername[MAX_PATH];
    bool  _bHasSavedUsername;

    WCHAR _wszSavedRemoteUsername[MAX_PATH];
    bool  _bHasSavedRemoteUsername;

    //用户保存上次登录的子账号
    WCHAR _wszSavedSubAccount[MAX_PATH];
    bool  _bHasSavedSubAccount;
};