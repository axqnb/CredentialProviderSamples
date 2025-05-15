//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// CSampleProvider implements ICredentialProvider, which is the main
// interface that logonUI uses to decide which tiles to display.
// In this sample, we will display one tile that uses each of the nine
// available UI controls.
//CSampleProvider实现了ICredentialProvider，这是主要的logonUI用来决定显示哪个磁贴的接口 
//在这个示例中，我们将显示一个使用9个中的每一个的tile可用的UI控件 
#include <credentialprovider.h>
#include "CSampleProvider.h"
#include "CSampleCredential.h"
#include "guid.h"
#include <wincred.h>
#include "libFpDriver_WL.h"

// CSampleProvider

CSampleProvider::CSampleProvider():
    _cRef(1),
    _bHasSavedUsername(FALSE)
{
    ZeroMemory(_wszSavedUsername, sizeof(_wszSavedUsername));

    DllAddRef();

    _pCredential = NULL;
}

CSampleProvider::~CSampleProvider()
{
    if (_pCredential != NULL)
    {
        _pCredential->Release();
        _pCredential = NULL;
    }

    DllRelease();
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.
HRESULT CSampleProvider::SetUsageScenario(
    __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    __in DWORD dwFlags
    )
{
    UNREFERENCED_PARAMETER(dwFlags);
    HRESULT hr;

    // Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
    // that we're not designed for that scenario.
    //登录场景
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
    case CPUS_CREDUI:
        _cpus = cpus;
        
        // Create and initialize our credential.
        // A more advanced credprov might only enumerate tiles for the user whose owns the locked
        // session, since those are the only creds that wil work
        //创建并初始化凭证。
        //更高级的credprov可能只枚举拥有锁的用户的磁片
        //会话，因为这些是唯一的信用将工作
   
        // 读取保存的用户名
        _ReadSavedUsername();

        _pCredential = new CSampleCredential();
        if (_pCredential != NULL)
        {
            PCWSTR wszPrepopulatedUsername = _bHasSavedUsername ? _wszSavedUsername : L"";

            if (cpus == CPUS_CREDUI)
            {
                _dwCredUIFlags = dwFlags;  // currently the only flags ever passed in are only valid for the credui scenario
                wszPrepopulatedUsername = L"";
            }
            hr = _pCredential->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, _dwCredUIFlags, wszPrepopulatedUsername);
            if (FAILED(hr))
            {
                _pCredential->Release();
                _pCredential = NULL;
            }
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
        break;

    case CPUS_CHANGE_PASSWORD:
    //case CPUS_CREDUI:
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }

    return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI for
// an authentication attempt.  It's the opposite of ICredentialProviderCredential::GetSerialization.
// GetSerialization is implement by a credential and serializes that credential.  Instead,
// SetSerialization takes the serialization and uses it to create a tile.
//
// SetSerialization is called for two main scenarios.  The first scenario is in the credui case
// where it is prepopulating a tile with credentials that the user chose to store in the OS.
// The second situation is in a remote logon case where the remote client may wish to 
// prepopulate a tile with a username, or in some cases, completely populate the tile and
// use it to logon without showing any UI.
//
// If you wish to see an example of SetSerialization, please see either the SampleCredentialProvider
// sample or the SampleCredUICredentialProvider sample.  [The logonUI team says, "The original sample that
// this was built on top of didn't have SetSerialization.  And when we decided SetSerialization was
// important enough to have in the sample, it ended up being a non-trivial amount of work to integrate
// it into the main sample.  We felt it was more important to get these samples out to you quickly than to
// hold them in order to do the work to integrate the SetSerialization changes from SampleCredentialProvider 
// into this sample.]

//SetSerialization接受那种你通常会返回到LogonUI的缓冲区
//验证尝试。它与ICredentialProviderCredential::GetSerialization相反。
//GetSerialization由一个凭据实现，并序列化该凭据。相反,
//SetSerialization接受序列化并使用它来创建一个tile。
//
//SetSerialization在两种情况下被调用。第一种情况是信用案例
//预填充用户选择存储在操作系统中的凭据。
//第二种情况是在远程登录的情况下，远程客户端可能希望
//使用用户名预填充贴片，或者在某些情况下，完全填充贴片和
//使用它登录而不显示任何UI。
//
//如果你想看一个SetSerialization的例子，请参阅SampleCredentialProvider
//样本或SampleCredUICredentialProvider样本。logonUI团队说:“原始样本
//这是建立在没有SetSerialization的基础上的。当我们决定SetSerialization是
//在示例中足够重要，它最终成为一个不平凡的工作量来集成
//它进入主样本。我们觉得尽快把这些样品寄给你比寄给你更重要
//保留它们，以便集成来自SampleCredentialProvider的SetSerialization更改
//到这个示例中。]

HRESULT CSampleProvider::SetSerialization(
    __in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs
    )
{
    UNREFERENCED_PARAMETER(pcpcs);
    return E_NOTIMPL;
}

//HRESULT CSampleProvider::SetSerialization(
//    __in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs
//)
//{
//    HRESULT hr = E_INVALIDARG;
//
//    if ((CLSID_CSample == pcpcs->clsidCredentialProvider) || (CPUS_CREDUI == _cpus))
//    {
//        // Get the current AuthenticationPackageID that we are supporting
//        ULONG ulNegotiateAuthPackage;
//        hr = RetrieveNegotiateAuthPackage(&ulNegotiateAuthPackage);
//
//        if (SUCCEEDED(hr))
//        {
//            if (CPUS_CREDUI == _cpus)
//            {
//                if (CREDUIWIN_IN_CRED_ONLY & _dwCredUIFlags)
//                {
//                    // If we are being told to enumerate only the incoming credential, we must not return
//                    // success unless we can enumerate it.  We'll set hr to failure here and let it be
//                    // overridden if the enumeration logic below succeeds.
//                    hr = E_INVALIDARG;
//                }
//                else if (_dwCredUIFlags & CREDUIWIN_AUTHPACKAGE_ONLY)
//                {
//                    if (ulNegotiateAuthPackage == pcpcs->ulAuthenticationPackage)
//                    {
//                        // In the credui case, SetSerialization should only ever return S_OK if it is able to serialize the input cred.
//                        // Unfortunately, SetSerialization had to be overloaded to indicate whether or not it will be able to GetSerialization 
//                        // for the specific Auth Package that is being requested for CREDUIWIN_AUTHPACKAGE_ONLY to work, so when that flag is 
//                        // set, it should return S_FALSE unless it is ALSO able to serialize the input cred, then it can return S_OK.
//                        // So in this case, we can set it to be S_FALSE because we support the authpackage, and then if we
//                        // can serialize the input cred, it will get overwritten with S_OK.
//                        hr = S_FALSE;
//                    }
//                    else
//                    {
//                        //we don't support this auth package, so we want to let logonUI know that by failing
//                        hr = E_INVALIDARG;
//                    }
//                }
//            }
//
//            if ((ulNegotiateAuthPackage == pcpcs->ulAuthenticationPackage) &&
//                (0 < pcpcs->cbSerialization && pcpcs->rgbSerialization))
//            {
//                KERB_INTERACTIVE_UNLOCK_LOGON* pkil = (KERB_INTERACTIVE_UNLOCK_LOGON*)pcpcs->rgbSerialization;
//                if (KerbInteractiveLogon == pkil->Logon.MessageType)
//                {
//                    // If there isn't a username, we can't serialize or create a tile for this credential.
//                    if (0 < pkil->Logon.UserName.Length && pkil->Logon.UserName.Buffer)
//                    {
//                        if ((CPUS_CREDUI == _cpus) && (CREDUIWIN_PACK_32_WOW & _dwCredUIFlags))
//                        {
//                            BYTE* rgbNativeSerialization;
//                            DWORD cbNativeSerialization;
//                            if (SUCCEEDED(KerbInteractiveUnlockLogonRepackNative(pcpcs->rgbSerialization, pcpcs->cbSerialization, &rgbNativeSerialization, &cbNativeSerialization)))
//                            {
//                                KerbInteractiveUnlockLogonUnpackInPlace((PKERB_INTERACTIVE_UNLOCK_LOGON)rgbNativeSerialization, cbNativeSerialization);
//
//                                _pkiulSetSerialization = (PKERB_INTERACTIVE_UNLOCK_LOGON)rgbNativeSerialization;
//                                hr = S_OK;
//                            }
//                        }
//                        else
//                        {
//                            BYTE* rgbSerialization;
//                            rgbSerialization = (BYTE*)HeapAlloc(GetProcessHeap(), 0, pcpcs->cbSerialization);
//                            HRESULT hrCreateCred = rgbSerialization ? S_OK : E_OUTOFMEMORY;
//
//                            if (SUCCEEDED(hrCreateCred))
//                            {
//                                CopyMemory(rgbSerialization, pcpcs->rgbSerialization, pcpcs->cbSerialization);
//                                KerbInteractiveUnlockLogonUnpackInPlace((KERB_INTERACTIVE_UNLOCK_LOGON*)rgbSerialization, pcpcs->cbSerialization);
//
//                                if (_pkiulSetSerialization)
//                                {
//                                    HeapFree(GetProcessHeap(), 0, _pkiulSetSerialization);
//                                }
//                                _pkiulSetSerialization = (KERB_INTERACTIVE_UNLOCK_LOGON*)rgbSerialization;
//                                if (SUCCEEDED(hrCreateCred))
//                                {
//                                    // we allow success to override the S_FALSE for the CREDUIWIN_AUTHPACKAGE_ONLY, but
//                                    // failure to create the cred shouldn't override that we can still handle
//                                    // the auth package
//                                    hr = hrCreateCred;
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//        }
//    }
//
//    return hr;
//}

// Called by LogonUI to give you a callback.  Providers often use the callback if they
// some event would cause them to need to change the set of tiles that they enumerated.
//由LogonUI调用给你一个回调。提供者通常使用回调，如果他们
//某些事件会导致它们需要更改所枚举的tile集合。
HRESULT CSampleProvider::Advise(
    __in ICredentialProviderEvents* pcpe,
    __in UINT_PTR upAdviseContext
    )
{
    UNREFERENCED_PARAMETER(pcpe);
    UNREFERENCED_PARAMETER(upAdviseContext);

    return E_NOTIMPL;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT CSampleProvider::UnAdvise()
{
    return E_NOTIMPL;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired 
// using the field descriptors.
//由LogonUI调用，以确定tile中的字段数。这表示所有的tile必须具有相同数量的字段
//这个数字必须包括可见和不可见字段。如果你想要瓷砖为给定的用法枚举不同的字段
//场景你必须把它们都包含在这个计数中，然后隐藏/显示它们使用字段描述符。
HRESULT CSampleProvider::GetFieldDescriptorCount(
    __out DWORD* pdwCount
    )
{
    *pdwCount = SFI_NUM_FIELDS;
    return S_OK;
}

// Gets the field descriptor for a particular field.
HRESULT CSampleProvider::GetFieldDescriptorAt(
    __in DWORD dwIndex, 
    __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
    )
{    
    HRESULT hr;

    // Verify dwIndex is a valid field.
    if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
    }
    else
    { 
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
// Sets pdwDefault to the index of the tile which should be used as the default.
// The default tile is the tile which will be shown in the zoomed view by default. If 
// more than one provider specifies a default the last used cred prov gets to pick 
// the default. If *pbAutoLogonWithDefault is TRUE, LogonUI will immediately call 
// GetSerialization on the credential you've specified as the default and will submit 
// that credential for authentication without showing any further UI.
//将pdwCount设置为我们希望此时显示的瓷砖数量。
//将pdwDefault设置为应该用作默认值的tile的索引。
//默认的tile是默认在缩放视图中显示的tile。如果
//多个提供者指定一个默认值，最后使用的信用证明可以选择
//默认值。如果* pautologonwithdefault为TRUE, LogonUI将立即调用
//对指定为默认值并将提交的凭据进行GetSerialization
//该凭据用于身份验证，而不显示任何进一步的UI。
HRESULT CSampleProvider::GetCredentialCount(
    __out DWORD* pdwCount,
    __out_range(<,*pdwCount) DWORD* pdwDefault,
    __out BOOL* pbAutoLogonWithDefault
    )
{
    *pdwCount = 1;
    *pdwDefault = 0;
    *pbAutoLogonWithDefault = FALSE;
    return S_OK;
}

// Returns the credential at the index specified by dwIndex. This function is called by logonUI to enumerate
// the tiles.
//一系列初始化字段的函数，暂时无需关心
HRESULT CSampleProvider::GetCredentialAt(
    __in DWORD dwIndex, 
    __deref_out ICredentialProviderCredential** ppcpc
    )
{
    HRESULT hr;
    if((dwIndex == 0) && ppcpc)
    {
        hr = _pCredential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Boilerplate code to create our provider.
//创建我们的提供程序的样板代码
HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
    HRESULT hr;

    CSampleProvider* pProvider = new CSampleProvider();

    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    
    return hr;
}

// 读取注册表中的用户名
HRESULT CSampleProvider::_ReadSavedUsername()
{
    HKEY hKey;
    DWORD dwType = REG_SZ;
    WCHAR wszUsername[MAX_PATH] = { 0 };
    DWORD cbData = sizeof(wszUsername);

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
            L"LastUsername",
            NULL,
            &dwType,
            (LPBYTE)wszUsername,
            &cbData
        );
        RegCloseKey(hKey);

        if (status == ERROR_SUCCESS)
        {
            StringCchCopyW(_wszSavedUsername, ARRAYSIZE(_wszSavedUsername), wszUsername);
            _bHasSavedUsername = true;
            return S_OK;
        }
    }
    _bHasSavedUsername = false;
    return S_FALSE;
}
