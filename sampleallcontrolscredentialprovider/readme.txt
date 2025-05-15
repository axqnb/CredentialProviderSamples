//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

Overview
--------
This sample implements a simple credential provider that uses each UI field type.

How to run this sample
--------------------------------
Once you have built the project, copy SampleAllControlsCredentialProvider.dll to the
System32 directory and run Register.reg from an elevated command prompt.
The credential should appear the next time a logon is invoked (such as logging off or rebooting).

What this sample demonstrates
-----------------------------
This sample demonstrates the use of each of the nine different UI field types.

Parts of the sample
-------------------
common.h - sets up what a tile looks like and how each of the UI controls will be displayed.
CSampleCredential.h/CSampleCredential.cpp - implements ICredentialProviderCredential, which describes one tile.
CSampleProvider.h/CSampleProvider.cpp - implements ICredentialProvider, which is the main interface used by LogonUI
										to talk to a credential provider.
Dll.h/Dll.cpp - standard dll setup for a dll that implements COM objects
helpers.h/helpers.cpp - useful functionality to deal with serializing credentials, UNICODE_STRING's, etc.



==========================二次开发调试====================
1、调试一些重要变量：
string resMessage = "Response:" + std::to_string(iRet);
wstring resMessageW(resMessage.begin(), resMessage.end());
MessageBox(NULL, resMessageW.c_str(), L"response", MB_OK);

string resMessage001 = "获取图像结构之后:" + std::to_string(Size);
wstring resMessageW001(resMessage001.begin(), resMessage001.end());
MessageBox(NULL, resMessageW001.c_str(), L"获取图像结构之后:", MB_OK);