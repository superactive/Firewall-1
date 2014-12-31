// Firewall.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include <Windows.h>
#include <stdio.h>
#include <comutil.h>
#include <atlcomcli.h>
#include <netfw.h>
#include <io.h>
#include <locale>

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )

#define NET_FW_IP_PROTOCOL_TCP_NAME L"TCP"
#define NET_FW_IP_PROTOCOL_UDP_NAME L"UDP"

#define NET_FW_RULE_DIR_IN_NAME L"In"
#define NET_FW_RULE_DIR_OUT_NAME L"Out"

#define NET_FW_RULE_ACTION_BLOCK_NAME L"Block"
#define NET_FW_RULE_ACTION_ALLOW_NAME L"Allow"

#define NET_FW_RULE_ENABLE_IN_NAME L"TRUE"
#define NET_FW_RULE_DISABLE_IN_NAME L"FALSE"


// 函数向前声明部分
void        DumpFWRulesInCollection(INetFwRule* FwRule, FILE * fp);
HRESULT     WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2);


// 主函数入口
int _tmain(int argc, _TCHAR* argv[])
{
	// 所有线程都使用同样的区域配置
	_configthreadlocale( _DISABLE_PER_THREAD_LOCALE );
	// 设置当前进程的区域配置为简体中文中国
	_tsetlocale( LC_ALL, /*_T("chinese_china")*/_T("Chinese_People's Republic of China") );

    HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    ULONG cFetched = 0; 
    CComVariant var;

    IUnknown *pEnumerator;
    IEnumVARIANT* pVariant = NULL;

    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    INetFwRule *pFwRule = NULL;

    long fwRuleCount;

    // 初始化COM
    hrComInit = CoInitializeEx(
                    0,
                    COINIT_APARTMENTTHREADED
                    );

	// 忽略RPC_E_CHANGED_MODE，原因是我们只关注已经存在的模式
    if (hrComInit != RPC_E_CHANGED_MODE)
    {
        if (FAILED(hrComInit))
        {
            wprintf(L"CoInitializeEx failed: 0x%08lx\n", hrComInit);
            goto Cleanup;
        }
    }

    // 获取和初始化INetFwPolicy2指针
    hr = WFCOMInitialize(&pNetFwPolicy2);
    if (FAILED(hr))
    {
        goto Cleanup;
    }

    // 获取INetFwRules的防火墙规则
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr))
    {
        wprintf(L"get_Rules failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

    // 获取防火墙规则的数量
    hr = pFwRules->get_Count(&fwRuleCount);
    if (FAILED(hr))
    {
        wprintf(L"get_Count failed: 0x%08lx\n", hr);
        goto Cleanup;
    }
    
	FILE * fp = NULL;
	_wfopen_s( &fp, L"FirewallRules.txt", L"w" );
    wprintf(L"The number of rules in the Windows Firewall are %d\n", fwRuleCount);
	fp ? fwprintf_s( fp, L"The number of rules in the Windows Firewall are %d\n", fwRuleCount ) : 0;

    // 获取一个pFwRules指针的枚举迭代器
    pFwRules->get__NewEnum(&pEnumerator);

    if(pEnumerator)
    {
        hr = pEnumerator->QueryInterface(__uuidof(IEnumVARIANT), (void **) &pVariant);
    }

    while(SUCCEEDED(hr) && hr != S_FALSE)
    {
        var.Clear();
        hr = pVariant->Next(1, &var, &cFetched);

        if (S_FALSE != hr)
        {
            if (SUCCEEDED(hr))
            {
                hr = var.ChangeType(VT_DISPATCH);
            }
            if (SUCCEEDED(hr))
            {
                hr = (V_DISPATCH(&var))->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&pFwRule));
            }

            if (SUCCEEDED(hr))
            {
                // 输出已经获取成功的这些规则
                DumpFWRulesInCollection(pFwRule, fp);
            }
        }
    }
	fp ? fclose(fp) : 0;
 
Cleanup:

    // 释放pFwRule指针
    if (pFwRule != NULL)
    {
        pFwRule->Release();
    }

    // 释放INetFwPolicy2数据
    if (pNetFwPolicy2 != NULL)
    {
        pNetFwPolicy2->Release();
    }

    // 卸载COM
    if (SUCCEEDED(hrComInit))
    {
        CoUninitialize();
    }
   
    return 0;
}


// 输出所有防火墙规则
void DumpFWRulesInCollection(INetFwRule* FwRule, FILE * fp)
{
    variant_t InterfaceArray;
    variant_t InterfaceString;  

    VARIANT_BOOL bEnabled;
    BSTR bstrVal;

    long lVal = 0;
    long lProfileBitmask = 0;

    NET_FW_RULE_DIRECTION fwDirection;
    NET_FW_ACTION fwAction;

    struct ProfileMapElement 
    {
        NET_FW_PROFILE_TYPE2 Id;
        LPCWSTR Name;
    };

    ProfileMapElement ProfileMap[3];
    ProfileMap[0].Id = NET_FW_PROFILE2_DOMAIN;
    ProfileMap[0].Name = L"Domain";
    ProfileMap[1].Id = NET_FW_PROFILE2_PRIVATE;
    ProfileMap[1].Name = L"Private";
    ProfileMap[2].Id = NET_FW_PROFILE2_PUBLIC;
    ProfileMap[2].Name = L"Public";

    wprintf(L"---------------------------------------------\n");
	fp ? fwprintf_s( fp, L"---------------------------------------------\n" ) : 0;

    if (SUCCEEDED(FwRule->get_Name(&bstrVal)))
    {
        wprintf(L"  Name:             %s\n", bstrVal);
		fp ? fwprintf_s( fp, L"  Name:             %s\n", bstrVal ) : 0;
    }

    if (SUCCEEDED(FwRule->get_Description(&bstrVal)))
    {
        wprintf(L"  Description:      %s\n", bstrVal);
		fp ? fwprintf_s( fp, L"  Description:      %s\n", bstrVal ) : 0;
    }

    if (SUCCEEDED(FwRule->get_ApplicationName(&bstrVal)))
    {
        wprintf(L"  Application Name: %s\n", bstrVal);
		fp ? fwprintf_s( fp, L"  Application Name: %s\n", bstrVal ) : 0;
    }

    if (SUCCEEDED(FwRule->get_ServiceName(&bstrVal)))
    {
        wprintf(L"  Service Name:     %s\n", bstrVal);
		fp ? fwprintf_s( fp, L"  Service Name:     %s\n", bstrVal ) : 0;
    }

    if (SUCCEEDED(FwRule->get_Protocol(&lVal)))
    {
        switch(lVal)
        {
            case NET_FW_IP_PROTOCOL_TCP: 

                wprintf(L"  IP Protocol:      %s\n", NET_FW_IP_PROTOCOL_TCP_NAME);
				fp ? fwprintf_s( fp, L"  IP Protocol:      %s\n", NET_FW_IP_PROTOCOL_TCP_NAME ) : 0;
                break;

            case NET_FW_IP_PROTOCOL_UDP: 

                wprintf(L"  IP Protocol:      %s\n", NET_FW_IP_PROTOCOL_UDP_NAME);
				fp ? fwprintf_s( fp, L"  IP Protocol:      %s\n", NET_FW_IP_PROTOCOL_UDP_NAME ) : 0;
                break;

            default:

                break;
        }

        if(lVal != NET_FW_IP_VERSION_V4 && lVal != NET_FW_IP_VERSION_V6)
        {
            if (SUCCEEDED(FwRule->get_LocalPorts(&bstrVal)))
            {
                wprintf(L"  Local Ports:      %s\n", bstrVal);
				fp ? fwprintf_s( fp, L"  Local Ports:      %s\n", bstrVal ) : 0;
            }

            if (SUCCEEDED(FwRule->get_RemotePorts(&bstrVal)))
            {
                wprintf(L"  Remote Ports:      %s\n", bstrVal);
				fp ? fwprintf_s( fp, L"  Remote Ports:      %s\n", bstrVal ) : 0;
            }
        }
        else
        {
            if (SUCCEEDED(FwRule->get_IcmpTypesAndCodes(&bstrVal)))
            {
                wprintf(L"  ICMP TypeCode:      %s\n", bstrVal);
				fp ? fwprintf_s( fp, L"  ICMP TypeCode:      %s\n", bstrVal ) : 0;
            }
        }
    }

    if (SUCCEEDED(FwRule->get_LocalAddresses(&bstrVal)))
    {
        wprintf(L"  LocalAddresses:   %s\n", bstrVal);
		fp ? fwprintf_s( fp, L"  LocalAddresses:   %s\n", bstrVal ) : 0;
    }

    if (SUCCEEDED(FwRule->get_RemoteAddresses(&bstrVal)))
    {
        wprintf(L"  RemoteAddresses:  %s\n", bstrVal);
		fp ? fwprintf_s( fp, L"  RemoteAddresses:  %s\n", bstrVal ) : 0;
    }

    if (SUCCEEDED(FwRule->get_Profiles(&lProfileBitmask)))
    {
		// 返回的数据的位掩码至少包含了一个以上的当前活跃配置文件，并且它们是相同时间生成的
        for ( int i = 0; i < 3; i++ )
        {
            if ( lProfileBitmask & ProfileMap[i].Id  )
            {
                wprintf(L"  Profile:  %s\n", ProfileMap[i].Name);
				fp ? fwprintf_s( fp, L"  Profile:  %s\n", ProfileMap[i].Name ) : 0;
            }
        }
    }

    if (SUCCEEDED(FwRule->get_Direction(&fwDirection)))
    {
        switch(fwDirection)
        {
            case NET_FW_RULE_DIR_IN:

                wprintf(L"  Direction:        %s\n", NET_FW_RULE_DIR_IN_NAME);
				fp ? fwprintf_s( fp, L"  Direction:        %s\n", NET_FW_RULE_DIR_IN_NAME ) : 0;
                break;

            case NET_FW_RULE_DIR_OUT:

                wprintf(L"  Direction:        %s\n", NET_FW_RULE_DIR_OUT_NAME);
				fp ? fwprintf_s( fp, L"  Direction:        %s\n", NET_FW_RULE_DIR_OUT_NAME ) : 0;
                break;

            default:

                break;
        }
    }

    if (SUCCEEDED(FwRule->get_Action(&fwAction)))
    {
        switch(fwAction)
        {
            case NET_FW_ACTION_BLOCK:

                wprintf(L"  Action:           %s\n", NET_FW_RULE_ACTION_BLOCK_NAME);
				fp ? fwprintf_s( fp, L"  Action:           %s\n", NET_FW_RULE_ACTION_BLOCK_NAME ) : 0;
                break;

            case NET_FW_ACTION_ALLOW:

                wprintf(L"  Action:           %s\n", NET_FW_RULE_ACTION_ALLOW_NAME);
				fp ? fwprintf_s( fp, L"  Action:           %s\n", NET_FW_RULE_ACTION_ALLOW_NAME ) : 0;
                break;

            default:

                break;
        }
    }

    if (SUCCEEDED(FwRule->get_Interfaces(&InterfaceArray)))
    {
        if(InterfaceArray.vt != VT_EMPTY)
        {
            SAFEARRAY    *pSa = NULL;

            pSa = InterfaceArray.parray;

            for(long index= pSa->rgsabound->lLbound; index < (long)pSa->rgsabound->cElements; index++)
            {
                SafeArrayGetElement(pSa, &index, &InterfaceString);
                wprintf(L"  Interfaces:       %s\n", (BSTR)InterfaceString.bstrVal);
				fp ? fwprintf_s( fp, L"  Interfaces:       %s\n", (BSTR)InterfaceString.bstrVal ) : 0;
            }
        }
    }

    if (SUCCEEDED(FwRule->get_InterfaceTypes(&bstrVal)))
    {
        wprintf(L"  Interface Types:  %s\n", bstrVal);
		fp ? fwprintf_s( fp, L"  Interface Types:  %s\n", bstrVal ) : 0;
    }

    if (SUCCEEDED(FwRule->get_Enabled(&bEnabled)))
    {
        if (bEnabled)
        {
            wprintf(L"  Enabled:          %s\n", NET_FW_RULE_ENABLE_IN_NAME);
			fp ? fwprintf_s( fp, L"  Enabled:          %s\n", NET_FW_RULE_ENABLE_IN_NAME ) : 0;
        }
        else
        {
            wprintf(L"  Enabled:          %s\n", NET_FW_RULE_DISABLE_IN_NAME);
			fp ? fwprintf_s( fp, L"  Enabled:          %s\n", NET_FW_RULE_DISABLE_IN_NAME ) : 0;
        }
    }

    if (SUCCEEDED(FwRule->get_Grouping(&bstrVal)))
    {
        wprintf(L"  Grouping:         %s\n", bstrVal);
		fp ? fwprintf_s( fp, L"  Grouping:         %s\n", bstrVal ) : 0;
    }

    if (SUCCEEDED(FwRule->get_EdgeTraversal(&bEnabled)))
    {
        if (bEnabled)
        {
            wprintf(L"  Edge Traversal:   %s\n", NET_FW_RULE_ENABLE_IN_NAME);
			fp ? fwprintf_s( fp, L"  Edge Traversal:   %s\n", NET_FW_RULE_ENABLE_IN_NAME ) : 0;
        }
        else
        {
            wprintf(L"  Edge Traversal:   %s\n", NET_FW_RULE_DISABLE_IN_NAME);
			fp ? fwprintf_s( fp, L"  Edge Traversal:   %s\n", NET_FW_RULE_DISABLE_IN_NAME ) : 0;
        }
    }
}


// 初始化防火墙策略INetFwPolicy2的COM接口
HRESULT WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2)
{
    HRESULT hr = S_OK;

    hr = CoCreateInstance(
        __uuidof(NetFwPolicy2), 
        NULL, 
        CLSCTX_INPROC_SERVER, 
        __uuidof(INetFwPolicy2), 
        (void**)ppNetFwPolicy2);

    if (FAILED(hr))
    {
        wprintf(L"CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
        goto Cleanup;        
    }

Cleanup:
    return hr;
}


