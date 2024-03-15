//////////////////////////////////////////////////////////////////////////////
//  RunRegProtectDLL
// 
//  By: Edward Amoruso
//      Rick Leinecker
//
//      Department of Computer Science
//      University of Central Florida
// 
//  Version: 13.7
//
//////////////////////////////////////////////////////////////////////////////

#include <iostream>     
#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <sstream>
#include <string>
#include <cstdlib>
#include <ctime>
#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <strsafe.h>
#include <detours.h>
#include <dpapi.h>
#include <unordered_set>
#include <locale>           // For std::wstring

#define NT
#define MSG_BOX     0       // Use this to disable message boxes
#define MSG_BOX2    0       // Use this in DLLmain

//////////////////////////////////////////////////////////////////////////////
// Microsoft Example Code with some modifications
#if 1
#define PULONG_PTR          PVOID
#define PLONG_PTR           PVOID
#define ULONG_PTR           PVOID
#define ENUMRESNAMEPROCA    PVOID
#define ENUMRESNAMEPROCW    PVOID
#define ENUMRESLANGPROCA    PVOID
#define ENUMRESLANGPROCW    PVOID
#define ENUMRESTYPEPROCA    PVOID
#define ENUMRESTYPEPROCW    PVOID
#define STGOPTIONS          PVOID

#pragma warning(disable:4127)   // Many of our asserts are constants.

#define ASSERT_ALWAYS(x)   \
    do {                                                        \
    if (!(x)) {                                                 \
            AssertMessage(#x, __FILE__, __LINE__);              \
            DebugBreak();                                       \
    }                                                           \
    } while (0)

#ifndef NDEBUG
#define ASSERT(x)           ASSERT_ALWAYS(x)
#else
#define ASSERT(x)
#endif

#define UNUSED(c)       (c) = (c)

//////////////////////////////////////////////////////////////////////////////
static HMODULE s_hInst = NULL;
static CHAR s_szDllPath[MAX_PATH];

BOOL ProcessEnumerate();
BOOL InstanceEnumerate(HINSTANCE hInst);

VOID AssertMessage(CONST PCHAR pszMsg, CONST PCHAR pszFile, ULONG nLine);

////////////////////////////////////////////////////////////// Logging System.
//
static BOOL s_bLog = 1;
static LONG s_nTlsIndent = -1;
static LONG s_nTlsThread = -1;
static LONG s_nThreadCnt = 0;

VOID _PrintEnter(const CHAR* psz, ...)
{
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent);
        TlsSetValue(s_nTlsIndent, (PVOID)(LONG_PTR)(nIndent + 1));
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        CHAR szBuf[1024];
        PCHAR pszBuf = szBuf;
        PCHAR pszEnd = szBuf + ARRAYSIZE(szBuf) - 1;
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
        }

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0 && pszBuf < pszEnd) {
            // Copy characters.
        }
        *pszEnd = '\0';
        SyelogV(SYELOG_SEVERITY_INFORMATION,
            szBuf, args);

        va_end(args);
    }
    SetLastError(dwErr);
}

VOID _PrintExit(const CHAR* psz, ...)
{
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent) - 1;
        ASSERT(nIndent >= 0);
        TlsSetValue(s_nTlsIndent, (PVOID)(LONG_PTR)nIndent);
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        CHAR szBuf[1024];
        PCHAR pszBuf = szBuf;
        PCHAR pszEnd = szBuf + ARRAYSIZE(szBuf) - 1;
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
        }

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0 && pszBuf < pszEnd) {
            // Copy characters.
        }
        *pszEnd = '\0';
        SyelogV(SYELOG_SEVERITY_INFORMATION,
            szBuf, args);

        va_end(args);
    }
    SetLastError(dwErr);
}

VOID _Print(const CHAR* psz, ...)
{
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent);
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        CHAR szBuf[1024];
        PCHAR pszBuf = szBuf;
        PCHAR pszEnd = szBuf + ARRAYSIZE(szBuf) - 1;
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
        }

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0 && pszBuf < pszEnd) {
            // Copy characters.
        }
        *pszEnd = '\0';
        SyelogV(SYELOG_SEVERITY_INFORMATION,
            szBuf, args);

        va_end(args);
    }

    SetLastError(dwErr);
}
#endif

//////////////////////////////////////////////////////////////////////////////
// Microsoft extern
extern "C" {
    extern HANDLE(WINAPI* Real_CreateFileW)(LPCWSTR a0,
        DWORD a1,
        DWORD a2,
        LPSECURITY_ATTRIBUTES a3,
        DWORD a4,
        DWORD a5,
        HANDLE a6);
    extern BOOL(WINAPI* Real_WriteFile)(HANDLE hFile,
        LPCVOID lpBuffer,
        DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped);
    extern BOOL(WINAPI* Real_FlushFileBuffers)(HANDLE hFile);
    extern BOOL(WINAPI* Real_CloseHandle)(HANDLE hObject);

    extern BOOL(WINAPI* Real_WaitNamedPipeW)(LPCWSTR lpNamedPipeName, DWORD nTimeOut);
    extern BOOL(WINAPI* Real_SetNamedPipeHandleState)(HANDLE hNamedPipe,
        LPDWORD lpMode,
        LPDWORD lpMaxCollectionCount,
        LPDWORD lpCollectDataTimeout);

    extern DWORD(WINAPI* Real_GetCurrentProcessId)(VOID);
    extern VOID(WINAPI* Real_GetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime);

    extern VOID(WINAPI* Real_InitializeCriticalSection)(LPCRITICAL_SECTION lpSection);
    extern VOID(WINAPI* Real_EnterCriticalSection)(LPCRITICAL_SECTION lpSection);
    extern VOID(WINAPI* Real_LeaveCriticalSection)(LPCRITICAL_SECTION lpSection);
}

//////////////////////////////////////////////////////////////////////////////
// Microsoft Sample Code VPrintf...
#if 1 
///////////////////////////////////////////////////////////////////// VPrintf.
// Completely side-effect free printf replacement (but no FP numbers).
//

static PCHAR do_base(PCHAR pszOut, UINT64 nValue, UINT nBase, PCSTR pszDigits)
{
    CHAR szTmp[96];
    int nDigit = sizeof(szTmp) - 2;
    for (; nDigit >= 0; nDigit--) {
        szTmp[nDigit] = pszDigits[nValue % nBase];
        nValue /= nBase;
    }
    for (nDigit = 0; nDigit < sizeof(szTmp) - 2 && szTmp[nDigit] == '0'; nDigit++) {
        // skip leading zeros.
    }
    for (; nDigit < sizeof(szTmp) - 1; nDigit++) {
        *pszOut++ = szTmp[nDigit];
    }
    *pszOut = '\0';
    return pszOut;
}

static PCHAR do_str(PCHAR pszOut, PCHAR pszEnd, PCSTR pszIn)
{
    while (*pszIn && pszOut < pszEnd) {
        *pszOut++ = *pszIn++;
    }
    *pszOut = '\0';
    return pszOut;
}

static PCHAR do_wstr(PCHAR pszOut, PCHAR pszEnd, PCWSTR pszIn)
{
    while (*pszIn && pszOut < pszEnd) {
        *pszOut++ = (CHAR)*pszIn++;
    }
    *pszOut = '\0';
    return pszOut;
}

static PCHAR do_estr(PCHAR pszOut, PCHAR pszEnd, PCSTR pszIn)
{
    while (*pszIn && pszOut < pszEnd) {
        if (*pszIn == '<') {
            if (pszOut + 4 > pszEnd) {
                break;
            }
            pszIn++;
            *pszOut++ = '&';
            *pszOut++ = 'l';
            *pszOut++ = 't';
            *pszOut++ = ';';
        }
        else if (*pszIn == '>') {
            if (pszOut + 4 > pszEnd) {
                break;
            }
            pszIn++;
            *pszOut++ = '&';
            *pszOut++ = 'g';
            *pszOut++ = 't';
            *pszOut++ = ';';
        }
        else if (*pszIn == '&') {
            if (pszOut + 5 > pszEnd) {
                break;
            }
            pszIn++;
            *pszOut++ = '&';
            *pszOut++ = 'a';
            *pszOut++ = 'm';
            *pszOut++ = 'p';
            *pszOut++ = ';';
        }
        else if (*pszIn == '\"') {
            if (pszOut + 6 > pszEnd) {
                break;
            }
            pszIn++;
            *pszOut++ = '&';
            *pszOut++ = 'q';
            *pszOut++ = 'u';
            *pszOut++ = 'o';
            *pszOut++ = 't';
            *pszOut++ = ';';
        }
        else if (*pszIn == '\'') {
            if (pszOut + 6 > pszEnd) {
                break;
            }
            pszIn++;
            *pszOut++ = '&';
            *pszOut++ = 'a';
            *pszOut++ = 'p';
            *pszOut++ = 'o';
            *pszOut++ = 's';
            *pszOut++ = ';';
        }
        else if (*pszIn < ' ') {
            BYTE c = (BYTE)(*pszIn++);
            if (c < 10 && pszOut + 4 <= pszEnd) {
                *pszOut++ = '&';
                *pszOut++ = '#';
                *pszOut++ = '0' + (c % 10);
                *pszOut++ = ';';
            }
            else if (c < 100 && pszOut + 5 <= pszEnd) {
                *pszOut++ = '&';
                *pszOut++ = '#';
                *pszOut++ = '0' + ((c / 10) % 10);
                *pszOut++ = '0' + (c % 10);
                *pszOut++ = ';';
            }
            else if (c < 1000 && pszOut + 6 <= pszEnd) {
                *pszOut++ = '&';
                *pszOut++ = '#';
                *pszOut++ = '0' + ((c / 100) % 10);
                *pszOut++ = '0' + ((c / 10) % 10);
                *pszOut++ = '0' + (c % 10);
                *pszOut++ = ';';
            }
            else {
                break;
            }
        }
        else {
            *pszOut++ = *pszIn++;
        }
    }
    *pszOut = '\0';
    return pszOut;
}

static PCHAR do_ewstr(PCHAR pszOut, PCHAR pszEnd, PCWSTR pszIn)
{
    while (*pszIn && pszOut < pszEnd) {
        if (*pszIn == '<') {
            if (pszOut + 4 > pszEnd) {
                break;
            }
            pszIn++;
            *pszOut++ = '&';
            *pszOut++ = 'l';
            *pszOut++ = 't';
            *pszOut++ = ';';
        }
        else if (*pszIn == '>') {
            if (pszOut + 4 > pszEnd) {
                break;
            }
            pszIn++;
            *pszOut++ = '&';
            *pszOut++ = 'g';
            *pszOut++ = 't';
            *pszOut++ = ';';
        }
        else if (*pszIn == '&') {
            if (pszOut + 5 > pszEnd) {
                break;
            }
            pszIn++;
            *pszOut++ = '&';
            *pszOut++ = 'a';
            *pszOut++ = 'm';
            *pszOut++ = 'p';
            *pszOut++ = ';';
        }
        else if (*pszIn == '\"') {
            if (pszOut + 6 > pszEnd) {
                break;
            }
            pszIn++;
            *pszOut++ = '&';
            *pszOut++ = 'q';
            *pszOut++ = 'u';
            *pszOut++ = 'o';
            *pszOut++ = 't';
            *pszOut++ = ';';
        }
        else if (*pszIn == '\'') {
            if (pszOut + 6 > pszEnd) {
                break;
            }
            pszIn++;
            *pszOut++ = '&';
            *pszOut++ = 'a';
            *pszOut++ = 'p';
            *pszOut++ = 'o';
            *pszOut++ = 's';
            *pszOut++ = ';';
        }
        else if (*pszIn < ' ' || *pszIn > 127) {
            WCHAR c = *pszIn++;
            if (c < 10 && pszOut + 4 <= pszEnd) {
                *pszOut++ = '&';
                *pszOut++ = '#';
                *pszOut++ = '0' + (CHAR)(c % 10);
                *pszOut++ = ';';
            }
            else if (c < 100 && pszOut + 5 <= pszEnd) {
                *pszOut++ = '&';
                *pszOut++ = '#';
                *pszOut++ = '0' + (CHAR)((c / 10) % 10);
                *pszOut++ = '0' + (CHAR)(c % 10);
                *pszOut++ = ';';
            }
            else if (c < 1000 && pszOut + 6 <= pszEnd) {
                *pszOut++ = '&';
                *pszOut++ = '#';
                *pszOut++ = '0' + (CHAR)((c / 100) % 10);
                *pszOut++ = '0' + (CHAR)((c / 10) % 10);
                *pszOut++ = '0' + (CHAR)(c % 10);
                *pszOut++ = ';';
            }
            else {
                break;
            }
        }
        else {
            *pszOut++ = (CHAR)*pszIn++;
        }
    }
    *pszOut = '\0';
    return pszOut;
}

#if _MSC_VER >= 1900
#pragma warning(push)
#pragma warning(disable:4456) // declaration hides previous local declaration
#endif

VOID VSafePrintf(PCSTR pszMsg, va_list args, PCHAR pszBuffer, LONG cbBuffer)
{
    PCHAR pszOut = pszBuffer;
    PCHAR pszEnd = pszBuffer + cbBuffer - 1;
    pszBuffer[0] = '\0';

    __try {
        while (*pszMsg && pszOut < pszEnd) {
            if (*pszMsg == '%') {
                CHAR szHead[4] = "";
                INT nLen;
                INT nWidth = 0;
                INT nPrecision = 0;
                BOOL fLeft = FALSE;
                BOOL fPositive = FALSE;
                BOOL fPound = FALSE;
                BOOL fBlank = FALSE;
                BOOL fZero = FALSE;
                BOOL fDigit = FALSE;
                BOOL fSmall = FALSE;
                BOOL fLarge = FALSE;
                BOOL f64Bit = FALSE;
                PCSTR pszArg = pszMsg;

                pszMsg++;

                for (; (*pszMsg == '-' ||
                    *pszMsg == '+' ||
                    *pszMsg == '#' ||
                    *pszMsg == ' ' ||
                    *pszMsg == '0'); pszMsg++) {
                    switch (*pszMsg) {
                    case '-': fLeft = TRUE; break;
                    case '+': fPositive = TRUE; break;
                    case '#': fPound = TRUE; break;
                    case ' ': fBlank = TRUE; break;
                    case '0': fZero = TRUE; break;
                    }
                }

                if (*pszMsg == '*') {
                    nWidth = va_arg(args, INT);
                    pszMsg++;
                }
                else {
                    while (*pszMsg >= '0' && *pszMsg <= '9') {
                        nWidth = nWidth * 10 + (*pszMsg++ - '0');
                    }
                }
                if (*pszMsg == '.') {
                    pszMsg++;
                    fDigit = TRUE;
                    if (*pszMsg == '*') {
                        nPrecision = va_arg(args, INT);
                        pszMsg++;
                    }
                    else {
                        while (*pszMsg >= '0' && *pszMsg <= '9') {
                            nPrecision = nPrecision * 10 + (*pszMsg++ - '0');
                        }
                    }
                }

                if (*pszMsg == 'h') {
                    fSmall = TRUE;
                    pszMsg++;
                }
                else if (*pszMsg == 'l') {
                    fLarge = TRUE;
                    pszMsg++;
                }
                else if (*pszMsg == 'I' && pszMsg[1] == '6' && pszMsg[2] == '4') {
                    f64Bit = TRUE;
                    pszMsg += 3;
                }

                if (*pszMsg == 's' || *pszMsg == 'e' || *pszMsg == 'c') {
                    // We ignore the length, precision, and alignment
                    // to avoid using a temporary buffer.

                    if (*pszMsg == 's') { // [GalenH] need to not use temp.
                        PVOID pvData = va_arg(args, PVOID);

                        pszMsg++;

                        if (fSmall) {
                            fLarge = FALSE;
                        }

                        __try {
                            if (pvData == NULL) {
                                pszOut = do_str(pszOut, pszEnd, "<NULL>");
                            }
                            else if (pvData < (PVOID)0x10000) {
                                pszOut = do_str(pszOut, pszEnd, "#");
                                pszOut = do_base(pszOut, (UINT64)pvData, 16,
                                    "0123456789ABCDEF");
                                pszOut = do_str(pszOut, pszEnd, "#");
                            }
                            else if (fLarge) {
                                pszOut = do_wstr(pszOut, pszEnd, (PWCHAR)pvData);
                            }
                            else {
                                pszOut = do_str(pszOut, pszEnd, (PCHAR)pvData);
                            }
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {
                            pszOut = do_str(pszOut, pszEnd, "-");
                            pszOut = do_base(pszOut, (UINT64)pvData, 16,
                                "0123456789ABCDEF");
                            pszOut = do_str(pszOut, pszEnd, "-");
                        }
                    }
                    else if (*pszMsg == 'e') {   // Escape the string.
                        PVOID pvData = va_arg(args, PVOID);

                        pszMsg++;

                        if (fSmall) {
                            fLarge = FALSE;
                        }

                        __try {
                            if (pvData == NULL) {
                                pszOut = do_str(pszOut, pszEnd, "<NULL>");
                            }
                            else if (pvData < (PVOID)0x10000) {
                                pszOut = do_str(pszOut, pszEnd, ">");
                                pszOut = do_base(pszOut, (UINT64)pvData, 16,
                                    "0123456789ABCDEF");
                                pszOut = do_str(pszOut, pszEnd, ">");
                            }
                            else if (fLarge) {
                                pszOut = do_ewstr(pszOut, pszEnd, (PWCHAR)pvData);
                            }
                            else {
                                pszOut = do_estr(pszOut, pszEnd, (PCHAR)pvData);
                            }
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {
                            pszOut = do_str(pszOut, pszEnd, "-");
                            pszOut = do_base(pszOut, (UINT64)pvData, 16,
                                "0123456789ABCDEF");
                            pszOut = do_str(pszOut, pszEnd, "-");
                        }
                    }
                    else {
                        CHAR szTemp[2];
                        pszMsg++;

                        szTemp[0] = (CHAR)va_arg(args, INT);
                        szTemp[1] = '\0';
                        pszOut = do_str(pszOut, pszEnd, szTemp);
                    }
                }
                else if (*pszMsg == 'd' || *pszMsg == 'i' || *pszMsg == 'o' ||
                    *pszMsg == 'x' || *pszMsg == 'X' || *pszMsg == 'b' ||
                    *pszMsg == 'u') {
                    CHAR szTemp[128];
                    UINT64 value;
                    if (f64Bit) {
                        value = va_arg(args, UINT64);
                    }
                    else {
                        value = va_arg(args, UINT);
                    }

                    if (*pszMsg == 'x') {
                        pszMsg++;
                        nLen = (int)(do_base(szTemp, value, 16, "0123456789abcdef") - szTemp);
                        if (fPound && value) {
                            do_str(szHead, szHead + sizeof(szHead) - 1, "0x");
                        }
                    }
                    else if (*pszMsg == 'X') {
                        pszMsg++;
                        nLen = (int)(do_base(szTemp, value, 16, "0123456789ABCDEF") - szTemp);
                        if (fPound && value) {
                            do_str(szHead, szHead + sizeof(szHead) - 1, "0X");
                        }
                    }
                    else if (*pszMsg == 'd') {
                        pszMsg++;
                        if ((INT64)value < 0) {
                            value = -(INT64)value;
                            do_str(szHead, szHead + sizeof(szHead) - 1, "-");
                        }
                        else if (fPositive) {
                            if (value > 0) {
                                do_str(szHead, szHead + sizeof(szHead) - 1, "+");
                            }
                        }
                        else if (fBlank) {
                            if (value > 0) {
                                do_str(szHead, szHead + sizeof(szHead) - 1, " ");
                            }
                        }
                        nLen = (int)(do_base(szTemp, value, 10, "0123456789") - szTemp);
                        nPrecision = 0;
                    }
                    else if (*pszMsg == 'u') {
                        pszMsg++;
                        nLen = (int)(do_base(szTemp, value, 10, "0123456789") - szTemp);
                        nPrecision = 0;
                    }
                    else if (*pszMsg == 'o') {
                        pszMsg++;
                        nLen = (int)(do_base(szTemp, value, 8, "01234567") - szTemp);
                        nPrecision = 0;

                        if (fPound && value) {
                            do_str(szHead, szHead + sizeof(szHead) - 1, "0");
                        }
                    }
                    else if (*pszMsg == 'b') {
                        pszMsg++;
                        nLen = (int)(do_base(szTemp, value, 2, "01") - szTemp);
                        nPrecision = 0;

                        if (fPound && value) {
                            do_str(szHead, szHead + sizeof(szHead) - 1, "0b");
                        }
                    }
                    else {
                        pszMsg++;
                        if ((INT64)value < 0) {
                            value = -(INT64)value;
                            do_str(szHead, szHead + sizeof(szHead) - 1, "-");
                        }
                        else if (fPositive) {
                            if (value > 0) {
                                do_str(szHead, szHead + sizeof(szHead) - 1, "+");
                            }
                        }
                        else if (fBlank) {
                            if (value > 0) {
                                do_str(szHead, szHead + sizeof(szHead) - 1, " ");
                            }
                        }
                        nLen = (int)(do_base(szTemp, value, 10, "0123456789") - szTemp);
                        nPrecision = 0;
                    }

                    INT nHead = 0;
                    for (; szHead[nHead]; nHead++) {
                        // Count characters in head string.
                    }

                    if (fLeft) {
                        if (nHead) {
                            pszOut = do_str(pszOut, pszEnd, szHead);
                            nLen += nHead;
                        }
                        pszOut = do_str(pszOut, pszEnd, szTemp);
                        for (; nLen < nWidth && pszOut < pszEnd; nLen++) {
                            *pszOut++ = ' ';
                        }
                    }
                    else if (fZero) {
                        if (nHead) {
                            pszOut = do_str(pszOut, pszEnd, szHead);
                            nLen += nHead;
                        }
                        for (; nLen < nWidth && pszOut < pszEnd; nLen++) {
                            *pszOut++ = '0';
                        }
                        pszOut = do_str(pszOut, pszEnd, szTemp);
                    }
                    else {
                        if (nHead) {
                            nLen += nHead;
                        }
                        for (; nLen < nWidth && pszOut < pszEnd; nLen++) {
                            *pszOut++ = ' ';
                        }
                        if (nHead) {
                            pszOut = do_str(pszOut, pszEnd, szHead);
                        }
                        pszOut = do_str(pszOut, pszEnd, szTemp);
                    }
                }
                else if (*pszMsg == 'p') {
                    CHAR szTemp[64];
                    ULONG_PTR value;
                    value = va_arg(args, ULONG_PTR);

                    if ((INT64)value == (INT64)-1 ||
                        (INT64)value == (INT64)-2) {
                        if (*pszMsg == 'p') {
                            pszMsg++;
                        }
                        szTemp[0] = '-';
                        szTemp[1] = ((INT64)value == (INT64)-1) ? '1' : '2';
                        szTemp[2] = '\0';
                        nLen = 2;
                    }
                    else {
                        if (*pszMsg == 'p') {
                            pszMsg++;
                            nLen = (int)(do_base(szTemp, (UINT64)value, 16, "0123456789abcdef") - szTemp);
                            if (fPound && value) {
                                do_str(szHead, szHead + sizeof(szHead) - 1, "0x");
                            }
                        }
                        else {
                            pszMsg++;
                            nLen = (int)(do_base(szTemp, (UINT64)value, 16, "0123456789ABCDEF") - szTemp);
                            if (fPound && value) {
                                do_str(szHead, szHead + sizeof(szHead) - 1, "0x");
                            }
                        }
                    }

                    INT nHead = 0;
                    for (; szHead[nHead]; nHead++) {
                        // Count characters in head string.
                    }

                    if (nHead) {
                        pszOut = do_str(pszOut, pszEnd, szHead);
                        nLen += nHead;
                    }
                    for (; nLen < nWidth && pszOut < pszEnd; nLen++) {
                        *pszOut++ = '0';
                    }
                    pszOut = do_str(pszOut, pszEnd, szTemp);
                }
                else {
                    pszMsg++;
                    while (pszArg < pszMsg && pszOut < pszEnd) {
                        *pszOut++ = *pszArg++;
                    }
                }
            }
            else {
                if (pszOut < pszEnd) {
                    *pszOut++ = *pszMsg++;
                }
            }
        }
        *pszOut = '\0';
        pszBuffer[cbBuffer - 1] = '\0';
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        PCHAR pszOut = pszBuffer;
        *pszOut = '\0';
        pszOut = do_str(pszOut, pszEnd, "-exception:");
        pszOut = do_base(pszOut, (UINT64)GetExceptionCode(), 10, "0123456789");
        pszOut = do_str(pszOut, pszEnd, "-");
    }
}

#if _MSC_VER >= 1900
#pragma warning(pop)
#endif

PCHAR SafePrintf(PCHAR pszBuffer, LONG cbBuffer, PCSTR pszMsg, ...)
{
    va_list args;
    va_start(args, pszMsg);
    VSafePrintf(pszMsg, args, pszBuffer, cbBuffer);
    va_end(args);

    while (*pszBuffer) {
        pszBuffer++;
    }
    return pszBuffer;
}

//////////////////////////////////////////////////////////////////////////////
//
static CRITICAL_SECTION s_csPipe;                       // Guards access to hPipe.
static HANDLE           s_hPipe = INVALID_HANDLE_VALUE;
static DWORD            s_nPipeError = 0;
static FILETIME         s_ftRetry = { 0,0 };
static BYTE             s_nFacility = SYELOG_FACILITY_APPLICATION;
static CHAR             s_szIdent[256] = "";
static DWORD            s_nProcessId = 0;

static inline INT syelogCompareTimes(CONST PFILETIME pft1, CONST PFILETIME pft2)
{
    INT64 ut1 = *(PINT64)pft1;
    INT64 ut2 = *(PINT64)pft2;

    if (ut1 < ut2) {
        return -1;
    }
    else if (ut1 > ut2) {
        return 1;
    }
    else {
        return 0;
    }
}

static inline VOID syelogAddMilliseconds(PFILETIME pft, DWORD nMilliseconds)
{
    *(PINT64&)pft += ((INT64)nMilliseconds * 10000);
}

//////////////////////////////////////////////////////////////////////////////
// Tries to insure that a named-pipe connection to the system log is open
// If the pipe closes, the next call will immediately try to re-open the pipe.
// If the pipe doesn't open again, we wait 5 minutes before trying again.
// We wait 5 minutes, because each attempt may take up to a full second to
// time out.
//
static BOOL syelogIsOpen(PFILETIME pftLog)
{
    if (s_hPipe != INVALID_HANDLE_VALUE) {
        return TRUE;
    }

    if (syelogCompareTimes(pftLog, &s_ftRetry) < 0) {
        return FALSE;
    }

    s_hPipe = Real_CreateFileW(SYELOG_PIPE_NAMEW,
        GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        SECURITY_ANONYMOUS, NULL);
    if (s_hPipe != INVALID_HANDLE_VALUE) {
        DWORD dwMode = PIPE_READMODE_MESSAGE;
        if (Real_SetNamedPipeHandleState(s_hPipe, &dwMode, NULL, NULL)) {
            return TRUE;
        }
    }

    if (Real_WaitNamedPipeW(SYELOG_PIPE_NAMEW, 2000)) { // Wait 2 seconds.
        // Pipe connected, change to message-read mode.
        //
        s_hPipe = Real_CreateFileW(SYELOG_PIPE_NAMEW,
            GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
            SECURITY_ANONYMOUS, NULL);
        if (s_hPipe != INVALID_HANDLE_VALUE) {
            DWORD dwMode = PIPE_READMODE_MESSAGE;
            if (Real_SetNamedPipeHandleState(s_hPipe, &dwMode, NULL, NULL)) {
                return TRUE;
            }
        }
    }

    // Couldn't open pipe.
    s_ftRetry = *pftLog;
    syelogAddMilliseconds(&s_ftRetry, 300000);           // Wait 5 minute before retry.

    return FALSE;
}

VOID SyelogOpen(PCSTR pszIdentifier, BYTE nFacility)
{
    Real_InitializeCriticalSection(&s_csPipe);

    if (pszIdentifier) {
        PCHAR pszOut = s_szIdent;
        PCHAR pszEnd = s_szIdent + ARRAYSIZE(s_szIdent) - 1;
        pszOut = do_str(pszOut, pszEnd, pszIdentifier);
        pszOut = do_str(pszOut, pszEnd, ": ");
        *pszEnd = '\0';
    }
    else {
        s_szIdent[0] = '\0';
    }

    s_nFacility = nFacility;
    s_nProcessId = Real_GetCurrentProcessId();
}

VOID SyelogExV(BOOL fTerminate, BYTE nSeverity, PCSTR pszMsgf, va_list args)
{
    SYELOG_MESSAGE Message;
    DWORD cbWritten = 0;

    Real_GetSystemTimeAsFileTime(&Message.ftOccurance);
    Message.fTerminate = fTerminate;
    Message.nFacility = s_nFacility;
    Message.nSeverity = nSeverity;
    Message.nProcessId = s_nProcessId;
    PCHAR pszBuf = Message.szMessage;
    PCHAR pszEnd = Message.szMessage + ARRAYSIZE(Message.szMessage) - 1;
    if (s_szIdent[0]) {
        pszBuf = do_str(pszBuf, pszEnd, s_szIdent);
    }
    *pszEnd = '\0';
    VSafePrintf(pszMsgf, args,
        pszBuf, (int)(Message.szMessage + sizeof(Message.szMessage) - 1 - pszBuf));

    pszEnd = Message.szMessage;
    for (; *pszEnd; pszEnd++) {
        // no internal contents.
    }

    // Insure that the message always ends with a '\n'
    //
    if (pszEnd > Message.szMessage) {
        if (pszEnd[-1] != '\n') {
            *pszEnd++ = '\n';
            *pszEnd++ = '\0';
        }
        else {
            *pszEnd++ = '\0';
        }
    }
    else {
        *pszEnd++ = '\n';
        *pszEnd++ = '\0';
    }
    Message.nBytes = (USHORT)(pszEnd - ((PCSTR)&Message));

    Real_EnterCriticalSection(&s_csPipe);

    if (syelogIsOpen(&Message.ftOccurance)) {
        if (!Real_WriteFile(s_hPipe, &Message, Message.nBytes, &cbWritten, NULL)) {
            s_nPipeError = GetLastError();
            if (s_nPipeError == ERROR_BAD_IMPERSONATION_LEVEL) {
                // Don't close the file just for a temporary impersonation level.
            }
            else {
                if (s_hPipe != INVALID_HANDLE_VALUE) {
                    Real_CloseHandle(s_hPipe);
                    s_hPipe = INVALID_HANDLE_VALUE;
                }
                if (syelogIsOpen(&Message.ftOccurance)) {
                    Real_WriteFile(s_hPipe, &Message, Message.nBytes, &cbWritten, NULL);
                }
            }
        }
    }

    Real_LeaveCriticalSection(&s_csPipe);
}

VOID SyelogV(BYTE nSeverity, PCSTR pszMsgf, va_list args)
{
    SyelogExV(FALSE, nSeverity, pszMsgf, args);
}

VOID Syelog(BYTE nSeverity, PCSTR pszMsgf, ...)
{
    va_list args;
    va_start(args, pszMsgf);
    SyelogExV(FALSE, nSeverity, pszMsgf, args);
    va_end(args);
}

VOID SyelogEx(BOOL fTerminate, BYTE nSeverity, PCSTR pszMsgf, ...)
{
    va_list args;
    va_start(args, pszMsgf);
    SyelogExV(fTerminate, nSeverity, pszMsgf, args);
    va_end(args);
}

VOID SyelogClose(BOOL fTerminate)
{
    if (fTerminate) {
        SyelogEx(TRUE, SYELOG_SEVERITY_NOTICE, "Requesting exit on close.\n");
    }

    Real_EnterCriticalSection(&s_csPipe);

    if (s_hPipe != INVALID_HANDLE_VALUE) {
        Real_FlushFileBuffers(s_hPipe);
        Real_CloseHandle(s_hPipe);
        s_hPipe = INVALID_HANDLE_VALUE;
    }

    Real_LeaveCriticalSection(&s_csPipe);
}
#endif 

//////////////////////////////////////////////////////////////////////////////
// 
extern "C" {
    HANDLE(WINAPI*
        Real_CreateFileW)(LPCWSTR a0,
            DWORD a1,
            DWORD a2,
            LPSECURITY_ATTRIBUTES a3,
            DWORD a4,
            DWORD a5,
            HANDLE a6)
        = CreateFileW;

    BOOL(WINAPI*
        Real_WriteFile)(HANDLE hFile,
            LPCVOID lpBuffer,
            DWORD nNumberOfBytesToWrite,
            LPDWORD lpNumberOfBytesWritten,
            LPOVERLAPPED lpOverlapped)
        = WriteFile;
    BOOL(WINAPI*
        Real_FlushFileBuffers)(HANDLE hFile)
        = FlushFileBuffers;
    BOOL(WINAPI*
        Real_CloseHandle)(HANDLE hObject)
        = CloseHandle;

    BOOL(WINAPI*
        Real_WaitNamedPipeW)(LPCWSTR lpNamedPipeName, DWORD nTimeOut)
        = WaitNamedPipeW;
    BOOL(WINAPI*
        Real_SetNamedPipeHandleState)(HANDLE hNamedPipe,
            LPDWORD lpMode,
            LPDWORD lpMaxCollectionCount,
            LPDWORD lpCollectDataTimeout)
        = SetNamedPipeHandleState;

    DWORD(WINAPI*
        Real_GetCurrentProcessId)(VOID)
        = GetCurrentProcessId;
    VOID(WINAPI*
        Real_GetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime)
        = GetSystemTimeAsFileTime;

    VOID(WINAPI*
        Real_InitializeCriticalSection)(LPCRITICAL_SECTION lpSection)
        = InitializeCriticalSection;
    VOID(WINAPI*
        Real_EnterCriticalSection)(LPCRITICAL_SECTION lpSection)
        = EnterCriticalSection;
    VOID(WINAPI*
        Real_LeaveCriticalSection)(LPCRITICAL_SECTION lpSection)
        = LeaveCriticalSection;
}

//////////////////////////////////////////////////////////////////////////////
// File related function assignments
#if 1 
BOOL(WINAPI* Real_CopyFileExA)(LPCSTR a0,
    LPCSTR a1,
    LPPROGRESS_ROUTINE a2,
    LPVOID a3,
    LPBOOL a4,
    DWORD a5)
    = CopyFileExA;

BOOL(WINAPI* Real_CopyFileExW)(LPCWSTR a0,
    LPCWSTR a1,
    LPPROGRESS_ROUTINE a2,
    LPVOID a3,
    LPBOOL a4,
    DWORD a5)
    = CopyFileExW;

BOOL(WINAPI* Real_CreateDirectoryExW)(LPCWSTR a0,
    LPCWSTR a1,
    LPSECURITY_ATTRIBUTES a2)
    = CreateDirectoryExW;

BOOL(WINAPI* Real_CreateDirectoryW)(LPCWSTR a0,
    LPSECURITY_ATTRIBUTES a1)
    = CreateDirectoryW;

BOOL(WINAPI* Real_CreateProcessW)(LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
    = CreateProcessW;

BOOL(WINAPI* Real_DeleteFileA)(LPCSTR a0)
= DeleteFileA;

BOOL(WINAPI* Real_DeleteFileW)(LPCWSTR a0)
= DeleteFileW;

HANDLE(WINAPI* Real_FindFirstFileExA)(LPCSTR a0,
    FINDEX_INFO_LEVELS a1,
    LPVOID a2,
    FINDEX_SEARCH_OPS a3,
    LPVOID a4,
    DWORD a5)
    = FindFirstFileExA;

HANDLE(WINAPI* Real_FindFirstFileExW)(LPCWSTR a0,
    FINDEX_INFO_LEVELS a1,
    LPVOID a2,
    FINDEX_SEARCH_OPS a3,
    LPVOID a4,
    DWORD a5)
    = FindFirstFileExW;

DWORD(WINAPI* Real_GetFileAttributesW)(LPCWSTR a0)
= GetFileAttributesW;

DWORD(WINAPI* Real_GetModuleFileNameW)(HMODULE a0,
    LPWSTR a1,
    DWORD a2)
    = GetModuleFileNameW;

DWORD(WINAPI* Real_GetModuleFileNameA)(HMODULE a0,
    LPSTR a1,
    DWORD a2)
    = GetModuleFileNameA;

FARPROC(WINAPI* Real_GetProcAddress)(struct HINSTANCE__* a0,
    LPCSTR a1)
    = GetProcAddress;

HMODULE(WINAPI* Real_LoadLibraryExW)(LPCWSTR a0,
    HANDLE a1,
    DWORD a2)
    = LoadLibraryExW;

BOOL(WINAPI* Real_MoveFileA)(LPCSTR a0,
    LPCSTR a1)
    = MoveFileA;

BOOL(WINAPI* Real_MoveFileExA)(LPCSTR a0,
    LPCSTR a1,
    DWORD a2)
    = MoveFileExA;

BOOL(WINAPI* Real_MoveFileExW)(LPCWSTR a0,
    LPCWSTR a1,
    DWORD a2)
    = MoveFileExW;

BOOL(WINAPI* Real_MoveFileW)(LPCWSTR a0,
    LPCWSTR a1)
    = MoveFileW;

HFILE(WINAPI* Real_OpenFile)(LPCSTR a0,
    struct _OFSTRUCT* a1,
    UINT a2)
    = OpenFile;
#endif

//////////////////////////////////////////////////////////////////////////////
// Registry related function assignments
#if 1
LONG(WINAPI* Real_RegCreateKeyExA)(HKEY a0,
    LPCSTR a1,
    DWORD a2,
    LPSTR a3,
    DWORD a4,
    REGSAM a5,
    LPSECURITY_ATTRIBUTES a6,
    PHKEY a7,
    LPDWORD a8)
    = RegCreateKeyExA;

LONG(WINAPI* Real_RegCreateKeyExW)(HKEY a0,
    LPCWSTR a1,
    DWORD a2,
    LPWSTR a3,
    DWORD a4,
    REGSAM a5,
    LPSECURITY_ATTRIBUTES a6,
    PHKEY a7,
    LPDWORD a8)
    = RegCreateKeyExW;

LONG(WINAPI* Real_RegDeleteKeyA)(HKEY a0,
    LPCSTR a1)
    = RegDeleteKeyA;

LONG(WINAPI* Real_RegDeleteKeyW)(HKEY a0,
    LPCWSTR a1)
    = RegDeleteKeyW;

LONG(WINAPI* Real_RegDeleteValueA)(HKEY a0,
    LPCSTR a1)
    = RegDeleteValueA;


LONG(WINAPI* Real_RegDeleteValueW)(HKEY a0,
    LPCWSTR a1)
    = RegDeleteValueW;

LONG(WINAPI* Real_RegEnumKeyExA)(HKEY a0,
    DWORD a1,
    LPSTR a2,
    LPDWORD a3,
    LPDWORD a4,
    LPSTR a5,
    LPDWORD a6,
    struct _FILETIME* a7)
    = RegEnumKeyExA;

LONG(WINAPI* Real_RegEnumKeyExW)(HKEY a0,
    DWORD a1,
    LPWSTR a2,
    LPDWORD a3,
    LPDWORD a4,
    LPWSTR a5,
    LPDWORD a6,
    struct _FILETIME* a7)
    = RegEnumKeyExW;

LONG(WINAPI* Real_RegEnumValueA)(HKEY a0,
    DWORD a1,
    LPSTR a2,
    LPDWORD a3,
    LPDWORD a4,
    LPDWORD a5,
    LPBYTE a6,
    LPDWORD a7)
    = RegEnumValueA;

LONG(WINAPI* Real_RegEnumValueW)(HKEY a0,
    DWORD a1,
    LPWSTR a2,
    LPDWORD a3,
    LPDWORD a4,
    LPDWORD a5,
    LPBYTE a6,
    LPDWORD a7)
    = RegEnumValueW;

LONG(WINAPI* Real_RegOpenKeyExA)(HKEY a0,
    LPCSTR a1,
    DWORD a2,
    REGSAM a3,
    PHKEY a4)
    = RegOpenKeyExA;

LONG(WINAPI* Real_RegOpenKeyExW)(HKEY a0,
    LPCWSTR a1,
    DWORD a2,
    REGSAM a3,
    PHKEY a4)
    = RegOpenKeyExW;

LONG(WINAPI* Real_RegQueryInfoKeyA)(HKEY a0,
    LPSTR a1,
    LPDWORD a2,
    LPDWORD a3,
    LPDWORD a4,
    LPDWORD a5,
    LPDWORD a6,
    LPDWORD a7,
    LPDWORD a8,
    LPDWORD a9,
    LPDWORD a10,
    struct _FILETIME* a11)
    = RegQueryInfoKeyA;

LONG(WINAPI* Real_RegQueryInfoKeyW)(HKEY a0,
    LPWSTR a1,
    LPDWORD a2,
    LPDWORD a3,
    LPDWORD a4,
    LPDWORD a5,
    LPDWORD a6,
    LPDWORD a7,
    LPDWORD a8,
    LPDWORD a9,
    LPDWORD a10,
    struct _FILETIME* a11)
    = RegQueryInfoKeyW;

LONG(WINAPI* Real_RegQueryValueExA)(HKEY a0,
    LPCSTR a1,
    LPDWORD a2,
    LPDWORD a3,
    LPBYTE a4,
    LPDWORD a5)
    = RegQueryValueExA;

LONG(WINAPI* Real_RegQueryValueExW)(HKEY a0,
    LPCWSTR a1,
    LPDWORD a2,
    LPDWORD a3,
    LPBYTE a4,
    LPDWORD a5)
    = RegQueryValueExW;

LONG(WINAPI* Real_RegSetValueExA)(HKEY a0,
    LPCSTR a1,
    DWORD a2,
    DWORD a3,
    const BYTE* a4,
    DWORD a5)
    = RegSetValueExA;

LONG(WINAPI* Real_RegSetValueExW)(HKEY a0,
    LPCWSTR a1,
    DWORD a2,
    DWORD a3,
    const BYTE* a4,
    DWORD a5)
    = RegSetValueExW;
#endif 

HFILE(WINAPI* Real__lcreat)(LPCSTR a0,
    int a1)
    = _lcreat;

HFILE(WINAPI* Real__lopen)(LPCSTR a0,
    int a1)
    = _lopen;

//////////////////////////////////////////////////////////////////////////////
// MS related detours
#if 1
BOOL WINAPI Mine_WaitNamedPipeW(LPCWSTR lpNamedPipeName, DWORD nTimeOut)
{
    return Real_WaitNamedPipeW(lpNamedPipeName, nTimeOut);
}

BOOL WINAPI Mine_CloseHandle(HANDLE hObject)
{
    return Real_CloseHandle(hObject);
}

VOID WINAPI Mine_GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
{
    Real_GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
}

BOOL WINAPI Mine_SetNamedPipeHandleState(HANDLE hNamedPipe,
    LPDWORD lpMode,
    LPDWORD lpMaxCollectionCount,
    LPDWORD lpCollectDataTimeout)
{
    return Real_SetNamedPipeHandleState(hNamedPipe,
        lpMode,
        lpMaxCollectionCount,
        lpCollectDataTimeout);
}

BOOL WINAPI Mine_WriteFile(HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped)
{
    return Real_WriteFile(hFile,
        lpBuffer,
        nNumberOfBytesToWrite,
        lpNumberOfBytesWritten,
        lpOverlapped);
}

BOOL WINAPI Mine_CreateProcessW(LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    _PrintEnter("CreateProcessW(%ls,%ls,%p,%p,%x,%x,%p,%ls,%p,%p)\n",
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);

    _Print("Calling DetourCreateProcessWithDllExW(,%hs)\n", s_szDllPath);

    BOOL rv = 0;
    __try {
        rv = DetourCreateProcessWithDllExW(lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation,
            s_szDllPath,
            Real_CreateProcessW);
    }
    __finally {
        _PrintExit("CreateProcessW(,,,,,,,,,) -> %x\n", rv);
    };
    return rv;
}

BOOL WINAPI Mine_CopyFileExA(LPCSTR a0,
    LPCSTR a1,
    LPPROGRESS_ROUTINE a2,
    LPVOID a3,
    LPBOOL a4,
    DWORD a5)
{
    _PrintEnter("CopyFileExA(%hs,%hs,%p,%p,%p,%x)\n", a0, a1, a2, a3, a4, a5);

    BOOL rv = 0;
    __try {
        rv = Real_CopyFileExA(a0, a1, a2, a3, a4, a5);
    }
    __finally {
        _PrintExit("CopyFileExA(,,,,,) -> %x\n", rv);
    };
    return rv;
}

BOOL WINAPI Mine_CopyFileExW(LPCWSTR a0,
    LPCWSTR a1,
    LPPROGRESS_ROUTINE a2,
    LPVOID a3,
    LPBOOL a4,
    DWORD a5)
{
    _PrintEnter("CopyFileExW(%ls,%ls,%p,%p,%p,%x)\n", a0, a1, a2, a3, a4, a5);

    BOOL rv = 0;
    __try {
        rv = Real_CopyFileExW(a0, a1, a2, a3, a4, a5);
    }
    __finally {
        _PrintExit("CopyFileExW(,,,,,) -> %x\n", rv);
    };
    return rv;
}

BOOL WINAPI Mine_CreateDirectoryExW(LPCWSTR a0,
    LPCWSTR a1,
    LPSECURITY_ATTRIBUTES a2)
{
    _PrintEnter("CreateDirectoryExW(%ls,%ls,%p)\n", a0, a1, a2);

    BOOL rv = 0;
    __try {
        rv = Real_CreateDirectoryExW(a0, a1, a2);
    }
    __finally {
        _PrintExit("CreateDirectoryExW(,,) -> %x\n", rv);
    };
    return rv;
}

BOOL WINAPI Mine_CreateDirectoryW(LPCWSTR a0,
    LPSECURITY_ATTRIBUTES a1)
{
    _PrintEnter("CreateDirectoryW(%ls,%p)\n", a0, a1);

    BOOL rv = 0;
    __try {
        rv = Real_CreateDirectoryW(a0, a1);
    }
    __finally {
        _PrintExit("CreateDirectoryW(,) -> %x\n", rv);
    };
    return rv;
}

HANDLE WINAPI Mine_CreateFileW(LPCWSTR a0,
    DWORD a1,
    DWORD a2,
    LPSECURITY_ATTRIBUTES a3,
    DWORD a4,
    DWORD a5,
    HANDLE a6)
{
    _PrintEnter(NULL);
    HANDLE rv = 0;
    __try {
        rv = Real_CreateFileW(a0, a1, a2, a3, a4, a5, a6);
    }
    __finally {
        _PrintExit("CreateFileW(%ls,%x,%x,%p,%x,%x,%p) -> %p\n",
            a0, a1, a2, a3, a4, a5, a6, rv);
    };
    return rv;
}

BOOL WINAPI Mine_DeleteFileA(LPCSTR a0)
{
    _PrintEnter("DeleteFileA(%hs)\n", a0);

    BOOL rv = 0;
    __try {
        rv = Real_DeleteFileA(a0);
    }
    __finally {
        _PrintExit("DeleteFileA() -> %x\n", rv);
    };
    return rv;
}

BOOL WINAPI Mine_DeleteFileW(LPCWSTR a0)
{
    _PrintEnter("DeleteFileW(%ls)\n", a0);

    BOOL rv = 0;
    __try {
        rv = Real_DeleteFileW(a0);
    }
    __finally {
        _PrintExit("DeleteFileW() -> %x\n", rv);
    };
    return rv;
}

HANDLE WINAPI Mine_FindFirstFileExA(LPCSTR a0,
    FINDEX_INFO_LEVELS a1,
    LPVOID a2,
    FINDEX_SEARCH_OPS a3,
    LPVOID a4,
    DWORD a5)
{
    _PrintEnter("FindFirstFileExA(%hs,%p,%p,%x,%p,%x)\n", a0, a1, a2, a3, a4, a5);

    HANDLE rv = 0;
    __try {
        rv = Real_FindFirstFileExA(a0, a1, a2, a3, a4, a5);
    }
    __finally {
        _PrintExit("FindFirstFileExA(,,,,,) -> %p\n", rv);
    };
    return rv;
}

HANDLE WINAPI Mine_FindFirstFileExW(LPCWSTR a0,
    FINDEX_INFO_LEVELS a1,
    LPVOID a2,
    FINDEX_SEARCH_OPS a3,
    LPVOID a4,
    DWORD a5)
{
    _PrintEnter(NULL);

    HANDLE rv = 0;
    __try {
        rv = Real_FindFirstFileExW(a0, a1, a2, a3, a4, a5);
    }
    __finally {
        _PrintExit("FindFirstFileExW(%ls,%x,%p,%x,%p,%x) -> %p\n",
            a0, a1, a2, a3, a4, a5, rv);
    };
    return rv;
}

DWORD WINAPI Mine_GetFileAttributesW(LPCWSTR a0)
{
    _PrintEnter(NULL);

    DWORD rv = 0;
    __try {
        rv = Real_GetFileAttributesW(a0);
    }
    __finally {
        _PrintExit("GetFileAttributesW(%ls) -> %x\n", a0, rv);
    };
    return rv;
}

DWORD WINAPI Mine_GetModuleFileNameW(HMODULE a0, LPWSTR a1, DWORD a2)
{
    _PrintEnter("GetModuleFileNameW(%p,%p,%x)\n", a0, a1, a2);
    DWORD rv = 0;
    __try {
        rv = Real_GetModuleFileNameW(a0, a1, a2);
    }
    __finally {
        _PrintExit("GetModuleFileNameW(%p,%p:%ls,%p) -> %p\n", a0, a1, a1, a2, rv);
    };
    return rv;
}

FARPROC WINAPI Mine_GetProcAddress(HINSTANCE a0,
    LPCSTR a1)
{
    WCHAR wzModule[MAX_PATH] = L"";
    PWCHAR pwzModule = wzModule;
    if (Real_GetModuleFileNameW(a0, wzModule, ARRAYSIZE(wzModule)) != 0) {
        if ((pwzModule = wcsrchr(wzModule, '\\')) == NULL) {
            if ((pwzModule = wcsrchr(wzModule, ':')) == NULL) {
                pwzModule = wzModule;
            }
            else {
                pwzModule++;                            // Skip ':'
            }
        }
        else {
            pwzModule++;                                // Skip '\\'
        }
    }
    else {
        wzModule[0] = '\0';
    }

    _PrintEnter(NULL);
    FARPROC rv = 0;
    __try {
        rv = Real_GetProcAddress(a0, a1);
    }
    __finally {
        if (pwzModule[0] == 0) {
            _PrintExit("GetProcAddress(%p,%hs) -> %p\n", a0, a1, rv);
        }
        else {
            _PrintExit("GetProcAddress(%p:%ls,%hs) -> %p\n", a0, pwzModule, a1, rv);
        }
    };
    return rv;
}

HMODULE WINAPI Mine_LoadLibraryExW(LPCWSTR a0,
    HANDLE a1,
    DWORD a2)
{
    _PrintEnter("LoadLibraryExW(%ls,%p,%x)\n", a0, a1, a2);

    HMODULE rv = 0;
    __try {
        rv = Real_LoadLibraryExW(a0, a1, a2);
    }
    __finally {
        _PrintExit("LoadLibraryExW(,,) -> %p\n", rv);
        if (rv) {
            InstanceEnumerate(rv);
        }
    };
    return rv;
}

BOOL WINAPI Mine_MoveFileA(LPCSTR a0,
    LPCSTR a1)
{
    _PrintEnter("MoveFileA(%hs,%hs)\n", a0, a1);

    BOOL rv = 0;
    __try {
        rv = Real_MoveFileA(a0, a1);
    }
    __finally {
        _PrintExit("MoveFileA(,) -> %x\n", rv);
    };
    return rv;
}

BOOL WINAPI Mine_MoveFileExA(LPCSTR a0,
    LPCSTR a1,
    DWORD a2)
{
    _PrintEnter("MoveFileExA(%hs,%hs,%x)\n", a0, a1, a2);

    BOOL rv = 0;
    __try {
        rv = Real_MoveFileExA(a0, a1, a2);
    }
    __finally {
        _PrintExit("MoveFileExA(,,) -> %x\n", rv);
    };
    return rv;
}

BOOL WINAPI Mine_MoveFileExW(LPCWSTR a0,
    LPCWSTR a1,
    DWORD a2)
{
    _PrintEnter("MoveFileExW(%ls,%ls,%x)\n", a0, a1, a2);

    BOOL rv = 0;
    __try {
        rv = Real_MoveFileExW(a0, a1, a2);
    }
    __finally {
        _PrintExit("MoveFileExW(,,) -> %x\n", rv);
    };
    return rv;
}

BOOL WINAPI Mine_MoveFileW(LPCWSTR a0,
    LPCWSTR a1)
{
    _PrintEnter("MoveFileW(%ls,%ls)\n", a0, a1);

    BOOL rv = 0;
    __try {
        rv = Real_MoveFileW(a0, a1);
    }
    __finally {
        _PrintExit("MoveFileW(,) -> %x\n", rv);
    };
    return rv;
}

HFILE WINAPI Mine_OpenFile(LPCSTR a0,
    LPOFSTRUCT a1,
    UINT a2)
{
    _PrintEnter("OpenFile(%hs,%p,%x)\n", a0, a1, a2);

    HFILE rv = 0;
    __try {
        rv = Real_OpenFile(a0, a1, a2);
    }
    __finally {
        _PrintExit("OpenFile(,,) -> %p\n", rv);
    };
    return rv;
}

#endif


////////////////////////////////////////////////////////////////////////////////////////////////////////
// Registry related detours
#if 1
LONG WINAPI Mine_RegCreateKeyExA(HKEY a0,
    LPCSTR a1,
    DWORD a2,
    LPSTR a3,
    DWORD a4,
    REGSAM a5,
    LPSECURITY_ATTRIBUTES a6,
    PHKEY a7,
    LPDWORD a8)
{
    //_PrintEnter("RegCreateKeyExA(%p,%hs,%x,%hs,%x,%x,%p,%p,%p)\n", a0, a1, a2, a3, a4, a5, a6, a7, a8);
    if(MSG_BOX) MessageBoxA(NULL, "RegCreateKeyExA", "Hooked", NULL);

    LONG rv = 0;
    __try {
        rv = Real_RegCreateKeyExA(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    }
    __finally {
        //_PrintExit("RegCreateKeyExA(,,,,,,,,) -> %x\n", rv);
    };
    return rv;
}

LONG WINAPI Mine_RegCreateKeyExW(HKEY a0,
    LPCWSTR a1,
    DWORD a2,
    LPWSTR a3,
    DWORD a4,
    REGSAM a5,
    LPSECURITY_ATTRIBUTES a6,
    PHKEY a7,
    LPDWORD a8)
{
    //_PrintEnter(NULL);
    if (MSG_BOX) MessageBoxA(NULL, "RegCreateKeyExW", "Hooked", NULL);

    LONG rv = 0;
    __try {
        
        rv = Real_RegCreateKeyExW(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    }
    __finally {

        //_PrintExit("RegCreateKeyExW(%p,%ls,%x,%ls,%x,%x,%p,%p,%p) -> %x\n",a0, a1, a2, a3, a4, a5, a6, a7, a8, rv);
    };
    return rv;
}

LONG WINAPI Mine_RegDeleteKeyA(HKEY a0,
    LPCSTR a1)
{
    //_PrintEnter(NULL);

    if (MSG_BOX) MessageBoxA(NULL, "RegDeleteKeyA", "Hooked", NULL);

    LONG rv = 0;
    __try {
        rv = Real_RegDeleteKeyA(a0, a1);
    }
    __finally {
        //_PrintExit("RegDeleteKeyA(%p,%hs) -> %x\n", a0, a1, rv);
    };
    return rv;
}

LONG WINAPI Mine_RegDeleteKeyW(HKEY a0,
    LPCWSTR a1)
{
    //_PrintEnter(NULL);

    if (MSG_BOX) MessageBoxA(NULL, "RegDeleteKeyW", "Hooked", NULL);

    LONG rv = 0;
    __try {
        rv = Real_RegDeleteKeyW(a0, a1);
    }
    __finally {
        //_PrintExit("RegDeleteKeyW(%p,%ls) -> %x\n", a0, a1, rv);
    };
    return rv;
}

LONG WINAPI Mine_RegDeleteValueA(HKEY a0,
    LPCSTR a1)
{
    //_PrintEnter("RegDeleteValueA(%p,%hs)\n", a0, a1);

    if (MSG_BOX) MessageBoxA(NULL, "RegDeleteValueA", "Hooked", NULL);

    LONG rv = 0;
    __try {
        
        rv = Real_RegDeleteValueA(a0, a1);
    }
    __finally {
        //_PrintExit("RegDeleteValueA(,) -> %x\n", rv);
    };
    return rv;
}

LONG WINAPI Mine_RegDeleteValueW(HKEY a0,
    LPCWSTR a1)
{
    //_PrintEnter("RegDeleteValueW(%p,%ls)\n", a0, a1);

    if (MSG_BOX) MessageBoxA(NULL, "RegDeleteValueW", "Hooked", NULL);

    LONG rv = 0;
    __try {
        rv = Real_RegDeleteValueW(a0, a1);
    }
    __finally {
        //_PrintExit("RegDeleteValueW(,) -> %x\n", rv);
    };
    return rv;
}

LONG WINAPI Mine_RegEnumKeyExA(HKEY a0,
    DWORD a1,
    LPSTR a2,
    LPDWORD a3,
    LPDWORD a4,
    LPSTR a5,
    LPDWORD a6,
    LPFILETIME a7)
{
    //_PrintEnter("RegEnumKeyExA(%p,%x,%p,%p,%p,%hs,%p,%p)\n", a0, a1, a2, a3, a4, a5, a6, a7);

    if (MSG_BOX) MessageBoxA(NULL, "RegEnumKeyExA", "Hooked", NULL);

    LONG rv = 0;
    __try {
        rv = Real_RegEnumKeyExA(a0, a1, a2, a3, a4, a5, a6, a7);
    }
    __finally {
        //_PrintExit("RegEnumKeyExA(,,%hs,,,%hs,,) -> %x\n", a2, a5, rv);
    };
    return rv;
}

LONG WINAPI Mine_RegEnumKeyExW(HKEY a0,
    DWORD a1,
    LPWSTR a2,
    LPDWORD a3,
    LPDWORD a4,
    LPWSTR a5,
    LPDWORD a6,
    struct _FILETIME* a7)
{
    //_PrintEnter("RegEnumKeyExW(%p,%x,%p,%p,%p,%ls,%p,%p)\n", a0, a1, a2, a3, a4, a5, a6, a7);

    if (MSG_BOX) MessageBoxA(NULL, "RegEnumKeyExW", "Hooked", NULL);

    LONG rv = 0;
    __try {
        rv = Real_RegEnumKeyExW(a0, a1, a2, a3, a4, a5, a6, a7);
    }
    __finally {
        //_PrintExit("RegEnumKeyExW(,,%ls,,,%ls,,) -> %x\n", a2, a5, rv);
    };
    return rv;
}

LONG WINAPI Mine_RegEnumValueA(HKEY a0,
    DWORD a1,
    LPSTR a2,
    LPDWORD a3,
    LPDWORD a4,
    LPDWORD a5,
    LPBYTE a6,
    LPDWORD a7)
{
    //_PrintEnter("RegEnumValueA(%p,%x,%p,%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4, a5, a6, a7);

    if (MSG_BOX) MessageBoxA(NULL, "RegEnumValueA", "Hooked", NULL);

    LONG rv = 0;
    __try {
        rv = Real_RegEnumValueA(a0, a1, a2, a3, a4, a5, a6, a7);
    }
    __finally {
        //_PrintExit("RegEnumValueA(,,%hs,,,,,) -> %x\n", a2, rv);
    };
    return rv;
}

LONG WINAPI Mine_RegEnumValueW(HKEY a0,
    DWORD a1,       // dwIndex
    LPWSTR a2,      // lpValueName
    LPDWORD a3,     // lpcchValueName
    LPDWORD a4,     // lpReserved
    LPDWORD a5,     // lpType -> type of data stored in the specified value
    LPBYTE a6,      // lpData -> pointer to a buffer that receives the value’s data
    LPDWORD a7)     // lpcbData -> size of the buffer in bytes
{
    //_PrintEnter("RegEnumValueW(%p,%x,%p,%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4, a5, a6, a7);

    if (MSG_BOX) MessageBoxA(NULL, "RegEnumValueW", "Hooked", NULL);

    LONG rv = 0;

    __try {

        rv = Real_RegEnumValueW(a0, a1, a2, a3, a4, a5, a6, a7);

        if (wcsncmp(a2, L"Item", 4) == 0 || wcsncmp(a2, L"SensitiveData", 13) == 0)
        {
            DATA_BLOB inputBlob;
            DATA_BLOB outputBlob = { 0 };

            inputBlob.pbData = a6;
            inputBlob.cbData = *a7;

            if (CryptUnprotectData(
                &inputBlob,
                NULL,               // set to NULL
                NULL,               // optional entropy
                NULL,               // reserved
                NULL,               // prompt structure 
                0,                  // set to 0 for no option is set
                &outputBlob))       // contains the decrypted data
            {
                errno_t re = wcsncpy_s((wchar_t*)a6, *a7, (wchar_t*)outputBlob.pbData, outputBlob.cbData);
            }
            else
            {
                // decryption failed, do nothing so values stay the same...    
            }

            delete[] outputBlob.pbData;
        }
    }
    __finally {

        //_PrintExit("RegEnumValueW(,,%ls,,,,,) -> %x\n", a2, rv);
    };

    return rv;
}

LONG WINAPI Mine_RegOpenKeyExA(HKEY a0,
    LPCSTR a1,
    DWORD a2,
    REGSAM a3,
    PHKEY a4)
{
    _PrintEnter(NULL);
    if (MSG_BOX) MessageBoxA(NULL, "RegOpenKeyExA", "Hooked", NULL);

    LONG rv = 0;
    __try {
        rv = Real_RegOpenKeyExA(a0, a1, a2, a3, a4);
    }
    __finally {
        _PrintExit("RegOpenKeyExA(%p,%hs,%x,%x,%p) -> %x\n",
            a0, a1, a2, a3, a4, rv);
    };
    return rv;
}

LONG WINAPI Mine_RegOpenKeyExW(HKEY a0,
    LPCWSTR a1,
    DWORD a2,
    REGSAM a3,
    PHKEY a4)
{
    //_PrintEnter(NULL);
    if (MSG_BOX) MessageBoxA(NULL, "RegOpenKeyExW", "Hooked", NULL);

    LONG rv = 0;
    __try {
        rv = Real_RegOpenKeyExW(a0, a1, a2, a3, a4);
    }
    __finally {
        //_PrintExit("RegOpenKeyExW(%p,%ls,%x,%x,%p) -> %x\n",
        //    a0, a1, a2, a3, a4, rv);
    };
    return rv;
}

LONG WINAPI Mine_RegQueryInfoKeyA(HKEY a0,
    LPSTR a1,
    LPDWORD a2,
    LPDWORD a3,
    LPDWORD a4,
    LPDWORD a5,
    LPDWORD a6,
    LPDWORD a7,
    LPDWORD a8,
    LPDWORD a9,
    LPDWORD a10,
    LPFILETIME a11)
{
    //_PrintEnter("RegQueryInfoKeyA(%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p)\n",a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);

    LONG rv = 0;
    __try {
        rv = Real_RegQueryInfoKeyA(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
    }
    __finally {
       // _PrintExit("RegQueryInfoKeyA(,%hs,,,,,,,,,,) -> %x\n", a1, rv);
    };
    return rv;
}

LONG WINAPI Mine_RegQueryInfoKeyW(HKEY a0,
    LPWSTR a1,
    LPDWORD a2,
    LPDWORD a3,
    LPDWORD a4,
    LPDWORD a5,
    LPDWORD a6,
    LPDWORD a7,
    LPDWORD a8,
    LPDWORD a9,
    LPDWORD a10,
    LPFILETIME a11)
{
    //_PrintEnter("RegQueryInfoKeyW(%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p)\n",a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);

    if(MSG_BOX) MessageBoxA(NULL, "RegQueryInfoKeyW", "Hooked", NULL);

    LONG rv = 0;
    __try {
        rv = Real_RegQueryInfoKeyW(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
    }
    __finally {
        //_PrintExit("RegQueryInfoKeyW(,%ls,,,,,,,,,,) -> %x\n", a1, rv);
    };
    return rv;
}

LONG WINAPI Mine_RegQueryValueExA(HKEY a0,
    LPCSTR a1,
    LPDWORD a2,
    LPDWORD a3,
    LPBYTE a4,
    LPDWORD a5)
{
    //_PrintEnter(NULL);

    if (MSG_BOX) MessageBoxA(NULL, "RegQueryValueExA", "Hooked", NULL);

    LONG rv = 0;
    bool decryptSuccess = false;

    __try {

        rv = Real_RegQueryValueExA(a0, a1, a2, a3, a4, a5);
#if 0
        if (a4 != nullptr && a5 != nullptr && *a5 > 0)
        {
            DATA_BLOB inputBlob;
            DATA_BLOB outputBlob = { 0 };   // Initialize with zeros

            inputBlob.pbData = a4;  // pointer to encrypted data buffer
            inputBlob.cbData = *a5; // size of encrypted data

            decryptSuccess = CryptUnprotectData(&inputBlob,
                NULL,               // set to NULL
                NULL,               // optional entropy
                NULL,               // reserved
                NULL,               // prompt structure 
                0,                  // set to 0 for no option is set
                &outputBlob);       // contains the decrypted data

            if (decryptSuccess) {
                // Copy values to from decryption to a4 and a5
                errno_t re = wcsncpy_s((wchar_t*)a4, *a5, (wchar_t*)outputBlob.pbData, outputBlob.cbData);
            }
            else {
                // Do nothing...
            }

            delete[] outputBlob.pbData;
        }
#endif
    }
    __finally {

        //_PrintExit("RegQueryValueExA(%p,%hs,%p,%p,%p,%p) -> %x\n",a0, a1, a2, a3, a4, a5, rv);
    };
    return rv;
}

LONG WINAPI Mine_RegQueryValueExW(HKEY a0,
    LPCWSTR a1, // lpValueName
    LPDWORD a2, // lpReserved
    LPDWORD a3, // lpType
    LPBYTE a4,  // lpData
    LPDWORD a5) // lpcbData
{
    LONG rv = 0;
    bool decryptSuccess = false;

    __try {

        rv = Real_RegQueryValueExW(a0, a1, a2, a3, a4, a5);

        if (MSG_BOX) MessageBoxA(NULL, "RegQueryValueExW", "Hooked", NULL);

        if (a4 != nullptr && a5 != nullptr && *a5 > 0)
        {
            DATA_BLOB inputBlob;
            DATA_BLOB outputBlob = { 0 };   // Initialize with zeros

            inputBlob.pbData = a4;  // pointer to encrypted data buffer
            inputBlob.cbData = *a5; // size of encrypted data

            decryptSuccess = CryptUnprotectData(&inputBlob,
                NULL,               // set to NULL
                NULL,               // optional entropy
                NULL,               // reserved
                NULL,               // prompt structure 
                0,                  // set to 0 for no option is set
                &outputBlob         // contains the decrypted data
            );       

            if (decryptSuccess)
            {
                // Copy values to from decryption to a4 and a5
                errno_t re = wcsncpy_s((wchar_t*)a4, *a5, (wchar_t*)outputBlob.pbData, outputBlob.cbData);
            }

            delete[] outputBlob.pbData;
        } 
    }
    __finally {
        
    };
    return rv;
}

LONG WINAPI Mine_RegSetValueExA(HKEY a0,
    LPCSTR a1,
    DWORD a2,
    DWORD a3,
    BYTE* a4,
    DWORD a5)
{
    _PrintEnter(NULL);

    if (MSG_BOX) MessageBoxA(NULL, "RegSetValueExA", "Hooked", NULL);

    LONG rv = 0;
    __try {
        rv = Real_RegSetValueExA(a0, a1, a2, a3, a4, a5);
    }
    __finally {
        _PrintExit("RegSetValueExA(%p,%hs,%x,%x,%p,%x) -> %x\n",
            a0, a1, a2, a3, a4, a5, rv);
    };
    return rv;
}

LONG WINAPI Mine_RegSetValueExW(HKEY a0,
    LPCWSTR a1, // lpValueName
    DWORD a2,   // Reserved
    DWORD a3,   // dwType
    BYTE* a4,   // lpData
    DWORD a5)   // cbData
{
    if (MSG_BOX) MessageBoxA(NULL, "RegSetValueExW", "Hooked", NULL);

    LONG rv = 0;
    bool encryptSuccess = false;

    __try {

        if (wcsncmp(a1, L"Item", 4) == 0 || wcsncmp(a1, L"SensitiveData", 13) == 0)
        {
            if (MSG_BOX) MessageBoxA(NULL, "Found Key in the List, encrypting data!", "Alert", NULL);

            DATA_BLOB inputBlob;
            DATA_BLOB outputBlob = { 0 };

            inputBlob.pbData = a4;
            inputBlob.cbData = a5;

            encryptSuccess = CryptProtectData(
                &inputBlob,                 // Data to encrypt
                NULL,                       // Description
                NULL,                       // Optional entropy
                NULL,                       // Reserved
                NULL,                       // No prompt
                0,                          // Flags to use CRYPTPROTECT_LOCAL_MACHINE, use 0 for both user/machine
                &outputBlob                 // Encrypted Data Out
            );

            if (encryptSuccess) {

                rv = Real_RegSetValueExW(a0, a1, a2, a3, outputBlob.pbData, outputBlob.cbData);
            }
            else {

                rv = Real_RegSetValueExW(a0, a1, a2, a3, a4, a5);
            }

            delete[] outputBlob.pbData;     // Cleanup allocated memory
        }
        else {

            rv = Real_RegSetValueExW(a0, a1, a2, a3, a4, a5);
        }
    }
    __finally {

        // Do Nothing...
    };
    return rv;
}

HFILE WINAPI Mine__lcreat(LPCSTR a0, int a1)
{
    _PrintEnter(NULL);
    HFILE rv = 0;
    __try {
        rv = Real__lcreat(a0, a1);
    }
    __finally {
        _PrintExit("_lcreat(%hs,%x) -> %p\n", a0, a1, rv);
    };
    return rv;
}

HFILE WINAPI Mine__lopen(LPCSTR a0, int a1)
{
    _PrintEnter(NULL);
    HFILE rv = 0;
    __try {
        rv = Real__lopen(a0, a1);
    }
    __finally {
        _PrintEnter("_lopen(%hs,%x) -> %p\n", a0, a1, rv);
    };
    return rv;
}
#endif

/////////////////////////////////////////////////////////////
// Attach Detours
//
PCHAR DetRealName(PCHAR psz)
{
    PCHAR pszBeg = psz;
    // Move to end of name.
    while (*psz) {
        psz++;
    }
    // Move back through A-Za-z0-9 names.
    while (psz > pszBeg &&
        ((psz[-1] >= 'A' && psz[-1] <= 'Z') ||
            (psz[-1] >= 'a' && psz[-1] <= 'z') ||
            (psz[-1] >= '0' && psz[-1] <= '9'))) {
        psz--;
    }
    return psz;
}

VOID DetAttach(PVOID* ppbReal, PVOID pbMine, PCHAR psz)
{
    LONG l = DetourAttach(ppbReal, pbMine);
    if (l != 0) {
        Syelog(SYELOG_SEVERITY_NOTICE,
            "Attach failed: `%s': error %d\n", DetRealName(psz), l);
    }
}

VOID DetDetach(PVOID* ppbReal, PVOID pbMine, PCHAR psz)
{
    LONG l = DetourDetach(ppbReal, pbMine);
    if (l != 0) {
        Syelog(SYELOG_SEVERITY_NOTICE,
            "Detach failed: `%s': error %d\n", DetRealName(psz), l);
    }
}

LONG AttachDetours(VOID)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetAttach(&(PVOID&)Real_CloseHandle, Mine_CloseHandle, (PCHAR)"CloseHandle");
    DetAttach(&(PVOID&)Real_CopyFileExA, Mine_CopyFileExA, (PCHAR)"CopyFileExA");
    DetAttach(&(PVOID&)Real_CopyFileExW, Mine_CopyFileExW, (PCHAR)"CopyFileExW");
    DetAttach(&(PVOID&)Real_CreateDirectoryExW, Mine_CreateDirectoryExW, (PCHAR)"CreateDirectoryExW");
    DetAttach(&(PVOID&)Real_CreateDirectoryW, Mine_CreateDirectoryW, (PCHAR)"CreateDirectoryW");
    DetAttach(&(PVOID&)Real_CreateFileW, Mine_CreateFileW, (PCHAR)"CreateFileW");
    DetAttach(&(PVOID&)Real_CreateProcessW, Mine_CreateProcessW, (PCHAR)"CreateProcessW");
    DetAttach(&(PVOID&)Real_DeleteFileA, Mine_DeleteFileA, (PCHAR)"DeleteFileA");
    DetAttach(&(PVOID&)Real_DeleteFileW, Mine_DeleteFileW, (PCHAR)"DeleteFileW");
    DetAttach(&(PVOID&)Real_FindFirstFileExA, Mine_FindFirstFileExA, (PCHAR)"FindFirstFileExA");
    DetAttach(&(PVOID&)Real_FindFirstFileExW, Mine_FindFirstFileExW, (PCHAR)"FindFirstFileExW");
    DetAttach(&(PVOID&)Real_GetFileAttributesW, Mine_GetFileAttributesW, (PCHAR)"GetFileAttributesW");
    DetAttach(&(PVOID&)Real_GetModuleFileNameW, Mine_GetModuleFileNameW, (PCHAR)"GetModuleFileNameW");
    DetAttach(&(PVOID&)Real_GetProcAddress, Mine_GetProcAddress, (PCHAR)"GetProcAddress");
    DetAttach(&(PVOID&)Real_GetSystemTimeAsFileTime, Mine_GetSystemTimeAsFileTime, (PCHAR)"GetSystemTimeAsFileTime");
    DetAttach(&(PVOID&)Real_LoadLibraryExW, Mine_LoadLibraryExW, (PCHAR)"LoadLibraryExW");
    DetAttach(&(PVOID&)Real_MoveFileA, Mine_MoveFileA, (PCHAR)"MoveFileA");
    DetAttach(&(PVOID&)Real_MoveFileExA, Mine_MoveFileExA, (PCHAR)"MoveFileExA");
    DetAttach(&(PVOID&)Real_MoveFileExW, Mine_MoveFileExW, (PCHAR)"MoveFileExW");
    DetAttach(&(PVOID&)Real_MoveFileW, Mine_MoveFileW, (PCHAR)"MoveFileW");
    DetAttach(&(PVOID&)Real_OpenFile, Mine_OpenFile, (PCHAR)"OpenFile");
    DetAttach(&(PVOID&)Real_RegCreateKeyExA, Mine_RegCreateKeyExA, (PCHAR)"RegCreateKeyExA");
    DetAttach(&(PVOID&)Real_RegCreateKeyExW, Mine_RegCreateKeyExW, (PCHAR)"RegCreateKeyExW");
    DetAttach(&(PVOID&)Real_RegDeleteKeyA, Mine_RegDeleteKeyA, (PCHAR)"RegDeleteKeyA");
    DetAttach(&(PVOID&)Real_RegDeleteKeyW, Mine_RegDeleteKeyW, (PCHAR)"RegDeleteKeyW");
    DetAttach(&(PVOID&)Real_RegDeleteValueA, Mine_RegDeleteValueA, (PCHAR)"RegDeleteValueA");
    DetAttach(&(PVOID&)Real_RegDeleteValueW, Mine_RegDeleteValueW, (PCHAR)"RegDeleteValueW");
    DetAttach(&(PVOID&)Real_RegEnumKeyExA, Mine_RegEnumKeyExA, (PCHAR)"RegEnumKeyExA");
    DetAttach(&(PVOID&)Real_RegEnumKeyExW, Mine_RegEnumKeyExW, (PCHAR)"RegEnumKeyExW");
    DetAttach(&(PVOID&)Real_RegEnumValueA, Mine_RegEnumValueA, (PCHAR)"RegEnumValueA");
    DetAttach(&(PVOID&)Real_RegEnumValueW, Mine_RegEnumValueW, (PCHAR)"RegEnumValueW");
    DetAttach(&(PVOID&)Real_RegOpenKeyExA, Mine_RegOpenKeyExA, (PCHAR)"RegOpenKeyExA");
    DetAttach(&(PVOID&)Real_RegOpenKeyExW, Mine_RegOpenKeyExW, (PCHAR)"RegOpenKeyExW");
    DetAttach(&(PVOID&)Real_RegQueryInfoKeyA, Mine_RegQueryInfoKeyA, (PCHAR)"RegQueryInfoKeyA");
    DetAttach(&(PVOID&)Real_RegQueryInfoKeyW, Mine_RegQueryInfoKeyW, (PCHAR)"RegQueryInfoKeyW");
    DetAttach(&(PVOID&)Real_RegQueryValueExA, Mine_RegQueryValueExA, (PCHAR)"RegQueryValueExA");
    DetAttach(&(PVOID&)Real_RegQueryValueExW, Mine_RegQueryValueExW, (PCHAR)"RegQueryValueExW");
    DetAttach(&(PVOID&)Real_RegSetValueExA, Mine_RegSetValueExA, (PCHAR)"RegSetValueExA");
    DetAttach(&(PVOID&)Real_RegSetValueExW, Mine_RegSetValueExW, (PCHAR)"RegSetValueExW");
    DetAttach(&(PVOID&)Real_SetNamedPipeHandleState, Mine_SetNamedPipeHandleState, (PCHAR)"SetNamedPipeHandleState");
    DetAttach(&(PVOID&)Real_WaitNamedPipeW, Mine_WaitNamedPipeW, (PCHAR)"WaitNamedPipeW");
    DetAttach(&(PVOID&)Real_WriteFile, Mine_WriteFile, (PCHAR)"WriteFile");
    DetAttach(&(PVOID&)Real__lcreat, Mine__lcreat, (PCHAR)"_lcreat");
    DetAttach(&(PVOID&)Real__lopen, Mine__lopen, (PCHAR)"_lopen");

    return DetourTransactionCommit();
}

LONG DetachDetours(VOID)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetDetach(&(PVOID&)Real_CloseHandle, Mine_CloseHandle, (PCHAR)"CloseHandle");
    DetDetach(&(PVOID&)Real_CopyFileExA, Mine_CopyFileExA, (PCHAR)"CopyFileExA");
    DetDetach(&(PVOID&)Real_CopyFileExW, Mine_CopyFileExW, (PCHAR)"CopyFileExW");
    DetDetach(&(PVOID&)Real_CreateDirectoryExW, Mine_CreateDirectoryExW, (PCHAR)"CreateDirectoryExW");
    DetDetach(&(PVOID&)Real_CreateDirectoryW, Mine_CreateDirectoryW, (PCHAR)"CreateDirectoryW");
    DetDetach(&(PVOID&)Real_CreateFileW, Mine_CreateFileW, (PCHAR)"CreateFileW");
    DetDetach(&(PVOID&)Real_CreateProcessW, Mine_CreateProcessW, (PCHAR)"CreateProcessW");
    DetDetach(&(PVOID&)Real_DeleteFileA, Mine_DeleteFileA, (PCHAR)"DeleteFileA");
    DetDetach(&(PVOID&)Real_DeleteFileW, Mine_DeleteFileW, (PCHAR)"DeleteFileW");
    DetDetach(&(PVOID&)Real_FindFirstFileExA, Mine_FindFirstFileExA, (PCHAR)"FindFirstFileExA");
    DetDetach(&(PVOID&)Real_FindFirstFileExW, Mine_FindFirstFileExW, (PCHAR)"FindFirstFileExW");
    DetDetach(&(PVOID&)Real_GetFileAttributesW, Mine_GetFileAttributesW, (PCHAR)"GetFileAttributesW");
    DetDetach(&(PVOID&)Real_GetModuleFileNameW, Mine_GetModuleFileNameW, (PCHAR)"GetModuleFileNameW");
    DetDetach(&(PVOID&)Real_GetProcAddress, Mine_GetProcAddress, (PCHAR)"GetProcAddress");
    DetDetach(&(PVOID&)Real_GetSystemTimeAsFileTime, Mine_GetSystemTimeAsFileTime, (PCHAR)"GetSystemTimeAsFileTime");
    DetDetach(&(PVOID&)Real_LoadLibraryExW, Mine_LoadLibraryExW, (PCHAR)"LoadLibraryExW");
    DetDetach(&(PVOID&)Real_MoveFileA, Mine_MoveFileA, (PCHAR)"MoveFileA");
    DetDetach(&(PVOID&)Real_MoveFileExA, Mine_MoveFileExA, (PCHAR)"MoveFileExA");
    DetDetach(&(PVOID&)Real_MoveFileExW, Mine_MoveFileExW, (PCHAR)"MoveFileExW");
    DetDetach(&(PVOID&)Real_MoveFileW, Mine_MoveFileW, (PCHAR)"MoveFileW");
    DetDetach(&(PVOID&)Real_OpenFile, Mine_OpenFile, (PCHAR)"OpenFile");
    DetDetach(&(PVOID&)Real_RegCreateKeyExA, Mine_RegCreateKeyExA, (PCHAR)"RegCreateKeyExA");
    DetDetach(&(PVOID&)Real_RegCreateKeyExW, Mine_RegCreateKeyExW, (PCHAR)"RegCreateKeyExW");
    DetDetach(&(PVOID&)Real_RegDeleteKeyA, Mine_RegDeleteKeyA, (PCHAR)"RegDeleteKeyA");
    DetDetach(&(PVOID&)Real_RegDeleteKeyW, Mine_RegDeleteKeyW, (PCHAR)"RegDeleteKeyW");
    DetDetach(&(PVOID&)Real_RegDeleteValueA, Mine_RegDeleteValueA, (PCHAR)"RegDeleteValueA");
    DetDetach(&(PVOID&)Real_RegDeleteValueW, Mine_RegDeleteValueW, (PCHAR)"RegDeleteValueW");
    DetDetach(&(PVOID&)Real_RegEnumKeyExA, Mine_RegEnumKeyExA, (PCHAR)"RegEnumKeyExA");
    DetDetach(&(PVOID&)Real_RegEnumKeyExW, Mine_RegEnumKeyExW, (PCHAR)"RegEnumKeyExW");
    DetDetach(&(PVOID&)Real_RegEnumValueA, Mine_RegEnumValueA, (PCHAR)"RegEnumValueA");
    DetDetach(&(PVOID&)Real_RegEnumValueW, Mine_RegEnumValueW, (PCHAR)"RegEnumValueW");
    DetDetach(&(PVOID&)Real_RegOpenKeyExA, Mine_RegOpenKeyExA, (PCHAR)"RegOpenKeyExA");
    DetDetach(&(PVOID&)Real_RegOpenKeyExW, Mine_RegOpenKeyExW, (PCHAR)"RegOpenKeyExW");
    DetDetach(&(PVOID&)Real_RegQueryInfoKeyA, Mine_RegQueryInfoKeyA, (PCHAR)"RegQueryInfoKeyA");
    DetDetach(&(PVOID&)Real_RegQueryInfoKeyW, Mine_RegQueryInfoKeyW, (PCHAR)"RegQueryInfoKeyW");
    DetDetach(&(PVOID&)Real_RegQueryValueExA, Mine_RegQueryValueExA, (PCHAR)"RegQueryValueExA");
    DetDetach(&(PVOID&)Real_RegQueryValueExW, Mine_RegQueryValueExW, (PCHAR)"RegQueryValueExW");
    DetDetach(&(PVOID&)Real_RegSetValueExA, Mine_RegSetValueExA, (PCHAR)"RegSetValueExA");
    DetDetach(&(PVOID&)Real_RegSetValueExW, Mine_RegSetValueExW, (PCHAR)"RegSetValueExW");
    DetDetach(&(PVOID&)Real_SetNamedPipeHandleState, Mine_SetNamedPipeHandleState, (PCHAR)"SetNamedPipeHandleState");
    DetDetach(&(PVOID&)Real_WaitNamedPipeW, Mine_WaitNamedPipeW, (PCHAR)"WaitNamedPipeW");
    DetDetach(&(PVOID&)Real_WriteFile, Mine_WriteFile, (PCHAR)"WriteFile");
    DetDetach(&(PVOID&)Real__lcreat, Mine__lcreat, (PCHAR)"_lcreat");
    DetDetach(&(PVOID&)Real__lopen, Mine__lopen, (PCHAR)"_lopen");

    return DetourTransactionCommit();
}
//
//////////////////////////////////////////////////////////////////////////////

VOID AssertMessage(CONST PCHAR pszMsg, CONST PCHAR pszFile, ULONG nLine)
{
    Syelog(SYELOG_SEVERITY_FATAL,
        "ASSERT(%s) failed in %s, line %d.\n", pszMsg, pszFile, nLine);
}

//////////////////////////////////////////////////////////////////////////////
//
PIMAGE_NT_HEADERS NtHeadersForInstance(HINSTANCE hInst)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hInst;
    __try {
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return NULL;
        }

        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader +
            pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            SetLastError(ERROR_INVALID_EXE_SIGNATURE);
            return NULL;
        }
        if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0) {
            SetLastError(ERROR_EXE_MARKED_INVALID);
            return NULL;
        }
        return pNtHeader;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    SetLastError(ERROR_EXE_MARKED_INVALID);

    return NULL;
}

BOOL InstanceEnumerate(HINSTANCE hInst)
{
    WCHAR wzDllName[MAX_PATH];

    PIMAGE_NT_HEADERS pinh = NtHeadersForInstance(hInst);
    if (pinh && Real_GetModuleFileNameW(hInst, wzDllName, ARRAYSIZE(wzDllName))) {
        Syelog(SYELOG_SEVERITY_INFORMATION,
            "### %08lx: %-43.43ls %08x\n",
            hInst, wzDllName, pinh->OptionalHeader.CheckSum);
        return TRUE;
    }
    return FALSE;
}

BOOL ProcessEnumerate()
{
    Syelog(SYELOG_SEVERITY_INFORMATION,
        "######################################################### Binaries\n");
    for (HINSTANCE hInst = NULL; (hInst = DetourEnumerateModules(hInst)) != NULL;) {
        InstanceEnumerate(hInst);
    }
    return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
// DLL module information
BOOL ThreadAttach(HMODULE hDll)
{
    (void)hDll;

    if (s_nTlsIndent >= 0) {
        TlsSetValue(s_nTlsIndent, (PVOID)0);
    }
    if (s_nTlsThread >= 0) {
        LONG nThread = InterlockedIncrement(&s_nThreadCnt);
        TlsSetValue(s_nTlsThread, (PVOID)(LONG_PTR)nThread);
    }
    return TRUE;
}

BOOL ThreadDetach(HMODULE hDll)
{
    (void)hDll;

    if (s_nTlsIndent >= 0) {
        TlsSetValue(s_nTlsIndent, (PVOID)0);
    }
    if (s_nTlsThread >= 0) {
        TlsSetValue(s_nTlsThread, (PVOID)0);
    }
    return TRUE;
}

BOOL ProcessAttach(HMODULE hDll)
{
    s_bLog = FALSE;
    s_nTlsIndent = TlsAlloc();
    s_nTlsThread = TlsAlloc();

    s_hInst = hDll;
    Real_GetModuleFileNameA(s_hInst, s_szDllPath, ARRAYSIZE(s_szDllPath));

    SyelogOpen("trcreg" DETOURS_STRINGIFY(DETOURS_BITS), SYELOG_FACILITY_APPLICATION);
    ProcessEnumerate();

    LONG error = AttachDetours();
    if (error != NO_ERROR) {
        Syelog(SYELOG_SEVERITY_FATAL, "### Error attaching detours: %d\n", error);
    }

    ThreadAttach(hDll);

    s_bLog = TRUE;
    return TRUE;
}

BOOL ProcessDetach(HMODULE hDll)
{
    ThreadDetach(hDll);
    s_bLog = FALSE;

    LONG error = DetachDetours();
    if (error != NO_ERROR) {
        Syelog(SYELOG_SEVERITY_FATAL, "### Error detaching detours: %d\n", error);
    }

    Syelog(SYELOG_SEVERITY_NOTICE, "### Closing.\n");
    SyelogClose(FALSE);

    if (s_nTlsIndent >= 0) {
        TlsFree(s_nTlsIndent);
    }
    if (s_nTlsThread >= 0) {
        TlsFree(s_nTlsThread);
    }
    return TRUE;
}
// 
//////////////////////////////////////////////////////////////////////////////


BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, PVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();
        if (MSG_BOX2) MessageBoxA(NULL, "Attached Hooking Process", "ATTENTION", NULL);
        return ProcessAttach(hModule);
    case DLL_PROCESS_DETACH:
        if (MSG_BOX2) MessageBoxA(NULL, "Detaching Hooking Process", "ATTENTION", NULL);
        return ProcessDetach(hModule);
    case DLL_THREAD_ATTACH:
        return ThreadAttach(hModule);
    case DLL_THREAD_DETACH:
        return ThreadDetach(hModule);
    }
    return TRUE;
}
