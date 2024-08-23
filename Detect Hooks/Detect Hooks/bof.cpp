#include "base\helpers.h"
#include <iostream>
#include <Windows.h>
#include <psapi.h>
/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base\mock.h"
#endif

extern "C" {
#include "beacon.h"
#include "sleepmask.h"
#include <Windows.h>
#include <iostream>
#include <Psapi.h>
    // Define the Dynamic Function Resolution declaration for the GetLastError function
    DFR(KERNEL32, GetLastError);
    // Map GetLastError to KERNEL32$GetLastError 
#define GetLastError KERNEL32$GetLastError 




    void DetectHooks(const char* filterFunctionName = NULL)
    {
        DFR_LOCAL(MSVCRT, strncmp);
        DFR_LOCAL(MSVCRT, memcmp);
        DFR_LOCAL(MSVCRT, strlen);

        PDWORD functionAddress = (PDWORD)0;

        HMODULE libraryBase = LoadLibraryA("ntdll");

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
        PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

        DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

        PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
        PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
        PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);


        // Iterate through exported functions of ntdll
        for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++)
        {
            // Resolve exported function name
            DWORD functionNameRVA = addressOfNamesRVA[i];
            DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
            char* functionName = (char*)functionNameVA;

            // Resolve exported function address
            DWORD_PTR functionAddressRVA = 0;
            functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
            functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);

            // Only interested in Nt|Zw functions
            if (strncmp(functionName, (char*)"Nt", 2) == 0 || strncmp(functionName, (char*)"Zw", 2) == 0)
            {
            #ifdef _WIN64
                // Code specific to 64-bit architecture
                if ((*(ULONG*)functionAddress != 0xb8d18b4c) == TRUE) {
                    // To Remove False Postive
                    if ((*((PBYTE)functionAddress) == 0xE9) || *((PBYTE)functionAddress + 3) == 0xE9) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[#] %s [ 0x%p ] ---> [ Hooked ] \n", functionName, functionAddress);
                    }
                }
            #else
                // Code specific to 32-bit architecture
                if ((*((PBYTE)functionAddress) != 0xB8 && *((PBYTE)functionAddress + 10) != 0xFF) && *((PBYTE)functionAddress + 11) != 0xD2)
                {
                    BeaconPrintf(CALLBACK_OUTPUT, "[#] %s [ 0x%p ] ---> [ Hooked ] \n", functionName, functionAddress);
                }
            #endif
            }
        }
    }




    void go(char* args, int len){

       
        DetectHooks();

    }
    /*
    void sleep_mask(PSLEEPMASK_INFO info, PFUNCTION_CALL funcCall) {
    }
    */
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    DetectHooks();

    /* To test a sleepmask BOF, the following mockup executors can be used
    // Mock up Beacon and run the sleep mask once
    bof::runMockedSleepMask(sleep_mask);

    // Mock up Beacon with the specific .stage C2 profile
    bof::runMockedSleepMask(sleep_mask,
        {
            .allocator = bof::profile::Allocator::VirtualAlloc,
            .obfuscate = bof::profile::Obfuscate::False,
            .useRWX = bof::profile::UseRWX::True,
            .module = "",
        },
        {
            .sleepTimeMs = 5000,
            .runForever = false,
        }
    );
    */

    return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got =
        bof::runMocked<>(go);
    std::vector<bof::output::OutputEntry> expected = {
        {CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}
    };
    // It is possible to compare the OutputEntry vectors, like directly
    // ASSERT_EQ(expected, got);
    // However, in this case, we want to compare the output, ignoring the case.
    ASSERT_EQ(expected.size(), got.size());
    ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif