#include "common_lib.h"
#include "syscall_if.h"
#include "um_lib_helper.h"

static QWORD m_secondaryThTid;

static
STATUS
(__cdecl _MemsetFunc)(
    IN_OPT      PVOID       Context
    )
{
    STATUS status;

    UNREFERENCED_PARAMETER(Context);

    //status = SyscallMemset(NULL, 0, 0);
    //if (!SUCCEEDED(status))
    //{
    //    LOG_FUNC_ERROR("SyscallMemset", status);
    //}

    return STATUS_SUCCESS;
}

STATUS
__main(
    DWORD       argc,
    char** argv
)
{
    STATUS status;
    BYTE buffer[128];
    BYTE valueToWrite = 0xAB;
    DWORD bytesToWrite = sizeof(buffer);
    PBYTE invalidAddress = NULL;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    __try
    {
        // Test case 1: Valid input
        status = SyscallMemset(buffer, bytesToWrite, valueToWrite);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("SyscallMemset", status);
            __leave;
        }

        // Verify that the buffer was properly filled
        for (DWORD i = 0; i < bytesToWrite; ++i)
        {
            if (buffer[i] != valueToWrite)
            {
                LOG_ERROR("Buffer validation failed at index %u! Expected: 0x%X, Found: 0x%X\n",
                    i, valueToWrite, buffer[i]);
                __leave;
            }
        }

        LOG_INFO("Test case 1: Valid input passed.\n");

        // Test case 2: Invalid address (NULL)
        status = SyscallMemset(invalidAddress, bytesToWrite, valueToWrite);
        if (status != STATUS_INVALID_PARAMETER1)
        {
            LOG_ERROR("Test case 2 failed! Expected: STATUS_INVALID_PARAMETER1, Found: 0x%X\n", status);
            __leave;
        }

        LOG_INFO("Test case 2: Invalid address passed.\n");

        // Test case 3: Invalid size (zero bytes to write)
        status = SyscallMemset(buffer, 0, valueToWrite);
        if (status != STATUS_INVALID_PARAMETER1)
        {
            LOG_ERROR("Test case 3 failed! Expected: STATUS_INVALID_PARAMETER1, Found: 0x%X\n", status);
            __leave;
        }

        LOG_INFO("Test case 3: Invalid size passed.\n");

        // Test case 4: Invalid permissions (simulate by using an invalid address)
        PBYTE protectedMemory = (PBYTE)0xDEADBEEF; // Example invalid memory address
        status = SyscallMemset(protectedMemory, bytesToWrite, valueToWrite);
        if (!SUCCEEDED(status))
        {
            LOG_INFO("Test case 4: Invalid permissions passed.\n");
        }
        else
        {
            LOG_ERROR("Test case 4 failed! Expected failure, but SyscallMemset succeeded.\n");
        }
    }
    __finally
    {
        LOG_INFO("Memset syscall testing completed.\n");
    }

    return STATUS_SUCCESS;
}
