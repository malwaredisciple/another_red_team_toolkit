#include <iostream>
#include <Windows.h>
#include <winternl.h>

WCHAR* set_commandline()
{
    WCHAR *old_commandline;
    const WCHAR *new_commandline = L"C:\\Windows\\system32\\calc.exe";
    USHORT old_commandline_length;
    USHORT new_commandline_length = sizeof(new_commandline);

    __asm
    {
        _find_commandline:
            mov eax, fs:0x30;               // PEB
            mov ebx, [eax + 0x10];          // _RTL_USER_PROCESS_PARAMETERS
            add ebx, 0x40;                  // Commandline UNICODE struct
            mov ecx, [ebx];                 // length of unicode buffer
            shr ecx, 1;                     // unicode string, so div by 2 to get length for our counter
            dec ecx;
            mov old_commandline_length, cx; // save length in local var
            mov esi, [ebx + 0x4];           // .Commandline buffer
            mov old_commandline, esi;       // save in local var
            mov esi, new_commandline;       // source is what we will use to overwrite the og cmdline
            mov edi, old_commandline;       // og cmdline to overwrite
            add edi, 2;                     // starts with " so we will skip first two bytes
            xor ecx, ecx;                   // init counter | string index

        _set_commandline_loop:
            xor eax, eax;                   // eax will hold our char
            mov al, [esi + ecx * 2];        // get char from new cmdline
            mov [edi + ecx * 2], al;        // overwrite char in old cmdline
            inc ecx;                        // inc counter
            cmp cx, old_commandline_length; // need to null out remaining chars in cmdline if our new cmdline is shorter than the og
            jge _zero_remaining;            //
            jmp _set_commandline_loop;      //

        _zero_remaining:
            mov [edi + ecx * 2], 0x0;
            inc ecx;
            mov cx, old_commandline_length;
            jle _zero_remaining;

        _exit_loop:
            xor eax, eax;
    }
    return old_commandline;
}

int main()
{
    WCHAR * commandline = set_commandline();
    std::wcout << commandline;
    return 0;
}
