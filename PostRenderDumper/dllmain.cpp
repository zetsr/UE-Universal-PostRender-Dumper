#include <windows.h>
#include <stdio.h>
#include <vector>
#include <psapi.h>
#include "MinHook/include/MinHook.h"
#include "SDK/SDK_Headers.hpp"

// CFG
#define TARGET_WIDTH  1920           // 窗口分辨率 W
#define TARGET_HEIGHT 1080           // 窗口分辨率 H
#define SIZE_X_OFFSET 0x40           // UCanvas->SizeX
#define SCAN_RANGE    500            // 硬编码
#define STABLE_FRAME_THRESHOLD 120   //硬编码

struct MatchInfo {
    int count = 0;
    uintptr_t lastRDX = 0;
    uintptr_t lastVTable = 0;
    bool isConfirmed = false;
};

MatchInfo TrackedMatches[SCAN_RANGE];
void* Originals[SCAN_RANGE] = { 0 };
HANDLE hProcess = NULL;
uintptr_t ModuleBase = 0;
uintptr_t ModuleSize = 0;
bool IsFound = false; // 全局标志：找到目标后停止一切逻辑

// 安全读取模板
template <typename T>
T SafeRead(uintptr_t addr) {
    T buffer = { 0 };
    SIZE_T read;
    if (ReadProcessMemory(hProcess, (LPCVOID)addr, &buffer, sizeof(T), &read)) return buffer;
    return { 0 };
}

// 检查地址是否位于主模块内
bool IsValidModuleAddress(uintptr_t addr) {
    return (addr >= ModuleBase && addr <= (ModuleBase + ModuleSize));
}

void __fastcall UniversalDumper(int index, void* rcx, void* rdx, void* r8) {
    // 如果已经确定了唯一函数，直接调用原函数并返回，不再进入扫描逻辑
    if (IsFound && !TrackedMatches[index].isConfirmed) {
        auto orig = (void(__fastcall*)(void*, void*, void*))Originals[index];
        if (orig) orig(rcx, rdx, r8);
        return;
    }

    uintptr_t addr = (uintptr_t)rdx;

    // 1. 基础过滤：UE 实例对齐检查
    if (addr > 0x100000000 && (addr % 16 == 0)) {
        int32_t readX = SafeRead<int32_t>(addr + SIZE_X_OFFSET);
        int32_t readY = SafeRead<int32_t>(addr + SIZE_X_OFFSET + 4);

        if (readX == TARGET_WIDTH && readY == TARGET_HEIGHT) {
            uintptr_t vtable = SafeRead<uintptr_t>(addr);

            if (IsValidModuleAddress(vtable)) {
                // 稳定性验证
                if (addr == TrackedMatches[index].lastRDX && vtable == TrackedMatches[index].lastVTable) {
                    TrackedMatches[index].count++;
                }
                else {
                    TrackedMatches[index].count = 0;
                    TrackedMatches[index].lastRDX = addr;
                    TrackedMatches[index].lastVTable = vtable;
                }

                // 达到稳定性阈值，认定为候选函数
                if (TrackedMatches[index].count >= STABLE_FRAME_THRESHOLD) {

                    // --- 核心逻辑：检查下一个 Index 是否也是候选 ---
                    int nextIndex = index + 1;
                    if (nextIndex < SCAN_RANGE) {
                        // 判定下一个是否也是候选（根据其稳定性计数）
                        if (TrackedMatches[nextIndex].count >= STABLE_FRAME_THRESHOLD) {

                            // 满足条件：当前是候选，且下一个也是候选
                            if (!IsFound) {
                                printf("[!] >>> TARGET LOCATED <<< Current Index: %d | Next Index: %d confirmed.\n", index, nextIndex);
                                printf("[!] >>> FINAL POSTRENDER: Index %d | RDX: %p\n", index, (void*)rdx);

                                TrackedMatches[index].isConfirmed = true; // 锁定当前 index
                                IsFound = true; // 停止全局扫描逻辑
                            }
                        }
                    }

                    // 如果已经锁定是当前这个 index，执行绘制
                    if (TrackedMatches[index].isConfirmed) {
                        SDK::UCanvas* canvas = (SDK::UCanvas*)rdx;
                        SDK::FLinearColor green = { 0.f, 1.f, 0.f, 1.f };
                        canvas->K2_DrawBox({ 2, 2 }, { 50, 50 }, 1.0f, green);
                    }
                }
            }
        }
    }

    auto orig = (void(__fastcall*)(void*, void*, void*))Originals[index];
    if (orig) orig(rcx, rdx, r8);
}

// --- 宏定义逻辑 (生成 0-499 个入口) ---
#define H_FUNC(i) void __fastcall H_##i(void* rcx, void* rdx, void* r8) { UniversalDumper(i, rcx, rdx, r8); }
#define REPEAT_10(m, n) m(n##0) m(n##1) m(n##2) m(n##3) m(n##4) m(n##5) m(n##6) m(n##7) m(n##8) m(n##9)
#define REPEAT_100(m, n) REPEAT_10(m, n##0) REPEAT_10(m, n##1) REPEAT_10(m, n##2) REPEAT_10(m, n##3) REPEAT_10(m, n##4) \
                         REPEAT_10(m, n##5) REPEAT_10(m, n##6) REPEAT_10(m, n##7) REPEAT_10(m, n##8) REPEAT_10(m, n##9)

H_FUNC(0) H_FUNC(1) H_FUNC(2) H_FUNC(3) H_FUNC(4) H_FUNC(5) H_FUNC(6) H_FUNC(7) H_FUNC(8) H_FUNC(9)
REPEAT_10(H_FUNC, 1) REPEAT_10(H_FUNC, 2) REPEAT_10(H_FUNC, 3) REPEAT_10(H_FUNC, 4) REPEAT_10(H_FUNC, 5)
REPEAT_10(H_FUNC, 6) REPEAT_10(H_FUNC, 7) REPEAT_10(H_FUNC, 8) REPEAT_10(H_FUNC, 9)
REPEAT_100(H_FUNC, 1) REPEAT_100(H_FUNC, 2) REPEAT_100(H_FUNC, 3) REPEAT_100(H_FUNC, 4)

void SetupHooks(void** vtable) {
    if (MH_Initialize() != MH_OK) return;
    hProcess = GetCurrentProcess();

    MODULEINFO mi;
    GetModuleInformation(hProcess, GetModuleHandleA(NULL), &mi, sizeof(mi));
    ModuleBase = (uintptr_t)mi.lpBaseOfDll;
    ModuleSize = mi.SizeOfImage;

#define P_H(i) (void*)H_##i
    std::vector<void*> hFns;
    hFns.push_back(P_H(0)); hFns.push_back(P_H(1)); hFns.push_back(P_H(2)); hFns.push_back(P_H(3)); hFns.push_back(P_H(4));
    hFns.push_back(P_H(5)); hFns.push_back(P_H(6)); hFns.push_back(P_H(7)); hFns.push_back(P_H(8)); hFns.push_back(P_H(9));

#define P_PUSH(i) hFns.push_back(P_H(i));
    REPEAT_10(P_PUSH, 1) REPEAT_10(P_PUSH, 2) REPEAT_10(P_PUSH, 3) REPEAT_10(P_PUSH, 4) REPEAT_10(P_PUSH, 5)
        REPEAT_10(P_PUSH, 6) REPEAT_10(P_PUSH, 7) REPEAT_10(P_PUSH, 8) REPEAT_10(P_PUSH, 9)
        REPEAT_100(P_PUSH, 1) REPEAT_100(P_PUSH, 2) REPEAT_100(P_PUSH, 3) REPEAT_100(P_PUSH, 4)

        for (int i = 1; i < SCAN_RANGE; i++) {
            if (vtable[i]) {
                if (MH_CreateHook(vtable[i], hFns[i], &Originals[i]) == MH_OK) {
                    MH_EnableHook(vtable[i]);
                }
            }
        }
}

DWORD WINAPI MainThread(LPVOID lpParam) {
    AllocConsole();
    FILE* f; freopen_s(&f, "CONOUT$", "w", stdout);
    printf("--- Post Render Auto-Finder ---\n");

    SDK::UEngine* engine = nullptr;
    while (true) {
        engine = SDK::UEngine::GetEngine();
        if (engine && engine->GameViewport) break;
        Sleep(100);
    }

    SetupHooks(*(void***)engine->GameViewport);
    printf("[*] Hooks applied. Waiting for candidate pair (N and N+1)...\n");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hM, DWORD r, LPVOID res) {
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hM);
        CreateThread(0, 0, MainThread, 0, 0, 0);
    }
    return TRUE;
}