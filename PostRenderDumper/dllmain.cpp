#include <windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <print>
#include <format>
#include <cstddef>
#include <psapi.h>
#include "MinHook/include/MinHook.h"
#include "SDK/SDK_Headers.hpp"
#include "AOBScan.hpp"

// https://github.com/zyantific/zydis
extern "C" {
#include "Zydis/Zydis.h"
}

// 配置
// 确保和目标客户端分辨率一致
#define TARGET_WIDTH  1920           // 窗口分辨率 W     // Windows Screen Size W
#define TARGET_HEIGHT 1080           // 窗口分辨率 H     // Windows Screen Size H

// 编译器直接从 SDK 提取 Dumper-7 生成的 UCanvas->SizeX 与 SizeY 真实偏移
#define SIZE_X_OFFSET offsetof(SDK::UCanvas, SizeX)
#define SIZE_Y_OFFSET offsetof(SDK::UCanvas, SizeY)

// 一般不用改
#define SCAN_RANGE    200            // 硬编码           // 扫描前 200 个函数（从 vtable[1] 开始）以寻找候选函数
#define STABLE_FRAME_THRESHOLD 120   // 硬编码           // 稳定性阈值：连续 120 帧（约 2 秒）满足条件才认定为候选函数

// 动态分辨率稳态超时（毫秒）：5 秒未能通过动态分辨率找到目标则回滚
#define DYNAMIC_RES_TIMEOUT_MS      5000

// 退出并解除所有 Hook 的热键
#define EXIT_HOTKEY                 VK_F1

// 特征码生成相关配置
#define SIG_MAX_SCAN_LEN   256       // 反汇编时最多累积的字节数上限
#define SIG_MAX_INSNS      48        // 最多反汇编的指令条数上限

// Tick 扫描相关配置
#define TICK_SCAN_RANGE             500      // 扫描虚表 1 到 500
#define TICK_SAMPLE_FRAMES          120      // 采样周期（帧数），与 PostRender 对齐
#define TICK_FREQ_TOLERANCE         15       // 调用频次允许的绝对误差范围（CallCount 与采样帧数的差距）
#define TICK_DT_TOLERANCE           0.015f   // DeltaTime 浮点比对允许的绝对误差

// 打印所使用的 AActor::Tick 函数签名格式
#define ACTOR_TICK_FUNCTION_SIGNATURE "void __fastcall AActor::Tick(AActor* _this, float DeltaSeconds)"

// 彩色日志宏
#define COLOR_RESET   "\033[0m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_RED     "\033[31m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_MAGENTA "\033[35m"

#define LOG_INFO(fmt, ...)   std::println(COLOR_BLUE "[*] " fmt COLOR_RESET, ##__VA_ARGS__)
#define LOG_SUCCESS(fmt, ...) std::println(COLOR_GREEN "[+] " fmt COLOR_RESET, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)   std::println(COLOR_YELLOW "[!] " fmt COLOR_RESET, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)  std::println(COLOR_RED "[-] " fmt COLOR_RESET, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...)  std::println(COLOR_CYAN "[*] " fmt COLOR_RESET, ##__VA_ARGS__)
#define LOG_SPECIAL(fmt, ...) std::println(COLOR_MAGENTA "[>>>] " fmt COLOR_RESET, ##__VA_ARGS__)

struct MatchInfo {
    int count = 0;
    uintptr_t lastRDX = 0;
    uintptr_t lastVTable = 0;
    bool isConfirmed = false;
};

MatchInfo TrackedMatches[SCAN_RANGE];
void* Originals[SCAN_RANGE] = { 0 };
void* OriginalVTableEntries[SCAN_RANGE] = { nullptr };
HANDLE hProcess = NULL;

FILE* g_ConsoleFile = nullptr;
int g_ActiveTargetWidth = TARGET_WIDTH;
int g_ActiveTargetHeight = TARGET_HEIGHT;
bool g_UsingDynamicResolution = false;
bool g_HasRolledBack = false;
ULONGLONG g_HookStartTime = 0;

uintptr_t ModuleBase = 0;
uintptr_t ModuleSize = 0;
bool IsFound = false; // 全局标志：找到目标后停止一切逻辑

// 预设特征码：? 表示通配符
std::vector<std::string> g_PredefinedSignatures = {
    "8B C2 35 ? ? ? ? 44",
    "48 8B 01 48 FF A0 ? ? ? ? CC CC CC CC CC CC"
};

// 是否启用了特征码优先挂钩模式
bool g_PreferredMode = false;

// 特征码命中的 vtable 索引标记
bool g_IsPreferredIndex[SCAN_RANGE] = { false };

struct TickEntryInfo {
    int callCount = 0;
    float lastMatchedDt = 0.0f;
    bool dtMatched = false;
};

struct TickScanContext {
    const char* name = "AActor";
    void* instance = nullptr;
    void** vtable = nullptr;
    bool isHooked = false;
    bool isCompleted = false;
    int confirmedIndex = -1; // 记录最终确认为 AActor::Tick 的虚表索引
    int postRenderFrameBaseline = 0;
    TickEntryInfo entries[TICK_SCAN_RANGE];
    void* originals[TICK_SCAN_RANGE] = { nullptr };
    void* origVtableEntries[TICK_SCAN_RANGE] = { nullptr };
};

// 单独记录 AActor 的挂钩上下文
TickScanContext g_ActorTickContext;

// 状态机全局标记
bool g_TickScanInitiated = false;
int g_PostRenderFrameCounter = 0;

using ActorTickFn = void(__fastcall*)(SDK::AActor*, float);
ActorTickFn g_OriginalActorTick = nullptr;

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

// 单字节的匹配信息：该字节值 + 是否为通配符
struct SigByte {
    uint8_t value;
    bool isWildcard;
};

// 对函数起始地址进行反汇编，产出逐字节的"是否通配符"标记表
// 返回值：标记表（长度 = 实际反汇编覆盖的总字节数），失败返回空 vector
static std::vector<SigByte> BuildByteMarkTable(uintptr_t funcAddr) {
    std::vector<SigByte> marks;

    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        return marks;
    }

    const size_t readLen = SIG_MAX_SCAN_LEN + 16;
    std::vector<uint8_t> raw(readLen, 0);
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)funcAddr, raw.data(), readLen, &bytesRead) || bytesRead == 0) {
        return marks;
    }

    marks.assign(bytesRead, SigByte{ 0, false });
    for (size_t i = 0; i < bytesRead; i++) {
        marks[i].value = raw[i];
    }

    size_t offset = 0;
    int insnCount = 0;

    while (offset < bytesRead && offset < SIG_MAX_SCAN_LEN && insnCount < SIG_MAX_INSNS) {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        ZyanStatus status = ZydisDecoderDecodeFull(
            &decoder,
            raw.data() + offset,
            bytesRead - offset,
            &instruction,
            operands
        );

        if (!ZYAN_SUCCESS(status)) {
            offset += 1;
            continue;
        }

        // 1. 处理位移字段（ModRM/SIB 中的 disp）
        if (instruction.raw.disp.size != 0) {
            size_t dispOff = offset + instruction.raw.disp.offset;
            size_t dispLen = instruction.raw.disp.size / 8;
            for (size_t i = 0; i < dispLen && (dispOff + i) < marks.size(); i++) {
                marks[dispOff + i].isWildcard = true;
            }
        }

        // 2. 处理立即数字段 - 将所有立即数都标记为通配符
        for (ZyanU8 opIdx = 0; opIdx < instruction.operand_count_visible; opIdx++) {
            const ZydisDecodedOperand& op = operands[opIdx];
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                for (int immIdx = 0; immIdx < 2; immIdx++) {
                    if (instruction.raw.imm[immIdx].size == 0) continue;

                    // 将所有立即数都标记为通配符
                    // 这样可以确保像 sub rsp, 0x40 中的 0x40 被正确处理
                    size_t immOff = offset + instruction.raw.imm[immIdx].offset;
                    size_t immLen = instruction.raw.imm[immIdx].size / 8;
                    for (size_t i = 0; i < immLen && (immOff + i) < marks.size(); i++) {
                        marks[immOff + i].isWildcard = true;
                    }
                }
            }
        }

        offset += instruction.length;
        insnCount++;
    }

    if (offset == 0) {
        return {};
    }

    marks.resize(offset);
    return marks;
}

// 将标记表转换为 AOB::Scan 所需的字符串格式，取前 len 字节
static std::string MarksToPatternString(const std::vector<SigByte>& marks, size_t len) {
    std::string result;
    result.reserve(len * 3);
    for (size_t i = 0; i < len; i++) {
        if (i != 0) result += ' ';
        if (marks[i].isWildcard) {
            result += '?';
        }
        else {
            std::format_to(std::back_inserter(result), "{:02X}", marks[i].value);
        }
    }
    return result;
}

// 特征码生成的详细结果，便于失败时打印诊断信息
struct SigGenDiagnostics {
    bool success = false;
    std::string signature;
    size_t bytesDisassembled = 0;   // 实际成功反汇编覆盖的总字节数
    size_t instructionsTried = 0;   // 尝试过多少条指令边界
    size_t longestLenTried = 0;     // 尝试过的最长长度
    size_t matchCountAtLongest = 0; // 最长长度时 AOB::Scan 命中的数量（用于判断是不是仍然重复）
};

// 尝试为函数生成"最短且唯一"的特征码
static SigGenDiagnostics GenerateUniqueSignature(uintptr_t funcAddr) {
    SigGenDiagnostics diag;

    // 自检：独立计算一遍 AOB::Scan 内部用来限定扫描范围的 .text 段边界
    // （BaseOfCode / SizeOfCode），确认 funcAddr 是否真的落在这个范围内。
    // 如果不落在范围内，AOB::Scan 无论传入什么 pattern 都不可能匹配到它，
    // 这正好能解释"匹配数恒为 0，即使是它自己的位置"这个现象。
    {
        HMODULE hMod = GetModuleHandleA(NULL);
        if (hMod) {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint8_t*)hMod + dos->e_lfanew);
            uintptr_t textStart = (uintptr_t)hMod + nt->OptionalHeader.BaseOfCode;
            uintptr_t textEnd = textStart + nt->OptionalHeader.SizeOfCode;
            bool inRange = (funcAddr >= textStart && funcAddr < textEnd);
            LOG_DEBUG("Self-check: .text range = [{:#x}, {:#x}) (size={:#x}), funcAddr={:#x}, inRange={}",
                textStart, textEnd, nt->OptionalHeader.SizeOfCode, funcAddr, inRange);
            LOG_DEBUG("Self-check: ModuleBase={:#x}, ModuleSize={:#x} (SizeOfImage), funcAddr offset from base={:#x}",
                ModuleBase, ModuleSize, funcAddr - ModuleBase);
        }
    }

    std::vector<SigByte> marks = BuildByteMarkTable(funcAddr);
    if (marks.empty()) {
        return diag;
    }
    diag.bytesDisassembled = marks.size();

    // 自检：用 funcAddr 自身最前面几个字节（纯精确匹配，不含任何通配符）
    // 直接测试 AOB::Scan 能否找到它自己。如果这个最简单的 sanity check
    // 都返回 0 个匹配，说明问题不在反汇编/通配符逻辑，而在 AOB::Scan
    // 本身的扫描范围或字节比对逻辑上。
    if (marks.size() >= 4) {
        std::string selfCheckPattern = MarksToPatternString(marks, 4);
        AOB::Result selfCheckResult = AOB::Scan(selfCheckPattern);
        LOG_DEBUG("Self-check: scanning for its own first 4 bytes \"{}\" -> {} match(es)",
            selfCheckPattern, selfCheckResult.size());
        if (selfCheckResult.size() > 0) {
            LOG_DEBUG("Self-check: first match address = {:#x} (expected {:#x})",
                (uintptr_t)selfCheckResult[0], funcAddr);
        }
    }

    // 策略1: 逐字节尝试（从短到长）
    // 这样可以找到像 "8B C2 35 ?? ?? ?? ?? 44" 这样在指令中间停止的最短唯一特征码
    diag.instructionsTried = 0;
    for (size_t len = 1; len <= marks.size() && len <= SIG_MAX_SCAN_LEN; len++) {
        // 特征码不能以通配符开头（否则匹配会不可靠）
        if (marks[len - 1].isWildcard) continue;

        std::string pattern = MarksToPatternString(marks, len);
        AOB::Result result = AOB::Scan(pattern);

        diag.longestLenTried = len;
        diag.matchCountAtLongest = result.size();
        diag.instructionsTried++;

        if (result.size() == 1) {
            diag.success = true;
            diag.signature = pattern;
            return diag;
        }
    }

    // 策略2: 回退到指令边界尝试
    // 如果逐字节尝试失败（理论上不会，但作为后备），使用指令边界
    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        return diag;
    }

    std::vector<uint8_t> raw(marks.size());
    for (size_t i = 0; i < marks.size(); i++) raw[i] = marks[i].value;

    std::vector<size_t> boundaries; // 每个可尝试的候选长度（指令边界，或跨越不可解码字节后的单字节步进点）
    size_t offset = 0;
    int insnCount = 0;
    while (offset < raw.size() && insnCount < SIG_MAX_INSNS) {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZyanStatus status = ZydisDecoderDecodeFull(
            &decoder, raw.data() + offset, raw.size() - offset, &instruction, operands);

        if (!ZYAN_SUCCESS(status)) {
            // 与 BuildByteMarkTable 保持一致：遇到不可解码字节（如函数间的 0xCC
            // 填充）时不停止，而是当作单字节前进，把该点也记录为一个候选边界，
            // 这样特征码候选长度才能"跨越"填充区，延伸到填充区之后的下一段真实
            // 指令（例如相邻函数的开头），与 IDA 的特征码生成行为保持一致。
            // 注意：不递增 insnCount，因为该上限用于限制"真实指令条数"，
            // 避免连续填充字节过早耗尽该上限、导致候选边界无法延伸过填充区。
            offset += 1;
            boundaries.push_back(offset);
            continue;
        }

        offset += instruction.length;
        boundaries.push_back(offset);
        insnCount++;
    }

    if (boundaries.empty()) {
        return diag;
    }

    for (size_t len : boundaries) {
        if (len == 0 || len > marks.size()) continue;
        if (marks[len - 1].isWildcard) continue;

        std::string pattern = MarksToPatternString(marks, len);
        AOB::Result result = AOB::Scan(pattern);

        diag.longestLenTried = len;
        diag.matchCountAtLongest = result.size();

        if (result.size() == 1) {
            diag.success = true;
            diag.signature = pattern;
            return diag;
        }
    }

    return diag; // 扫描到最大长度仍不唯一，判定失败（diag.success 保持 false）
}

void __fastcall UniversalActorTickDumper(int funcIdx, void* rcx, void* rdx, void* r8);

#define REPEAT_10(m, n) m(n##0) m(n##1) m(n##2) m(n##3) m(n##4) m(n##5) m(n##6) m(n##7) m(n##8) m(n##9)
#define REPEAT_100(m, n) REPEAT_10(m, n##0) REPEAT_10(m, n##1) REPEAT_10(m, n##2) REPEAT_10(m, n##3) REPEAT_10(m, n##4) \
                         REPEAT_10(m, n##5) REPEAT_10(m, n##6) REPEAT_10(m, n##7) REPEAT_10(m, n##8) REPEAT_10(m, n##9)

// 仅针对 AActor 展开 0-499 个入口（扫描阶段使用通用寄存器传递，避免破坏其他 171 个未知签名的虚函数）
#define ACTOR_TICK_H(i) void __fastcall H_ActorTick_##i(void* rcx, void* rdx, void* r8) { UniversalActorTickDumper(i, rcx, rdx, r8); }

ACTOR_TICK_H(0) ACTOR_TICK_H(1) ACTOR_TICK_H(2) ACTOR_TICK_H(3) ACTOR_TICK_H(4)
ACTOR_TICK_H(5) ACTOR_TICK_H(6) ACTOR_TICK_H(7) ACTOR_TICK_H(8) ACTOR_TICK_H(9)
REPEAT_10(ACTOR_TICK_H, 1) REPEAT_10(ACTOR_TICK_H, 2) REPEAT_10(ACTOR_TICK_H, 3) REPEAT_10(ACTOR_TICK_H, 4) REPEAT_10(ACTOR_TICK_H, 5)
REPEAT_10(ACTOR_TICK_H, 6) REPEAT_10(ACTOR_TICK_H, 7) REPEAT_10(ACTOR_TICK_H, 8) REPEAT_10(ACTOR_TICK_H, 9)
REPEAT_100(ACTOR_TICK_H, 1) REPEAT_100(ACTOR_TICK_H, 2) REPEAT_100(ACTOR_TICK_H, 3) REPEAT_100(ACTOR_TICK_H, 4)

static std::vector<void*> GetActorTickDispatchTable() {
    std::vector<void*> table;
    table.reserve(TICK_SCAN_RANGE);

#define P_ACTOR_H(i) (void*)H_ActorTick_##i
    table.push_back(P_ACTOR_H(0)); table.push_back(P_ACTOR_H(1)); table.push_back(P_ACTOR_H(2)); table.push_back(P_ACTOR_H(3)); table.push_back(P_ACTOR_H(4));
    table.push_back(P_ACTOR_H(5)); table.push_back(P_ACTOR_H(6)); table.push_back(P_ACTOR_H(7)); table.push_back(P_ACTOR_H(8)); table.push_back(P_ACTOR_H(9));

#define P_PUSH_ACTOR(i) table.push_back(P_ACTOR_H(i));
    REPEAT_10(P_PUSH_ACTOR, 1) REPEAT_10(P_PUSH_ACTOR, 2) REPEAT_10(P_PUSH_ACTOR, 3) REPEAT_10(P_PUSH_ACTOR, 4) REPEAT_10(P_PUSH_ACTOR, 5)
        REPEAT_10(P_PUSH_ACTOR, 6) REPEAT_10(P_PUSH_ACTOR, 7) REPEAT_10(P_PUSH_ACTOR, 8) REPEAT_10(P_PUSH_ACTOR, 9)
        REPEAT_100(P_PUSH_ACTOR, 1) REPEAT_100(P_PUSH_ACTOR, 2) REPEAT_100(P_PUSH_ACTOR, 3) REPEAT_100(P_PUSH_ACTOR, 4)

#undef P_PUSH_ACTOR
#undef P_ACTOR_H
        return table;
}

static void HookActorTickVTable(void* instance) {
    if (!instance || g_ActorTickContext.isHooked) return;
    g_ActorTickContext.instance = instance;
    g_ActorTickContext.vtable = *(void***)instance;

    if (!g_ActorTickContext.vtable) {
        LOG_ERROR("Failed to read vtable for AActor!");
        return;
    }

    LOG_INFO("Starting to create hooks for AActor vtable entries (1 to {})...", TICK_SCAN_RANGE - 1);

    std::vector<void*> handlers = GetActorTickDispatchTable();

    int successCount = 0;
    int failCount = 0;

    for (int i = 1; i < TICK_SCAN_RANGE; i++) {
        void* func = g_ActorTickContext.vtable[i];
        if (func && IsValidModuleAddress((uintptr_t)func)) {
            g_ActorTickContext.origVtableEntries[i] = func;

            MH_STATUS createStatus = MH_CreateHook(func, handlers[i], &g_ActorTickContext.originals[i]);
            if (createStatus == MH_OK) {
                MH_STATUS enableStatus = MH_EnableHook(func);
                bool success = (enableStatus == MH_OK);
                if (success) successCount++; else failCount++;
                if (success) {
                    LOG_SUCCESS("AActor Hook Index: {:<4} | Address: {:#014x} | Status: SUCCESS", i, (uintptr_t)func);
                }
                else {
                    LOG_ERROR("AActor Hook Index: {:<4} | Address: {:#014x} | Status: ENABLE_FAILED", i, (uintptr_t)func);
                }
            }
            else {
                failCount++;
                LOG_ERROR("AActor Hook Index: {:<4} | Address: {:#014x} | Status: CREATE_FAILED", i, (uintptr_t)func);
            }
        }
        else {
            LOG_INFO("AActor Hook Index: {:<4} | Address: (null/invalid) | Status: SKIPPED", i);
        }
    }

    g_ActorTickContext.isHooked = true;
    LOG_INFO("AActor Hook setup complete. Success: {} | Failed: {} | Total: {}",
        successCount, failCount, TICK_SCAN_RANGE - 1);
}

struct WindowSearchContext {
    DWORD targetPid;
    HWND bestHwnd;
    int maxArea;
    int width;
    int height;
};

static BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
    WindowSearchContext* ctx = reinterpret_cast<WindowSearchContext*>(lParam);
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == ctx->targetPid && IsWindowVisible(hwnd)) {
        RECT rect = { 0 };
        if (GetClientRect(hwnd, &rect)) {
            int w = rect.right - rect.left;
            int h = rect.bottom - rect.top;
            int area = w * h;
            if (area > ctx->maxArea) {
                ctx->maxArea = area;
                ctx->bestHwnd = hwnd;
                ctx->width = w;
                ctx->height = h;
            }
        }
    }
    return TRUE;
}

static bool GetProcessWindowResolution(int& outWidth, int& outHeight) {
    WindowSearchContext ctx = { 0 };
    ctx.targetPid = GetCurrentProcessId();
    ctx.bestHwnd = NULL;
    ctx.maxArea = 0;
    ctx.width = 0;
    ctx.height = 0;

    EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&ctx));

    if (ctx.bestHwnd != NULL && ctx.width > 0 && ctx.height > 0) {
        outWidth = ctx.width;
        outHeight = ctx.height;
        return true;
    }
    return false;
}

static void UnloadAndCloseConsole() {
    // 解除所有已建立的 Hook 并恢复现场
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();

    // 释放并关闭控制台句柄
    if (g_ConsoleFile) {
        fclose(g_ConsoleFile);
        g_ConsoleFile = nullptr;
    }
    FreeConsole();
}

void __fastcall DedicatedActorTickHook(SDK::AActor* rcx, float deltaSeconds) {
    static bool s_Exited = false;
    if (s_Exited) return;

    bool shouldExit = false;

    // 仅针对目标采样 Actor 打印日志，避免场景中数百个 Actor 同时输出刷屏
    if (rcx == g_ActorTickContext.instance) {
        LOG_DEBUG("[AActor::Tick] Actor: {:#x} | DeltaTime: {:.6f} | [Press F1 to exit]", (uintptr_t)rcx, deltaSeconds);

        if ((GetAsyncKeyState(EXIT_HOTKEY) & 0x8000) && !s_Exited) {
            shouldExit = true;
        }
    }

    auto orig = g_OriginalActorTick;
    if (orig) {
        orig(rcx, deltaSeconds);
    }

    if (shouldExit && !s_Exited) {
        s_Exited = true;
        LOG_SPECIAL("F1 pressed. Unhooking all functions and closing console...");
        UnloadAndCloseConsole();
    }
}

static void ReportProcessEvent() {
    SDK::UWorld* world = SDK::UWorld::GetWorld();
    if (!world) {
        LOG_ERROR("Failed to get UWorld for ProcessEvent!");
        return;
    }

    void* processEventAddr = SDK::InSDKUtils::GetVirtualFunction<void*>(world, SDK::Offsets::ProcessEventIdx);
    if (!processEventAddr) {
        LOG_ERROR("Failed to get ProcessEvent address!");
        return;
    }

    LOG_SPECIAL("[ProcessEvent Result]");
    LOG_INFO("VTable Index      : {}", SDK::Offsets::ProcessEventIdx);
    LOG_INFO("Memory Address    : {:#x}", (uintptr_t)processEventAddr);

    LOG_INFO("Generating unique signature for ProcessEvent...");
    SigGenDiagnostics diag = GenerateUniqueSignature((uintptr_t)processEventAddr);
    if (diag.success) {
        LOG_SUCCESS("Signature         : {}", diag.signature);
    }
    else {
        LOG_ERROR("Signature         : FAILED TO GENERATE UNIQUE AOB");
        LOG_ERROR("Diagnostics       : disassembled {} bytes, tried {} instruction boundaries",
            diag.bytesDisassembled, diag.instructionsTried);
        if (diag.longestLenTried > 0) {
            LOG_ERROR("                    longest pattern tried = {} bytes, still matched {} locations",
                diag.longestLenTried, diag.matchCountAtLongest);
        }
    }
    LOG_SPECIAL("----");
}

static void EvaluateAndReportTickCandidates(TickScanContext& ctx) {
    if (!ctx.isHooked || ctx.isCompleted) return;

    LOG_SPECIAL("[{}] Tick Candidates Evaluation", ctx.name);

    int matchFound = 0;
    for (int i = 1; i < TICK_SCAN_RANGE; i++) {
        const TickEntryInfo& entry = ctx.entries[i];

        // 判定条件：调用次数与采样基准帧数相近，且 DeltaTime 参数比对一致
        int freqDiff = std::abs(entry.callCount - TICK_SAMPLE_FRAMES);
        if (freqDiff <= TICK_FREQ_TOLERANCE && entry.dtMatched) {
            matchFound++;
            uintptr_t realFunc = (uintptr_t)ctx.origVtableEntries[i];

            // 临时解挂读取纯净字节，生成 AOB
            MH_DisableHook((void*)realFunc);
            SigGenDiagnostics diag = GenerateUniqueSignature(realFunc);
            MH_EnableHook((void*)realFunc);

            LOG_SUCCESS("Candidate Index: {}", i);
            LOG_INFO("  Function Signature : {}", ACTOR_TICK_FUNCTION_SIGNATURE);
            LOG_INFO("  Call Count         : {} (Frame Baseline: {})", entry.callCount, TICK_SAMPLE_FRAMES);
            LOG_INFO("  Matched Delta      : {:.6f}", entry.lastMatchedDt);
            LOG_INFO("  Function Addr      : {:#x}", realFunc);

            if (diag.success) {
                LOG_SUCCESS("  Signature          : {}", diag.signature);
            }
            else {
                LOG_WARN("  Signature          : FAILED TO GENERATE UNIQUE AOB");
            }

            // 锁定第一个匹配项作为最终挂钩目标
            if (ctx.confirmedIndex == -1) {
                ctx.confirmedIndex = i;
            }
        }
    }

    if (matchFound == 0) {
        LOG_WARN("No candidate functions matched the Tick criteria for {}.", ctx.name);
    }
    LOG_SPECIAL("----");

    // 扫描判定完成：彻底解挂并移除所有通用的临时 Hook，恢复游戏环境的原生调用
    for (int i = 1; i < TICK_SCAN_RANGE; i++) {
        if (ctx.origVtableEntries[i]) {
            MH_DisableHook(ctx.origVtableEntries[i]);
            MH_RemoveHook(ctx.origVtableEntries[i]);
        }
    }
    ctx.isCompleted = true;

    // 为已确认的唯一目标单独挂载专属的 float 签名 Hook
    if (ctx.confirmedIndex != -1) {
        void* targetFunc = ctx.origVtableEntries[ctx.confirmedIndex];
        MH_STATUS cStatus = MH_CreateHook(targetFunc, (LPVOID)DedicatedActorTickHook, (LPVOID*)&g_OriginalActorTick);
        if (cStatus == MH_OK) {
            MH_STATUS eStatus = MH_EnableHook(targetFunc);
            if (eStatus == MH_OK) {
                LOG_SPECIAL("Dedicated AActor::Tick hook successfully activated on Index {}! Starting per-frame DeltaTime logging.", ctx.confirmedIndex);
            }
            else {
                LOG_ERROR("Failed to enable dedicated AActor::Tick hook (Status: {})", (int)eStatus);
            }
        }
        else {
            LOG_ERROR("Failed to create dedicated AActor::Tick hook (Status: {})", (int)cStatus);
        }
    }

    // 所有检测与 Hook 流程均已完成，生成并报告 ProcessEvent 特征码与虚表索引
    ReportProcessEvent();
}

static void ProcessTickAutoScan() {
    SDK::UWorld* world = SDK::UWorld::GetWorld();
    if (!world) return;

    // 第一阶段：初始化并挂钩 AActor
    if (!g_TickScanInitiated) {
        SDK::AActor* sampleActor = nullptr;

        // 获取场景中的第一个有效 AActor
        if (world->PersistentLevel && world->PersistentLevel->Actors.Num() > 0) {
            for (int i = 0; i < world->PersistentLevel->Actors.Num(); i++) {
                SDK::AActor* a = world->PersistentLevel->Actors[i];
                if (a && a->VTable) {
                    sampleActor = a;
                    break;
                }
            }
        }

        if (sampleActor) {
            LOG_SUCCESS("Sample AActor acquired: {:#x}", (uintptr_t)sampleActor);
            HookActorTickVTable(sampleActor);
        }
        else {
            LOG_WARN("Could not acquire a valid sample AActor yet, will retry next frame.");
            return;
        }

        g_TickScanInitiated = true;
        g_PostRenderFrameCounter = 0;
        LOG_INFO("AActor Tick profiling started. Collecting samples for {} frames...", TICK_SAMPLE_FRAMES);
        return;
    }

    // 第二阶段：帧计数与采样
    g_PostRenderFrameCounter++;

    // 达到采样阈值，开始综合评定并输出 AOB
    if (g_PostRenderFrameCounter >= TICK_SAMPLE_FRAMES) {
        EvaluateAndReportTickCandidates(g_ActorTickContext);
    }
}

// 校验传入的指针/寄存器原始数据是否与目标 DeltaTime 在误差内一致
// 注意：x64 下 float 通常通过 XMM1/XMM2 传递，但在通用整型寄存器或按引用传递/内联结构时，
// 寄存器底层位模式即为 float 的 IEEE-754 表达，或其指向的内存保存着 float
static bool IsFloatMatching(uintptr_t rawValue, float expectedDt) {
    if (expectedDt <= 0.0f) return false;

    // 1. 尝试直接把低 32 位当做 IEEE 754 浮点值（值传递/寄存器复制模式）
    uint32_t val32 = static_cast<uint32_t>(rawValue & 0xFFFFFFFF);
    float asDirectFloat = *reinterpret_cast<float*>(&val32);
    if (std::abs(asDirectFloat - expectedDt) <= TICK_DT_TOLERANCE) {
        return true;
    }

    // 2. 尝试作为指针解引用读取（引用传递模式，如 FVector/FDeltaTime 结构）
    if (rawValue > 0x10000 && (rawValue % alignof(float) == 0)) {
        float derefFloat = SafeRead<float>(rawValue);
        if (std::abs(derefFloat - expectedDt) <= TICK_DT_TOLERANCE) {
            return true;
        }
    }

    return false;
}

void __fastcall UniversalActorTickDumper(int funcIdx, void* rcx, void* rdx, void* r8) {
    // 如果已完成扫描判定，直接放行原调用
    if (g_ActorTickContext.isCompleted) {
        auto orig = (void(__fastcall*)(void*, void*, void*))g_ActorTickContext.originals[funcIdx];
        if (orig) orig(rcx, rdx, r8);
        return;
    }

    // 仅针对目标 AActor 实例的虚函数调用进行统计
    if (rcx == g_ActorTickContext.instance) {
        TickEntryInfo& entry = g_ActorTickContext.entries[funcIdx];
        entry.callCount++;

        SDK::UWorld* world = SDK::UWorld::GetWorld();
        if (world) {
            float currentDt = SDK::UGameplayStatics::GetWorldDeltaSeconds(world);

            // 检查第二个参数 (rdx) 或第三个参数 (r8)
            if (IsFloatMatching((uintptr_t)rdx, currentDt)) {
                entry.dtMatched = true;
                entry.lastMatchedDt = currentDt;
            }
            else if (IsFloatMatching((uintptr_t)r8, currentDt)) {
                entry.dtMatched = true;
                entry.lastMatchedDt = currentDt;
            }
        }
    }

    auto orig = (void(__fastcall*)(void*, void*, void*))g_ActorTickContext.originals[funcIdx];
    if (orig) orig(rcx, rdx, r8);
}

void __fastcall UniversalDumper(int index, void* rcx, void* rdx, void* r8) {
    // 如果已经确定了唯一函数，直接调用原函数并返回，不再进入扫描逻辑
    if (IsFound && !TrackedMatches[index].isConfirmed) {
        auto orig = (void(__fastcall*)(void*, void*, void*))Originals[index];
        if (orig) orig(rcx, rdx, r8);
        return;
    }

    // 稳态超时检查：如果动态获取的分辨率在指定时间内未能匹配确认，回滚到硬编码配置
    if (g_UsingDynamicResolution && !g_HasRolledBack && !IsFound) {
        if (GetTickCount64() - g_HookStartTime >= DYNAMIC_RES_TIMEOUT_MS) {
            LOG_WARN("Steady state timeout ({}ms): UCanvas->Size does not match dynamic resolution ({}x{}). Rolling back to hardcoded TARGET ({}x{}).",
                DYNAMIC_RES_TIMEOUT_MS, g_ActiveTargetWidth, g_ActiveTargetHeight, TARGET_WIDTH, TARGET_HEIGHT);
            g_ActiveTargetWidth = TARGET_WIDTH;
            g_ActiveTargetHeight = TARGET_HEIGHT;
            g_UsingDynamicResolution = false;
            g_HasRolledBack = true;

            for (int i = 0; i < SCAN_RANGE; i++) {
                TrackedMatches[i].count = 0;
                TrackedMatches[i].lastRDX = 0;
                TrackedMatches[i].lastVTable = 0;
            }
        }
    }

    uintptr_t addr = (uintptr_t)rdx;

    // 1. 基础过滤：UE 实例对齐检查
    if (addr > 0x100000000 && (addr % 16 == 0)) {
        int32_t readX = SafeRead<int32_t>(addr + SIZE_X_OFFSET);
        int32_t readY = SafeRead<int32_t>(addr + SIZE_Y_OFFSET);

        if (readX == g_ActiveTargetWidth && readY == g_ActiveTargetHeight) {
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
                            // 优先模式下只允许特征码命中的当前 index 被确认，避免把匹配项的下一个非匹配函数误判为目标。
                            bool allowConfirmInPreferredMode = (!g_PreferredMode) || g_IsPreferredIndex[index];
                            if (allowConfirmInPreferredMode && !IsFound) {
                                LOG_SPECIAL(">>> TARGET LOCATED <<< Current Index: {} | Next Index: {} confirmed.", index, nextIndex);
                                LOG_SPECIAL(">>> FINAL POSTRENDER: Index {} | RDX: {:#x}", index, (uintptr_t)rdx);

                                TrackedMatches[index].isConfirmed = true;
                                IsFound = true;

                                // 使用保存的原始函数地址
                                uintptr_t realFuncAddr = (uintptr_t)OriginalVTableEntries[index];

                                // 打印诊断信息
                                LOG_INFO("OriginalVTableEntries[{}] = {:#x}", index, realFuncAddr);
                                LOG_INFO("vtable[{}({:#x})] = {:#x}", index, (uintptr_t) & ((void**)vtable)[index], (uintptr_t)((void**)vtable)[index]);

                                // 检查地址是否在 .text 段内
                                HMODULE hMod = GetModuleHandleA(NULL);
                                if (hMod) {
                                    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
                                    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint8_t*)hMod + dos->e_lfanew);
                                    uintptr_t textStart = (uintptr_t)hMod + nt->OptionalHeader.BaseOfCode;
                                    uintptr_t textEnd = textStart + nt->OptionalHeader.SizeOfCode;
                                    bool inRange = (realFuncAddr >= textStart && realFuncAddr < textEnd);
                                    LOG_INFO("realFuncAddr in .text: {} (range: {:#x} - {:#x})", inRange, textStart, textEnd);
                                }

                                // 临时禁用 Hook 以读取原始字节
                                LOG_INFO("Temporarily disabling hook on index {}...", index);
                                void* targetFunc = (void*)realFuncAddr;
                                bool hookDisabled = (MH_DisableHook(targetFunc) == MH_OK);

                                if (!hookDisabled) {
                                    LOG_WARN("Warning: Failed to disable hook (status: {}), bytes may be modified!", hookDisabled);
                                    // 尝试直接读取，可能已经被其他 Hook 修改
                                }

                                // 读取原始字节
                                std::vector<uint8_t> originalBytes(64);
                                SIZE_T bytesRead;
                                if (ReadProcessMemory(hProcess, (LPCVOID)realFuncAddr, originalBytes.data(), 64, &bytesRead)) {
                                    std::print(COLOR_CYAN "[*] First {} bytes at {:#x}: " COLOR_RESET, bytesRead, realFuncAddr);
                                    for (size_t i = 0; i < bytesRead; i++) {
                                        std::print("{:02X} ", originalBytes[i]);
                                    }
                                    std::println("");
                                }

                                // 如果地址不在 .text 段或者 MH_DisableHook 失败，尝试使用 vtable 中的值
                                if (!hookDisabled || !IsValidModuleAddress(realFuncAddr)) {
                                    LOG_WARN("Trying alternative: using vtable slot value...");
                                    realFuncAddr = (uintptr_t)((void**)vtable)[index];
                                    LOG_INFO("Alternative address: {:#x}", realFuncAddr);

                                    // 再次检查是否在 .text 段
                                    if (hMod) {
                                        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
                                        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint8_t*)hMod + dos->e_lfanew);
                                        uintptr_t textStart = (uintptr_t)hMod + nt->OptionalHeader.BaseOfCode;
                                        uintptr_t textEnd = textStart + nt->OptionalHeader.SizeOfCode;
                                        bool inRange = (realFuncAddr >= textStart && realFuncAddr < textEnd);
                                        LOG_INFO("Alternative address in .text: {}", inRange);
                                    }
                                }

                                LOG_INFO("Generating unique signature for PostRender (this may take a moment)...");

                                SigGenDiagnostics diag = GenerateUniqueSignature(realFuncAddr);

                                // 重新启用 Hook（如果之前禁用了的话）
                                if (hookDisabled) {
                                    LOG_INFO("Re-enabling hook on index {}...", index);
                                    MH_EnableHook(targetFunc);
                                }

                                std::println("[PostRender Result]");
                                if (diag.success) {
                                    LOG_SUCCESS("Signature        : {}", diag.signature);
                                }
                                else {
                                    LOG_ERROR("Signature        : FAILED (skipped)");
                                    LOG_ERROR("Diagnostics      : disassembled {} bytes, tried {} instruction boundaries",
                                        diag.bytesDisassembled, diag.instructionsTried);
                                    if (diag.longestLenTried > 0) {
                                        LOG_ERROR("                     longest pattern tried = {} bytes, still matched {} locations",
                                            diag.longestLenTried, diag.matchCountAtLongest);
                                    }
                                    LOG_ERROR("                     consider raising SIG_MAX_SCAN_LEN / SIG_MAX_INSNS further if the function is long");
                                }
                                LOG_SUCCESS("Memory Address    : {:#x}", realFuncAddr);
                                LOG_SUCCESS("VTable Index      : {}", index);
                                std::println("----");

                                // 目标已确认：禁用除 PostRender 本身以外的所有其余 Hook，
                                // 避免后续每一帧都对其它（可能已销毁/被复用的）vtable 条目
                                // 继续执行扫描逻辑，减少无谓开销和误判风险。
                                LOG_INFO("Disabling remaining {} unused hooks...", SCAN_RANGE - 2);
                                int disabledCount = 0;
                                for (int j = 1; j < SCAN_RANGE; j++) {
                                    if (j == index) continue; // 保留 PostRender 自身的 Hook（用于持续绘制）
                                    if (Originals[j]) {
                                        // Originals[j] 非空说明 MH_CreateHook 当初成功过，
                                        // 但 MH_DisableHook 需要的是"目标函数地址"而非 trampoline 地址，
                                        // 这里通过 vtable 反查回原始目标地址来禁用。
                                        void* target = ((void**)vtable)[j];
                                        if (target && MH_DisableHook(target) == MH_OK) {
                                            disabledCount++;
                                        }
                                    }
                                }
                                LOG_INFO("Disabled {} hooks. Only PostRender (index {}) remains active.",
                                    disabledCount, index);
                            }
                        }
                    }

                    // 如果已经锁定是当前这个 index，执行绘制并驱动 Tick 扫描
                    if (TrackedMatches[index].isConfirmed) {
                        SDK::UCanvas* canvas = (SDK::UCanvas*)rdx;
                        SDK::FLinearColor green = { 0.f, 1.f, 0.f, 1.f };
                        canvas->K2_DrawBox({ 2, 2 }, { 50, 50 }, 1.0f, green);

                        // 自动定位 AActor::Tick
                        ProcessTickAutoScan();
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

H_FUNC(0) H_FUNC(1) H_FUNC(2) H_FUNC(3) H_FUNC(4) H_FUNC(5) H_FUNC(6) H_FUNC(7) H_FUNC(8) H_FUNC(9)
REPEAT_10(H_FUNC, 1) REPEAT_10(H_FUNC, 2) REPEAT_10(H_FUNC, 3) REPEAT_10(H_FUNC, 4) REPEAT_10(H_FUNC, 5)
REPEAT_10(H_FUNC, 6) REPEAT_10(H_FUNC, 7) REPEAT_10(H_FUNC, 8) REPEAT_10(H_FUNC, 9)
REPEAT_100(H_FUNC, 1) REPEAT_100(H_FUNC, 2) REPEAT_100(H_FUNC, 3) REPEAT_100(H_FUNC, 4)

// 解析单条预设特征码字符串为逐字节模式
static bool ParsePredefinedSignature(const std::string& sig, std::vector<SigByte>& out) {
    out.clear();

    std::istringstream iss(sig);
    std::string token;

    while (iss >> token) {
        if (token == "?" || token == "??") {
            out.push_back(SigByte{ 0, true });
            continue;
        }

        if (token.size() != 2) {
            return false;
        }

        auto hexVal = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
            };

        int hi = hexVal(token[0]);
        int lo = hexVal(token[1]);
        if (hi < 0 || lo < 0) {
            return false;
        }

        out.push_back(SigByte{ static_cast<uint8_t>((hi << 4) | lo), false });
    }

    return !out.empty();
}

// 判断指定地址开始的字节是否匹配预设特征码
static bool MatchPredefinedPatternAtAddress(uintptr_t addr, const std::vector<SigByte>& pattern) {
    if (!addr || pattern.empty()) {
        return false;
    }

    std::vector<uint8_t> bytes(pattern.size(), 0);
    SIZE_T read = 0;

    if (!ReadProcessMemory(hProcess, (LPCVOID)addr, bytes.data(), bytes.size(), &read) || read != bytes.size()) {
        return false;
    }

    for (size_t i = 0; i < pattern.size(); ++i) {
        if (pattern[i].isWildcard) {
            continue;
        }
        if (bytes[i] != pattern[i].value) {
            return false;
        }
    }

    return true;
}

// 扫描 GameViewport vtable 中所有虚函数头部，返回命中预设特征码的索引列表
static std::vector<int> ScanVTableForPredefinedSignatures(void** vtable) {
    std::vector<int> matchedIndices;

    if (!vtable) {
        return matchedIndices;
    }

    std::vector<std::vector<SigByte>> patterns;
    patterns.reserve(g_PredefinedSignatures.size());

    for (const std::string& sig : g_PredefinedSignatures) {
        std::vector<SigByte> pattern;
        if (ParsePredefinedSignature(sig, pattern)) {
            patterns.push_back(std::move(pattern));
        }
        else {
            LOG_WARN("Invalid predefined signature skipped: {}", sig);
        }
    }

    if (patterns.empty()) {
        return matchedIndices;
    }

    for (int i = 1; i < SCAN_RANGE; ++i) {
        void* fn = vtable[i];
        if (!fn) {
            continue;
        }

        uintptr_t addr = (uintptr_t)fn;
        if (!IsValidModuleAddress(addr)) {
            continue;
        }

        for (size_t pi = 0; pi < patterns.size(); ++pi) {
            if (MatchPredefinedPatternAtAddress(addr, patterns[pi])) {
                matchedIndices.push_back(i);
                LOG_SPECIAL("Predefined signature #{} matched vtable[{}] at {:#x}", pi + 1, i, addr);
                break;
            }
        }
    }

    return matchedIndices;
}

void SetupHooks(void** vtable) {
    if (MH_Initialize() != MH_OK) return;
    hProcess = GetCurrentProcess();

    MODULEINFO mi;
    GetModuleInformation(hProcess, GetModuleHandleA(NULL), &mi, sizeof(mi));
    ModuleBase = (uintptr_t)mi.lpBaseOfDll;
    ModuleSize = mi.SizeOfImage;

    g_PreferredMode = false;
    for (int i = 0; i < SCAN_RANGE; ++i) {
        g_IsPreferredIndex[i] = false;
    }

#define P_H(i) (void*)H_##i
    std::vector<void*> hFns;
    hFns.push_back(P_H(0)); hFns.push_back(P_H(1)); hFns.push_back(P_H(2)); hFns.push_back(P_H(3)); hFns.push_back(P_H(4));
    hFns.push_back(P_H(5)); hFns.push_back(P_H(6)); hFns.push_back(P_H(7)); hFns.push_back(P_H(8)); hFns.push_back(P_H(9));

#define P_PUSH(i) hFns.push_back(P_H(i));
    REPEAT_10(P_PUSH, 1) REPEAT_10(P_PUSH, 2) REPEAT_10(P_PUSH, 3) REPEAT_10(P_PUSH, 4) REPEAT_10(P_PUSH, 5)
        REPEAT_10(P_PUSH, 6) REPEAT_10(P_PUSH, 7) REPEAT_10(P_PUSH, 8) REPEAT_10(P_PUSH, 9)
        REPEAT_100(P_PUSH, 1) REPEAT_100(P_PUSH, 2) REPEAT_100(P_PUSH, 3) REPEAT_100(P_PUSH, 4)

        LOG_INFO("Scanning GameViewport vtable for predefined signatures before hooking...");
    std::vector<int> matchedIndices = ScanVTableForPredefinedSignatures(vtable);

    std::vector<int> indicesToHook;
    bool preferredMode = !matchedIndices.empty();

    if (preferredMode) {
        g_PreferredMode = true;

        for (int idx : matchedIndices) {
            if (idx >= 0 && idx < SCAN_RANGE) {
                g_IsPreferredIndex[idx] = true;
            }
        }

        std::vector<bool> needHook(SCAN_RANGE, false);
        for (int idx : matchedIndices) {
            if (idx >= 1 && idx < SCAN_RANGE) {
                needHook[idx] = true;
            }

            int nextIdx = idx + 1;
            if (nextIdx >= 1 && nextIdx < SCAN_RANGE) {
                needHook[nextIdx] = true;
            }
        }

        for (int i = 1; i < SCAN_RANGE; ++i) {
            if (needHook[i]) {
                indicesToHook.push_back(i);
            }
        }

        LOG_SUCCESS("Predefined signature matched {} vtable index(es). Preferred mode enabled.", matchedIndices.size());

        std::string idxList;
        for (int idx : indicesToHook) {
            if (!idxList.empty()) idxList += ", ";
            idxList += std::to_string(idx);
        }
        LOG_INFO("Preferred hook indices (matched + next): {}", idxList);
    }
    else {
        LOG_WARN("No predefined signature matched. Falling back to full vtable hooking.");

        for (int i = 1; i < SCAN_RANGE; ++i) {
            indicesToHook.push_back(i);
        }
    }

    LOG_INFO("Starting to create hooks for {} vtable entries...", indicesToHook.size());

    int successCount = 0;
    int failCount = 0;
    int skippedRemaining = 0;
    size_t processedCount = 0;

    for (int i : indicesToHook) {
        // 极早期防御：如果在建 Hook 过程中（理论上极少见，因为 IsFound 通常要等
        // STABLE_FRAME_THRESHOLD 帧之后才会被置位）目标已经确定，则提前停止创建
        // 剩余 Hook。正常情况下真正的清理发生在 UniversalDumper 确认目标后，
        // 通过禁用已建立的其余 Hook 来实现（见下方 MH_DisableHook 逻辑）。
        if (IsFound) {
            skippedRemaining = (int)(indicesToHook.size() - processedCount);
            LOG_WARN("Target already found, stopping hook creation early at index {}. Remaining {} entries skipped.",
                i, skippedRemaining);
            break;
        }
        processedCount++;

        if (vtable[i]) {
            // 在创建 Hook 之前保存原始函数地址
            OriginalVTableEntries[i] = vtable[i];

            MH_STATUS createStatus = MH_CreateHook(vtable[i], hFns[i], &Originals[i]);
            if (createStatus == MH_OK) {
                MH_STATUS enableStatus = MH_EnableHook(vtable[i]);
                bool success = (enableStatus == MH_OK);
                if (success) successCount++; else failCount++;
                if (success) {
                    LOG_SUCCESS("Hook Index: {:<4} | Address: {:#014x} | Status: SUCCESS", i, (uintptr_t)vtable[i]);
                }
                else {
                    LOG_ERROR("Hook Index: {:<4} | Address: {:#014x} | Status: ENABLE_FAILED", i, (uintptr_t)vtable[i]);
                }
            }
            else {
                failCount++;
                LOG_ERROR("Hook Index: {:<4} | Address: {:#014x} | Status: CREATE_FAILED", i, (uintptr_t)vtable[i]);
            }
        }
        else {
            LOG_INFO("Hook Index: {:<4} | Address: (null) | Status: SKIPPED", i);
        }
    }

    LOG_INFO("Hook setup complete. Success: {} | Failed: {} | Skipped(early-stop): {} | Total: {}",
        successCount, failCount, skippedRemaining, indicesToHook.size());
}

DWORD WINAPI MainThread(LPVOID lpParam) {
    AllocConsole();
    freopen_s(&g_ConsoleFile, "CONOUT$", "w", stdout);

    // 启用 ANSI 转义序列支持（彩色日志）
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD consoleMode = 0;
    if (GetConsoleMode(hConsole, &consoleMode)) {
        consoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hConsole, consoleMode);
    }

    LOG_SPECIAL("[github.com/zetsr] / [www.unknowncheats.me/forum/members/4701133.html]");

    // 优先尝试自动获取当前进程的窗口分辨率
    int dynW = 0, dynH = 0;
    if (GetProcessWindowResolution(dynW, dynH)) {
        g_ActiveTargetWidth = dynW;
        g_ActiveTargetHeight = dynH;
        g_UsingDynamicResolution = true;
        LOG_SUCCESS("Automatically detected window resolution: {} x {}", dynW, dynH);
    }
    else {
        g_ActiveTargetWidth = TARGET_WIDTH;
        g_ActiveTargetHeight = TARGET_HEIGHT;
        g_UsingDynamicResolution = false;
        LOG_WARN("Failed to detect window resolution automatically, falling back to hardcoded: {} x {}", TARGET_WIDTH, TARGET_HEIGHT);
    }

    // 打印当前使用的配置
    std::println("[Configuration]");
    LOG_INFO("Active Target Res      : {} x {} (Dynamic: {})", g_ActiveTargetWidth, g_ActiveTargetHeight, g_UsingDynamicResolution);
    LOG_INFO("Fallback Hardcoded Res : {} x {}", TARGET_WIDTH, TARGET_HEIGHT);
    LOG_INFO("Fallback Timeout       : {} ms", DYNAMIC_RES_TIMEOUT_MS);
    LOG_INFO("SIZE_X_OFFSET          : {:#x}", SIZE_X_OFFSET);
    LOG_INFO("SIZE_Y_OFFSET          : {:#x}", SIZE_Y_OFFSET);
    LOG_INFO("SCAN_RANGE             : {}", SCAN_RANGE);
    LOG_INFO("STABLE_FRAME_THRESHOLD : {}", STABLE_FRAME_THRESHOLD);
    LOG_INFO("TICK_SCAN_RANGE        : {}", TICK_SCAN_RANGE);
    LOG_INFO("TICK_SAMPLE_FRAMES     : {}", TICK_SAMPLE_FRAMES);
    LOG_INFO("TICK_FREQ_TOLERANCE    : {}", TICK_FREQ_TOLERANCE);
    LOG_INFO("TICK_DT_TOLERANCE      : {:.4f}", TICK_DT_TOLERANCE);
    std::println("----");

    LOG_INFO("Waiting for SDK::UEngine::GetEngine() and GameViewport...");

    SDK::UEngine* engine = nullptr;
    int waitTicks = 0;
    while (true) {
        engine = SDK::UEngine::GetEngine();
        if (engine && engine->GameViewport) break;

        // 每隔约 5 秒打印一次等待状态，避免看起来像"卡死"，方便区分死循环与真正的初始化耗时
        waitTicks++;
        if (waitTicks % 50 == 0) {
            LOG_INFO("Still waiting... engine={:#x}, GameViewport={:#x} (elapsed ~{} sec)",
                (uintptr_t)engine, engine ? (uintptr_t)engine->GameViewport : 0, waitTicks / 10);
        }

        Sleep(100);
    }

    LOG_SUCCESS("Engine and GameViewport acquired. engine={:#x}, GameViewport={:#x}",
        (uintptr_t)engine, (uintptr_t)engine->GameViewport);

    // 记录 Hook 开始时间基准，用于稳态超时回滚判定
    g_HookStartTime = GetTickCount64();
    SetupHooks(*(void***)engine->GameViewport);
    LOG_INFO("Hooks applied. Waiting for candidate pair (N and N+1)...");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hM, DWORD r, LPVOID res) {
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hM);
        CreateThread(0, 0, MainThread, 0, 0, 0);
    }
    return TRUE;
}