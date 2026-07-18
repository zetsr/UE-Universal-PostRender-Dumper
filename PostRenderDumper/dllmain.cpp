#include <windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <print>
#include <format>
#include <psapi.h>
#include "MinHook/include/MinHook.h"
#include "SDK/SDK_Headers.hpp"
#include "AOBScan.hpp"

// https://github.com/zyantific/zydis
extern "C" {
#include "Zydis/Zydis.h"
}

// CFG
#define TARGET_WIDTH  1920           // 窗口分辨率 W     // Windows Screen Size W
#define TARGET_HEIGHT 1080           // 窗口分辨率 H     // Windows Screen Size H
#define SIZE_X_OFFSET 0x40           // UCanvas->SizeX   // 0x40 是大部分 UE 版本 的 UCanvas 结构体中 SizeX 的偏移，具体以 Dumper-7 生成的 SDK 为准
#define SCAN_RANGE    200            // 硬编码           // 扫描前 200 个函数（从 vtable[1] 开始）以寻找候选函数
#define STABLE_FRAME_THRESHOLD 120   // 硬编码           // 稳定性阈值：连续 120 帧（约 2 秒）满足条件才认定为候选函数

// 特征码生成相关配置
#define SIG_MAX_SCAN_LEN   256       // 反汇编时最多累积的字节数上限
#define SIG_MAX_INSNS      48        // 最多反汇编的指令条数上限

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

    // ========== 策略1: 逐字节尝试（从短到长） ==========
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

    // ========== 策略2: 回退到指令边界尝试 ==========
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

// ------------------------------------------------------------------------------------

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

                                std::println("========== PostRender Result ==========");
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
                                std::println("========================================");

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

        LOG_INFO("Starting to create hooks for {} vtable entries...", SCAN_RANGE - 1);

    int successCount = 0;
    int failCount = 0;
    int skippedRemaining = 0;

    for (int i = 1; i < SCAN_RANGE; i++) {
        // 极早期防御：如果在建 Hook 过程中（理论上极少见，因为 IsFound 通常要等
        // STABLE_FRAME_THRESHOLD 帧之后才会被置位）目标已经确定，则提前停止创建
        // 剩余 Hook。正常情况下真正的清理发生在 UniversalDumper 确认目标后，
        // 通过禁用已建立的其余 Hook 来实现（见下方 MH_DisableHook 逻辑）。
        if (IsFound) {
            skippedRemaining = SCAN_RANGE - i;
            LOG_WARN("Target already found, stopping hook creation early at index {}. Remaining {} entries skipped.",
                i, skippedRemaining);
            break;
        }

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
        successCount, failCount, skippedRemaining, SCAN_RANGE - 1);
}

DWORD WINAPI MainThread(LPVOID lpParam) {
    AllocConsole();
    FILE* f; freopen_s(&f, "CONOUT$", "w", stdout);

    // 启用 ANSI 转义序列支持（彩色日志）
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD consoleMode = 0;
    if (GetConsoleMode(hConsole, &consoleMode)) {
        consoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hConsole, consoleMode);
    }

    LOG_SPECIAL("--- Post Render Auto-Finder ---");

    // 需求 1：打印分辨率、SIZE_X_OFFSET、SCAN_RANGE、STABLE_FRAME_THRESHOLD
    std::println("========== Configuration ==========");
    LOG_INFO("Target Resolution      : {} x {}", TARGET_WIDTH, TARGET_HEIGHT);
    LOG_INFO("SIZE_X_OFFSET          : {:#x}", SIZE_X_OFFSET);
    LOG_INFO("SCAN_RANGE             : {}", SCAN_RANGE);
    LOG_INFO("STABLE_FRAME_THRESHOLD : {}", STABLE_FRAME_THRESHOLD);
    std::println("====================================");

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