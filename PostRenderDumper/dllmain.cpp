#include <windows.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <mutex>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "MinHook/include/MinHook.h"
#include "SDK/SDK_Headers.hpp"
#include "AOBScan.hpp"

extern "C" {
#include "Zydis/Zydis.h"
}

namespace Dumper
{

struct FConfig
{
    // 确保和目标客户端分辨率一致
    static constexpr int32_t TargetWidth = 1920;   // 窗口分辨率 W     // Windows Screen Size W
    static constexpr int32_t TargetHeight = 1080;  // 窗口分辨率 H     // Windows Screen Size H

    // 编译器直接从 SDK 提取 Dumper-7 生成的 UCanvas->SizeX 与 SizeY 真实偏移
    static constexpr size_t SizeXOffset = offsetof(SDK::UCanvas, SizeX);
    static constexpr size_t SizeYOffset = offsetof(SDK::UCanvas, SizeY);

    // 扫描前 200 个函数（从 vtable[1] 开始）以寻找候选函数
    static constexpr int32_t ScanRange = 200;

    // 稳定性阈值：连续 120 帧（约 2 秒）满足条件才认定为候选函数
    static constexpr int32_t StableFrameThreshold = 120;

    // 动态分辨率稳态超时（毫秒）：5 秒未能通过动态分辨率找到目标则回滚
    static constexpr uint32_t DynamicResolutionTimeoutMs = 5000;

    // 预设特征码命中的候选全部为误报时，回退到全量虚函数挂钩的超时（毫秒）
    static constexpr uint32_t PreferredFallbackTimeoutMs = 5000;

    // 退出并解除所有 Hook 的热键
    static constexpr int32_t ExitHotkey = VK_F1;

    // 特征码生成：反汇编时最多累积的字节数与指令条数上限
    static constexpr size_t SignatureMaxScanLength = 256;
    static constexpr int32_t SignatureMaxInstructions = 48;

    // Tick 扫描：扫描虚表 1 到 500，采样 120 帧，并给出调用频次与 DeltaTime 的允许误差
    static constexpr int32_t TickScanRange = 500;
    static constexpr int32_t TickSampleFrames = 120;
    static constexpr int32_t TickFrequencyTolerance = 15;
    static constexpr float TickDeltaTimeTolerance = 0.015f;

    // 打印所使用的 AActor::Tick 函数签名格式
    static constexpr std::string_view ActorTickFunctionSignature = "void __fastcall AActor::Tick(AActor* _this, float DeltaSeconds)";

    // 预设特征码：? 表示通配符
    static constexpr std::array<std::string_view, 3> PostRenderSignatures = { {
        "8B C2 35 ? ? ? ? 44",
        "48 8B 01 48 FF A0 ? ? ? ? CC CC CC CC CC CC",
        "40 55 53 57 48 8D"
    } };

    // AActor::Tick 预设特征码：? 表示通配符
    static constexpr std::array<std::string_view, 1> ActorTickSignatures = { {
        "40 53 48 83 EC"
    } };
};

enum class ELogLevel : uint8_t
{
    Debug,
    Info,
    Success,
    Warning,
    Error,
    Special
};

class FLog
{
public:
    static void Initialize()
    {
        const HANDLE Console = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD Mode = 0;
        if (GetConsoleMode(Console, &Mode) != FALSE)
        {
            SetConsoleMode(Console, Mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
        SetConsoleOutputCP(CP_UTF8);
    }

    template <typename... TArgs>
    static void Debug(std::format_string<TArgs...> Format, TArgs&&... Args)
    {
        Print(ELogLevel::Debug, std::format(Format, std::forward<TArgs>(Args)...));
    }

    template <typename... TArgs>
    static void Info(std::format_string<TArgs...> Format, TArgs&&... Args)
    {
        Print(ELogLevel::Info, std::format(Format, std::forward<TArgs>(Args)...));
    }

    template <typename... TArgs>
    static void Success(std::format_string<TArgs...> Format, TArgs&&... Args)
    {
        Print(ELogLevel::Success, std::format(Format, std::forward<TArgs>(Args)...));
    }

    template <typename... TArgs>
    static void Warning(std::format_string<TArgs...> Format, TArgs&&... Args)
    {
        Print(ELogLevel::Warning, std::format(Format, std::forward<TArgs>(Args)...));
    }

    template <typename... TArgs>
    static void Error(std::format_string<TArgs...> Format, TArgs&&... Args)
    {
        Print(ELogLevel::Error, std::format(Format, std::forward<TArgs>(Args)...));
    }

    template <typename... TArgs>
    static void Special(std::format_string<TArgs...> Format, TArgs&&... Args)
    {
        Print(ELogLevel::Special, std::format(Format, std::forward<TArgs>(Args)...));
    }

    static void Section(std::string_view Title)
    {
        Print(ELogLevel::Special, std::format("\n==== {} ====", Title));
    }

    template <typename... TArgs>
    static void Field(ELogLevel Level, std::string_view Key, std::format_string<TArgs...> Format, TArgs&&... Args)
    {
        Print(Level, std::format("  {:<12}: {}", Key, std::format(Format, std::forward<TArgs>(Args)...)));
    }

private:
    static void Print(ELogLevel Level, std::string_view Message);
    static std::string_view GetTag(ELogLevel Level);
    static std::string_view GetTagColor(ELogLevel Level);
    static std::string_view GetBodyColor(ELogLevel Level);
    static std::mutex& GetMutex();
};

void FLog::Print(ELogLevel Level, std::string_view Message)
{
    SYSTEMTIME Time{};
    GetLocalTime(&Time);

    const std::string Line = std::format(
        "\x1b[90m[{:02}:{:02}:{:02}.{:03}]\x1b[0m {}{}\x1b[0m {}{}\x1b[0m\n",
        static_cast<int32_t>(Time.wHour),
        static_cast<int32_t>(Time.wMinute),
        static_cast<int32_t>(Time.wSecond),
        static_cast<int32_t>(Time.wMilliseconds),
        GetTagColor(Level),
        GetTag(Level),
        GetBodyColor(Level),
        Message);

    const std::lock_guard<std::mutex> Lock(GetMutex());
    std::print("{}", Line);
    std::fflush(stdout);
}

std::string_view FLog::GetTag(ELogLevel Level)
{
    switch (Level)
    {
    case ELogLevel::Debug: return "[DBG ]";
    case ELogLevel::Info: return "[INFO]";
    case ELogLevel::Success: return "[ OK ]";
    case ELogLevel::Warning: return "[WARN]";
    case ELogLevel::Error: return "[FAIL]";
    case ELogLevel::Special: return "[ >> ]";
    }

    return "[????]";
}

std::string_view FLog::GetTagColor(ELogLevel Level)
{
    switch (Level)
    {
    case ELogLevel::Debug: return "\x1b[90m";
    case ELogLevel::Info: return "\x1b[36m";
    case ELogLevel::Success: return "\x1b[1;32m";
    case ELogLevel::Warning: return "\x1b[1;33m";
    case ELogLevel::Error: return "\x1b[1;91m";
    case ELogLevel::Special: return "\x1b[1;35m";
    }

    return "";
}

std::string_view FLog::GetBodyColor(ELogLevel Level)
{
    switch (Level)
    {
    case ELogLevel::Debug: return "\x1b[90m";
    case ELogLevel::Info: return "";
    case ELogLevel::Success: return "\x1b[32m";
    case ELogLevel::Warning: return "\x1b[33m";
    case ELogLevel::Error: return "\x1b[91m";
    case ELogLevel::Special: return "\x1b[35m";
    }

    return "";
}

std::mutex& FLog::GetMutex()
{
    static std::mutex Mutex;
    return Mutex;
}

struct FMatchInfo
{
    int32_t Count = 0;
    uintptr_t LastCanvas = 0;
    uintptr_t LastVTable = 0;
    bool bConfirmed = false;
};

struct FTickEntryInfo
{
    int32_t CallCount = 0;
    float LastMatchedDelta = 0.0f;
    bool bDeltaMatched = false;
};

struct FSignatureResult
{
    bool bSuccess = false;
    std::string Signature;
    size_t BytesDisassembled = 0;
    size_t CandidatesTested = 0;
    size_t LongestLength = 0;
    size_t LongestMatchCount = 0;
};

class FSignatureGenerator
{
public:
    static FSignatureResult Generate(uintptr_t FunctionAddress);

private:
    struct FByteMark
    {
        uint8_t Value = 0;
        bool bWildcard = false;
    };

    struct FDisassembly
    {
        std::vector<FByteMark> Marks;
        std::vector<size_t> Boundaries;
    };

    static FDisassembly Disassemble(uintptr_t FunctionAddress);
    static void MarkWildcards(std::vector<FByteMark>& Marks, size_t Offset, size_t Length);
    static std::string BuildPattern(const std::vector<FByteMark>& Marks, size_t Length);
};

void ReportProcessEvent();

template <size_t N>
std::vector<FAOBPattern> ParsePatterns(const std::array<std::string_view, N>& Sources)
{
    std::vector<FAOBPattern> Patterns;
    Patterns.reserve(N);

    for (const std::string_view Source : Sources)
    {
        std::optional<FAOBPattern> Pattern = FAOBPattern::Parse(Source);
        if (!Pattern)
        {
            FLog::Warning("Invalid predefined signature skipped: {}", Source);
            continue;
        }
        Patterns.push_back(std::move(*Pattern));
    }

    return Patterns;
}

std::string JoinIndices(const std::vector<int32_t>& Indices)
{
    std::string Result;
    for (size_t Index = 0; Index < Indices.size(); ++Index)
    {
        if (Index != 0) Result += ", ";
        Result += std::to_string(Indices[Index]);
    }
    return Result;
}

struct FWindowSearchContext
{
    DWORD ProcessId = 0;
    HWND BestWindow = nullptr;
    int32_t MaxArea = 0;
    int32_t Width = 0;
    int32_t Height = 0;
};

BOOL CALLBACK EnumWindowCallback(HWND Window, LPARAM Parameter)
{
    auto* Context = reinterpret_cast<FWindowSearchContext*>(Parameter);

    DWORD ProcessId = 0;
    GetWindowThreadProcessId(Window, &ProcessId);
    if (ProcessId != Context->ProcessId || IsWindowVisible(Window) == FALSE) return TRUE;

    RECT Rect{};
    if (GetClientRect(Window, &Rect) == FALSE) return TRUE;

    const int32_t Width = Rect.right - Rect.left;
    const int32_t Height = Rect.bottom - Rect.top;
    const int32_t Area = Width * Height;
    if (Area <= Context->MaxArea) return TRUE;

    Context->MaxArea = Area;
    Context->BestWindow = Window;
    Context->Width = Width;
    Context->Height = Height;
    return TRUE;
}

bool TryGetProcessResolution(int32_t& Width, int32_t& Height)
{
    FWindowSearchContext Context;
    Context.ProcessId = GetCurrentProcessId();
    EnumWindows(EnumWindowCallback, reinterpret_cast<LPARAM>(&Context));

    if (Context.BestWindow == nullptr || Context.Width <= 0 || Context.Height <= 0) return false;

    Width = Context.Width;
    Height = Context.Height;
    return true;
}

class FActorTickScanner
{
public:
    void Advance();
    void ProcessCall(int32_t Index, void* Rcx, void* Rdx, void* R8);

private:
    static constexpr size_t Range = static_cast<size_t>(FConfig::TickScanRange);

    static void __fastcall DedicatedHook(SDK::AActor* Actor, float DeltaSeconds);

    static SDK::AActor* FindSampleActor(SDK::UWorld* World);
    bool StartProfiling(SDK::AActor* Actor, bool bForceFull);
    std::vector<int32_t> ScanPredefinedIndices() const;
    void EvaluateCandidates();
    void RemoveTemporaryHooks();
    bool IsDeltaMatching(uintptr_t RawValue, float ExpectedDelta) const;
    void InvokeOriginal(int32_t Index, void* Rcx, void* Rdx, void* R8) const;

    SDK::AActor* SampleActor = nullptr;
    void** VTable = nullptr;

    std::array<FTickEntryInfo, Range> Entries{};
    std::array<void*, Range> Originals{};
    std::array<void*, Range> OriginalTargets{};
    std::array<bool, Range> PreferredIndices{};

    void* DedicatedTrampoline = nullptr;
    int32_t ConfirmedIndex = -1;
    int32_t FrameCounter = 0;
    bool bHooked = false;
    bool bCompleted = false;
    bool bPreferredMode = false;
    bool bStarted = false;
    bool bExited = false;
    bool bLoggedMissingActor = false;
};

class FDumper
{
public:
    static FDumper& Get();

    void Run();
    void ProcessVirtualCall(int32_t Index, void* Rcx, void* Rdx, void* R8);
    void Shutdown();

    FActorTickScanner& GetActorTickScanner() { return TickScanner; }
    const FActorTickScanner& GetActorTickScanner() const { return TickScanner; }

private:
    static constexpr size_t Range = static_cast<size_t>(FConfig::ScanRange);

    FDumper() = default;

    void OpenConsole();
    void CloseConsole();
    void DetectResolution();
    void PrintConfiguration() const;
    void WaitForEngine();
    void HookViewport(void** VTable);
    void HookViewportIndices(const std::vector<int32_t>& Indices);
    std::vector<int32_t> ScanPredefinedIndices() const;
    void UpdateDynamicResolution();
    void UpdatePreferredFallback();
    bool TryReadCanvas(const void* Candidate, int32_t& SizeX, int32_t& SizeY, uintptr_t& VTableAddress) const;
    bool UpdateStability(int32_t Index, uintptr_t CanvasAddress, uintptr_t VTableAddress);
    void ConfirmTarget(int32_t Index);
    void DisableHooksExcept(int32_t Index);
    void InvokeOriginal(int32_t Index, void* Rcx, void* Rdx, void* R8) const;
    void DrawMarker(SDK::UCanvas* Canvas) const;

    FILE* Console = nullptr;
    SDK::UEngine* Engine = nullptr;
    void** ViewportVTable = nullptr;

    std::array<FMatchInfo, Range> Matches{};
    std::array<void*, Range> Originals{};
    std::array<void*, Range> OriginalTargets{};
    std::array<bool, Range> PreferredIndices{};

    FActorTickScanner TickScanner;

    int32_t ActiveTargetWidth = FConfig::TargetWidth;
    int32_t ActiveTargetHeight = FConfig::TargetHeight;
    int32_t ConfirmedIndex = -1;
    bool bConsoleAllocated = false;
    bool bUsingDynamicResolution = false;
    bool bHasRolledBack = false;
    bool bIsFound = false;
    bool bPreferredMode = false;
    bool bShutdown = false;
    ULONGLONG HookStartTime = 0;
};

template <int32_t Index>
void __fastcall ViewportThunk(void* Rcx, void* Rdx, void* R8)
{
    FDumper::Get().ProcessVirtualCall(Index, Rcx, Rdx, R8);
}

template <int32_t Index>
void __fastcall ActorTickThunk(void* Rcx, void* Rdx, void* R8)
{
    FDumper::Get().GetActorTickScanner().ProcessCall(Index, Rcx, Rdx, R8);
}

template <int32_t... Indices>
std::array<void*, sizeof...(Indices)> MakeViewportThunkTable(std::integer_sequence<int32_t, Indices...>)
{
    return { { reinterpret_cast<void*>(&ViewportThunk<Indices>)... } };
}

template <int32_t... Indices>
std::array<void*, sizeof...(Indices)> MakeActorTickThunkTable(std::integer_sequence<int32_t, Indices...>)
{
    return { { reinterpret_cast<void*>(&ActorTickThunk<Indices>)... } };
}

const std::array<void*, static_cast<size_t>(FConfig::ScanRange)>& GetViewportThunks()
{
    static const std::array<void*, static_cast<size_t>(FConfig::ScanRange)> Thunks =
        MakeViewportThunkTable(std::make_integer_sequence<int32_t, FConfig::ScanRange>{});
    return Thunks;
}

const std::array<void*, static_cast<size_t>(FConfig::TickScanRange)>& GetActorTickThunks()
{
    static const std::array<void*, static_cast<size_t>(FConfig::TickScanRange)> Thunks =
        MakeActorTickThunkTable(std::make_integer_sequence<int32_t, FConfig::TickScanRange>{});
    return Thunks;
}

FDumper& FDumper::Get()
{
    static FDumper Instance;
    return Instance;
}

void FDumper::Run()
{
    OpenConsole();

    FLog::Section("UE Universal PostRender Dumper");
    FLog::Info("Author  : github.com/zetsr");
    FLog::Info("Profile : unknowncheats.me/forum/members/4701133.html");

    DetectResolution();
    PrintConfiguration();
    WaitForEngine();

    FLog::Success("Engine and GameViewport acquired (engine={:#x}, viewport={:#x}).",
        reinterpret_cast<uintptr_t>(Engine),
        reinterpret_cast<uintptr_t>(Engine->GameViewport));

    void* ViewportTable = nullptr;
    if (!FMemory::IsReadable(Engine->GameViewport, sizeof(ViewportTable)))
    {
        FLog::Error("The GameViewport object is not readable; aborting.");
        return;
    }
    std::memcpy(&ViewportTable, Engine->GameViewport, sizeof(ViewportTable));

    HookStartTime = GetTickCount64();
    HookViewport(static_cast<void**>(ViewportTable));

    FLog::Info("Hooks applied. Waiting for the PostRender candidate pair (N and N+1)...");
}

void FDumper::OpenConsole()
{
    if (AllocConsole() != FALSE)
    {
        freopen_s(&Console, "CONOUT$", "w", stdout);
        SetConsoleTitleW(L"UE Universal PostRender Dumper");
        bConsoleAllocated = true;
    }
    FLog::Initialize();
}

void FDumper::CloseConsole()
{
    if (Console != nullptr)
    {
        std::fclose(Console);
        Console = nullptr;
    }

    if (bConsoleAllocated)
    {
        FreeConsole();
        bConsoleAllocated = false;
    }
}

void FDumper::DetectResolution()
{
    int32_t Width = 0;
    int32_t Height = 0;

    if (TryGetProcessResolution(Width, Height))
    {
        ActiveTargetWidth = Width;
        ActiveTargetHeight = Height;
        bUsingDynamicResolution = true;
        FLog::Success("Detected game window resolution: {}x{}.", Width, Height);
        return;
    }

    ActiveTargetWidth = FConfig::TargetWidth;
    ActiveTargetHeight = FConfig::TargetHeight;
    bUsingDynamicResolution = false;
    FLog::Warning("Failed to detect the game window resolution; using the configured {}x{}.", FConfig::TargetWidth, FConfig::TargetHeight);
}

void FDumper::PrintConfiguration() const
{
    FLog::Section("Configuration");
    FLog::Field(ELogLevel::Info, "Resolution", "{}x{} (dynamic: {})", ActiveTargetWidth, ActiveTargetHeight, bUsingDynamicResolution ? "yes" : "no");
    FLog::Field(ELogLevel::Info, "Fallback", "{}x{}", FConfig::TargetWidth, FConfig::TargetHeight);
    FLog::Field(ELogLevel::Info, "Res Timeout", "{} ms", FConfig::DynamicResolutionTimeoutMs);
    FLog::Field(ELogLevel::Info, "Fallback Wait", "{} ms", FConfig::PreferredFallbackTimeoutMs);
    FLog::Field(ELogLevel::Info, "Size Offsets", "X={:#x}, Y={:#x}", FConfig::SizeXOffset, FConfig::SizeYOffset);
    FLog::Field(ELogLevel::Info, "Scan Range", "{}", FConfig::ScanRange);
    FLog::Field(ELogLevel::Info, "Stable Frames", "{}", FConfig::StableFrameThreshold);
    FLog::Field(ELogLevel::Info, "Tick Range", "{}", FConfig::TickScanRange);
    FLog::Field(ELogLevel::Info, "Tick Frames", "{}", FConfig::TickSampleFrames);
    FLog::Field(ELogLevel::Info, "Tick Freq Tol", "{}", FConfig::TickFrequencyTolerance);
    FLog::Field(ELogLevel::Info, "Tick DT Tol", "{:.4f}", FConfig::TickDeltaTimeTolerance);
}

void FDumper::WaitForEngine()
{
    FLog::Info("Waiting for UEngine::GetEngine() and the game viewport...");

    int32_t Attempts = 0;
    while (true)
    {
        Engine = SDK::UEngine::GetEngine();
        if (Engine != nullptr && Engine->GameViewport != nullptr) return;

        ++Attempts;
        if (Attempts % 50 == 0)
        {
            FLog::Info("Still waiting for the engine and viewport ({} s elapsed).", Attempts / 10);
        }
        Sleep(100);
    }
}

void FDumper::HookViewport(void** VTable)
{
    ViewportVTable = VTable;
    if (ViewportVTable == nullptr)
    {
        FLog::Error("The GameViewport vtable is null; aborting.");
        return;
    }

    if (MH_Initialize() != MH_OK)
    {
        FLog::Error("MinHook initialization failed; aborting.");
        return;
    }

    FLog::Section("GameViewport Hook Setup");
    FLog::Info("Scanning the GameViewport vtable for predefined signatures...");

    const std::vector<int32_t> MatchedIndices = ScanPredefinedIndices();
    std::vector<int32_t> IndicesToHook;

    if (!MatchedIndices.empty())
    {
        bPreferredMode = true;

        std::array<bool, Range> bNeedHook{};
        for (const int32_t Index : MatchedIndices)
        {
            const size_t Slot = static_cast<size_t>(Index);
            PreferredIndices[Slot] = true;
            bNeedHook[Slot] = true;
            if (Index + 1 < FConfig::ScanRange) bNeedHook[Slot + 1] = true;
        }

        for (int32_t Index = 1; Index < FConfig::ScanRange; ++Index)
        {
            if (bNeedHook[static_cast<size_t>(Index)]) IndicesToHook.push_back(Index);
        }

        FLog::Success("Preferred mode enabled with {} signature match(es).", MatchedIndices.size());
        FLog::Field(ELogLevel::Info, "Matches", "{}", JoinIndices(MatchedIndices));
        FLog::Field(ELogLevel::Info, "Hooking", "{}", JoinIndices(IndicesToHook));
    }
    else
    {
        bPreferredMode = false;
        FLog::Warning("No predefined signature matched the GameViewport vtable; using the full hooking path.");

        for (int32_t Index = 1; Index < FConfig::ScanRange; ++Index)
        {
            IndicesToHook.push_back(Index);
        }
    }

    HookViewportIndices(IndicesToHook);
}

void FDumper::HookViewportIndices(const std::vector<int32_t>& Indices)
{
    const auto& Thunks = GetViewportThunks();

    int32_t Created = 0;
    int32_t Failed = 0;
    int32_t Skipped = 0;

    for (const int32_t Index : Indices)
    {
        if (bIsFound)
        {
            FLog::Warning("The target is already located; the remaining hook creation is skipped.");
            break;
        }

        const size_t Slot = static_cast<size_t>(Index);
        if (Originals[Slot] != nullptr) continue;

        void* Function = ViewportVTable[Index];
        if (Function == nullptr || !GetModuleInfo().ContainsText(reinterpret_cast<uintptr_t>(Function)))
        {
            ++Skipped;
            FLog::Debug("Skipped vtable[{}]: null entry or outside the code section.", Index);
            continue;
        }

        const MH_STATUS CreateStatus = MH_CreateHook(Function, Thunks[Slot], &Originals[Slot]);
        if (CreateStatus != MH_OK)
        {
            ++Failed;
            Originals[Slot] = nullptr;
            FLog::Warning("Hook creation failed: index={} address={:#x} status={}.",
                Index, reinterpret_cast<uintptr_t>(Function), static_cast<int32_t>(CreateStatus));
            continue;
        }

        OriginalTargets[Slot] = Function;

        const MH_STATUS EnableStatus = MH_EnableHook(Function);
        if (EnableStatus != MH_OK)
        {
            ++Failed;
            MH_RemoveHook(Function);
            Originals[Slot] = nullptr;
            OriginalTargets[Slot] = nullptr;
            FLog::Warning("Hook enable failed: index={} address={:#x} status={}.",
                Index, reinterpret_cast<uintptr_t>(Function), static_cast<int32_t>(EnableStatus));
            continue;
        }

        ++Created;
    }

    FLog::Info("Viewport hooks: {} created, {} failed, {} skipped.", Created, Failed, Skipped);
}

std::vector<int32_t> FDumper::ScanPredefinedIndices() const
{
    std::vector<int32_t> MatchedIndices;

    const std::vector<FAOBPattern> Patterns = ParsePatterns(FConfig::PostRenderSignatures);
    if (Patterns.empty()) return MatchedIndices;

    for (int32_t Index = 1; Index < FConfig::ScanRange; ++Index)
    {
        void* Function = ViewportVTable[Index];
        if (Function == nullptr) continue;

        const uintptr_t Address = reinterpret_cast<uintptr_t>(Function);
        for (size_t PatternIndex = 0; PatternIndex < Patterns.size(); ++PatternIndex)
        {
            if (!Patterns[PatternIndex].MatchAt(Address)) continue;

            MatchedIndices.push_back(Index);
            FLog::Special("Predefined signature #{} matched vtable[{}] at {:#x}.", PatternIndex + 1, Index, Address);
            break;
        }
    }

    return MatchedIndices;
}

void FDumper::UpdateDynamicResolution()
{
    if (!bUsingDynamicResolution || bHasRolledBack || bIsFound) return;
    if (GetTickCount64() - HookStartTime < FConfig::DynamicResolutionTimeoutMs) return;

    FLog::Warning("The dynamic resolution did not match within {} ms (active {}x{}); rolling back to {}x{}.",
        FConfig::DynamicResolutionTimeoutMs,
        ActiveTargetWidth,
        ActiveTargetHeight,
        FConfig::TargetWidth,
        FConfig::TargetHeight);

    ActiveTargetWidth = FConfig::TargetWidth;
    ActiveTargetHeight = FConfig::TargetHeight;
    bUsingDynamicResolution = false;
    bHasRolledBack = true;

    for (FMatchInfo& Match : Matches)
    {
        Match.Count = 0;
        Match.LastCanvas = 0;
        Match.LastVTable = 0;
    }
}

void FDumper::UpdatePreferredFallback()
{
    if (!bPreferredMode || bIsFound) return;
    if (GetTickCount64() - HookStartTime < FConfig::PreferredFallbackTimeoutMs) return;

    FLog::Warning("All predefined signature candidates stayed unconfirmed for {} ms; expanding to the full vtable hooking path.",
        FConfig::PreferredFallbackTimeoutMs);

    bPreferredMode = false;
    for (bool& bPreferred : PreferredIndices)
    {
        bPreferred = false;
    }

    std::vector<int32_t> Indices;
    for (int32_t Index = 1; Index < FConfig::ScanRange; ++Index)
    {
        if (Originals[static_cast<size_t>(Index)] == nullptr) Indices.push_back(Index);
    }

    if (Indices.empty()) return;
    HookViewportIndices(Indices);
}

bool FDumper::TryReadCanvas(const void* Candidate, int32_t& SizeX, int32_t& SizeY, uintptr_t& VTableAddress) const
{
    const uintptr_t Address = reinterpret_cast<uintptr_t>(Candidate);
    if (Address <= 0x100000000ULL || Address % 16 != 0) return false;

    const size_t Required = (std::max)(FConfig::SizeXOffset, FConfig::SizeYOffset) + sizeof(int32_t);
    const size_t Length = (std::max)(Required, sizeof(void*));
    if (!FMemory::IsReadable(Candidate, Length)) return false;

    const auto* Bytes = static_cast<const uint8_t*>(Candidate);
    void* VTable = nullptr;
    std::memcpy(&VTable, Bytes, sizeof(VTable));
    std::memcpy(&SizeX, Bytes + FConfig::SizeXOffset, sizeof(SizeX));
    std::memcpy(&SizeY, Bytes + FConfig::SizeYOffset, sizeof(SizeY));

    VTableAddress = reinterpret_cast<uintptr_t>(VTable);
    return true;
}

bool FDumper::UpdateStability(int32_t Index, uintptr_t CanvasAddress, uintptr_t VTableAddress)
{
    FMatchInfo& Match = Matches[static_cast<size_t>(Index)];
    if (Match.LastCanvas == CanvasAddress && Match.LastVTable == VTableAddress)
    {
        ++Match.Count;
    }
    else
    {
        Match.Count = 0;
        Match.LastCanvas = CanvasAddress;
        Match.LastVTable = VTableAddress;
    }

    return Match.Count >= FConfig::StableFrameThreshold;
}

void FDumper::ConfirmTarget(int32_t Index)
{
    const size_t Slot = static_cast<size_t>(Index);

    bIsFound = true;
    ConfirmedIndex = Index;
    Matches[Slot].bConfirmed = true;

    FLog::Section("PostRender Target Confirmed");
    FLog::Field(ELogLevel::Success, "VTable Index", "{}", Index);
    FLog::Field(ELogLevel::Info, "Address", "{:#x}", reinterpret_cast<uintptr_t>(OriginalTargets[Slot]));

    void* Target = OriginalTargets[Slot];
    const MH_STATUS DisableStatus = MH_DisableHook(Target);
    const FSignatureResult Result = FSignatureGenerator::Generate(reinterpret_cast<uintptr_t>(Target));
    MH_EnableHook(Target);

    if (DisableStatus != MH_OK)
    {
        FLog::Warning("Failed to disable the confirmed hook before signature generation (status {}).",
            static_cast<int32_t>(DisableStatus));
    }

    if (Result.bSuccess)
    {
        FLog::Field(ELogLevel::Success, "Signature", "{}", Result.Signature);
    }
    else
    {
        FLog::Field(ELogLevel::Error, "Signature", "generation failed");
        FLog::Field(ELogLevel::Error, "Diagnostics", "{} bytes disassembled, {} length(s) tested",
            Result.BytesDisassembled, Result.CandidatesTested);
        if (Result.LongestLength != 0)
        {
            FLog::Field(ELogLevel::Error, "Longest", "{} bytes matched {} location(s)",
                Result.LongestLength, Result.LongestMatchCount);
        }
    }

    DisableHooksExcept(Index);
}

void FDumper::DisableHooksExcept(int32_t Index)
{
    int32_t Disabled = 0;

    for (int32_t Other = 1; Other < FConfig::ScanRange; ++Other)
    {
        if (Other == Index) continue;

        void* Target = OriginalTargets[static_cast<size_t>(Other)];
        if (Target == nullptr) continue;
        if (MH_DisableHook(Target) == MH_OK) ++Disabled;
    }

    FLog::Info("Disabled {} redundant hook(s); only index {} remains active.", Disabled, Index);
}

void FDumper::InvokeOriginal(int32_t Index, void* Rcx, void* Rdx, void* R8) const
{
    const auto Original = reinterpret_cast<void(__fastcall*)(void*, void*, void*)>(Originals[static_cast<size_t>(Index)]);
    if (Original != nullptr) Original(Rcx, Rdx, R8);
}

void FDumper::DrawMarker(SDK::UCanvas* Canvas) const
{
    if (Canvas == nullptr) return;

    const SDK::FLinearColor Color{ 0.0f, 1.0f, 0.0f, 1.0f };
    Canvas->K2_DrawBox({ 2.0f, 2.0f }, { 50.0f, 50.0f }, 1.0f, Color);
}

void FDumper::ProcessVirtualCall(int32_t Index, void* Rcx, void* Rdx, void* R8)
{
    if (bIsFound && Index != ConfirmedIndex)
    {
        InvokeOriginal(Index, Rcx, Rdx, R8);
        return;
    }

    UpdateDynamicResolution();
    UpdatePreferredFallback();

    if (!bIsFound)
    {
        int32_t SizeX = 0;
        int32_t SizeY = 0;
        uintptr_t VTableAddress = 0;

        if (TryReadCanvas(Rdx, SizeX, SizeY, VTableAddress) &&
            SizeX == ActiveTargetWidth &&
            SizeY == ActiveTargetHeight &&
            GetModuleInfo().ContainsImage(VTableAddress))
        {
            const size_t Slot = static_cast<size_t>(Index);
            if (UpdateStability(Index, reinterpret_cast<uintptr_t>(Rdx), VTableAddress) &&
                Index + 1 < FConfig::ScanRange &&
                Matches[Slot + 1].Count >= FConfig::StableFrameThreshold &&
                (!bPreferredMode || PreferredIndices[Slot]))
            {
                ConfirmTarget(Index);
            }
        }
    }

    const size_t Slot = static_cast<size_t>(Index);
    if (Matches[Slot].bConfirmed)
    {
        DrawMarker(reinterpret_cast<SDK::UCanvas*>(Rdx));
        TickScanner.Advance();
    }

    InvokeOriginal(Index, Rcx, Rdx, R8);
}

void FDumper::Shutdown()
{
    if (bShutdown) return;
    bShutdown = true;

    MH_DisableHook(MH_ALL_HOOKS);
    CloseConsole();
}

FSignatureGenerator::FDisassembly FSignatureGenerator::Disassemble(uintptr_t FunctionAddress)
{
    FDisassembly Disassembled;

    const FModuleInfo& Module = GetModuleInfo();
    if (!Module.ContainsText(FunctionAddress)) return Disassembled;

    const size_t Available = static_cast<size_t>(Module.Text.End - FunctionAddress);
    const size_t ReadLength = (std::min)(Available, FConfig::SignatureMaxScanLength + 15);
    if (ReadLength == 0) return Disassembled;

    std::vector<uint8_t> Bytes(ReadLength);
    std::memcpy(Bytes.data(), reinterpret_cast<const void*>(FunctionAddress), ReadLength);

    Disassembled.Marks.resize(ReadLength);
    for (size_t Index = 0; Index < ReadLength; ++Index)
    {
        Disassembled.Marks[Index].Value = Bytes[Index];
    }

    ZydisDecoder Decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
    {
        Disassembled.Marks.clear();
        return Disassembled;
    }

    size_t Offset = 0;
    int32_t InstructionCount = 0;

    while (Offset < Bytes.size() &&
        Offset < FConfig::SignatureMaxScanLength &&
        InstructionCount < FConfig::SignatureMaxInstructions)
    {
        ZydisDecodedInstruction Instruction;
        ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

        const ZyanStatus Status = ZydisDecoderDecodeFull(
            &Decoder,
            Bytes.data() + Offset,
            Bytes.size() - Offset,
            &Instruction,
            Operands);

        if (!ZYAN_SUCCESS(Status))
        {
            Offset += 1;
            Disassembled.Boundaries.push_back(Offset);
            continue;
        }

        if (Instruction.raw.disp.size != 0)
        {
            MarkWildcards(Disassembled.Marks, Offset + Instruction.raw.disp.offset, Instruction.raw.disp.size / 8);
        }

        for (const auto& RawImmediate : Instruction.raw.imm)
        {
            if (RawImmediate.size == 0) continue;
            MarkWildcards(Disassembled.Marks, Offset + RawImmediate.offset, RawImmediate.size / 8);
        }

        Offset += Instruction.length;
        Disassembled.Boundaries.push_back(Offset);
        ++InstructionCount;
    }

    Disassembled.Marks.resize(Offset);
    return Disassembled;
}

void FSignatureGenerator::MarkWildcards(std::vector<FByteMark>& Marks, size_t Offset, size_t Length)
{
    for (size_t Index = 0; Index < Length && Offset + Index < Marks.size(); ++Index)
    {
        Marks[Offset + Index].bWildcard = true;
    }
}

std::string FSignatureGenerator::BuildPattern(const std::vector<FByteMark>& Marks, size_t Length)
{
    static constexpr char HexDigits[] = "0123456789ABCDEF";

    std::string Pattern;
    Pattern.reserve(Length * 3);

    for (size_t Index = 0; Index < Length; ++Index)
    {
        if (Index != 0) Pattern += ' ';

        if (Marks[Index].bWildcard)
        {
            Pattern += '?';
            continue;
        }

        Pattern += HexDigits[(Marks[Index].Value >> 4) & 0xF];
        Pattern += HexDigits[Marks[Index].Value & 0xF];
    }

    return Pattern;
}

FSignatureResult FSignatureGenerator::Generate(uintptr_t FunctionAddress)
{
    FSignatureResult Result;

    const FDisassembly Disassembled = Disassemble(FunctionAddress);
    Result.BytesDisassembled = Disassembled.Marks.size();

    for (const size_t Length : Disassembled.Boundaries)
    {
        if (Length == 0 || Length > Disassembled.Marks.size()) continue;
        if (Disassembled.Marks[Length - 1].bWildcard) continue;

        const std::string PatternText = BuildPattern(Disassembled.Marks, Length);
        const std::optional<FAOBPattern> Pattern = FAOBPattern::Parse(PatternText);
        if (!Pattern) continue;

        const std::vector<uintptr_t> Matches = FAOBScanner::Scan(*Pattern);
        ++Result.CandidatesTested;
        Result.LongestLength = Length;
        Result.LongestMatchCount = Matches.size();

        if (Matches.size() == 1)
        {
            Result.bSuccess = true;
            Result.Signature = PatternText;
            return Result;
        }
    }

    return Result;
}

void FActorTickScanner::Advance()
{
    if (bCompleted || bExited) return;

    SDK::UWorld* World = SDK::UWorld::GetWorld();
    if (World == nullptr) return;

    if (!bStarted)
    {
        SDK::AActor* Actor = FindSampleActor(World);
        if (Actor == nullptr)
        {
            if (!bLoggedMissingActor)
            {
                bLoggedMissingActor = true;
                FLog::Warning("No valid sample AActor is available yet; retrying every frame.");
            }
            return;
        }

        bLoggedMissingActor = false;
        FLog::Success("Sample AActor acquired: {:#x}.", reinterpret_cast<uintptr_t>(Actor));

        bStarted = StartProfiling(Actor, false);
        if (!bStarted) FLog::Warning("The AActor tick profiling could not start; retrying every frame.");
        return;
    }

    ++FrameCounter;
    if (FrameCounter >= FConfig::TickSampleFrames) EvaluateCandidates();
}

SDK::AActor* FActorTickScanner::FindSampleActor(SDK::UWorld* World)
{
    if (World == nullptr || World->PersistentLevel == nullptr) return nullptr;

    const int32_t Count = World->PersistentLevel->Actors.Num();
    for (int32_t Index = 0; Index < Count; ++Index)
    {
        SDK::AActor* Actor = World->PersistentLevel->Actors[Index];
        if (Actor == nullptr) continue;

        void* ActorVTable = nullptr;
        if (!FMemory::IsReadable(Actor, sizeof(ActorVTable))) continue;
        std::memcpy(&ActorVTable, Actor, sizeof(ActorVTable));
        if (ActorVTable != nullptr) return Actor;
    }

    return nullptr;
}

bool FActorTickScanner::StartProfiling(SDK::AActor* Actor, bool bForceFull)
{
    if (bHooked && !bForceFull) return true;
    if (Actor == nullptr) return false;

    SampleActor = Actor;

    void* InstanceVTable = nullptr;
    if (!FMemory::IsReadable(Actor, sizeof(InstanceVTable)))
    {
        FLog::Error("The sample AActor is not readable; the tick scan is aborted.");
        return false;
    }
    std::memcpy(&InstanceVTable, Actor, sizeof(InstanceVTable));

    VTable = static_cast<void**>(InstanceVTable);
    if (VTable == nullptr)
    {
        FLog::Error("The AActor vtable is null; the tick scan is aborted.");
        return false;
    }

    std::fill(Entries.begin(), Entries.end(), FTickEntryInfo{});
    std::fill(PreferredIndices.begin(), PreferredIndices.end(), false);

    ConfirmedIndex = -1;
    bPreferredMode = false;
    FrameCounter = 0;

    std::vector<int32_t> IndicesToHook;

    if (!bForceFull)
    {
        FLog::Info("Scanning the AActor vtable for predefined signatures...");
        const std::vector<int32_t> MatchedIndices = ScanPredefinedIndices();

        if (!MatchedIndices.empty())
        {
            bPreferredMode = true;
            for (const int32_t Index : MatchedIndices)
            {
                PreferredIndices[static_cast<size_t>(Index)] = true;
                IndicesToHook.push_back(Index);
            }

            FLog::Success("Preferred mode enabled with {} AActor signature match(es).", MatchedIndices.size());
            FLog::Field(ELogLevel::Info, "Matches", "{}", JoinIndices(MatchedIndices));
        }
        else
        {
            FLog::Warning("No predefined AActor::Tick signature matched; using the full hooking path.");
        }
    }
    else
    {
        FLog::Warning("All preferred AActor tick candidates were false positives; retrying with the full hooking path.");
    }

    if (IndicesToHook.empty())
    {
        bPreferredMode = false;
        for (int32_t Index = 1; Index < FConfig::TickScanRange; ++Index)
        {
            IndicesToHook.push_back(Index);
        }
    }

    const auto& Thunks = GetActorTickThunks();

    int32_t Created = 0;
    int32_t Failed = 0;

    for (const int32_t Index : IndicesToHook)
    {
        const size_t Slot = static_cast<size_t>(Index);
        void* Function = VTable[Index];
        if (Function == nullptr || !GetModuleInfo().ContainsText(reinterpret_cast<uintptr_t>(Function))) continue;

        const MH_STATUS CreateStatus = MH_CreateHook(Function, Thunks[Slot], &Originals[Slot]);
        if (CreateStatus != MH_OK)
        {
            ++Failed;
            Originals[Slot] = nullptr;
            FLog::Warning("AActor hook creation failed: index={} address={:#x} status={}.",
                Index, reinterpret_cast<uintptr_t>(Function), static_cast<int32_t>(CreateStatus));
            continue;
        }

        OriginalTargets[Slot] = Function;

        const MH_STATUS EnableStatus = MH_EnableHook(Function);
        if (EnableStatus != MH_OK)
        {
            ++Failed;
            MH_RemoveHook(Function);
            Originals[Slot] = nullptr;
            OriginalTargets[Slot] = nullptr;
            FLog::Warning("AActor hook enable failed: index={} address={:#x} status={}.",
                Index, reinterpret_cast<uintptr_t>(Function), static_cast<int32_t>(EnableStatus));
            continue;
        }

        ++Created;
    }

    bHooked = true;
    FLog::Info("AActor tick hooks: {} created, {} failed.", Created, Failed);
    FLog::Info("AActor tick profiling started; collecting {} frame(s) of samples.", FConfig::TickSampleFrames);
    return true;
}

std::vector<int32_t> FActorTickScanner::ScanPredefinedIndices() const
{
    std::vector<int32_t> MatchedIndices;
    if (VTable == nullptr) return MatchedIndices;

    const std::vector<FAOBPattern> Patterns = ParsePatterns(FConfig::ActorTickSignatures);
    if (Patterns.empty()) return MatchedIndices;

    for (int32_t Index = 1; Index < FConfig::TickScanRange; ++Index)
    {
        void* Function = VTable[Index];
        if (Function == nullptr) continue;

        const uintptr_t Address = reinterpret_cast<uintptr_t>(Function);
        for (size_t PatternIndex = 0; PatternIndex < Patterns.size(); ++PatternIndex)
        {
            if (!Patterns[PatternIndex].MatchAt(Address)) continue;

            MatchedIndices.push_back(Index);
            FLog::Special("Predefined AActor signature #{} matched vtable[{}] at {:#x}.", PatternIndex + 1, Index, Address);
            break;
        }
    }

    return MatchedIndices;
}

void FActorTickScanner::EvaluateCandidates()
{
    if (!bHooked || bCompleted) return;

    FLog::Section("AActor Tick Candidate Evaluation");

    int32_t MatchCount = 0;

    for (int32_t Index = 1; Index < FConfig::TickScanRange; ++Index)
    {
        const FTickEntryInfo& Entry = Entries[static_cast<size_t>(Index)];

        if (std::abs(Entry.CallCount - FConfig::TickSampleFrames) > FConfig::TickFrequencyTolerance) continue;
        if (!Entry.bDeltaMatched) continue;

        ++MatchCount;

        const size_t Slot = static_cast<size_t>(Index);
        void* Target = OriginalTargets[Slot];
        const uintptr_t Address = reinterpret_cast<uintptr_t>(Target);

        const MH_STATUS DisableStatus = MH_DisableHook(Target);
        const FSignatureResult Signature = FSignatureGenerator::Generate(Address);
        MH_EnableHook(Target);

        if (DisableStatus != MH_OK)
        {
            FLog::Warning("Failed to disable the AActor tick hook before signature generation (status {}).",
                static_cast<int32_t>(DisableStatus));
        }

        FLog::Field(ELogLevel::Success, "Candidate", "{}", Index);
        FLog::Field(ELogLevel::Info, "Address", "{:#x}", Address);
        FLog::Field(ELogLevel::Info, "Call Count", "{} / {}", Entry.CallCount, FConfig::TickSampleFrames);
        FLog::Field(ELogLevel::Info, "Delta Time", "{:.6f}", Entry.LastMatchedDelta);
        FLog::Field(ELogLevel::Info, "Signature", "{}", FConfig::ActorTickFunctionSignature);

        if (Signature.bSuccess)
        {
            FLog::Field(ELogLevel::Success, "AOB", "{}", Signature.Signature);
        }
        else
        {
            FLog::Field(ELogLevel::Warning, "AOB", "generation failed");
        }

        if (ConfirmedIndex == -1) ConfirmedIndex = Index;
    }

    if (MatchCount == 0)
    {
        FLog::Warning("No AActor tick candidate satisfied the sampling criteria.");

        if (bPreferredMode)
        {
            RemoveTemporaryHooks();
            StartProfiling(SampleActor, true);
            return;
        }
    }

    void* ConfirmedTarget = nullptr;
    if (ConfirmedIndex != -1)
    {
        ConfirmedTarget = OriginalTargets[static_cast<size_t>(ConfirmedIndex)];
    }

    RemoveTemporaryHooks();
    bCompleted = true;
    bPreferredMode = false;

    if (ConfirmedTarget != nullptr)
    {
        const MH_STATUS CreateStatus = MH_CreateHook(ConfirmedTarget, reinterpret_cast<LPVOID>(&FActorTickScanner::DedicatedHook), &DedicatedTrampoline);
        if (CreateStatus != MH_OK)
        {
            DedicatedTrampoline = nullptr;
            FLog::Error("Failed to create the dedicated AActor::Tick hook (status {}).", static_cast<int32_t>(CreateStatus));
        }
        else
        {
            const MH_STATUS EnableStatus = MH_EnableHook(ConfirmedTarget);
            if (EnableStatus != MH_OK)
            {
                FLog::Error("Failed to enable the dedicated AActor::Tick hook (status {}).", static_cast<int32_t>(EnableStatus));
            }
            else
            {
                FLog::Success("Dedicated AActor::Tick hook activated on vtable index {}.", ConfirmedIndex);
            }
        }
    }

    ReportProcessEvent();
}

void FActorTickScanner::RemoveTemporaryHooks()
{
    for (int32_t Index = 1; Index < FConfig::TickScanRange; ++Index)
    {
        const size_t Slot = static_cast<size_t>(Index);
        void* Target = OriginalTargets[Slot];
        if (Target == nullptr) continue;

        MH_DisableHook(Target);
        MH_RemoveHook(Target);
        OriginalTargets[Slot] = nullptr;
        Originals[Slot] = nullptr;
    }

    bHooked = false;
}

bool FActorTickScanner::IsDeltaMatching(uintptr_t RawValue, float ExpectedDelta) const
{
    if (ExpectedDelta <= 0.0f) return false;

    const uint32_t Bits = static_cast<uint32_t>(RawValue & 0xFFFFFFFFULL);
    const float DirectValue = std::bit_cast<float>(Bits);
    if (std::abs(DirectValue - ExpectedDelta) <= FConfig::TickDeltaTimeTolerance) return true;

    const bool bLooksLikePointer = RawValue > 0x10000 && RawValue % alignof(float) == 0;
    if (bLooksLikePointer && FMemory::IsReadable(reinterpret_cast<const void*>(RawValue), sizeof(float)))
    {
        float Dereferenced = 0.0f;
        std::memcpy(&Dereferenced, reinterpret_cast<const void*>(RawValue), sizeof(Dereferenced));
        if (std::abs(Dereferenced - ExpectedDelta) <= FConfig::TickDeltaTimeTolerance) return true;
    }

    return false;
}

void FActorTickScanner::InvokeOriginal(int32_t Index, void* Rcx, void* Rdx, void* R8) const
{
    const auto Original = reinterpret_cast<void(__fastcall*)(void*, void*, void*)>(Originals[static_cast<size_t>(Index)]);
    if (Original != nullptr) Original(Rcx, Rdx, R8);
}

void FActorTickScanner::ProcessCall(int32_t Index, void* Rcx, void* Rdx, void* R8)
{
    if (bCompleted || bExited)
    {
        InvokeOriginal(Index, Rcx, Rdx, R8);
        return;
    }

    if (Rcx == SampleActor)
    {
        FTickEntryInfo& Entry = Entries[static_cast<size_t>(Index)];
        ++Entry.CallCount;

        SDK::UWorld* World = SDK::UWorld::GetWorld();
        if (World != nullptr)
        {
            const float DeltaSeconds = SDK::UGameplayStatics::GetWorldDeltaSeconds(World);

            if (IsDeltaMatching(reinterpret_cast<uintptr_t>(Rdx), DeltaSeconds))
            {
                Entry.bDeltaMatched = true;
                Entry.LastMatchedDelta = DeltaSeconds;
            }
            else if (IsDeltaMatching(reinterpret_cast<uintptr_t>(R8), DeltaSeconds))
            {
                Entry.bDeltaMatched = true;
                Entry.LastMatchedDelta = DeltaSeconds;
            }
        }
    }

    InvokeOriginal(Index, Rcx, Rdx, R8);
}

void __fastcall FActorTickScanner::DedicatedHook(SDK::AActor* Actor, float DeltaSeconds)
{
    FActorTickScanner& Scanner = FDumper::Get().GetActorTickScanner();
    if (Scanner.bExited) return;

    bool bExitRequested = false;

    if (Actor == Scanner.SampleActor)
    {
        FLog::Debug("AActor::Tick  index={:<4}  actor={:#x}  delta={:.6f}",
            Scanner.ConfirmedIndex, reinterpret_cast<uintptr_t>(Actor), DeltaSeconds);

        if ((GetAsyncKeyState(FConfig::ExitHotkey) & 0x8000) != 0) bExitRequested = true;
    }

    const auto Original = reinterpret_cast<void(__fastcall*)(SDK::AActor*, float)>(Scanner.DedicatedTrampoline);
    if (Original != nullptr) Original(Actor, DeltaSeconds);

    if (bExitRequested && !Scanner.bExited)
    {
        Scanner.bExited = true;
        FLog::Special("Exit hotkey pressed; removing all hooks and closing the console.");
        FDumper::Get().Shutdown();
    }
}

void ReportProcessEvent()
{
    SDK::UWorld* World = SDK::UWorld::GetWorld();
    if (World == nullptr)
    {
        FLog::Error("Failed to obtain UWorld for ProcessEvent.");
        return;
    }

    void* Address = SDK::InSDKUtils::GetVirtualFunction<void*>(World, SDK::Offsets::ProcessEventIdx);
    if (Address == nullptr)
    {
        FLog::Error("Failed to resolve the ProcessEvent address.");
        return;
    }

    FLog::Section("ProcessEvent Result");
    FLog::Field(ELogLevel::Info, "VTable Index", "{}", SDK::Offsets::ProcessEventIdx);
    FLog::Field(ELogLevel::Info, "Address", "{:#x}", reinterpret_cast<uintptr_t>(Address));

    const FSignatureResult Result = FSignatureGenerator::Generate(reinterpret_cast<uintptr_t>(Address));
    if (Result.bSuccess)
    {
        FLog::Field(ELogLevel::Success, "Signature", "{}", Result.Signature);
        return;
    }

    FLog::Field(ELogLevel::Error, "Signature", "generation failed");
    FLog::Field(ELogLevel::Error, "Diagnostics", "{} bytes disassembled, {} length(s) tested",
        Result.BytesDisassembled, Result.CandidatesTested);

    if (Result.LongestLength != 0)
    {
        FLog::Field(ELogLevel::Error, "Longest", "{} bytes matched {} location(s)",
            Result.LongestLength, Result.LongestMatchCount);
    }
}

DWORD WINAPI MainThread(LPVOID)
{
    FDumper::Get().Run();
    return 0;
}

}

BOOL APIENTRY DllMain(HMODULE Module, DWORD Reason, LPVOID)
{
    if (Reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(Module);
        CreateThread(nullptr, 0, Dumper::MainThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
