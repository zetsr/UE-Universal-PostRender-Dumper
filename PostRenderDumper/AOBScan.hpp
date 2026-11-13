#pragma once

#include <windows.h>

#undef min
#undef max

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace Dumper
{

struct FTextSection
{
    uintptr_t Begin = 0;
    uintptr_t End = 0;

    bool Contains(uintptr_t Address, size_t Length = 1) const
    {
        if (Begin == 0 || End <= Begin) return false;
        if (Address < Begin || Address > End) return false;
        return Length <= static_cast<size_t>(End - Address);
    }
};

struct FModuleInfo
{
    uintptr_t Base = 0;
    size_t ImageSize = 0;
    FTextSection Text;

    bool ContainsImage(uintptr_t Address, size_t Length = 1) const
    {
        if (Base == 0 || ImageSize == 0) return false;
        if (Address < Base || Address > Base + ImageSize) return false;
        return Length <= static_cast<size_t>(Base + ImageSize - Address);
    }

    bool ContainsText(uintptr_t Address, size_t Length = 1) const
    {
        return Text.Contains(Address, Length);
    }
};

inline FModuleInfo CreateModuleInfo()
{
    FModuleInfo Info;

    const HMODULE Module = GetModuleHandleA(nullptr);
    if (Module == nullptr) return Info;

    const auto* DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(Module);
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return Info;

    const auto* NtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(Module) + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) return Info;

    Info.Base = reinterpret_cast<uintptr_t>(Module);
    Info.ImageSize = NtHeaders->OptionalHeader.SizeOfImage;

    const IMAGE_SECTION_HEADER* SectionHeaders = IMAGE_FIRST_SECTION(NtHeaders);
    for (WORD Index = 0; Index < NtHeaders->FileHeader.NumberOfSections; ++Index)
    {
        const IMAGE_SECTION_HEADER& Header = SectionHeaders[Index];
        const bool bExecutable = (Header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool bCode = (Header.Characteristics & IMAGE_SCN_CNT_CODE) != 0;
        if (!bExecutable || !bCode) continue;

        Info.Text.Begin = Info.Base + Header.VirtualAddress;
        Info.Text.End = Info.Text.Begin + Header.Misc.VirtualSize;
        break;
    }

    if (Info.Text.Begin == 0 || Info.Text.End <= Info.Text.Begin)
    {
        const uintptr_t TextBegin = Info.Base + NtHeaders->OptionalHeader.BaseOfCode;
        const size_t TextSize = NtHeaders->OptionalHeader.SizeOfCode;
        if (TextSize != 0)
        {
            Info.Text.Begin = TextBegin;
            Info.Text.End = TextBegin + TextSize;
        }
    }

    return Info;
}

inline const FModuleInfo& GetModuleInfo()
{
    static const FModuleInfo Info = CreateModuleInfo();
    return Info;
}

struct FMemory
{
    static bool IsReadable(const void* Address, size_t Length)
    {
        if (Address == nullptr || Length == 0) return false;

        const uintptr_t Begin = reinterpret_cast<uintptr_t>(Address);
        const uintptr_t End = Begin + Length;
        if (End < Begin) return false;

        uintptr_t Current = Begin;
        while (Current < End)
        {
            MEMORY_BASIC_INFORMATION Information{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(Current), &Information, sizeof(Information)) == 0) return false;
            if (Information.State != MEM_COMMIT) return false;
            if ((Information.Protect & PAGE_NOACCESS) != 0) return false;
            if ((Information.Protect & PAGE_GUARD) != 0) return false;
            if (Information.Protect == PAGE_EXECUTE) return false;

            const uintptr_t RegionEnd = reinterpret_cast<uintptr_t>(Information.BaseAddress) + Information.RegionSize;
            if (RegionEnd <= Current) return false;
            Current = RegionEnd;
        }

        return true;
    }
};

class FAOBPattern
{
public:
    FAOBPattern() = default;

    static std::optional<FAOBPattern> Parse(std::string_view Text);

    bool IsValid() const { return !Entries.empty(); }
    size_t Num() const { return Entries.size(); }
    const std::string& GetText() const { return Text; }

    bool MatchAt(uintptr_t Address) const;
    std::vector<uintptr_t> Scan() const;

private:
    struct FEntry
    {
        uint8_t Value = 0;
        bool bWildcard = false;
    };

    static int32_t HexValue(char Character)
    {
        if (Character >= '0' && Character <= '9') return Character - '0';
        if (Character >= 'A' && Character <= 'F') return Character - 'A' + 10;
        if (Character >= 'a' && Character <= 'f') return Character - 'a' + 10;
        return -1;
    }

    static void ScanSection(uintptr_t Begin, uintptr_t End, const FAOBPattern& Pattern, std::vector<uintptr_t>& Results);

    std::vector<FEntry> Entries;
    std::string Text;
    size_t FirstKnownIndex = 0;
    uint8_t FirstKnownValue = 0;
    bool bHasKnownByte = false;
};

inline std::optional<FAOBPattern> FAOBPattern::Parse(std::string_view Text)
{
    FAOBPattern Pattern;
    Pattern.Text = std::string(Text);

    size_t Position = 0;
    while (Position < Text.size())
    {
        while (Position < Text.size() && (Text[Position] == ' ' || Text[Position] == '\t')) ++Position;
        if (Position >= Text.size()) break;

        const size_t TokenBegin = Position;
        while (Position < Text.size() && Text[Position] != ' ' && Text[Position] != '\t') ++Position;
        const std::string_view Token = Text.substr(TokenBegin, Position - TokenBegin);

        if (Token == "?" || Token == "??")
        {
            Pattern.Entries.push_back(FEntry{ 0, true });
            continue;
        }

        if (Token.size() != 2) return std::nullopt;

        const int32_t High = HexValue(Token[0]);
        const int32_t Low = HexValue(Token[1]);
        if (High < 0 || Low < 0) return std::nullopt;

        if (!Pattern.bHasKnownByte)
        {
            Pattern.bHasKnownByte = true;
            Pattern.FirstKnownIndex = Pattern.Entries.size();
            Pattern.FirstKnownValue = static_cast<uint8_t>((High << 4) | Low);
        }

        Pattern.Entries.push_back(FEntry{ static_cast<uint8_t>((High << 4) | Low), false });
    }

    if (Pattern.Entries.empty()) return std::nullopt;
    return Pattern;
}

inline bool FAOBPattern::MatchAt(uintptr_t Address) const
{
    if (!IsValid()) return false;
    if (!GetModuleInfo().ContainsText(Address, Entries.size())) return false;

    const auto* Bytes = reinterpret_cast<const uint8_t*>(Address);
    for (size_t Index = 0; Index < Entries.size(); ++Index)
    {
        if (Entries[Index].bWildcard) continue;
        if (Bytes[Index] != Entries[Index].Value) return false;
    }

    return true;
}

inline void FAOBPattern::ScanSection(uintptr_t Begin, uintptr_t End, const FAOBPattern& Pattern, std::vector<uintptr_t>& Results)
{
    const size_t Length = Pattern.Entries.size();
    if (End <= Begin || static_cast<size_t>(End - Begin) < Length) return;

    const auto* ScanPointer = reinterpret_cast<const uint8_t*>(Begin);
    const auto* ScanEnd = reinterpret_cast<const uint8_t*>(End) - Length;

    const FEntry* Entries = Pattern.Entries.data();
    const size_t FirstIndex = Pattern.FirstKnownIndex;
    const uint8_t FirstValue = Pattern.FirstKnownValue;

    while (ScanPointer <= ScanEnd)
    {
        const auto* Match = static_cast<const uint8_t*>(
            std::memchr(ScanPointer + FirstIndex, FirstValue, static_cast<size_t>(ScanEnd - ScanPointer) + 1));
        if (Match == nullptr) break;

        ScanPointer = Match - FirstIndex;

        bool bIsMatch = true;
        for (size_t Index = 0; Index < Length; ++Index)
        {
            if (Entries[Index].bWildcard) continue;
            if (ScanPointer[Index] != Entries[Index].Value)
            {
                bIsMatch = false;
                break;
            }
        }

        if (bIsMatch) Results.push_back(reinterpret_cast<uintptr_t>(ScanPointer));
        ++ScanPointer;
    }
}

inline std::vector<uintptr_t> FAOBPattern::Scan() const
{
    std::vector<uintptr_t> Results;
    if (!IsValid() || !bHasKnownByte) return Results;

    const FTextSection& Text = GetModuleInfo().Text;
    if (Text.Begin == 0 || Text.End <= Text.Begin) return Results;

    const uintptr_t Begin = Text.Begin;
    const uintptr_t End = Text.End;
    const size_t Total = static_cast<size_t>(End - Begin);
    if (Total < Num()) return Results;

    unsigned int ThreadCount = std::thread::hardware_concurrency();
    if (ThreadCount == 0) ThreadCount = 4;
    if (Total < 4096) ThreadCount = 1;

    const size_t ChunkSize = Total / ThreadCount;
    std::vector<std::vector<uintptr_t>> ChunkResults(ThreadCount);
    std::vector<std::thread> Workers;
    Workers.reserve(ThreadCount);

    for (unsigned int Index = 0; Index < ThreadCount; ++Index)
    {
        const uintptr_t ChunkBegin = Begin + ChunkSize * Index;
        uintptr_t ChunkEnd = End;
        if (Index + 1 < ThreadCount)
        {
            ChunkEnd = ChunkBegin + ChunkSize + Num() - 1;
            if (ChunkEnd > End) ChunkEnd = End;
        }

        Workers.emplace_back([ChunkBegin, ChunkEnd, this, &ChunkResult = ChunkResults[Index]]()
            {
                ScanSection(ChunkBegin, ChunkEnd, *this, ChunkResult);
            });
    }

    for (std::thread& Worker : Workers)
    {
        if (Worker.joinable()) Worker.join();
    }

    for (const std::vector<uintptr_t>& ChunkResult : ChunkResults)
    {
        Results.insert(Results.end(), ChunkResult.begin(), ChunkResult.end());
    }

    return Results;
}

struct FAOBScanner
{
    static std::vector<uintptr_t> Scan(const FAOBPattern& Pattern)
    {
        return Pattern.Scan();
    }

    static std::vector<uintptr_t> Scan(std::string_view Text)
    {
        const std::optional<FAOBPattern> Pattern = FAOBPattern::Parse(Text);
        if (!Pattern) return {};
        return Pattern->Scan();
    }
};

}
