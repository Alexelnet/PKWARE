#include <iostream>
#include <iomanip>
#include <algorithm>
#include <bitset>
#include <vector>
#include <filesystem>
#include <miniz.h>
#include "fmt/base.h"

#include "ConsoleProgress.hpp"


static constexpr uint32_t kFactor = 0x08088405;
static constexpr uint32_t kInvFactor = 0xd94fa8cd;

constexpr auto kCRCPolynomialDivision = 0xedb88320;


static constexpr size_t kLutSize = 256;
std::array<uint32_t, kLutSize> g_CRC32LUT;
std::array<uint32_t, kLutSize> g_InvCRC32LUT;


constexpr uint8_t GetLSByte(uint32_t value)
{
    return static_cast<uint8_t>(value);
}

constexpr uint8_t GetMSByte(uint32_t value)
{
    return static_cast<uint8_t>(value >> 24);
}

// From BKCrack
template <int begin, int end>
constexpr auto mask = uint32_t{~0u << begin & ~0u >> (32 - end)};

// From BKCrack
template <int x>
constexpr auto maxdiff = uint32_t{mask<0, x> + 0xff};


uint32_t ComputeCRC32(uint32_t crc, uint8_t inputByte)
{
    crc ^= inputByte;

    for (uint32_t i = 0; i < 8; i++)
        crc = (crc & 1) ? (crc >> 1) ^ kCRCPolynomialDivision : (crc >> 1);

    return crc;
}

void ComputeCRC32LUTs()
{
    for (size_t i = 0; i < kLutSize; i++)
    {
        auto crc = ComputeCRC32(0, i);

        g_CRC32LUT[i] = crc;
        g_InvCRC32LUT[GetMSByte(crc)] = crc << 8 ^ i;
    }
}

static uint32_t CRFC32(uint32_t value, uint8_t byte)
{
    return value >> 8 ^ g_CRC32LUT[GetLSByte(value) ^ byte];
}

static uint32_t InvCRC32(uint32_t crc32, uint8_t byte)
{
    return crc32 << 8 ^ g_InvCRC32LUT[GetMSByte(crc32)] ^ byte;
}

// From BKCrack
static uint32_t getYi_24_32(uint32_t zi, uint32_t zim1)
{
    return (InvCRC32(zi, 0) ^ zim1) << 24;
}

// From BKCrack
static uint32_t getZim1_10_32(uint32_t zi_2_32)
{
    return InvCRC32(zi_2_32, 0) & mask<10, 32>;
}


struct Keys
{
    uint32_t key0 = 0x12345678;
    uint32_t key1 = 0x23456789;
    uint32_t key2 = 0x34567890;

    Keys(uint32_t key0, uint32_t key1, uint32_t key2) : key0(key0), key1(key1), key2(key2)
    {

    }

    void Update(uint8_t p)
    {
        key0 = CRFC32(key0, p);
        key1 = (key1 + GetLSByte(key0)) * kFactor + 1;
        key2 = CRFC32(key2, GetMSByte(key1));
    }

    void InvUpdate(uint8_t c)
    {
        key2 = InvCRC32(key2, GetMSByte(key1));
        key1 = (key1 - 1) * 0xd94fa8cd - GetLSByte(key0);
        key0 = InvCRC32(key0, c ^ ComputeKey3());
    }

    void InvUpdate(const std::vector<uint8_t>& ciphertext, size_t current, size_t target)
    {
        for (size_t i = current; i > target; --i)
            InvUpdate(ciphertext[i - 1]);
    }

    [[nodiscard]]
    uint8_t ComputeKey3() const
    {
        uint16_t temp = key2 | 3;
        return GetLSByte((temp * (temp ^ 1)) >> 8);
    }
};


struct Data
{
    static constexpr size_t s_EncryptionHeaderSize = 12;

    std::vector<uint8_t> plainText;
    std::vector<uint8_t> cipherText;

    size_t offset;
    std::vector<uint8_t> keystream;

    Data(std::vector<uint8_t> ciphertextArg, std::vector<uint8_t> plaintextArg) :
        cipherText(std::move(ciphertextArg)),
        plainText(std::move(plaintextArg))
    {
        offset = s_EncryptionHeaderSize;

        keystream.resize(plainText.size());

        for (size_t i = 0; i < plainText.size(); ++i)
            keystream[i] = cipherText[offset + i] ^ plainText[i];
    }
};





// Implementation from BKCrack
class Solver
{
public:
    static constexpr size_t contiguousSize = 8;
    static constexpr size_t attackSize = 12;

    const size_t index;

    const Data& data;

    std::optional<Keys>& solution;
    std::mutex& solutionsMutex;

    Progress& progress;

    std::array<uint32_t, contiguousSize> zlist;
    std::array<uint32_t, contiguousSize> ylist;
    std::array<uint32_t, contiguousSize> xlist;

    Solver(const Data& data, size_t index, std::optional<Keys>& solution, std::mutex& solutionsMutex, Progress& progress) :
        data(data),
        index(index + 1 - contiguousSize),
        solution(solution),
        solutionsMutex(solutionsMutex),
        progress(progress)
    {
    }

    void ExploreZlists(int32_t i)
    {
        if (i != 0)
        {
            const auto zim1_10_32 = getZim1_10_32(zlist[i]);

            const auto ki_minus1 = data.keystream[index + i - 1];
            const auto hi6 = zim1_10_32 & mask<10, 16>;

            for (uint32_t low8 = 0; low8 < kLutSize; ++low8)
            {
                uint32_t zim1_2_16 = hi6 | (low8 << 2);

                if (static_cast<uint8_t>(((zim1_2_16 | 2u) * (zim1_2_16 | 3u)) >> 8) != ki_minus1)
                    continue;

                zlist[i - 1] = zim1_10_32 | zim1_2_16;

                zlist[i] &= mask<2, 32>;
                zlist[i] |= (InvCRC32(zlist[i], 0) ^ zlist[i - 1]) >> 8;

                if (i < 7)
                    ylist[i + 1] = getYi_24_32(zlist[i + 1], zlist[i]);

                ExploreZlists(i - 1);
                if (progress.state != Progress::State::Normal)
                    return;
            }
        }
        else
        {
            for (auto y7_8_24 = uint32_t{}, prod = (kInvFactor * GetMSByte(ylist[7]) << 24) - kInvFactor; y7_8_24 < (1U << 24); y7_8_24 += 1 << 8, prod += kInvFactor << 8)
            {
                for (uint32_t y7_0_8 = 0; y7_0_8 < kLutSize; ++y7_0_8)
                {
                    uint32_t test = prod + kInvFactor * y7_0_8;

                    if (std::abs(int32_t(GetMSByte(test)) - int32_t(GetMSByte(ylist[6]))) > 1)
                        continue;

                    if (test - (ylist[6] & mask<24, 32>) <= maxdiff<24>)
                    {
                        ylist[7] = y7_0_8 | y7_8_24 | (ylist[7] & mask<24, 32>);
                        ExploreYlists(7);

                        if (progress.state != Progress::State::Normal)
                            return;
                    }
                }
            }
        }
    }

    void ExploreYlists(int32_t i)
    {
        if (i != 3)
        {
            const auto fy = (ylist[i] - 1) * kInvFactor;
            const auto ffy = (fy - 1) * kInvFactor;

            for (uint32_t xi_0_8 = 0; xi_0_8 < kLutSize; ++xi_0_8)
            {
                auto test = (fy - xi_0_8 - 1) * kInvFactor;
                if (std::abs(int32_t(GetMSByte(test)) - int32_t(GetMSByte(ylist[i - 2]))) > 1)
                    continue;

                const auto yim1 = fy - xi_0_8;

                if (ffy - kInvFactor * xi_0_8 - (ylist[i - 2] & mask<24, 32>) <= maxdiff<24> &&
                    GetMSByte(yim1) == GetMSByte(ylist[i - 1]))
                {
                    ylist[i - 1] = yim1;
                    xlist[i] = xi_0_8;

                    ExploreYlists(i - 1);
                }
            }
        }
        else
            TestXlist();
    }


    void TestXlist()
    {
        for (auto i = 5; i <= 7; i++)
            xlist[i] = (CRFC32(xlist[i - 1], data.plainText[index + i - 1]) & mask<8, 32>) | GetLSByte(xlist[i]);

        auto x = xlist[7];
        for (auto i = 6; i >= 3; i--)
            x = InvCRC32(x, data.plainText[index + i]);

        const auto y1_26_32 = getYi_24_32(zlist[1], zlist[0]) & mask<26, 32>;
        if (((ylist[3] - 1) * kInvFactor - GetLSByte(x) - 1) * kInvFactor - y1_26_32 > maxdiff<26>)
            return;

        auto keysForward = Keys{xlist[7], ylist[7], zlist[7]};
        keysForward.Update(data.plainText[index + 7]);

        for (auto p = data.plainText.begin() + index + 8, c = data.cipherText.begin() + data.offset + index + 8;
             p != data.plainText.end(); ++p, ++c)
        {
            if ((*c ^ keysForward.ComputeKey3()) != *p)
                return;
            keysForward.Update(*p);
        }

        auto keysBackward = Keys{x, ylist[3], zlist[3]};
        for (auto p = std::reverse_iterator{data.plainText.begin() + index + 3}, c = std::reverse_iterator{data.cipherText.begin() + data.offset + index + 3}; p != data.plainText.rend(); ++p, ++c)
        {
            keysBackward.InvUpdate(*c);
            if ((*c ^ keysBackward.ComputeKey3()) != *p)
                return;
        }

        auto indexBackward = data.offset;

        keysBackward.InvUpdate(data.cipherText, indexBackward, 0);
        {
            const auto lock = std::scoped_lock{solutionsMutex};
            solution = keysBackward;
        }

        progress.state = Progress::State::EarlyExit;
    }
};

std::optional<Keys> Solve(const Data& data, const std::vector<uint32_t>& zi_2_32_vector, int32_t& start, size_t index, int32_t jobs, Progress& progress)
{
    const auto* candidates = zi_2_32_vector.data();
    const auto size = static_cast<int32_t>(zi_2_32_vector.size());

    auto solutions = std::optional<Keys>(std::nullopt);
    auto solutionsMutex = std::mutex{};
    auto worker = Solver(data, index, solutions, solutionsMutex, progress);

    progress.done = start;
    progress.total = size;

    const auto threadCount = std::clamp(jobs, 1, size);
    auto threads = std::vector<std::thread>();
    auto nextCandidateIndex = std::atomic(start);

    for (auto i = 0; i < threadCount; ++i)
        threads.emplace_back(
                             [&nextCandidateIndex, size, &progress, candidates, worker]() mutable
                             {
                                 for (auto i = nextCandidateIndex++; i < size; i = nextCandidateIndex++)
                                 {
                                     worker.zlist[7] = candidates[i];
                                     worker.ExploreZlists(7);
                                     progress.done++;

                                     if (progress.state != Progress::State::Normal)
                                         break;
                                 }
                             });

    for (auto& thread: threads)
        thread.join();

    start = std::min(nextCandidateIndex.load(), size);

    return solutions;
}


// Implementation from BKCrack
class Reductor
{
    static uint8_t ComputeKeystreamByte(uint32_t zi)
    {
        return static_cast<uint8_t>(((zi | 2u) * (zi | 3u)) >> 8);
    }

public:
    Reductor(const std::vector<uint8_t>& keystream) :
        m_Keystream(keystream)
    {
        index = keystream.size() - 1;
        zi_vector.reserve(1 << 22);

        const uint8_t k_last = keystream[index];

        for (uint32_t hi22 = 0; hi22 < (1u << 22); ++hi22)
        {
            uint32_t base = hi22 << 10;

            bool ok = false;
            for (uint32_t low8 = 0; low8 < kLutSize && !ok; ++low8)
                if (ComputeKeystreamByte(base | (low8 << 2)) == k_last)
                    ok = true;

            if (ok)
                zi_vector.push_back(base);
        }
    }

    void Reduce()
    {
        constexpr size_t trackThresh = 1 << 16;
        constexpr size_t waitThresh = 1 << 8;

        bool tracking = false, waiting = false;
        size_t bestSize = trackThresh, wait = 0;
        size_t bestIndex = index;
        std::vector<uint32_t> bestCopy;

        std::vector<uint32_t> zim1_10_32_vec;
        zim1_10_32_vec.reserve(1 << 22);
        std::bitset<1 << 22> zim1_seen;

        for (size_t i = index; i >= Solver::contiguousSize; --i)
        {
            zim1_10_32_vec.clear();
            zim1_seen.reset();
            size_t num_zim1_2_32 = 0;

            const uint8_t k_i = m_Keystream[i];
            const uint8_t k_im1 = m_Keystream[i - 1];

            for (auto zi_10_32: zi_vector)
            {
                for (uint32_t low8 = 0; low8 < kLutSize; ++low8)
                {
                    if (ComputeKeystreamByte(zi_10_32 | (low8 << 2)) != k_i)
                        continue;

                    uint32_t zim1_10_32 =
                            getZim1_10_32(zi_10_32 | (low8 << 2));

                    if (zim1_seen[zim1_10_32 >> 10])
                        continue;

                    size_t countMatch = 0;
                    for (uint32_t low8p = 0; low8p < kLutSize; ++low8p)
                        if (ComputeKeystreamByte(zim1_10_32 | (low8p << 2)) == k_im1)
                            ++countMatch;

                    if (countMatch)
                    {
                        zim1_10_32_vec.push_back(zim1_10_32);
                        zim1_seen.set(zim1_10_32 >> 10);
                        num_zim1_2_32 += countMatch;
                    }
                }
            }

            if (num_zim1_2_32 <= bestSize)
            {
                tracking = true;
                bestIndex = i - 1;
                bestSize = num_zim1_2_32;
                waiting = false;
            }
            else if (tracking)
            {
                if (bestIndex == i)
                {
                    bestCopy.swap(zi_vector);
                    if (bestSize <= waitThresh)
                    {
                        waiting = true;
                        wait = bestSize * 4;
                    }
                }
                if (waiting && --wait == 0)
                    break;
            }

            zi_vector.swap(zim1_10_32_vec);
        }

        if (tracking)
        {
            if (bestIndex != Solver::contiguousSize - 1)
                zi_vector.swap(bestCopy);
            index = bestIndex;
        }
        else
            index = Solver::contiguousSize - 1;
    }

    void Generate()
    {
        const uint8_t k_idx = m_Keystream[index];
        const size_t base = zi_vector.size();

        for (size_t i = 0; i < base; ++i)
        {
            uint32_t zi_10_32 = zi_vector[i];

            bool firstDone = false;
            for (uint32_t low8 = 0; low8 < kLutSize; ++low8)
            {
                uint32_t zi = zi_10_32 | (low8 << 2);
                if (ComputeKeystreamByte(zi) != k_idx)
                    continue;

                if (!firstDone)
                {
                    zi_vector[i] = zi;
                    firstDone = true;
                }
                else
                    zi_vector.push_back(zi);
            }
        }
    }

    [[nodiscard]]
    const std::vector<uint32_t>& GetCandidates() const
    {
        return zi_vector;
    }

    [[nodiscard]]
    size_t GetIndex() const
    {
        return index;
    }

private:
    size_t index;

    const std::vector<uint8_t>& m_Keystream;
    std::vector<uint32_t> zi_vector;
};


static std::vector<uint8_t> ConvertToByteVector(const std::string& plaintextString)
{
    std::vector<uint8_t> result;
    result.insert(result.end(), plaintextString.begin(), plaintextString.end());

    return result;
}


void PrintArchiveContentInfo(std::filesystem::path path)
{
    mz_zip_archive zip{};

    if (!mz_zip_reader_init_file(&zip, path.c_str(), 0))
    {
        fmt::print(stderr, "Failed to open ZIP file: {}\n", path.c_str());
        return;
    }

    fmt::println("Path: {}", path.c_str());
    fmt::println("Index Encryption Compression CRC32    Uncompressed  Packed size File name");
    fmt::println("----- ---------- ----------- -------- ------------ ------------ ----------------");

    int numFiles = static_cast<int>(mz_zip_reader_get_num_files(&zip));

    for (int i = 0; i < numFiles; i++)
    {
        mz_zip_archive_file_stat stat;

        if (!mz_zip_reader_file_stat(&zip, i, &stat))
        {
            fmt::println(stderr, "Failed to get file stat at index {}", i);
            continue;
        }

        const char* compression = stat.m_method == 0 ? "Store" : stat.m_method == MZ_DEFLATED ? "Deflate" : "Other";
        const char* encryption = (stat.m_bit_flag & 1) ? "ZipCrypto" : "None";

        fmt::println("{:>5} {:>10} {:>11} {:08x} {:12} {:12} {}",
                   i,
                   encryption,
                   compression,
                   stat.m_crc32,
                   stat.m_uncomp_size,
                   stat.m_comp_size,
                   stat.m_filename);
    }

    mz_zip_reader_end(&zip);
}




int main()
{
    PrintArchiveContentInfo("secrets.zip");

    // Initializing the lookup tables for the CRC32 and inverse CRC32
    ComputeCRC32LUTs();

    int32_t threadCount = 28;

    std::vector<uint8_t> plaintext = ConvertToByteVector("<?xml version=\"1.0\" ");

    // Extracted from the archive with the help of a HexEditor, from the offset reported by miniz library
    std::vector<uint8_t> ciphertext =
    {
        0xb1, 0xa7, 0x47, 0x2a, 0xc6, 0x05, 0x15, 0x3a, 0x3b, 0x0e, 0x6e, 0x47, 0x8f, 0x20, 0x00, 0xd0, 0x82, 0xa5,
        0xcb, 0x02, 0x1f, 0x2f, 0xa5, 0x13, 0x9a, 0x50, 0xf7, 0xc1, 0xf9, 0x3d, 0x10, 0xb7
    };

    Data data(std::move(ciphertext), std::move(plaintext));

    Reductor reductor(data.keystream);
    reductor.Reduce();
    reductor.Generate();

    fmt::println("Solving for {} candidates", reductor.GetCandidates().size());

    int32_t start = 0; //176000;
    ConsoleProgress progress(std::cout);
    std::optional<Keys> solution = Solve(data, reductor.GetCandidates(), start, reductor.GetIndex(), threadCount, progress);

    if (!solution)
    {
        fmt::println("No solution found.");
        return 1;
    }

    fmt::println("Keys: {:08X} {:08X} {:08X}", solution.value().key0, solution.value().key1, solution.value().key2);
}