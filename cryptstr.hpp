#pragma once

#include <string>
#include <array>
#include <cstddef>

#define finline __forceinline

namespace cryptstr {
    class crypt {
    public:
        static constexpr auto time_str = __TIME__;
        static constexpr int hours = (time_str[0] - '0') * 10 + (time_str[1] - '0');
        static constexpr int minutes = (time_str[3] - '0') * 10 + (time_str[4] - '0');
        static constexpr int seconds = (time_str[6] - '0') * 10 + (time_str[7] - '0');
        static constexpr int randTime = hours * minutes * seconds;
    public:

        static constexpr unsigned long long multiplier = 964136223846793005ULL;
        static constexpr unsigned long long increment = 1ULL;
        static constexpr int randomized = ((123456789ULL * multiplier + randTime + increment) % (1ULL << 63)) % 999999999999999999;

        static constexpr int rkey = (randomized % randTime) * randTime;
        static constexpr size_t max_len = 256;

        template <size_t N>
        static constexpr std::array<char, N> xorencrypt(const char(&str)[N]) noexcept {
            std::array<char, N> result{};
            for (size_t i = 0; i < N - 1 && str[i] != '\0'; ++i) {
                result[i] = str[i] ^ rkey;
            }
            return result;
        }

        template <size_t N>
        static std::string xordecrypt(const std::array<char, N>& enc) noexcept {
            std::string r;
            for (size_t i = 0; i < N && enc[i] != '\0'; ++i) {
                r.push_back(enc[i] ^ rkey);
            }
            return r;
        }

    public:
        template <size_t N>
        static std::string get(const char(&str)[N]) noexcept {
            auto encrypted = xorencrypt(str);
            return xordecrypt(encrypted);
        }
    };
}

#define crypt(str) []() noexcept { \
    constexpr auto encrypted = ::cryptstr::crypt::xorencrypt(str); \
    return ::cryptstr::crypt::xordecrypt(encrypted); \
}()
