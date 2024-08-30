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

        static constexpr unsigned long long a = 16264525ULL;
        static constexpr unsigned long long c = 8013904223ULL;
        static constexpr unsigned long long m = 0xFFFFFFFF;

        static constexpr int rkey = (((a * randTime + c) % m) % randTime) * randTime;
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
        static std::array<char, N - 1> xordecrypt(const std::array<char, N>& enc) noexcept {
            std::array<char, N - 1> r = std::array<char, N - 1>();
            for (size_t i = 0; i < N && enc[i] != '\0'; ++i) {
                r[i] = enc[i] ^ rkey;
            }
            return r;
        }

        template <size_t N>
        static const char* decryptToCString(const std::array<char, N>& enc) noexcept {
            static std::array<char, N - 1> decrypted = xordecrypt(enc);
            return decrypted.data();
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
    return ::cryptstr::crypt::decryptToCString(encrypted); \
}()
