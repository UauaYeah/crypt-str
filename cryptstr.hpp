#pragma once

#include <string>
#include <array>
#include <cstddef>
#include <type_traits>
#include <iostream>

#define finline __forceinline

namespace cryptstr {
    class crypt {
    public:
        static constexpr auto time_str = __TIME__;
        static constexpr int hours = (time_str[0] - '0') * 10 + (time_str[1] - '0');
        static constexpr int minutes = (time_str[3] - '0') * 10 + (time_str[4] - '0');
        static constexpr int seconds = (time_str[6] - '0') * 10 + (time_str[7] - '0');
        static constexpr int randTime = (hours * minutes * seconds);

        static constexpr unsigned long long a = 16264525ULL;
        static constexpr unsigned long long c = 8013904223ULL;
        static constexpr unsigned long long m = 0xFFFFFFFFF;
        static constexpr int rkey = ((((a * randTime + c) % m) % 3ULL)) * 0xFF;

        template <typename T, size_t N>
        static constexpr std::array<T, N> xorencrypt(const T(&str)[N]) noexcept {
            std::array<T, N> result{};
            for (size_t i = 0; i < N - 1 && str[i] != '\0'; ++i) {
                result[i] = str[i] ^ rkey;
            }
            return result;
        }

        template <typename T, size_t N>
        static constexpr std::array<T, N> xordecrypt(const std::array<T, N>& enc) noexcept {
            std::array<T, N> result{};
            for (size_t i = 0; i < N - 1 && enc[i] != '\0'; ++i) {
                result[i] = enc[i] ^ rkey;
            }
            return result;
        }
    };
}

#define crypt_(str) ([]() noexcept { \
    using str_type = std::remove_cv_t<std::remove_pointer_t<decltype(str)>>; \
    constexpr size_t size = sizeof(str) / sizeof(str[0]); \
    using crypt_type = ::cryptstr::crypt; \
    constexpr auto encrypted = crypt_type::xorencrypt(str); \
    return crypt_type::xordecrypt(encrypted).data(); \
}())
#define crypt(str) (crypt_(str))
