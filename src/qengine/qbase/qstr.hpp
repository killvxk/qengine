/*
/**************************************************************************************************************************************************************************
*																											                                                              *
* This class is ONLY intended to prevent plaintext cstring from being output to the binary                                                                                *
* This does not use the polyq algorithm and is NOT hash-checked, it's one and only purpose is the most basic possible encryption to prevent string-searching the binary   *
*                                                                                                                                                                         *
*                                                                                                                                                                         *
* Credit for this class should mostly, if not entirely, go to the original author of skCrypt:                                                                             *
*                                                                                                                                                                         *
* https://github.com/javaloader/Sky-Crypt-C-11-String-Encryptor-                                                                                                          *
*                                                                                                                                                                         *
* Preprocessor / Constexpr is tricky, so i modified the naming convention(s) and a few specificities from his class to fit qengine's formatting                           *
*																											                                                              *                      
***************************************************************************************************************************************************************************
*/

#pragma region Header Guard

#ifndef QSTR_H
#define QSTR_H

#pragma endregion

#pragma region Imports

#pragma region std

#include <tuple>
#include <string>
#include <memory>
#include <algorithm>
#include <cstdint>

#pragma endregion

#pragma endregion

#pragma region constexpr Qualifier Removal

template <class C>
using qclean_type = typename std::remove_const_t<std::remove_reference_t<C>>;

#pragma endregion

#pragma region Output Macro

#define QSTR(__STR__) []() { \
		constexpr static auto _QSTR_ = qstr_object \
			<sizeof(__STR__) / sizeof(__STR__[0]), qclean_type< decltype( __STR__[0] ) >>((qclean_type<decltype(__STR__[0])>*)__STR__); \
				return _QSTR_; }()

#pragma endregion

#pragma region Compile-time Constants

const constexpr std::int8_t _QSTR_KEY = ~(__TIME__[7] | __TIME__[4] | __TIME__[0]);

#pragma endregion

template <const std::int32_t _size, typename T>
class qstr_object
{

private:

    mutable T _storage[_size]{};

    __forceinline constexpr void qcrypt(const T *data) noexcept {

        for (int i = 0; i < _size; i++)
            _storage[i] = ( ( data[i] ^ _QSTR_KEY ) ^ ( (__TIME__[0] ^  __TIME__[4] ^ __TIME__[6]) ^ 0xFF ) );
    }

public:

#pragma region Ctor

    __forceinline constexpr qstr_object(const T *data) noexcept {

        qcrypt(data);
    }

#pragma endregion

    __forceinline const std::int32_t size() const noexcept {

        return _size;
    }

    __forceinline const bool __cdecl is_crypted() const noexcept {

        return _storage[_size - 1] != 0;
    }

    __forceinline T* crypter_routine() noexcept {

        if (is_crypted())
            qcrypt(_storage);

        return _storage;
    }

    __forceinline void __cdecl clear() noexcept {

        RtlZeroMemory(_storage, _size);
    }

    __forceinline __cdecl operator T* () noexcept {

        return const_cast<T*>(
            crypter_routine()
        );
    }

    __forceinline const T* get() noexcept {

        return const_cast<T*>(
            crypter_routine()
        );
    }
};

#pragma region Header Guard

#endif

#pragma endregion