#pragma region Header Guard

#ifndef QTYPE_ENC_H
#define QTYPE_ENC_H

#pragma endregion

#pragma region Imports

#pragma region std

#include <string>
#include <vector>
#include <cstdlib>

#pragma endregion

#pragma region qengine

#include "../../qhook/qhook_dtc.hpp"

#pragma endregion

#pragma region Extended

#include <immintrin.h>

#pragma endregion

#pragma endregion

/*
	---------------------- Details on Class Global is_ctor_lock and it's Purpose: ---------------------

	§11.4.5/3 [class.base.init]
	* ISO / IEC 14882 : 2023 §11.4.5 [class.ctor] / §11.9.3 [class.base.init]
	The bullets read (emphasis added):

	… virtual bases …

	… direct bases …
	3) non-static data members are initialized in the order of declaration in the class definition.
	4) Finally, the body of the constructor is executed.

-------------------------------------------------------------------------------------------------------

	C++ Copy-Move Ctor's Implicate by Precept that All Members must be Explicitly / Implicitly Initialized BEFORE the Subsequent Body of the Explicitly Defined Copy-Move Ctor itself,
	the Ctor Default boolean Argument skip_ctor is a Workaround for this, as in our Case we MUST lock a Global Mutex before Modulating Global States in the Parent Classes Located in qtype_enchash.hpp

	---------------------- Details on Redundant Ctor Initializers ---------------------

	Compiler's Generate Warnings without Explicit Initializer-List Members for ALL Globals, EVEN IF you Initialize them Later in the Ctor Body,
	the NULL Initializer List is to Surpress this Warning State at Little - No Performance Cost Dependent on Compiler Optimization Settings, and has no Actual Affect on the Output Application
*/
#pragma region Class Expansion Macros

#ifndef QPRIMITIVE_TYPE_MUTATIONS

#define QEXPAND_PRIMITIVE_T(__NAME__, __TYPE__) \
class __NAME__ { \
private: \
	mut __TYPE__ _value; \
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public: \
	__optimized_ctor __NAME__(imut __TYPE__ value = (__TYPE__)NULL) nex { \
		std::lock_guard<std::recursive_mutex> lock(mtx);\
		set(value); \
		is_ctor_lock = false; \
	} \
	__optimized_dtor ~__NAME__() nex { \
		VOLATILE_NULL(_value); \
	} \
	__compelled_inline imut __TYPE__ __stackcall get() imut nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		qcipher_provider::cipher_decrypt(&_value, &_value, sizeof(__TYPE__)); \
		imut auto value = _value; \
		qcipher_provider::cipher_encrypt(&_value, &_value, sizeof(__TYPE__)); \
		return value; \
	} \
	__compelled_inline imut bool __regcall set(imut __TYPE__ value) nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = value; \
		return qcipher_provider::cipher_encrypt(&_value, &_value, sizeof(_value)); \
	} \
	__compelled_inline __NAME__ __regcall operator+(imut __TYPE__ value) imut nex { \
		return __NAME__(get() + value); \
	}; \
	__compelled_inline __NAME__ __regcall operator-(imut __TYPE__ value) imut nex { \
		return __NAME__(get() - value); \
	} \
	__compelled_inline __NAME__ __regcall operator/(imut __TYPE__ value) imut nex { \
		return __NAME__(get() / value); \
	} \
	__compelled_inline __NAME__ __regcall operator*(imut __TYPE__ value) imut nex { \
		return __NAME__(get() * value); \
	} \
	__compelled_inline __NAME__ __regcall operator&(imut __TYPE__ value) imut nex { \
		return __NAME__(get() & value); \
	} \
	__compelled_inline __NAME__ __regcall operator|(imut __TYPE__ value) imut nex { \
		return __NAME__(get() | value); \
	} \
	__compelled_inline __NAME__ __regcall operator%(imut __TYPE__ value) imut nex { \
		return __NAME__(get() % value); \
	} \
	__compelled_inline __NAME__ __regcall operator^(imut __TYPE__ value) imut nex { \
		return __NAME__(get() ^ value); \
	} \
	__compelled_inline __NAME__ __regcall operator<<(imut __TYPE__ value) imut nex { \
		return __NAME__(get() << value); \
	} \
	__compelled_inline __NAME__ __regcall operator>>(imut __TYPE__ value) imut nex { \
		return __NAME__(get() >> value); \
	} \
	__compelled_inline __NAME__& __regcall operator+=(imut __TYPE__ value) nex { \
		set(get() + value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator-=(imut __TYPE__ value) nex { \
		set(get() - value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator++() nex { \
		return this->operator+=(1); \
	} \
	__compelled_inline __NAME__& __regcall operator--() nex { \
		return this->operator-=(1); \
	} \
	__compelled_inline __NAME__& __regcall operator*=(imut __TYPE__ value) nex { \
		set(get() * value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator/=(imut __TYPE__ value) nex { \
		set(get() / value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator%=(imut __TYPE__ value) nex { \
		set(get() % value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator^=(imut __TYPE__ value) nex { \
		set(get() ^ value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator&=(imut __TYPE__ value) nex { \
		set(get() & value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator|=(imut __TYPE__ value) nex { \
		set(get() | value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator<<=(imut __TYPE__ value) nex { \
		set(get() << value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator>>=(imut __TYPE__ value) nex { \
		set(get() >> value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator=(imut __TYPE__ value) nex { \
		set(value); \
		return *this; \
	} \
	__compelled_inline __NAME__(const __NAME__& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
		return *this;\
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = std::move(other._value);\
		is_ctor_lock = false;\
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
			_value = std::move(other._value);\
		is_ctor_lock = false;\
		return *this;\
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex { \
		return get(); \
	} \
};

#define QEXPAND_PRECISION_T(__NAME__, __TYPE__) \
class __NAME__ { \
private: \
	__TYPE__ _value; \
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public: \
	__compelled_inline __fpcall __NAME__(imut __TYPE__ value) nex { \
		std::lock_guard<std::recursive_mutex> lock(mtx);\
		set(value); \
		is_ctor_lock = false; \
	} \
	__optimized_dtor ~__NAME__() nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		VOLATILE_NULL(_value); \
	} \
	__compelled_inline imut __TYPE__ __stackcall get() imut nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		qcipher_provider::cipher_decrypt((c_void)&_value, (imut c_void)&_value, sizeof(__TYPE__)); \
		imut auto value = _value; \
		qcipher_provider::cipher_encrypt((c_void)&_value, (imut c_void)&_value, sizeof(__TYPE__)); \
		return value; \
	} \
	__compelled_inline imut bool __fpcall set(imut __TYPE__ value) nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = value; \
		return qcipher_provider::cipher_encrypt((c_void)&_value, (imut c_void)&_value, sizeof(_value)); \
	} \
	__compelled_inline __NAME__ __fpcall operator+(imut __TYPE__ value) imut nex { \
		return __NAME__(get() + value); \
	} \
	__compelled_inline __NAME__ __fpcall operator-(imut __TYPE__ value) imut nex { \
		return __NAME__(get() - value); \
	} \
	__compelled_inline __NAME__ __fpcall operator/(imut __TYPE__ value) imut nex { \
		return __NAME__(get() / value); \
	} \
	__compelled_inline __NAME__ __fpcall operator*(imut __TYPE__ value) imut nex { \
		return __NAME__(get() * value); \
	} \
	__compelled_inline __NAME__& __fpcall operator+=(imut __TYPE__ value) nex { \
		set(get() + value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __fpcall operator-=(imut __TYPE__ value) nex { \
		set(get() - value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __fpcall operator*=(imut __TYPE__ value) nex { \
		set(get() * value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __fpcall operator/=(imut __TYPE__ value) nex { \
		set(get() / value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __fpcall operator=(imut __TYPE__ value) nex { \
		set(value); \
		return *this; \
	} \
	__compelled_inline __NAME__(const __NAME__& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
		return *this;\
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = std::move(other._value);\
		is_ctor_lock = false;\
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = std::move(other._value);\
		is_ctor_lock = false;\
		return *this;\
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex { \
		return get(); \
	} \
};

#else

#define QEXPAND_PRIMITIVE_T(__NAME__, __TYPE__) \
class __NAME__ { \
private: \
	cmut<__TYPE__> _value; \
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public: \
	__optimized_ctor __NAME__(imut __TYPE__ value = (__TYPE__)NULL) nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(value); \
		is_ctor_lock  = false; \
	} \
	__optimized_dtor ~__NAME__() nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		SECURE_ZERO_MEMORY(&_value, sizeof(cmut<__TYPE__>)); \
	} \
	__compelled_inline imut __TYPE__ __stackcall get() imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		qcipher_provider::cipher_decrypt(imut_cast<cmut<__TYPE__>*>(&_value), imut_cast<cmut<__TYPE__>*>(&_value), sizeof(cmut<__TYPE__>)); \
		imut __TYPE__ value = imut_cast<cmut<__TYPE__>*>(&_value)->get(); \
		qcipher_provider::cipher_encrypt(imut_cast<cmut<__TYPE__>*>(&_value), imut_cast<cmut<__TYPE__>*>(&_value), sizeof(cmut<__TYPE__>)); \
		return value; \
	} \
	__compelled_inline imut bool __regcall set(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = value; \
		return qcipher_provider::cipher_encrypt(&_value, &_value, sizeof(_value)); \
	} \
	__compelled_inline __NAME__ __regcall operator+(imut __TYPE__ value) imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return __NAME__(get() + value); \
	}; \
	__compelled_inline __NAME__ __regcall operator-(imut __TYPE__ value) imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return __NAME__(get() - value); \
	} \
	__compelled_inline __NAME__ __regcall operator/(imut __TYPE__ value) imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return __NAME__(get() / value); \
	} \
	__compelled_inline __NAME__ __regcall operator*(imut __TYPE__ value) imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return __NAME__(get() * value); \
	} \
	__compelled_inline __NAME__ __regcall operator&(imut __TYPE__ value) imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return __NAME__(get() & value); \
	} \
	__compelled_inline __NAME__ __regcall operator|(imut __TYPE__ value) imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return __NAME__(get() | value); \
	} \
	__compelled_inline __NAME__ __regcall operator%(imut __TYPE__ value) imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return __NAME__(get() % value); \
	} \
	__compelled_inline __NAME__ __regcall operator^(imut __TYPE__ value) imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return __NAME__(get() ^ value); \
	} \
	__compelled_inline __NAME__ __regcall operator<<(imut __TYPE__ value) imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return __NAME__(get() << value); \
	} \
	__compelled_inline __NAME__ __regcall operator>>(imut __TYPE__ value) imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return __NAME__(get() >> value); \
	} \
	__compelled_inline __NAME__& __regcall operator+=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(get() + value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator-=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(get() - value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator++() nex { \
		return this->operator+=(1); \
	} \
	__compelled_inline __NAME__& __regcall operator--() nex { \
		return this->operator-=(1); \
	} \
	__compelled_inline __NAME__& __regcall operator*=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(get() * value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator/=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(get() / value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator%=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(get() % value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator^=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(get() ^ value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator&=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(get() & value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator|=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(get() | value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator<<=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(get() << value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator>>=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(get() >> value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __regcall operator=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(value); \
		return *this; \
	} \
	__compelled_inline __NAME__(const __NAME__& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
		return *this;\
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = std::move(other._value);\
		is_ctor_lock = false;\
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = std::move(other._value);\
		is_ctor_lock = false;\
		return *this;\
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex { \
		return get(); \
	} \
};

#define QEXPAND_PRECISION_T(__NAME__, __TYPE__) \
class __NAME__ { \
private: \
	cmut<__TYPE__> _value; \
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public: \
	__compelled_inline __fpcall __NAME__(imut __TYPE__ value) nex { \
		std::lock_guard<std::recursive_mutex> lock(mtx);\
		set(value); \
		is_ctor_lock = false; \
	} \
	__optimized_dtor ~__NAME__() nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		SECURE_ZERO_MEMORY(&_value, sizeof(cmut<__TYPE__>)); \
	} \
	__compelled_inline imut __TYPE__ __stackcall get() imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		qcipher_provider::cipher_decrypt(imut_cast<cmut<__TYPE__>*>(&_value), imut_cast<cmut<__TYPE__>*>(&_value), sizeof(cmut<__TYPE__>)); \
		imut __TYPE__ value = imut_cast<cmut<__TYPE__>*>(&_value)->get(); \
		qcipher_provider::cipher_encrypt(imut_cast<cmut<__TYPE__>*>(&_value), imut_cast<cmut<__TYPE__>*>(&_value), sizeof(cmut<__TYPE__>)); \
		return value; \
	} \
	__compelled_inline imut bool __fpcall set(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = value; \
		return qcipher_provider::cipher_encrypt((c_void)&_value, (imut c_void)&_value, sizeof(_value)); \
	} \
	__compelled_inline __NAME__ __fpcall operator+(imut __TYPE__ value) imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return __NAME__(get() + value); \
	} \
	__compelled_inline __NAME__ __fpcall operator-(imut __TYPE__ value) imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return __NAME__(get() - value); \
	} \
	__compelled_inline __NAME__ __fpcall operator/(imut __TYPE__ value) imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return __NAME__(get() / value); \
	} \
	__compelled_inline __NAME__ __fpcall operator*(imut __TYPE__ value) imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return __NAME__(get() * value); \
	} \
	__compelled_inline __NAME__& __fpcall operator+=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(get() + value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __fpcall operator-=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(get() - value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __fpcall operator*=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(get() * value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __fpcall operator/=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(get() / value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __fpcall operator=(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(value); \
		return *this; \
	} \
	__compelled_inline __NAME__(const __NAME__& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
		return *this;\
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value); \
		is_ctor_lock = false;\
	} \
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = std::move(other._value);\
		is_ctor_lock = false;\
		return *this;\
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex { \
		return get(); \
	} \
};

#endif

#define QEXPAND_VECTOR_T(__NAME__, __TYPE__, __LOAD__, __STORE__) \
class __NAME__ { \
private: \
	alignas(sizeof(__TYPE__)) noregister std::uint8_t _value[sizeof(__TYPE__)]; \
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public: \
	__compelled_inline __fpcall __NAME__(imut __TYPE__ value) nex { \
		std::lock_guard<std::recursive_mutex> lock(mtx);\
		set(value); \
		is_ctor_lock = false; \
	} \
	__optimized_dtor ~__NAME__() nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		SECURE_ZERO_MEMORY(_value, sizeof(__TYPE__)); \
	} \
	__compelled_inline imut __TYPE__ __stackcall get() imut nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		qcipher_provider::cipher_decrypt(volatile_cast<std::uint8_t*>(_value), volatile_cast<std::uint8_t*>(_value), sizeof(__TYPE__)); \
		imut __TYPE__ value = __LOAD__((imut __TYPE__*)volatile_cast<std::uint8_t*>(_value)); \
		qcipher_provider::cipher_encrypt(volatile_cast<std::uint8_t*>(_value), volatile_cast<std::uint8_t*>(_value), sizeof(__TYPE__)); \
		return value; \
	} \
	__compelled_inline imut bool __fpcall set(imut __TYPE__ value) nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		__STORE__((__TYPE__*)volatile_cast<std::uint8_t*>(_value), value); \
		return qcipher_provider::cipher_encrypt(volatile_cast<std::uint8_t*>(_value), volatile_cast<std::uint8_t*>(_value), sizeof(__TYPE__)); \
	} \
	__compelled_inline __TYPE__ __fpcall load(imut __TYPE__* value) nex { \
		if(!value) return {NULL}; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		imut __TYPE__ _value_ = __LOAD__(value); \
		__STORE__((__TYPE__*)volatile_cast<std::uint8_t*>(_value), _value_); \
		qcipher_provider::cipher_encrypt(volatile_cast<std::uint8_t*>(_value), volatile_cast<std::uint8_t*>(_value), sizeof(__TYPE__)); \
		return _value_; \
	} \
	__compelled_inline imut bool __fpcall store(imut __TYPE__* value) nex { \
		if(!value) return false; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		qcipher_provider::cipher_decrypt(volatile_cast<std::uint8_t*>(_value), volatile_cast<std::uint8_t*>(_value), sizeof(__TYPE__)); \
		__STORE__((__TYPE__*)volatile_cast<std::uint8_t*>(_value), *value); \
		return qcipher_provider::cipher_encrypt(volatile_cast<std::uint8_t*>(_value), volatile_cast<std::uint8_t*>(_value), sizeof(__TYPE__)); \
	} \
	__compelled_inline __NAME__& __fpcall operator=(imut __TYPE__ value) nex { \
		set(value); \
		return *this; \
	} \
	__compelled_inline __NAME__(const __NAME__& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		std::memcpy((void*)_value, (void*)other._value, sizeof(__TYPE__)); \
		is_ctor_lock = false;\
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		std::memcpy((void*)_value, (void*)other._value, sizeof(__TYPE__)); \
		is_ctor_lock = false;\
		return *this;\
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		std::memcpy((void*)_value, (void*)other._value, sizeof(__TYPE__)); \
		is_ctor_lock = false;\
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		std::memcpy((void*)_value, (void*)other._value, sizeof(__TYPE__)); \
		is_ctor_lock = false;\
		return *this;\
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex { \
		return get(); \
	} \
};

#define QEXPAND_STRING_T(__NAME__, __TYPE__, __CHTYPE__, __PREFIX__) \
class __NAME__ { \
private: \
	mut __TYPE__ _value = __PREFIX__##""; \
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public: \
	__compelled_inline __stackcall __NAME__(imut __TYPE__ value) nex { \
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(value); \
		is_ctor_lock = false; \
	} \
	__optimized_ctor __NAME__(imut __CHTYPE__* value = __PREFIX__##"") nex { \
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(__TYPE__(value)); \
		is_ctor_lock = false; \
	} \
	__optimized_dtor ~__NAME__() nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		SECURE_ZERO_MEMORY(_value.data(), _value.size() * sizeof(__CHTYPE__)); \
	} \
	__compelled_inline __TYPE__* __stackcall get_underlying() imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return (__TYPE__*)&_value; \
	} \
	__compelled_inline imut __TYPE__ __stackcall get() imut nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		qcipher_provider::cipher_decrypt(_value.data(), _value.data(), _value.size() * sizeof(__CHTYPE__)); \
		auto value = _value; \
		qcipher_provider::cipher_encrypt(_value.data(), _value.data(), _value.size() * sizeof(__CHTYPE__)); \
		return value; \
	} \
	__compelled_inline imut bool __stackcall set(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = value; \
		return qcipher_provider::cipher_encrypt(_value.data(), _value.data(), _value.size() * sizeof(__CHTYPE__)); \
	} \
	__compelled_inline __NAME__ __stackcall operator+(imut __TYPE__& value) imut nex { \
		return __NAME__(get() + value); \
	} \
	__compelled_inline __NAME__& __stackcall operator+=(imut __TYPE__& value) nex { \
		set(get() + value); \
		return *this; \
	} \
	__compelled_inline __NAME__& __stackcall operator=(imut __TYPE__& value) nex { \
		set(value); \
		return *this; \
	} \
	__compelled_inline __NAME__(const __NAME__& other) noexcept { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false;\
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false;\
		return *this; \
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false;\
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept { \
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false;\
		return *this; \
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex { \
		return get(); \
	} \
};

#pragma endregion

namespace qengine{

	namespace qtype_enc {

#pragma region Singleton

		extern bool is_init;

#pragma endregion

#pragma region Types

#pragma region Template / User Defined

	template<typename T>
	class qe_struct {

	private:

#pragma region Encrypted value

		mut T _value;

		mut std::recursive_mutex mtx;

		/*
			§12.6.2/8 [class.base.init]
			C++17 Standard Draft N4659
			(Section 12.6.2: Initializing bases and members, paragraph 8)
			"A mem-initializer is evaluated as part of the initialization of the object. In particular, it is evaluated before the body of the constructor is entered (12.6.2/5). If a constructor’s parameter expression or a mem-initializer uses this, it designates a partially-constructed object..."
			"...Any operations on such an object other than calling its non-virtual member functions, accessing its non-static data members, or performing class member access that uses the . or -> operators are undefined behavior unless the object’s lifetime has begun (6.7.3)."

			The CXX Standard Allows for, infact Implements and even Promotes something which shouldn't exist - The Ability for a Move / Copy Ctor to Interrupt the Execution of the Base Ctor,
			Likewise Writing code in the Move / Copy Ctor, that DEPENDS on the Base Ctor's FULL EXECUTION, can and will Fail without Proper Guards / Fixes.
			This means you have to Write Code that May NOT Expect for the Object Instance to be Initialized, to any Degree ;

			In our case Specifically, it Means that the Mutex we Locked out of Necessity in the cmut Ctor, shall still be Locked by the Ctor, when Executing an Entirely Different Method which is REQUIRED to be
			Thread-Safe and likewise Requires a Mutex Guard.
		*/
		volatile bool is_ctor_lock = false;

#pragma endregion

	public:

#pragma region Ctor / Dtor

		__optimized_ctor qe_struct( imut T value = T{} ) nex {

			is_ctor_lock = true;

			std::lock_guard<std::recursive_mutex> lock(mtx);

			set(value);

			is_ctor_lock = false;
		}

		__optimized_dtor ~qe_struct() nex {

			SECURE_ZERO_MEMORY(&_value, sizeof(T));
		}

#pragma endregion

#pragma region Accessors

		__compelled_inline imut T __stackcall get() imut nex {

			if (!is_ctor_lock) 
				std::lock_guard<std::recursive_mutex> lock(mtx);

			qcipher_provider::cipher_decrypt(&_value, &_value, sizeof(T));

			T value = _value;

			qcipher_provider::cipher_encrypt(&_value, &_value, sizeof(T));

			return value;
		}

		template<typename _T>
		__compelled_inline decltype(auto) __regcall get( _T T::* member ) imut nex {

			T decrypted = get();

			return decrypted.*member;
		}

		__compelled_inline imut bool __regcall set(imut T value) nex {

			if (!is_ctor_lock) 
				std::lock_guard<std::recursive_mutex> lock(mtx);

			_value = value;

			return qcipher_provider::cipher_encrypt(&_value, &_value, sizeof(T));
		}

		template<typename _T>
		__compelled_inline imut bool __regcall set( _T T::* member, _T value ) nex {

			if (!is_ctor_lock) 
				std::lock_guard<std::recursive_mutex> lock(mtx);

			qcipher_provider::cipher_decrypt(&_value, &_value, sizeof(T));

			_value.*member = value;

			return qcipher_provider::cipher_encrypt(&_value, &_value, sizeof(T));
		}

#pragma endregion

#pragma region Operators

		__compelled_inline qe_struct<T>& __regcall operator=(imut T value) nex {
			set(value);
			return *this;
		}

		__compelled_inline __stackcall operator T() imut nex {
			return get();
		}

#pragma endregion

#pragma region Deleted Ctors && Move-Copy Operators

		__compelled_inline qe_struct(const qe_struct<T>& other) noexcept {

			if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

			if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);

			_value = other._value;

			is_ctor_lock = false;
		}
		__compelled_inline qe_struct<T>& operator=(qe_struct<T>& other) noexcept {

			if (this == &other) return *this;

			if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

			if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);

			_value = other._value;

			is_ctor_lock = false;

			return *this;
		}
		__compelled_inline qe_struct(qe_struct<T>&& other) noexcept {

			if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

			_value = std::move(other._value);

			is_ctor_lock = false;
		}
		__compelled_inline qe_struct<T>& operator=(qe_struct<T>&& other) noexcept {

			if (this == &other) return *this;

			if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

			_value = std::move(other._value);

			is_ctor_lock = false;

			return *this;
		}

#pragma endregion

	};

#pragma endregion

#pragma region Primitive

#pragma region 8-bit
	
	QEXPAND_PRIMITIVE_T(qe_int8, std::int8_t);

	QEXPAND_PRIMITIVE_T(qe_uint8, std::uint8_t);

#pragma endregion

#pragma region 16-bit

	QEXPAND_PRIMITIVE_T(qe_int16, std::int16_t);

	QEXPAND_PRIMITIVE_T(qe_uint16, std::uint16_t);

#pragma endregion

#pragma region 32-bit

	QEXPAND_PRIMITIVE_T(qe_int32, std::int32_t);

	QEXPAND_PRIMITIVE_T(qe_uint32, std::uint32_t);

#pragma endregion

#pragma region 64-bit

	QEXPAND_PRIMITIVE_T(qe_int64, std::int64_t);

	QEXPAND_PRIMITIVE_T(qe_uint64, std::uint64_t);

#pragma endregion

#pragma endregion

#pragma region Other Primitive Types
		
QEXPAND_PRIMITIVE_T(qe_bool, bool);

#pragma endregion

#undef QEXPAND_PRIMITIVE_T

#pragma region Floating Point

#pragma region 32-bit

QEXPAND_PRECISION_T(qe_float, float);

#pragma endregion

#pragma region 64-bit

QEXPAND_PRECISION_T(qe_double, double);

QEXPAND_PRECISION_T(qe_longdouble, long double);

#pragma endregion

#pragma endregion

#undef QEXPAND_PRECISION_T

#pragma region Extended Types

#pragma region SSE2
		
QEXPAND_VECTOR_T(qe_m128i, __m128i, _mm_load_si128, _mm_store_si128);

#pragma endregion

#ifndef QDISABLE_EXTENDED_TYPES

#ifndef QDISABLE_AVX512F_TYPES

#pragma region AVX2

QEXPAND_VECTOR_T(qe_m256i, __m256i, _mm256_load_si256, _mm256_store_si256);

#pragma endregion

#endif

#ifndef QDISABLE_AVX512F_TYPES

#pragma region AVX512f

QEXPAND_VECTOR_T(qe_m512i, __m512i, _mm512_load_si512, _mm512_store_si512);

#pragma endregion

#endif

#endif

#pragma endregion

#undef QEXPAND_VECTOR_T

#pragma region String Types

#pragma region String

QEXPAND_STRING_T(qe_string, std::string, char, (const char*));

#pragma endregion

#pragma region Wide String

QEXPAND_STRING_T(qe_wstring, std::wstring, wchar_t, L);

#pragma endregion

#pragma endregion

#undef QEXPAND_STRING_T

#pragma region Heap Allocation

		class qe_malloc {

		private:

#pragma region Global Variables

			c_void local_alloc;

			std::size_t alloc_len;

			mut std::recursive_mutex mtx;

			/*
				In Regards to the New Class-Scope Variable is_ctor_lock and it's Purpose:

				§12.6.2/8 [class.base.init]
				C++17 Standard Draft N4659
				(Section 12.6.2: Initializing bases and members, paragraph 8)
				"A mem-initializer is evaluated as part of the initialization of the object. In particular, it is evaluated before the body of the constructor is entered (12.6.2/5). If a constructor’s parameter expression or a mem-initializer uses this, it designates a partially-constructed object..."
				"...Any operations on such an object other than calling its non-virtual member functions, accessing its non-static data members, or performing class member access that uses the . or -> operators are undefined behavior unless the object’s lifetime has begun (6.7.3)."

				The CXX Standard Allows for, infact Implements and even Promotes something which shouldn't exist - The Ability for a Move / Copy Ctor to Interrupt the Execution of the Base Ctor,
				Likewise Writing code in the Move / Copy Ctor, that DEPENDS on the Base Ctor's FULL EXECUTION, can and will Fail without Proper Guards / Fixes.
				This means you have to Write Code that May NOT Expect for the Object Instance to be Initialized, to any Degree ;

				In our case Specifically, it Means that the Mutex we Locked out of Necessity in the cmut Ctor, shall still be Locked by the Ctor, when Executing an Entirely Different Method which is REQUIRED to be
				Thread-Safe and likewise Requires a Mutex Guard.
			*/
			volatile bool is_ctor_lock = true;

#pragma endregion

		public:

#pragma region Proxy objects

#pragma region Subscript proxy

			// nested class to support subscript assignment
			class index_proxyE {

			private:

#pragma region Globals

				qe_malloc& parent;

				std::size_t index;

#pragma endregion

			public:

#pragma region Ctor

				index_proxyE(imut std::size_t index_, qe_malloc& instance) nex : index(index_), parent(instance) { }

#pragma endregion

#pragma region Operator overrides

				std::uint8_t& operator=(std::uint8_t value) nex {

					parent.set(index, value);

					return value;   // return the passed assignment value rather than using up absurd resources to decrypt, re-encrypt everything using get()
				}

				__compelled_inline __stackcall operator std::uint8_t() imut nex {

					return parent.get(index);
				}

#pragma endregion
			};

#pragma endregion

#pragma endregion

#pragma region Ctor

			__optimized_ctor qe_malloc(

				imut std::size_t len,

				imut c_void src = nullptr

			) : alloc_len(len), local_alloc(malloc(len)) {

				std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!local_alloc)
					return;

				SECURE_ZERO_MEMORY(local_alloc, len);

				if (src)
					set(src, 0, len);
				else
					qcipher_provider::cipher_encrypt(local_alloc, local_alloc, len);

				is_ctor_lock = false;
			}

#pragma endregion

#pragma region Get accessors

			__compelled_inline imut bool __regcall get(
				
				c_void				dst,

				imut std::uintptr_t pos,
				
				imut std::size_t	len
			
			) nex {
				
				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!dst || !len || alloc_len < (pos + len))
					return false;

				if (!qcipher_provider::cipher_decrypt_range(reinterpret_cast<std::uint8_t*>(local_alloc) + pos, local_alloc, pos, len))
					return false;

				accelmem::a_memcpy(
					
					dst,

					local_alloc,

					len
				);

				if (!qcipher_provider::cipher_encrypt_range(reinterpret_cast<std::uint8_t*>(local_alloc) + pos, local_alloc, pos, len))
					return false;

				return true;
			}

			__compelled_inline std::uint8_t __regcall get(imut std::size_t index) nex {

				std::uint8_t rbyte = NULL;

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				get(&rbyte, index, sizeof(std::uint8_t));

				return rbyte;
			}

			template<typename T>
			__compelled_inline T __regcall get_t(imut std::uintptr_t pos) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (alloc_len < (pos + sizeof(T)))
					return T(NULL);

				T rT = T(NULL);

				get(&rT, pos, sizeof(T));

				return rT;
			}

			__compelled_inline c_void __stackcall get_data_pointer() nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				return local_alloc;
			}

			__compelled_inline std::size_t __stackcall get_data_size() nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				return alloc_len;
			}

#pragma endregion

#pragma region Set accessors

			//WARNING: appending length to the allocation here will cause exceptions / UB
			__compelled_inline imut bool __regcall set(
				
				c_void src,

				imut std::uintptr_t pos,

				imut std::size_t len

			) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!src || !len || alloc_len < (pos + len))
					return false;

				accelmem::a_memcpy(
					
					reinterpret_cast<std::uint8_t*>(local_alloc) + pos,

					src,

					len
				);

				if (!qcipher_provider::cipher_encrypt_range(reinterpret_cast<std::uint8_t*>(local_alloc) + pos, local_alloc, pos, len))
					return false;

				return true;
			}

			__compelled_inline imut bool __regcall _memset(

				imut std::uintptr_t pos,

				imut std::uint8_t value,

				imut std::size_t len

			) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!len || alloc_len < (pos + len))
					return false;

				accelmem::a_memset(
					
					reinterpret_cast<std::uint8_t*>(local_alloc) + pos,

					len,

					value
				);

				if (!qcipher_provider::cipher_encrypt_range(reinterpret_cast<std::uint8_t*>(local_alloc) + pos, local_alloc, pos, len))
					return false;

				return true;
			}

			template<typename T>
			__compelled_inline imut bool __regcall set(std::uintptr_t pos, T value) nex {
				
				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				return set(&value, pos, sizeof(T));
			}

#pragma endregion

#pragma region Utility functions

			//size is only the length in bytes of the allocation to be appended or destroyed
			__compelled_inline imut bool __regcall resize(imut std::size_t len) nex {
				
				if (!len)
					return false;

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!qcipher_provider::cipher_decrypt(local_alloc, local_alloc, len))
					return false;

				c_void ralloc = realloc(local_alloc, len);

				if (!ralloc)
					return false;

				if (ralloc != local_alloc)
					local_alloc = std::move(ralloc);

				if (!qcipher_provider::cipher_encrypt(local_alloc, local_alloc, len))
					return false;

				alloc_len = len;

				return true;
			}

			__compelled_inline void __stackcall zero() nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				_memset(0u, NULL, alloc_len);
			}

#pragma endregion

#pragma region Operators

			index_proxyE __regcall operator[](std::size_t index) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				return index_proxyE(index, *this);
			}

#pragma endregion

#pragma region Deleted Ctors && Move-Copy Operators

			__compelled_inline qe_malloc(const qe_malloc& other) noexcept {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);

				local_alloc = malloc(other.alloc_len);

				alloc_len = other.alloc_len;

				is_ctor_lock = false;
			}
			__compelled_inline qe_malloc& operator=(qe_malloc& other) noexcept {

				if (this == &other) return *this;

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);

				local_alloc = malloc(other.alloc_len);

				alloc_len = other.alloc_len;

				is_ctor_lock = false;

				return *this;
			}
			__compelled_inline qe_malloc(qe_malloc&& other) noexcept {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				local_alloc = std::move(other.local_alloc);

				alloc_len = std::move(other.alloc_len);

				is_ctor_lock = false;
			}
			__compelled_inline qe_malloc& operator=(qe_malloc&& other) noexcept {

				if (this == &other) return *this;

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				local_alloc = std::move(other.local_alloc);

				alloc_len = std::move(other.alloc_len);

				is_ctor_lock = false;

				return *this;
			}

#pragma endregion

#pragma region Destructor

			__compelled_inline imut bool __stackcall secure_destroy() nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!local_alloc || !alloc_len)
					return false;

				SECURE_ZERO_MEMORY(local_alloc, alloc_len);
				VOLATILE_NULL(alloc_len);

				free(local_alloc);
			}

			__compelled_inline __stackcall ~qe_malloc() nex {

				secure_destroy();
			}

#pragma endregion
		};

#pragma endregion

#pragma region Extended Typedefs

#ifdef _WIN64

		typedef qe_uint64 qe_uintptr_t;
		typedef qe_uint64 qe_size_t;

#else

		typedef qe_uint32 qe_uintptr_t;
		typedef qe_uint32 qe_size_t;

#endif

#pragma endregion

	};

#pragma region Static Declarators

	bool qtype_enc::is_init = false;

#pragma endregion

}

#endif
