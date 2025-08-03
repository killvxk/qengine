#pragma region Header Guard

#ifndef QENCHASH_T_H
#define QENCHASH_T_H

#pragma endregion

#pragma region Imports

#pragma region qengine

#include "../hashtypes/qtype_hash.hpp"

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

#define QEXPAND_PRIMITIVE_T(__NAME__, __TYPE__, __QTYPE__)\
class __NAME__ {\
private:\
	__QTYPE__ _value;\
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public:\
	__optimized_ctor __NAME__(imut __TYPE__ value = 0) nex {\
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_init)\
			init_qtype_hash();\
		set(value);\
		is_ctor_lock = false; \
	}\
	__compelled_inline __stackcall ~__NAME__() nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		SECURE_ZERO_MEMORY((volatile void*)&_value, sizeof(_value)); \
	}\
	__compelled_inline __TYPE__ __stackcall get() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		auto value = _value.get();\
		qcipher_provider::cipher_decrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(__TYPE__));\
		value = *_value.open_data_ptr();\
		qcipher_provider::cipher_encrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(__TYPE__));\
		_value.close_data_ptr();\
		return value;\
	}\
	__compelled_inline bool __regcall set(imut __TYPE__ value) nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		*_value.open_data_ptr() = value;\
		qcipher_provider::cipher_encrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(__TYPE__));\
		return _value.close_data_ptr();\
	}\
	__compelled_inline imut c_void __stackcall open_data_ptr() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return _value.open_data_ptr();\
	}\
	__compelled_inline imut c_void __stackcall get_raw_memory_address() imut nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return imut_cast<__TYPE__*>(_value.get_raw_memory_address());\
	}\
	__compelled_inline __NAME__ __regcall operator+(imut __TYPE__ value) imut nex {\
		return __NAME__(get() + value);\
	};\
	__compelled_inline __NAME__ __regcall operator-(imut __TYPE__ value) imut nex {\
		return __NAME__(get() - value);\
	}\
	__compelled_inline __NAME__ __regcall operator/(imut __TYPE__ value) imut nex {\
		return __NAME__(get() / value);\
	}\
	__compelled_inline __NAME__ __regcall operator*(imut __TYPE__ value) imut nex {\
		return __NAME__(get() * value);\
	}\
	__compelled_inline __NAME__ __regcall operator&(imut __TYPE__ value) imut nex {\
		return __NAME__(get() & value);\
	}\
	__compelled_inline __NAME__ __regcall operator|(imut __TYPE__ value) imut nex {\
		return __NAME__(get() | value);\
	}\
	__compelled_inline __NAME__ __regcall operator%(imut __TYPE__ value) imut nex {\
		return __NAME__(get() % value);\
	}\
	__compelled_inline __NAME__ __regcall operator^(imut __TYPE__ value) imut nex {\
		return __NAME__(get() ^ value);\
	}\
	__compelled_inline __NAME__ __regcall operator<<(imut __TYPE__ value) imut nex {\
		return __NAME__(get() << value);\
	}\
	__compelled_inline __NAME__ __regcall operator>>(imut __TYPE__ value) imut nex {\
		return __NAME__(get() >> value);\
	}\
	__compelled_inline __NAME__& __regcall operator+=(imut __TYPE__ value) nex {\
		set(get() + value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator-=(imut __TYPE__ value) nex {\
		set(get() - value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator++() nex {\
		operator+=(1i8);\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator--() nex {\
		operator-=(1i8);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator*=(imut __TYPE__ value) nex {\
		set(get() * value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator/=(imut __TYPE__ value) nex {\
		set(get() / value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator%=(imut __TYPE__ value) nex {\
		set(get() % value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator^=(imut __TYPE__ value) nex {\
		set(get() ^ value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator&=(imut __TYPE__ value) nex {\
		set(get() & value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator|=(imut __TYPE__ value) nex {\
		set(get() | value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator<<=(imut __TYPE__ value) nex {\
		set(get() << value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator>>=(imut __TYPE__ value) nex {\
		set(get() >> value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator=(imut __TYPE__ value) nex {\
		set(value);\
		return *this;\
	}\
	__compelled_inline __NAME__(const __NAME__& other) noexcept : _value(NULL, true) { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false; \
		return *this; \
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept : _value(NULL, true) { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept { \
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false; \
		return *this; \
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex {\
		return get();\
	}\
};

#define QEXPAND_PRECISION_T(__NAME__, __TYPE__, __QTYPE__)\
class __NAME__ {\
private:\
	__QTYPE__ _value;\
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public:\
	__compelled_inline __fpcall __NAME__(imut __TYPE__ value = 0.f) nex {\
		if (!is_init)\
			init_qtype_hash();\
		set(value);\
		is_ctor_lock = false; \
	}\
	__optimized_dtor ~__NAME__() nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		SECURE_ZERO_MEMORY((volatile void*)&_value, sizeof(_value)); \
	}\
	__compelled_inline __TYPE__ __stackcall get() imut nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		auto value = _value.get();\
		qcipher_provider::cipher_decrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(__TYPE__));\
		value = *_value.open_data_ptr();\
		qcipher_provider::cipher_encrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(__TYPE__));\
		_value.close_data_ptr();\
		return value;\
	}\
	__compelled_inline bool __regcall set(imut __TYPE__ value) nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		*_value.open_data_ptr() = value;\
		qcipher_provider::cipher_encrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(__TYPE__));\
		return _value.close_data_ptr();\
	}\
	__compelled_inline imut c_void __stackcall open_data_ptr() imut nex {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return _value.open_data_ptr();\
	}\
	__compelled_inline imut c_void __stackcall get_raw_memory_address() imut nex {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return imut_cast<__TYPE__*>(_value.get_raw_memory_address());\
	}\
	__compelled_inline __NAME__ __regcall operator+(imut __TYPE__ value) imut nex {\
		return __NAME__(get() + value);\
	};\
	__compelled_inline __NAME__ __regcall operator-(imut __TYPE__ value) imut nex {\
		return __NAME__(get() - value);\
	}\
	__compelled_inline __NAME__ __regcall operator/(imut __TYPE__ value) imut nex {\
		return __NAME__(get() / value);\
	}\
	__compelled_inline __NAME__ __regcall operator*(imut __TYPE__ value) imut nex {\
		return __NAME__(get() * value);\
	}\
	__compelled_inline __NAME__& __regcall operator+=(imut __TYPE__ value) nex {\
		set(get() + value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator-=(imut __TYPE__ value) nex {\
		set(get() - value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator++() nex {\
		operator+=(1i8);\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator--() nex {\
		operator-=(1i8);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator*=(imut __TYPE__ value) nex {\
		set(get() * value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator/=(imut __TYPE__ value) nex {\
		set(get() / value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator=(imut __TYPE__ value) nex {\
		set(value);\
		return *this;\
	}\
	__compelled_inline __NAME__(const __NAME__& other) noexcept : _value(NULL, true) { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false; \
		return *this; \
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept : _value(NULL, true) { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept { \
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false; \
		return *this; \
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex {\
		return get();\
	}\
};

#else

#define QEXPAND_PRIMITIVE_T(__NAME__, __TYPE__, __QTYPE__)\
class __NAME__ {\
private:\
	__QTYPE__ _value;\
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public:\
	__optimized_ctor __NAME__(imut __TYPE__ value = 0) nex { \
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_init)\
			init_qtype_hash();\
		set(value);\
		is_ctor_lock = false; \
	}\
	__compelled_inline __stackcall ~__NAME__() nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		SECURE_ZERO_MEMORY((volatile void*)&_value, sizeof(_value)); \
	}\
	__compelled_inline __TYPE__ __stackcall get() imut nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		auto value = _value.get();\
		qcipher_provider::cipher_decrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(cmut<__TYPE__>));\
		value = _value.open_data_ptr()->get();\
		qcipher_provider::cipher_encrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(cmut<__TYPE__>));\
		_value.close_data_ptr();\
		return value;\
	}\
	__compelled_inline bool __regcall set(imut __TYPE__ value) nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value.open_data_ptr()->set(value);\
		qcipher_provider::cipher_encrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(cmut<__TYPE__>));\
		return _value.close_data_ptr();\
	}\
	__compelled_inline cmut<__TYPE__>* __stackcall open_data_ptr() imut nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return _value.open_data_ptr();\
	}\
	__compelled_inline cmut<__TYPE__>* __stackcall get_raw_memory_address() imut nex {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return imut_cast<cmut<__TYPE__>*>(_value.get_raw_memory_address());\
	}\
	__compelled_inline __NAME__ __regcall operator+(imut __TYPE__ value) imut nex {\
		return __NAME__(get() + value);\
	};\
	__compelled_inline __NAME__ __regcall operator-(imut __TYPE__ value) imut nex {\
		return __NAME__(get() - value);\
	}\
	__compelled_inline __NAME__ __regcall operator/(imut __TYPE__ value) imut nex {\
		return __NAME__(get() / value);\
	}\
	__compelled_inline __NAME__ __regcall operator*(imut __TYPE__ value) imut nex {\
		return __NAME__(get() * value);\
	}\
	__compelled_inline __NAME__ __regcall operator&(imut __TYPE__ value) imut nex {\
		return __NAME__(get() & value);\
	}\
	__compelled_inline __NAME__ __regcall operator|(imut __TYPE__ value) imut nex {\
		return __NAME__(get() | value);\
	}\
	__compelled_inline __NAME__ __regcall operator%(imut __TYPE__ value) imut nex {\
		return __NAME__(get() % value);\
	}\
	__compelled_inline __NAME__ __regcall operator^(imut __TYPE__ value) imut nex {\
		return __NAME__(get() ^ value);\
	}\
	__compelled_inline __NAME__ __regcall operator<<(imut __TYPE__ value) imut nex {\
		return __NAME__(get() << value);\
	}\
	__compelled_inline __NAME__ __regcall operator>>(imut __TYPE__ value) imut nex {\
		return __NAME__(get() >> value);\
	}\
	__compelled_inline __NAME__& __regcall operator+=(imut __TYPE__ value) nex {\
		set(get() + value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator-=(imut __TYPE__ value) nex {\
		set(get() - value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator++() nex {\
		operator+=(1i8);\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator--() nex {\
		operator-=(1i8);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator*=(imut __TYPE__ value) nex {\
		set(get() * value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator/=(imut __TYPE__ value) nex {\
		set(get() / value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator%=(imut __TYPE__ value) nex {\
		set(get() % value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator^=(imut __TYPE__ value) nex {\
		set(get() ^ value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator&=(imut __TYPE__ value) nex {\
		set(get() & value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator|=(imut __TYPE__ value) nex {\
		set(get() | value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator<<=(imut __TYPE__ value) nex {\
		set(get() << value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator>>=(imut __TYPE__ value) nex {\
		set(get() >> value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator=(imut __TYPE__ value) nex {\
		set(value);\
		return *this;\
	}\
	__compelled_inline __NAME__(const __NAME__& other) noexcept : _value(NULL, true) { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false; \
		return *this; \
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept : _value(NULL, true) { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept { \
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false; \
		return *this; \
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex {\
		return get();\
	}\
};

#define QEXPAND_PRECISION_T(__NAME__, __TYPE__, __QTYPE__)\
class __NAME__ {\
private:\
	__QTYPE__ _value;\
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public:\
	__compelled_inline __fpcall __NAME__(imut __TYPE__ value = 0.f) nex {\
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_init)\
			init_qtype_hash();\
		set(value);\
		is_ctor_lock = false; \
	}\
	__optimized_dtor ~__NAME__() nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		SECURE_ZERO_MEMORY((volatile void*)&_value, sizeof(_value)); \
	}\
	__compelled_inline __TYPE__ __stackcall get() imut nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		auto value = _value.get();\
		qcipher_provider::cipher_decrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(cmut<__TYPE__>));\
		value = _value.open_data_ptr()->get();\
		qcipher_provider::cipher_encrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(cmut<__TYPE__>));\
		_value.close_data_ptr();\
		return value;\
	}\
	__compelled_inline bool __regcall set(imut __TYPE__ value) nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value.open_data_ptr()->set(value);\
		qcipher_provider::cipher_encrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(cmut<__TYPE__>));\
		return _value.close_data_ptr();\
	}\
	__compelled_inline cmut<__TYPE__>* __stackcall open_data_ptr() imut nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return _value.open_data_ptr();\
	}\
	__compelled_inline cmut<__TYPE__>* __stackcall get_raw_memory_address() imut nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return imut_cast<cmut<__TYPE__>*>(_value.get_raw_memory_address());\
	}\
	__compelled_inline __NAME__ __regcall operator+(imut __TYPE__ value) imut nex {\
		return __NAME__(get() + value);\
	};\
	__compelled_inline __NAME__ __regcall operator-(imut __TYPE__ value) imut nex {\
		return __NAME__(get() - value);\
	}\
	__compelled_inline __NAME__ __regcall operator/(imut __TYPE__ value) imut nex {\
		return __NAME__(get() / value);\
	}\
	__compelled_inline __NAME__ __regcall operator*(imut __TYPE__ value) imut nex {\
		return __NAME__(get() * value);\
	}\
	__compelled_inline __NAME__& __regcall operator+=(imut __TYPE__ value) nex {\
		set(get() + value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator-=(imut __TYPE__ value) nex {\
		set(get() - value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator++() nex {\
		operator+=(1i8);\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator--() nex {\
		operator-=(1i8);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator*=(imut __TYPE__ value) nex {\
		set(get() * value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator/=(imut __TYPE__ value) nex {\
		set(get() / value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator=(imut __TYPE__ value) nex {\
		set(value);\
		return *this;\
	}\
	__compelled_inline __NAME__(const __NAME__& other) noexcept : _value(NULL, true) { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false; \
		return *this; \
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept : _value(NULL, true) { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept { \
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false; \
		return *this; \
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex {\
		return get();\
	}\
};

#endif

#define QEXPAND_VECTOR_T(__NAME__, __TYPE__, __STORE__, __QTYPE__)\
class __NAME__ {\
private:\
	__QTYPE__ _value;\
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public:\
	__optimized_ctor __NAME__(imut __TYPE__ value) nex : _value(value) {\
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_init)\
			init_qtype_hash();\
		set(value);\
		is_ctor_lock = false; \
	}\
	__compelled_inline __stackcall ~__NAME__() nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		SECURE_ZERO_MEMORY((volatile void*)&_value, sizeof(_value)); \
	}\
	__compelled_inline imut __TYPE__ __stackcall get() imut nex { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		auto value = _value.get();\
		qcipher_provider::cipher_decrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(__TYPE__));\
		value = _value.get();\
		qcipher_provider::cipher_encrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(__TYPE__));\
		_value.close_data_ptr();\
		return value;\
	}\
	__compelled_inline imut bool __regcall set(imut __TYPE__ value) nex {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		auto* buffer_ptr = _value.open_data_ptr();\
		__STORE__(reinterpret_cast<__TYPE__*>(buffer_ptr), value);\
		qcipher_provider::cipher_encrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(__TYPE__));\
		return _value.close_data_ptr();\
	}\
	__compelled_inline __TYPE__ __fpcall load(imut __TYPE__* value) nex { \
		if(!value) return {NULL}; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		set(*value); \
		return get(); \
	} \
	__compelled_inline imut bool __fpcall store(imut __TYPE__* value) nex { \
		if(!value) return false; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return set(*value); \
	} \
	__compelled_inline imut c_void __stackcall open_data_ptr() imut nex {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return _value.open_data_ptr();\
	}\
	__compelled_inline imut c_void __stackcall get_raw_memory_address() imut nex {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return _value.get_raw_memory_address();\
	}\
	__compelled_inline __NAME__& __fpcall operator=(imut __TYPE__ value) nex { \
		set(value); \
		return *this; \
	} \
	__compelled_inline __NAME__(const __NAME__& other) noexcept : _value({NULL}, true) { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept { \
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false; \
		return *this; \
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept : _value({NULL}, true) { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept { \
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false; \
		return *this; \
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex {\
		return get();\
	}\
};

#define QEXPAND_STRING_T(__NAME__, __TYPE__, __QTYPE__, __CHTYPE__, __PREFIX__)\
class __NAME__ {\
private:\
	__QTYPE__ _value;\
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public:\
	__compelled_inline __stackcall __NAME__(imut __TYPE__ value) nex { \
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_init)\
			init_qtype_hash();\
		set(value);\
		is_ctor_lock = false; \
	} \
	__optimized_ctor __NAME__(imut __CHTYPE__* value = __PREFIX__##"") { \
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_init)\
			init_qtype_hash();\
		set(value);\
		is_ctor_lock = false; \
	}\
	__compelled_inline __stackcall ~__NAME__() nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		SECURE_ZERO_MEMORY((volatile c_void)_value.get_raw_memory_address()->data(), _value.get_length()); \
		SECURE_ZERO_MEMORY((volatile c_void)&_value, sizeof(_value)); \
	}\
	__compelled_inline __TYPE__ __stackcall get() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		auto value = _value.get();\
		qcipher_provider::cipher_decrypt(imut_cast<__CHTYPE__*>(_value.open_data_ptr()), imut_cast<__CHTYPE__*>(_value.open_data_ptr()), _value.get().size() * sizeof(__CHTYPE__));\
		value = *_value.open_str_ptr();\
		qcipher_provider::cipher_encrypt(imut_cast<__CHTYPE__*>(_value.open_data_ptr()), imut_cast<__CHTYPE__*>(_value.open_data_ptr()), _value.get().size() * sizeof(__CHTYPE__));\
		_value.close_data_ptr();\
		return value;\
	}\
	__compelled_inline bool __stackcall set(imut __TYPE__ value) nex {\
		*_value.open_str_ptr() = value;\
		qcipher_provider::cipher_encrypt(imut_cast<__CHTYPE__*>(_value.open_data_ptr()), imut_cast<__CHTYPE__*>(_value.open_data_ptr()), _value.get().size() * sizeof(__CHTYPE__));\
		return _value.close_data_ptr();\
	}\
	__compelled_inline imut c_void __stackcall open_data_ptr() nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return imut_cast<__CHTYPE__*>(_value.open_data_ptr());\
	}\
	__compelled_inline imut __TYPE__* __stackcall get_raw_memory_address() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return _value.get_raw_memory_address();\
	}\
	__compelled_inline __NAME__ __stackcall operator+(imut __TYPE__& value) imut nex {\
		return __NAME__(get() + value);\
	}\
	__compelled_inline __NAME__& __stackcall operator+=(imut __TYPE__& value) nex {\
		set(get() + value);\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator=(imut __TYPE__ value) nex {\
		set(value);\
		return *this;\
	}\
	__compelled_inline __NAME__(const __NAME__& other) noexcept : _value(__PREFIX__##"", true) { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false; \
		return *this; \
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept : _value(__PREFIX__##"", true) { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept { \
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false; \
		return *this; \
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex {\
		return get();\
	}\
};

#pragma endregion

#pragma region Namespacing

namespace qengine {

	namespace qtype_enchash {

#pragma endregion

#pragma region Singleton 

		inline bool is_init = false;

#pragma endregion

#pragma region Static Methods

		// As of Now, only one Violation Callback is allowed for all Hash-Checked Objects (I can't see reason for there needing to be more than one, however if you find Reason / Need - leave feedback and I can Change this)
		__compelled_inline void __regcall set_violation_callback(qcallback::qmem_exception_rogue_c callback = qtype_hash::violation_callback_d) nex {

			if (is_init)
				return;

			qtype_hash::init_hash_t(callback);

			is_init = true;
		}

		__compelled_inline void __stackcall init_qtype_hash(qcallback::qmem_exception_rogue_c callback = qtype_hash::violation_callback_d) nex {

			if (is_init || qtype_hash::is_init)
				return;

			set_violation_callback(callback);
		}

#pragma endregion

#pragma region Types

#pragma region Template / User Defined

template<typename T>
class qeh_struct {

		private:

#pragma region Encrypted value

			qtype_hash::qh_struct<T> _value;

			mut std::recursive_mutex mtx;

			volatile bool is_ctor_lock = true;

#pragma endregion

		public:

#pragma region Ctor / Dtor

			__optimized_ctor qeh_struct(imut T value = T{}) nex {

				std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!is_init)
					init_qtype_hash();

				set(value);

				is_ctor_lock = false;
			}

			__compelled_inline __stackcall ~qeh_struct() nex {
				
				if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				SECURE_ZERO_MEMORY(&_value, sizeof(_value));
			}

#pragma endregion

#pragma region Accessors

			__compelled_inline imut T __stackcall get() imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				// Invoke get() accessor to memcmp checksums, as checksums are for ciphertext, this must happen before open_data_ptr() is called
				auto value = _value.get();

				qcipher_provider::cipher_decrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(T));

				value = *_value.open_data_ptr();

				qcipher_provider::cipher_encrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(T));

				_value.close_data_ptr();

				return value;
			}

			template<typename _T>
			__compelled_inline imut _T __regcall get(imut _T T::* member) imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				imut auto decrypted = get();

				return decrypted.*member;
			}

			__compelled_inline imut bool __regcall set(imut T value) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);
				
				*_value.open_data_ptr() = value;

				qcipher_provider::cipher_encrypt(_value.open_data_ptr(), _value.open_data_ptr(), sizeof(T));

				return _value.close_data_ptr();
			}

			template<typename _T>
			__compelled_inline imut bool __regcall set(_T T::* member, imut _T value) nex{

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				auto decrypted = get();

				decrypted.*member = value;

				return set(decrypted);
			}

			__compelled_inline imut c_void __stackcall open_data_ptr() imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				return _value.open_data_ptr();
			}

			__compelled_inline imut c_void __stackcall get_raw_memory_address() imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				return imut_cast<T*>(_value.get_raw_memory_address());
			}

#pragma endregion

#pragma region Operators

			__compelled_inline qeh_struct<T>& __regcall operator=(imut T value) nex {

				set(value);
				return *this;
			}

			__compelled_inline __stackcall operator T() imut nex {

				return get();
			}

#pragma endregion

#pragma region Deleted Ctors && Move-Copy Operators

			__compelled_inline qeh_struct(const qeh_struct<T>& other) noexcept {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);

				_value = other._value;

				is_ctor_lock = false;
			}

			__compelled_inline qeh_struct<T>& operator=(qeh_struct<T>& other) noexcept {

				if (this == &other) return *this;

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);

				_value = other._value;

				is_ctor_lock = false;

				return *this;
			}

			__compelled_inline qeh_struct(qeh_struct<T>&& other) noexcept {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				_value = std::move(other._value);

				is_ctor_lock = false;
			}

			__compelled_inline qeh_struct<T>& operator=(qeh_struct<T>&& other) noexcept {

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

QEXPAND_PRIMITIVE_T(qeh_int8, std::int8_t, qtype_hash::qh_int8);

QEXPAND_PRIMITIVE_T(qeh_uint8, std::uint8_t, qtype_hash::qh_uint8);

#pragma endregion

#pragma region 16-bit

QEXPAND_PRIMITIVE_T(qeh_int16, std::int16_t, qtype_hash::qh_int16);

QEXPAND_PRIMITIVE_T(qeh_uint16, std::uint16_t, qtype_hash::qh_uint16);

#pragma endregion

#pragma region 32-bit

QEXPAND_PRIMITIVE_T(qeh_int32, std::int32_t, qtype_hash::qh_int32);

QEXPAND_PRIMITIVE_T(qeh_uint32, std::uint32_t, qtype_hash::qh_uint32);

#pragma endregion

#pragma region 64-bit

QEXPAND_PRIMITIVE_T(qeh_int64, std::int64_t, qtype_hash::qh_int64);

QEXPAND_PRIMITIVE_T(qeh_uint64, std::uint64_t, qtype_hash::qh_uint64);

#pragma endregion

#pragma endregion

#pragma region Other Primitive Types
// This will define Unnecessary / Non-standard functions for Boolean - Just don't use them. No one adds / subs Booleans Anyways
QEXPAND_PRIMITIVE_T(qeh_bool, bool, qtype_hash::qh_bool);

#pragma endregion

#undef QEXPAND_PRIMITIVE_T

#pragma region Floating Point

#pragma region 32-bit

QEXPAND_PRECISION_T(qeh_float, float, qtype_hash::qh_float);

#pragma endregion

#pragma region 64-bit

QEXPAND_PRECISION_T(qeh_double, double, qtype_hash::qh_double);

QEXPAND_PRECISION_T(qeh_longdouble, long double, qtype_hash::qh_longdouble);

#pragma endregion

#pragma endregion

#undef QEXPAND_PRECISION_T

#pragma region Extended Types

#pragma region SSE2

QEXPAND_VECTOR_T(qeh_m128i, __m128i, _mm_store_si128, qtype_hash::qh_m128i);

#pragma endregion

#ifndef QDISABLE_EXTENDED_TYPES

#ifndef QDISABLE_AVX2_TYPES

#pragma region AVX2

QEXPAND_VECTOR_T(qeh_m256i, __m256i, _mm256_store_si256, qtype_hash::qh_m256i);

#pragma endregion

#endif

#ifndef QDISABLE_AVX512F_TYPES

#pragma region AVX512f

QEXPAND_VECTOR_T(qeh_m512i, __m512i, _mm512_store_si512, qtype_hash::qh_m512i);

#pragma endregion

#endif

#endif

#pragma endregion

#undef QEXPAND_VECTOR_T

#pragma region String Types

#pragma region String

QEXPAND_STRING_T(qeh_string, std::string, qtype_hash::qh_string, char, (const char*));

#pragma endregion

#pragma region Wide String

QEXPAND_STRING_T(qeh_wstring, std::wstring, qtype_hash::qh_wstring, wchar_t, L);

#pragma endregion

#undef QEXPAND_STRING_T

#pragma endregion

#pragma region Heap Allocation

		class qeh_malloc {

		private:

#pragma region Globals

			mut qtype_hash::qh_malloc allocation;

			mut std::recursive_mutex mtx;

			volatile bool is_ctor_lock = true;

#pragma endregion

#pragma region Subscript proxy

			// nested class to support subscript assignment
			class index_proxyEH {

			private:

#pragma region Globals

				qeh_malloc& parent;

				mut size_t index;

#pragma endregion

			public:
#pragma region Ctor

				index_proxyEH(std::size_t index_, qeh_malloc& instance) nex : index(index_), parent(instance) { }

#pragma endregion

#pragma region Operator overrides

				__compelled_inline std::uint8_t& operator=(std::uint8_t value) nex {

					parent.set(index, value);
					return value;   // return the passed assignment value rather than using up absurd resources to decrypt, re-encrypt everything using get()
				}

				__compelled_inline __regcall operator std::uint8_t() imut nex {

					return parent.get(index);
				}

#pragma endregion
			};

#pragma endregion

		public:

#pragma region Ctor

			__compelled_inline __regcall qeh_malloc( 
				
				imut std::size_t	len,

				imut c_void			src = nullptr
			
			) nex : allocation(len, src) {

				std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!len)
					return;

				if (!is_init)
					init_qtype_hash();

				if (!allocation.open_data_ptr())
					return;

				set(src, 0, len);

				is_ctor_lock = false;
			}

#pragma endregion

#pragma region Get Accessors

			__compelled_inline imut bool __regcall get(
				
				c_void dst,

				imut std::uintptr_t pos, 
								
				imut std::size_t len

			) imut nex {

				if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!dst || !len)
					return false;

				if (!qcipher_provider::cipher_decrypt_range(dst, allocation.open_data_ptr(), pos, len))
					return false;

				if (!qcipher_provider::cipher_encrypt_range(reinterpret_cast<std::uint8_t*>(allocation.open_data_ptr()) + pos, allocation.open_data_ptr(), pos, len))
					return false;

				return allocation.close_data_ptr();
			}

			__compelled_inline std::uint8_t __regcall get( imut std::uintptr_t pos ) imut nex {

				std::uint8_t rbyte = NULL;

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				get(&rbyte, pos, sizeof(std::uint8_t));

				return rbyte;
			}

			__compelled_inline imut c_void __stackcall get_raw_memory_address() imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				return allocation.get_raw_memory_address();
			}

#pragma endregion

#pragma region Set Accessors

			__compelled_inline imut bool __regcall set( 

				c_void src,
				
				imut std::uintptr_t pos, 
				
				imut std::size_t len
			
			) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!src || !len)
					return false;

				accelmem::a_memcpy(reinterpret_cast<std::uint8_t*>(allocation.open_data_ptr()) + pos, src, len);

				if (!qcipher_provider::cipher_encrypt_range(reinterpret_cast<std::uint8_t*>(allocation.open_data_ptr()) + pos, allocation.open_data_ptr(), pos, len))
					return false;

				return allocation.close_data_ptr();
			}

			template<typename T>
			__compelled_inline void __regcall set( imut std::uintptr_t pos, T value ) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				set(&value, pos, sizeof(decltype(value)));
			}

#pragma endregion

#pragma region Utility functions

			__compelled_inline void __regcall reallocate( imut std::size_t size ) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				allocation.reallocate(size);
			}

			__compelled_inline imut c_void open_data_ptr() nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				return allocation.open_data_ptr();
			}

#pragma endregion

#pragma region Operators

			__compelled_inline index_proxyEH __regcall operator[]( imut std::size_t index ) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				return index_proxyEH(index, *this);
			}

#pragma endregion

#pragma region Deleted Ctors && Move-Copy Operators

			__compelled_inline qeh_malloc(const qeh_malloc& other) noexcept : allocation(0u, nullptr, true) {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);

				allocation = other.allocation;

				is_ctor_lock = false;
			}
			__compelled_inline qeh_malloc& operator=(qeh_malloc& other) noexcept {

				if (this == &other) return *this;

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);

				allocation = other.allocation;

				is_ctor_lock = false;

				return *this;
			}
			__compelled_inline qeh_malloc(qeh_malloc&& other) noexcept : allocation(0u, nullptr, true) {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				allocation = std::move(other.allocation);

				is_ctor_lock = false;
			}
			__compelled_inline qeh_malloc& operator=(qeh_malloc&& other) noexcept {

				if (this == &other) return *this;

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				allocation = std::move(other.allocation);

				is_ctor_lock = false;

				return *this;
			}

#pragma endregion

#pragma region Destructor

			__compelled_inline ~qeh_malloc() nex {
				
				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);
			}

#pragma endregion
		};

#pragma endregion

#pragma region Extended Typedefs

	#ifdef _WIN64

			typedef qeh_uint64 qeh_uintptr_t;
			typedef qeh_uint64 qeh_size_t;

	#else

			typedef qeh_uint32 qeh_uintptr_t;
			typedef qeh_uint32 qeh_size_t;

	#endif

#pragma endregion

#pragma region Namespacing

	} 

}

#pragma endregion

#endif