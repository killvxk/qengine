#pragma region Header Guard

#ifndef QTYPE_HASH_H
#define QTYPE_HASH_H

#pragma endregion

#pragma region Imports

#pragma region qengine

#include "../polytypes/qtype_enc.hpp"

#pragma endregion

#pragma endregion

#pragma region Class Expansion Macros


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
#ifndef QPRIMITIVE_TYPE_MUTATIONS

#define QEXPAND_PRIMITIVE_T(__NAME__, __TYPE__)\
class __NAME__ {\
private:\
	mut __TYPE__ _value = NULL;\
	mut std::uint32_t digest32 = NULL;\
	mut bool is_cipher_alteration = false;\
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public:\
	__optimized_ctor __NAME__(imut __TYPE__ value = 0, imut bool skip_ctor = false) nex : digest32(NULL), _value(NULL) {\
		if(skip_ctor){ is_ctor_lock = false; return; }\
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		if(!is_init)\
			init_hash_t();\
		set(value);\
		is_ctor_lock = false; \
	}\
	__optimized_dtor ~__NAME__() nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		VOLATILE_NULL(_value);\
		VOLATILE_NULL(digest32);\
		VOLATILE_NULL(is_cipher_alteration);\
	}\
	__compelled_inline __TYPE__* __stackcall open_data_ptr() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		is_cipher_alteration = true;\
		return volatile_cast<__TYPE__*>(&_value);\
	}\
	__compelled_inline imut bool __stackcall close_data_ptr() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		digest32 = qcipher_provider::hash_digest(&_value, sizeof(__TYPE__));\
		is_cipher_alteration = false;\
		return true;\
	}\
	__compelled_inline __TYPE__ __stackcall get() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_cipher_alteration) {\
			imut auto digest = qcipher_provider::hash_digest(&_value, sizeof(__TYPE__));\
			if (digest != digest32)\
				violation_callback(qengine::qexcept::q_rogueaccess(digest32, digest), &_value);\
		}\
		return _value;\
	}\
	__compelled_inline void __regcall set(imut __TYPE__ value) nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		digest32 = qcipher_provider::hash_digest(imut_cast<__TYPE__*>(&value), sizeof(__TYPE__));\
		_value = value;\
	}\
	__compelled_inline __TYPE__* __stackcall get_raw_memory_address() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return &_value;\
	}\
	__compelled_inline __NAME__ __regcall operator+(imut __TYPE__ value) imut nex {\
		return __NAME__(get() + value);\
	}\
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
		set(static_cast<__TYPE__>(get() + value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator-=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() - value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator++() nex {\
		operator+=(1);\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator--() nex {\
		operator-=(1);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator*=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() * value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator/=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() / value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator%=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() % value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator^=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() ^ value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator&=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() & value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator|=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() | value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator<<=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() << value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator>>=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() >> value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator=(imut __TYPE__ value) nex {\
		set(value);\
		return *this;\
	}\
	__compelled_inline __NAME__(const __NAME__& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
		digest32 = other.digest32; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
		digest32 = other.digest32; \
		return *this;\
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = std::move(other._value);\
		is_ctor_lock = false;\
		digest32 = std::move(other.digest32); \
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = std::move(other._value);\
		is_ctor_lock = false;\
		digest32 = std::move(other.digest32); \
		return *this;\
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex {\
		return get();\
	}; \
};

#define QEXPAND_PRECISION_T(__NAME__, __TYPE__)\
class __NAME__ {\
private:\
	mut __TYPE__ _value = 0.f;\
	mut std::uint32_t digest32;\
	mut bool is_cipher_alteration = false;\
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public:\
	__compelled_inline __fpcall __NAME__(imut __TYPE__ value = 0.0f, imut bool skip_ctor = false) nex : digest32(NULL), _value(NULL) {\
		if(skip_ctor){ is_ctor_lock = false; return; }\
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_init)\
			init_hash_t();\
		set(value);\
		is_ctor_lock = false; \
	}\
	__optimized_dtor ~__NAME__() nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		VOLATILE_NULL(_value);\
		VOLATILE_NULL(digest32);\
		VOLATILE_NULL(is_cipher_alteration);\
	}\
	__compelled_inline __TYPE__* __stackcall open_data_ptr() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		is_cipher_alteration = true;\
		return &_value;\
	}\
	__compelled_inline imut bool __stackcall close_data_ptr() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		digest32 = qcipher_provider::hash_digest(&_value, sizeof(__TYPE__));\
		is_cipher_alteration = false;\
		return true;\
	}\
	__compelled_inline __TYPE__ __stackcall get() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_cipher_alteration) {\
			imut auto digest = qcipher_provider::hash_digest(&_value, sizeof(__TYPE__));\
			if (digest != digest32)\
				violation_callback(qengine::qexcept::q_rogueaccess(digest32, digest), &_value);\
		}\
		return _value;\
	}\
	__compelled_inline void __regcall set(imut __TYPE__ value) nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		digest32 = qcipher_provider::hash_digest(imut_cast<__TYPE__*>(&value), sizeof(value));\
		_value = value;\
	}\
	__compelled_inline __TYPE__* __stackcall get_raw_memory_address() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return &_value;\
	}\
	__compelled_inline __NAME__ __fpcall operator+(imut __TYPE__ value) imut nex {\
		return __NAME__(get() + value);\
	}\
	__compelled_inline __NAME__ __fpcall operator-(imut __TYPE__ value) imut nex {\
		return __NAME__(get() - value);\
	}\
	__compelled_inline __NAME__ __fpcall operator/(imut __TYPE__ value) imut nex {\
		return __NAME__(get() / value);\
	}\
	__compelled_inline __NAME__ __fpcall operator*(imut __TYPE__ value) imut nex {\
		return __NAME__(get() * value);\
	}\
	__compelled_inline __NAME__& __fpcall operator+=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() + value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __fpcall operator-=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() - value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator++() nex {\
		operator+=(1.f);\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator--() nex {\
		operator-=(1.f);\
		return *this;\
	}\
	__compelled_inline __NAME__& __fpcall operator*=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() * value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __fpcall operator/=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() / value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __fpcall operator=(imut __TYPE__ value) nex {\
		set(value);\
		return *this;\
	}\
	__compelled_inline __NAME__(const __NAME__& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
		digest32 = other.digest32; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
		digest32 = other.digest32; \
		return *this;\
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = std::move(other._value);\
		is_ctor_lock = false;\
		digest32 = std::move(other.digest32); \
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = std::move(other._value);\
		is_ctor_lock = false;\
		digest32 = std::move(other.digest32); \
		return *this;\
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex {\
		return get();\
	}\
};

#else

#define QEXPAND_PRIMITIVE_T(__NAME__, __TYPE__)\
class __NAME__ {\
private:\
	cmut<__TYPE__> _value = NULL;\
	mut std::uint32_t digest32 = NULL;\
	mut bool is_cipher_alteration = false;\
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public:\
	__optimized_ctor __NAME__(imut __TYPE__ value = 0, imut bool skip_ctor = false) nex : digest32(NULL), _value(NULL) {\
		if(skip_ctor){ is_ctor_lock = false; return; }\
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		if(!is_init)\
			init_hash_t();\
		set(value);\
		is_ctor_lock = false; \
	}\
	__optimized_dtor ~__NAME__() nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		SECURE_ZERO_MEMORY(&_value, sizeof(cmut<__TYPE__>));\
		VOLATILE_NULL(digest32);\
		VOLATILE_NULL(is_cipher_alteration);\
	}\
	__compelled_inline cmut<__TYPE__>* __stackcall open_data_ptr() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		is_cipher_alteration = true;\
		return imut_cast<cmut<__TYPE__>*>(&_value);\
	}\
	__compelled_inline imut bool __stackcall close_data_ptr() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		digest32 = qcipher_provider::hash_digest(imut_cast<cmut<__TYPE__>*>(&_value), sizeof(cmut<__TYPE__>));\
		is_cipher_alteration = false;\
		return true;\
	}\
	__compelled_inline __TYPE__ __stackcall get() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_cipher_alteration) {\
			imut  auto digest = qcipher_provider::hash_digest(imut_cast<cmut<__TYPE__>*>(&_value), sizeof(cmut<__TYPE__>));\
			if (digest != digest32)\
				violation_callback(qengine::qexcept::q_rogueaccess(digest32, digest), imut_cast<cmut<__TYPE__>*>(&_value));\
		}\
		return imut_cast<cmut<__TYPE__>*>(&_value)->get();\
	}\
	__compelled_inline void __regcall set(imut __TYPE__ value) nex { \
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = value;\
		digest32 = qcipher_provider::hash_digest(imut_cast<cmut<__TYPE__>*>(&_value), sizeof(cmut<__TYPE__>));\
	}\
	__compelled_inline cmut<__TYPE__>* __stackcall get_raw_memory_address() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return imut_cast<cmut<__TYPE__>*>(&_value);\
	}\
	__compelled_inline __NAME__ __regcall operator+(imut __TYPE__ value) imut nex {\
		return __NAME__(get() + value);\
	}\
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
		set(static_cast<__TYPE__>(get() + value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator-=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() - value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator++() nex {\
		operator+=(1);\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator--() nex {\
		operator-=(1);\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator*=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() * value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator/=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() / value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator%=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() % value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator^=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() ^ value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator&=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() & value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator|=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() | value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator<<=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() << value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator>>=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() >> value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __regcall operator=(imut __TYPE__ value) nex {\
		set(value);\
		return *this;\
	}\
	__compelled_inline __NAME__(const __NAME__& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
		digest32 = other.digest32; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
		digest32 = other.digest32; \
		return *this;\
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = std::move(other._value);\
		is_ctor_lock = false;\
		digest32 = std::move(other.digest32); \
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = std::move(other._value);\
		is_ctor_lock = false;\
		digest32 = std::move(other.digest32); \
		return *this;\
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex {\
		return get();\
	}; \
};

#define QEXPAND_PRECISION_T(__NAME__, __TYPE__)\
class __NAME__ {\
private:\
	cmut<__TYPE__> _value = 0.f;\
	mut std::uint32_t digest32 = NULL;\
	mut bool is_cipher_alteration = false;\
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public:\
	__compelled_inline __fpcall __NAME__(imut __TYPE__ value = 0.0f, imut bool skip_ctor = false) nex : digest32(NULL), _value(NULL) {\
		if(skip_ctor){ is_ctor_lock = false; return; }\
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_init)\
			init_hash_t();\
		set(value);\
		is_ctor_lock = false; \
	}\
	__optimized_dtor ~__NAME__() nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		SECURE_ZERO_MEMORY(&_value, sizeof(cmut<__TYPE__>));\
		VOLATILE_NULL(digest32);\
		VOLATILE_NULL(is_cipher_alteration);\
	}\
	__compelled_inline cmut<__TYPE__>* __stackcall open_data_ptr() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		is_cipher_alteration = true;\
		return imut_cast<cmut<__TYPE__>*>(&_value);\
	}\
	__compelled_inline imut bool __stackcall close_data_ptr() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		digest32 = qcipher_provider::hash_digest(imut_cast<cmut<__TYPE__>*>(&_value), sizeof(cmut<__TYPE__>));\
		is_cipher_alteration = false;\
		return true;\
	}\
	__compelled_inline __TYPE__ __stackcall get() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_cipher_alteration) {\
			imut  auto digest = qcipher_provider::hash_digest(imut_cast<cmut<__TYPE__>*>(&_value), sizeof(cmut<__TYPE__>));\
			if (digest != digest32)\
			violation_callback(qengine::qexcept::q_rogueaccess(digest32, digest), imut_cast<cmut<__TYPE__>*>(&_value));\
		}\
		return imut_cast<cmut<__TYPE__>*>(&_value)->get();\
	}\
	__compelled_inline void __regcall set(imut __TYPE__ value) nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = value;\
		digest32 = qcipher_provider::hash_digest(imut_cast<cmut<__TYPE__>*>(&_value), sizeof(cmut<__TYPE__>));\
	}\
	__compelled_inline cmut<__TYPE__>* __stackcall get_raw_memory_address() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return imut_cast<cmut<__TYPE__>*>(&_value);\
	}\
	__compelled_inline __NAME__ __fpcall operator+(imut __TYPE__ value) imut nex {\
		return __NAME__(get() + value);\
	}\
	__compelled_inline __NAME__ __fpcall operator-(imut __TYPE__ value) imut nex {\
		return __NAME__(get() - value);\
	}\
	__compelled_inline __NAME__ __fpcall operator/(imut __TYPE__ value) imut nex {\
		return __NAME__(get() / value);\
	}\
	__compelled_inline __NAME__ __fpcall operator*(imut __TYPE__ value) imut nex {\
		return __NAME__(get() * value);\
	}\
	__compelled_inline __NAME__& __fpcall operator+=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() + value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __fpcall operator-=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() - value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator++() nex {\
		operator+=(1.f);\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator--() nex {\
		operator-=(1.f);\
		return *this;\
	}\
	__compelled_inline __NAME__& __fpcall operator*=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() * value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __fpcall operator/=(imut __TYPE__ value) nex {\
		set(static_cast<__TYPE__>(get() / value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __fpcall operator=(imut __TYPE__ value) nex {\
		set(value);\
		return *this;\
	}\
	__compelled_inline __NAME__(const __NAME__& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
		digest32 = other.digest32; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		_value = other._value;\
		is_ctor_lock = false;\
		digest32 = other.digest32; \
		return *this;\
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = std::move(other._value);\
		is_ctor_lock = false;\
		digest32 = std::move(other.digest32); \
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		_value = std::move(other._value);\
		is_ctor_lock = false;\
		digest32 = std::move(other.digest32); \
		return *this;\
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex {\
		return get();\
	}\
};

#endif

#define QEXPAND_VECTOR_T(__NAME__, __TYPE__, __LOAD__, __STORE__)\
class __NAME__ {\
private:\
	alignas(sizeof(__TYPE__)) mut noregister std::uint8_t _value[sizeof(__TYPE__)]{NULL};\
	mut std::uint32_t digest32 = NULL;\
	mut bool is_cipher_alteration = false;\
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public:\
	__compelled_inline __fpcall __NAME__(imut __TYPE__ value, imut bool skip_ctor = false) nex : digest32(NULL) {\
		if(skip_ctor){ is_ctor_lock = false; return; }\
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_init)\
			init_hash_t();\
		set(value);\
		is_ctor_lock = false; \
	}\
	__optimized_dtor ~__NAME__() nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		SECURE_ZERO_MEMORY(_value, sizeof(__TYPE__));\
		VOLATILE_NULL(digest32);\
		VOLATILE_NULL(is_cipher_alteration);\
	}\
	__compelled_inline std::uint8_t* __stackcall open_data_ptr() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		is_cipher_alteration = true;\
		return (std::uint8_t*)_value;\
	}\
	__compelled_inline imut bool __stackcall close_data_ptr() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		digest32 = qcipher_provider::hash_digest((std::uint8_t*)_value, sizeof(__TYPE__));\
		is_cipher_alteration = false;\
		return true;\
	}\
	__compelled_inline __TYPE__ __stackcall get() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_cipher_alteration) {\
			auto digest = qcipher_provider::hash_digest((c_void)(_value), sizeof(_value));\
			if (digest != digest32)\
				violation_callback(qengine::qexcept::q_rogueaccess(digest32, digest), (c_void)_value);\
		}\
		return __LOAD__((__TYPE__*)_value);\
	}\
	__compelled_inline void __fpcall set(imut __TYPE__ value) {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		__STORE__((__TYPE__*)_value, value);\
		digest32 = qcipher_provider::hash_digest((c_void)_value, sizeof(__TYPE__));\
	}\
	__compelled_inline std::uint8_t* __stackcall get_raw_memory_address() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return (std::uint8_t*)_value;\
	}\
	__compelled_inline __TYPE__ __fpcall load(imut __TYPE__* value) nex { \
		if(!value) return {NULL}; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		__STORE__((__TYPE__*)_value, *value); \
		return *value; \
	} \
	__compelled_inline imut bool __fpcall store(imut __TYPE__* value) nex { \
		if(!value) return false; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		__STORE__((__TYPE__*)_value, *value); \
		return true; \
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
		digest32 = other.digest32; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);\
		std::memcpy((void*)_value, (void*)other._value, sizeof(__TYPE__)); \
		is_ctor_lock = false;\
		digest32 = other.digest32; \
		return *this;\
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept {\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		std::memcpy((void*)_value, (void*)other._value, sizeof(__TYPE__)); \
		is_ctor_lock = false;\
		digest32 = std::move(other.digest32); \
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept {\
		if (this == &other) return *this;\
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);\
		std::memcpy((void*)_value, (void*)other._value, sizeof(__TYPE__)); \
		is_ctor_lock = false;\
		digest32 = std::move(other.digest32); \
		return *this;\
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex {\
		return get();\
	}\
};

#define QEXPAND_STRING_T(__NAME__, __TYPE__, __CHTYPE__, __PREFIX__)\
class __NAME__ {\
private:\
	mut __TYPE__ _value = __PREFIX__##"";\
	mut std::uint32_t digest32 = NULL;\
	mut bool is_cipher_alteration = false;\
	mut std::recursive_mutex mtx; \
	volatile bool is_ctor_lock = true; \
public:\
	__compelled_inline __stackcall __NAME__(imut __TYPE__ value, imut bool skip_ctor = false) nex : digest32(NULL), _value(__PREFIX__##"") {\
		if(skip_ctor){ is_ctor_lock = false; return; }\
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_init)\
			init_hash_t();\
		set(value);\
		is_ctor_lock = false; \
	}\
	__optimized_ctor __NAME__(imut __CHTYPE__* value = __PREFIX__##"", imut bool skip_ctor = false) nex : digest32(NULL), _value(__PREFIX__##"") {\
		if(skip_ctor){ is_ctor_lock = false; return; }\
		std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_init)\
			init_hash_t();\
		set(__TYPE__(value));\
		is_ctor_lock = false; \
	}\
	__optimized_dtor ~__NAME__() nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		SECURE_ZERO_MEMORY(imut_cast<__CHTYPE__*>(this->_value.c_str()), _value.size() * sizeof(__CHTYPE__));\
		VOLATILE_NULL(digest32);\
		VOLATILE_NULL(is_cipher_alteration);\
	}\
	__compelled_inline __TYPE__* __stackcall open_str_ptr() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		is_cipher_alteration = true;\
		return &_value;\
	}\
	__compelled_inline imut __CHTYPE__* __stackcall open_data_ptr() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		is_cipher_alteration = true;\
		return _value.c_str();\
	}\
	__compelled_inline bool __stackcall close_data_ptr() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		digest32 = qcipher_provider::hash_digest(imut_cast<__CHTYPE__*>(_value.c_str()), _value.size() * sizeof(__CHTYPE__));\
		is_cipher_alteration = false;\
		return true;\
	}\
	__compelled_inline __TYPE__ __stackcall get() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!is_cipher_alteration) {\
			imut auto digest = qcipher_provider::hash_digest(imut_cast<__CHTYPE__*>(_value.c_str()), _value.size() * sizeof(__CHTYPE__));\
			if (digest != digest32)\
				violation_callback(qengine::qexcept::q_rogueaccess(digest32, digest), reinterpret_cast<c_void>(&_value));\
		}\
		return _value;\
	}\
	__compelled_inline imut std::size_t __stackcall get_length() nex{\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return _value.size() * sizeof(__CHTYPE__);\
	} \
	__compelled_inline void __stackcall set(imut __TYPE__ value) nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		digest32 = qcipher_provider::hash_digest(imut_cast<__CHTYPE__*>(value.c_str()), value.size() * sizeof(__CHTYPE__));\
		_value = value;\
	}\
	__compelled_inline __TYPE__* __stackcall get_raw_memory_address() imut nex {\
		if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		return &_value;\
	}\
	__compelled_inline __NAME__ __stackcall operator+(imut __TYPE__& value) imut nex {\
		return __NAME__(get() + value);\
	}\
	__compelled_inline __NAME__& __stackcall operator+=(imut __TYPE__& value) nex {\
		set(static_cast<__TYPE__>(get() + value));\
		return *this;\
	}\
	__compelled_inline __NAME__& __stackcall operator=(imut __TYPE__ value) nex {\
		set(value);\
		return *this;\
	}\
	__compelled_inline __NAME__(const __NAME__& other) noexcept { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false; \
		digest32 = other.digest32; \
	}\
	__compelled_inline __NAME__& operator=(__NAME__& other) noexcept {\
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx); \
		_value = other._value; \
		is_ctor_lock = false;\
		digest32 = other.digest32; \
		return *this; \
	}\
	__compelled_inline __NAME__(__NAME__&& other) noexcept { \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false;\
		digest32 = std::move(other.digest32); \
	}\
	__compelled_inline __NAME__& operator=(__NAME__&& other) noexcept { \
		if (this == &other) return *this; \
		if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx); \
		_value = std::move(other._value);\
		is_ctor_lock = false;\
		digest32 = std::move(other.digest32); \
		return *this; \
	}\
	__compelled_inline __stackcall operator __TYPE__() imut nex {\
		return get();\
	}\
};

#pragma endregion

namespace qengine {

	namespace qtype_hash {

#pragma region Globals

		extern noregister qengine::qcallback::qmem_exception_rogue_c violation_callback;

		extern bool is_init;

#pragma endregion

#pragma region Global Static Methods / Callbacks

		// This is the Default Template for a Callback to Process Tampering / Access Violations; It simply Checks to Ensure the Callback Reason is Memory Alteration, and then Returns to Caller
		static __symbolic void __regcall violation_callback_d(qengine::qexcept::q_rogueaccess except, c_void data) nex {

			if (except.id != qengine::qexcept::MEMORY_ALTERATION) // ensure this callback has been raised due to memory alteration
				return;
		}

		static __compelled_inline void __regcall set_violation_callback(qengine::qcallback::qmem_exception_rogue_c callback = violation_callback_d) nex {

			violation_callback = callback;

			is_init = true;
		}

		static __compelled_inline void __regcall init_hash_t(qengine::qcallback::qmem_exception_rogue_c callback = violation_callback_d) nex {

			set_violation_callback(callback);
		}

#pragma endregion

#pragma region Types

#pragma region Template / User-Defined

template<typename T>
class qh_struct{

		private:

	#pragma region Globals

			mut T _value;

			mut std::uint32_t digest32;

			mut bool is_cipher_alteration = false;

			mut std::recursive_mutex mtx;

			volatile bool is_ctor_lock = true;

	#pragma endregion

		public:

	#pragma region Ctor / Dtor

			__optimized_ctor qh_struct( imut T value = T{} , imut bool skip_ctor = false) nex {

				if (skip_ctor) {

					is_ctor_lock = false;

					return;
				}

				std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!is_init)
					init_hash_t();

				set(value);

				is_ctor_lock = false;
			}

			__optimized_dtor ~qh_struct() nex {
			
				if(!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				SECURE_ZERO_MEMORY(volatile_cast<T*>(&this->_value), sizeof(T));
				VOLATILE_NULL(digest32);
				VOLATILE_NULL(is_cipher_alteration);
			}
			
	#pragma endregion

	#pragma region Accessors

			__compelled_inline T* __stackcall open_data_ptr() imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				is_cipher_alteration = true;

				return &_value;
			}

			__compelled_inline imut bool __stackcall close_data_ptr() imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				digest32 = qcipher_provider::hash_digest(&_value, sizeof(T));

				is_cipher_alteration = false;

				return true;
			}

			__compelled_inline imut T __stackcall get() imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!is_cipher_alteration) {

					auto _digest32 = qcipher_provider::hash_digest(&_value, sizeof(T));

					if (_digest32 != digest32)
						violation_callback(qengine::qexcept::q_rogueaccess(digest32, _digest32), &_value);
				}

				return _value;
			}

			template<typename _T>
			__compelled_inline decltype(auto) __regcall get( _T T::* member ) imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!is_cipher_alteration) {

					auto _digest32 = qcipher_provider::hash_digest(&_value, sizeof(T));

					if (_digest32 != digest32)
						violation_callback(qengine::qexcept::q_rogueaccess(digest32, _digest32), &_value);
				}

				return _value.*member;
			}

			__compelled_inline void __regcall set( imut T value ) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				digest32 = qcipher_provider::hash_digest( imut_cast<T*>(&value), sizeof(T));

				_value = value;
			}

			template<typename _T>
			__compelled_inline imut bool __regcall set( _T T::* member, imut _T value ) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				_value.*member = std::move(value);

				digest32 = qcipher_provider::hash_digest(volatile_cast<T*>(&_value), sizeof(T));

				return true;
			}

			__compelled_inline T* __stackcall get_raw_memory_address() imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				return &_value;
			}

	#pragma endregion

	#pragma region Operators

			__compelled_inline qh_struct& __regcall operator=(imut T value) nex {
				set(value);
				return *this;
			}

			__compelled_inline __stackcall operator T() imut nex {
				return get();
			}

	#pragma endregion

#pragma region Deleted Ctors && Move-Copy Operators

			__compelled_inline qh_struct(const qh_struct<T>& other) noexcept {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);

				_value = other._value;

				is_ctor_lock = false;

				digest32 = other.digest32;
			}

			__compelled_inline qh_struct<T>& operator=(qh_struct<T>& other) noexcept {

				if (this == &other) return *this;

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);

				_value = other._value;

				is_ctor_lock = false;

				digest32 = other.digest32;

				return *this;
			}

			__compelled_inline qh_struct(qh_struct<T>&& other) noexcept {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				_value = std::move(other._value);

				is_ctor_lock = false;

				digest32 = std::move(other.digest32);
			}

			__compelled_inline qh_struct<T>& operator=(qh_struct<T>&& other) noexcept {

				if (this == &other) return *this;

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				_value = std::move(other._value);

				is_ctor_lock = false;

				digest32 = std::move(other.digest32);

				return *this;
			}

#pragma endregion

		};

#pragma endregion

#pragma region Primitive

#pragma region 8-bit

		QEXPAND_PRIMITIVE_T(qh_int8, std::int8_t);

		QEXPAND_PRIMITIVE_T(qh_uint8, std::uint8_t);

#pragma endregion

#pragma region 16-bit

		QEXPAND_PRIMITIVE_T(qh_int16, std::int16_t);

		QEXPAND_PRIMITIVE_T(qh_uint16, std::uint16_t);

#pragma endregion

#pragma region 32-bit

		QEXPAND_PRIMITIVE_T(qh_int32, std::int32_t);
		QEXPAND_PRIMITIVE_T(qh_uint32, std::uint32_t);

#pragma endregion

#pragma region 64-bit

		QEXPAND_PRIMITIVE_T(qh_int64, std::int64_t);

		QEXPAND_PRIMITIVE_T(qh_uint64, std::uint64_t);

#pragma endregion

#pragma endregion

#pragma region Other Primitive Types

QEXPAND_PRIMITIVE_T(qh_bool, bool);

#pragma endregion

#undef QEXPAND_PRIMITIVE_T

#pragma region Floating Point

#pragma region 32-bit

QEXPAND_PRECISION_T(qh_float, float);

#pragma endregion

#pragma region 64-bit

QEXPAND_PRECISION_T(qh_double, double);

QEXPAND_PRECISION_T(qh_longdouble, long double);

#pragma endregion

#pragma endregion

#undef QEXPAND_PRECISION_T

#pragma region Extended Types

#pragma region SSE2

QEXPAND_VECTOR_T(qh_m128i, __m128i, _mm_load_si128, _mm_store_si128);

#pragma endregion

#ifndef QDISABLE_EXTENDED_TYPES

#ifndef QDISABLE_AVX2_TYPES

#pragma region AVX2

QEXPAND_VECTOR_T(qh_m256i, __m256i, _mm256_load_si256, _mm256_store_si256);

#pragma endregion

#endif

#ifndef QDISABLE_AVX512F_TYPES

#pragma region AVX512f

QEXPAND_VECTOR_T(qh_m512i, __m512i, _mm512_load_si512, _mm512_store_si512);

#pragma endregion

#endif

#pragma endregion

#endif

#pragma endregion

#undef QEXPAND_VECTOR_T

#pragma region String Types

#pragma region String

QEXPAND_STRING_T(qh_string, std::string, char, (const char*));

#pragma endregion

#pragma region Wide String

QEXPAND_STRING_T(qh_wstring, std::wstring, wchar_t, L);
		
#pragma endregion

#pragma endregion

#undef QEXPAND_STRING_T

#pragma region Heap Allocation

		class qh_malloc {

		private:

#pragma region Globals

			mut c_void local_alloc;

			mut size_t alloc_len;

			mut std::uint32_t digest32;

			mut bool is_cipher_alteration;

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

#pragma region Subscript proxy

			// nested class to support subscript assignment
			class index_proxyH {

			private:

#pragma region Globals

				qh_malloc& parent;

				std::size_t index;

#pragma endregion

			public:
			
#pragma region Ctor

				index_proxyH(imut std::size_t index_, qh_malloc& instance) : index(index_), parent(instance) { }

#pragma endregion

#pragma region Operator overrides

				__compelled_inline std::uint8_t& __regcall operator=(std::uint8_t value) nex {
					parent.set(index, value);
					return value;   // return the passed assignment value rather than using up absurd resources to decrypt, re-encrypt everything using get()
				}

				__compelled_inline __stackcall operator std::uint8_t() imut nex {
					return parent.get(index);
				}

#pragma endregion
			};

#pragma endregion

		public:

#pragma region Ctor

			__compelled_inline __regcall qh_malloc(
				
				imut std::size_t len, 
				
				imut c_void src = nullptr,

				imut bool skip_ctor = false
			
			) nex : alloc_len(len), local_alloc(malloc(len)) {

				if (skip_ctor) {

					is_ctor_lock = false;

					return;
				}

				std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!len || !local_alloc)
					return;

				if (!is_init)
					init_hash_t();

				set(src, 0, len);

				is_ctor_lock = false;
			}

#pragma endregion

#pragma region Get / Set

			__compelled_inline imut c_void __stackcall open_data_ptr() imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				is_cipher_alteration = true;

				return local_alloc;
			}

			__compelled_inline imut bool __stackcall close_data_ptr() imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				digest32 = qcipher_provider::hash_digest(local_alloc, alloc_len);

				is_cipher_alteration = false;

				return true;
			}

			__compelled_inline imut bool __regcall get(
				
				c_void dst, 
				
				imut std::uintptr_t pos, 
				
				imut std::size_t len
			
			) imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!local_alloc || !dst || alloc_len < (pos + len))
					return false;

				if (!is_cipher_alteration) {

					auto _digest32 = qcipher_provider::hash_digest(local_alloc, alloc_len);

					if (_digest32 != digest32) {

						violation_callback(qengine::qexcept::q_rogueaccess(digest32, _digest32), local_alloc);
						return false;
					}
				}

				accelmem::a_memcpy(
					
					dst,

					reinterpret_cast<std::uint8_t*>(local_alloc) + pos,

					len
				);

				return true;
			}

			__compelled_inline std::uint8_t __regcall get(imut std::uintptr_t index) nex {

				std::uint8_t rbyte = 0x0u;

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!get(&rbyte, index, sizeof(std::uint8_t)))
					return 0x0u; // Handle failure case  

				return rbyte;
			}

			__compelled_inline imut bool __regcall set(
				
				c_void src, 
				
				std::uintptr_t pos, 
				
				std::size_t len
			
			) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!local_alloc || !src || alloc_len < (pos + len))
					return false;

				accelmem::a_memcpy(reinterpret_cast<c_void>(reinterpret_cast<std::uint8_t*>(local_alloc) + pos), src, len);

				digest32 = qcipher_provider::hash_digest(local_alloc, alloc_len);

				return true;
			}


			template <typename T>
			__compelled_inline imut bool __regcall set( 
				
				imut std::uintptr_t pos,
				
				imut T value
			
			) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!set(imut_cast<T*>(&value), pos, sizeof(T)))
					return false;

				return true;
			}

			__compelled_inline imut bool __regcall _memset(

				imut std::uintptr_t pos,

				imut std::size_t len,

				imut std::uint8_t value

			) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!len || (alloc_len < pos + len))
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

#pragma endregion

#pragma region Property Accessors

			__compelled_inline std::size_t __stackcall length() imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				return alloc_len;
			}

			__compelled_inline c_void __stackcall get_raw_memory_address() imut nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				return local_alloc;
			}

#pragma endregion

#pragma region Utility functions

			__compelled_inline imut bool __stackcall zero() nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				return _memset(0, alloc_len, 0x0u);
			}

			__compelled_inline imut bool __regcall reallocate(std::size_t len) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!len)
					return false;

				c_void ralloc = realloc(local_alloc, len);
				
				if (!ralloc)
					return false;

				if (ralloc != local_alloc)
					local_alloc = std::move(ralloc);

				alloc_len = len;

				return true;
			}

#pragma endregion

#pragma region Operators

			__compelled_inline index_proxyH __regcall operator[](std::size_t index) nex {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				return index_proxyH(index, *this);
			}

#pragma endregion

#pragma region Deleted Ctors && Move-Copy Operators

			__compelled_inline qh_malloc(const qh_malloc& other) noexcept {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);

				local_alloc = malloc(other.alloc_len);

				alloc_len = other.alloc_len;

				is_ctor_lock = false;
			}
			__compelled_inline qh_malloc& operator=(qh_malloc& other) noexcept {

				if (this == &other) return *this;

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				if (!other.is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(other.mtx);

				local_alloc = malloc(other.alloc_len);

				alloc_len = other.alloc_len;

				is_ctor_lock = false;

				return *this;
			}
			__compelled_inline qh_malloc(qh_malloc&& other) noexcept {

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				local_alloc = std::move(other.local_alloc);

				alloc_len = std::move(other.alloc_len);

				is_ctor_lock = false;
			}
			__compelled_inline qh_malloc& operator=(qh_malloc&& other) noexcept {

				if (this == &other) return *this;

				if (!is_ctor_lock) std::lock_guard<std::recursive_mutex> lock(mtx);

				local_alloc = std::move(other.local_alloc);

				alloc_len = std::move(other.alloc_len);

				is_ctor_lock = false;

				return *this;
			}

#pragma endregion

#pragma region Destructor

			__compelled_inline __stackcall ~qh_malloc() nex {

				if (!local_alloc || !alloc_len)
					return;

				SECURE_ZERO_MEMORY(local_alloc, alloc_len);

				VOLATILE_NULL(alloc_len);

				free(local_alloc);
			}

#pragma endregion
		};

#pragma endregion

#pragma region Extended Typedefs

	#ifdef _WIN64

			typedef qh_uint64 qh_uintptr_t;
			typedef qh_uint64 qh_size_t;

	#else

			typedef qh_uint32 qh_uintptr_t;
			typedef qh_uint32 qh_size_t;

	#endif

#pragma endregion

	}  

#pragma region Static Declarators

	noregister	qcallback::qmem_exception_rogue_c qengine::qtype_hash::violation_callback;

	bool		qengine::qtype_hash::is_init = false;

#pragma endregion
} 

#endif