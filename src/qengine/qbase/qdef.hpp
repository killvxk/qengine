#pragma region Header Guard

#ifndef QDEF_H
#define QDEF_H

#pragma endregion

#pragma region Imports

#pragma region Windows

#define NOMINMAX

#include <windows.h>
#include <Psapi.h>

#pragma endregion

#pragma region qengine

#include "../qimport/qimport.hpp"
#include "qcallback.hpp"
#include "qpreprocess.hpp"
#include "qstr.hpp"

#pragma endregion

#pragma endregion

#pragma region Preprocessor

#ifdef _MSC_VER

#define WINDOWS_IGNORE_PACKING_MISMATCH
#pragma warning(disable: 4700 4701 2362)

#endif

#pragma endregion

#pragma region Obfuscated Imports

/*
	If you are Weary of Runtime Imports due to your Target Application of qengine, you can Define QUSE_ITABLE_VIRTUALPROTECT to use the VirtualProtect Function Directly from the Windows API which Includes it in the 
	DiskImage Import / IDATA List
*/
#ifndef QUSE_ITABLE_VIRTUALPROTECT
inline const auto virtualprotect_rtImp_inst = qengine::qimport::qimp::get_fn_import_object<BOOL, LPVOID, SIZE_T, DWORD, DWORD*>(QSTR(L"kernel32.dll").get(), QSTR("VirtualProtect").get());
#else
inline const auto virtualprotect_rtImp_inst = VirtualProtect;
#endif

#pragma endregion

#pragma region Ulterior Qualifier / Type References

// I like Rust's syntax as far as the explicit qualifiers go, it's more verbose but it's explicit and clear

typedef void* c_void;

#define mut mutable

#define imut const

#define imutexpr constexpr

// It gets old retyping noexcept
#define nex noexcept

// Our intention in declaring many variables as volatile in qengine, is to prevent the addressing of the variables from being optimized into registers
// The polyc algorithm requires absolute allocation addressing currently, and moving these addresses into registers or copying creates engine-breaking problem(s)
#define noregister volatile

#define muteval volatile

// It makes zero sense for the language to state a const cast is occuring when no such thing is in reality, renaming to volatility cast for context
#define volatile_cast const_cast

// I am taking rusts theme and running with it, fuck off
#define imut_cast const_cast 

#pragma endregionss

#pragma region Polyc Algorithm Constants

static imut constexpr auto QCTIME_SEED = __TIME__[7];

#define BYTE_SET 0xFFui8

#ifdef _WIN64

#define BIT_SCRAMBLE 0x0F0F0F0F0F0F0F01ui64

#else

#define BIT_SCRAMBLE 0x0F0F0F0Fui32

#endif

#pragma endregion

#pragma region Method Attributes

#ifdef _MSC_VER

#define __fpcall __vectorcall // Only use __vectorcall for MSVC
#define __apicall __stdcall
#define __regcall __fastcall	//	pass up to two arguments through registers(?) if supported by OS bitwidth vs Variable type
#define __stackcall __cdecl		//	pass arguments on stack / no arguments contained allow caller to cleanup stack

#else

#define __fpcall // Define it as empty for other compilers like GCC
#define __fpcall 
#define __apicall 
#define __regcall
#define __stackcall

#endif

#if defined(_MSC_VER)
#define NO_INLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define NO_INLINE __attribute__((noinline))
#else
#define NO_INLINE
#endif

#define __symbolic NO_INLINE

#define __apicall __stdcall

#define __compelled_inline FORCE_INLINE	// compell function duplication / inlining and disable windows SEH 

#define _auto_type_ decltype(auto)	//	automatic type deduction for function returns

#define __optimized_ctor __compelled_inline __regcall	//	this forces compiler optimization depending on the argument list, IF the function can be inlined it will be which is arguably the least expensive calling method, however if the compiler fails yet to inline, the argument will be passed through registers if the arguments match the bitwidth of the operating system

#define __optimized_dtor __compelled_inline __stackcall

#define __inlineable inline	//	this is a suggestion, not a command. why was it included in the language standard as a commanding word that has garaunteed effect?

/* specify vectorcall if the project is compiled using extended types as this is better than fastcall for floating point objects */
#ifdef __SSE2__

#define __fpcall __vectorcall

#else

#define __fpcall __fastcall

#endif

#pragma endregion

#pragma endregion

#pragma region SEH Obfuscation

	//  Dereference a ring -3 pointer rather than call _CxxRaiseException() directly to avoid another import table entry
	//	Basic CXX exception handling callback obfuscation, call WINAPI_SEH_INIT(); at beginning of scope && WINAPI_SEH_END() or ';' at the end of the scope and it will be executed from a statically compiled SEH table entry for x86_64, or SEH handled on stack for x86
#define WINAPI_SEH_INIT() __try { static volatile int* __INVALID_REGION__ = 0x0u; *__INVALID_REGION__ = 0xFFFFFFFFui32; } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {

#define WINAPI_SEH_END() }

//	Allocate un un-allocatable amount of memory to force EH trigger
//	Basic CXX exception handling callback obfuscation, call CXX_EH_INIT(); at beginning of scope && CXX_EH_END() or ';' at the end of the scope and it will be executed from a statically compiled EH fn
#define CXX_EH_INIT() try { int* __INVALID_ALLOC__ = new int[(std::size_t)std::numeric_limits<std::size_t>::max]; } catch ( const std::bad_alloc& except ) { 

#define CXX_EH_END() } 

#pragma endregion 

#pragma region Inline Template FNs

/*
	Defining these as Functions / Lambdas Increases Versatility in Conditional's of POLYC128 and Increases Security
*/
imut auto lambda_rol_shl_byte = [](imut std::uint8_t& b1, imut std::uint16_t& b2) -> std::uint8_t {
	
	return rshl(b1, b2);
};

imut auto lambda_rol_shr_byte = [](imut std::uint8_t& b1, imut std::uint16_t& b2) -> std::uint8_t {
	
	return rshr(b1, b2);
};


template <typename T, typename T2>
static __compelled_inline imut T __regcall rol_shl(T base, T2 modifier) nex {

	return rshl(base, modifier);
}

template <typename T, typename T2>
static __compelled_inline imut T __regcall rol_shr(T base, T2 modifier) nex {

	return rshr(base, modifier);
}

#pragma endregion

#pragma region Macros

//#define __RAND__(_high_, _low_) ((rand() % _high_ + _low_))
#define __RAND__(_high_, _low_) ([]() -> std::uint32_t{ \
    auto ___R___ = (rand() % (_high_) + (_low_)); \
    return static_cast<std::uint32_t>(___R___ ? ___R___ : (_high_)); \
}())

#pragma region Memory

#define __XORBYTE__(_byte_, _xval_) for(auto _m_ = 0; _m_ < sizeof(decltype(_xval_)); ++_m_) _byte_ ^= reinterpret_cast<std::uint8_t*>(&_xval_)[_m_] 

#define __XORWORD__(_word_, __xval__) for(auto _n_ = 0; _n_ < sizeof(decltype(_word_)); ++_n_) __XORBYTE__( reinterpret_cast<std::uint8_t*>(&_word_)[_n_], __xval__ )

#pragma endregion

#pragma endregion

#pragma endregion

#endif