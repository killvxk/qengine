#pragma region Header Guard

#ifndef QIMPORT_H
#define QIMPORT_H

#pragma endregion

#pragma region Imports

#pragma region Operating System

#define NOMINMAX // Prevents Windows headers from defining min/max macros that can conflict with std::min/std::max
#include <windows.h> // Windows API for dynamic library loading and function resolution

#pragma endregion

#pragma region std

#include <string> // Provides std::string and std::wstring for string handling

#pragma endregion

#pragma region External 

#include "../extern/cmut/cmut.hxx"

#pragma endregion

#pragma endregion

namespace qengine {

	namespace qimport {

#pragma region Type Definitions

// string_t is defined as std::wstring if _UNICODE is set, otherwise std::string
#ifdef _UNICODE 
		typedef std::wstring string_t; // Wide string for Unicode builds
#else
		typedef std::string string_t; // Narrow string for ANSI builds
#endif

#pragma endregion

		// qimp: Provides static methods for dynamic DLL function invocation
		class qimp {

		private:

			// Internal function invocation helper
			// Casts a function pointer (by address) to the correct type and calls it with arguments
			// T: Return type, args: Argument types
			template<typename T, typename... args>
			static inline T __stdcall invoke_internal(std::uintptr_t fn, args... arguments) noexcept {
				// The function pointer is cast to the correct type and called with the provided arguments.
				// cmut is used to wrap the function pointer for possible mutation/obfuscation.
				return static_cast<T>(reinterpret_cast<T(WINAPI*)(args...)>(reinterpret_cast<void*>(cmut<std::uintptr_t>(fn).get()))(arguments...));
			}

		public:

			// Invoke a function from a DLL by name
			// T: Return type, args: Argument types
			// library_name: Name of the DLL (string_t)
			// fn_str: Name of the function (std::string)
			// arguments: Arguments to pass to the function
			template<typename T, typename... args>
			static inline T __stdcall invoke(const string_t library_name, const std::string fn_str, args... arguments) noexcept {
				// Load the DLL into the process address space. Returns a handle to the module.
				const auto handle = LoadLibrary(library_name.c_str());
				// Get the address of the function by name from the loaded module.
				const auto fn = GetProcAddress(handle, fn_str.c_str());
				// Call the function using the internal helper, forwarding all arguments.
#ifdef QPRIMITIVE_TYPE_MUTATIONS
				return invoke_internal<T>(cmut<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(fn)).get(), arguments...);
#else
				return invoke_internal<T>(reinterpret_cast<std::uintptr_t>(fn), arguments...);
#endif
			}

			// Invoke a function from a DLL by ordinal number
			// T: Return type, args: Argument types
			// library_name: Name of the DLL (string_t)
			// ordinal_number: Ordinal number of the function
			// arguments: Arguments to pass to the function
			template<typename T, typename... args>
			static inline T __stdcall invoke(const string_t library_name, const std::uint16_t ordinal_number, args... arguments) noexcept {
				// Load the DLL into the process address space. Returns a handle to the module.
				const auto handle = LoadLibrary(library_name.c_str());
				// Get the address of the function by ordinal from the loaded module.
				const auto fn = GetProcAddress(handle, MAKEINTRESOURCEA(ordinal_number));
				// Call the function using the internal helper, forwarding all arguments.
#ifdef QPRIMITIVE_TYPE_MUTATIONS
				return invoke_internal<T>(cmut<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(fn)).get(), arguments...);
#else
				return invoke_internal<T>(reinterpret_cast<std::uintptr_t>(fn), arguments...);
#endif
			}

			// Retrieve a function pointer from a DLL by name
			// Returns a callable function pointer of the correct type
			// T: Return type, args: Argument types
			// library_name: Name of the DLL (string_t)
			// fn_str: Name of the function (std::string)
			template<typename T, typename... args>
			static inline T(__stdcall* get_fn_import_object(const string_t library_name, const std::string fn_str) noexcept ) (args...) {
				// Load the DLL into the process address space. Returns a handle to the module.
				const auto handle = LoadLibrary(library_name.c_str());
				// Get the address of the function by name from the loaded module.
				const auto fn = GetProcAddress(handle, fn_str.c_str());
				// Return the function pointer cast to the correct type for direct invocation.
				return reinterpret_cast<T(__stdcall*)(args...)>(reinterpret_cast<void*>(fn));
			}

		};

	}
}

#endif