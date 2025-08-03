#pragma region Header Guard

#ifndef POLYC_H
#define POLYC_H

#pragma endregion

#pragma region Imports

#pragma region qengine

#include "../qbase/qdef.hpp"

#pragma endregion

#pragma region std

#pragma endregion

#include <ctime>
#include <chrono>
#include <random>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>

#pragma endregion

#pragma region Preprocessor

#pragma pack(push, 1)

#pragma endregion

namespace qengine {

	namespace polycXOR {

#pragma endregion

#pragma region Pointer Table Entry Structure

		typedef struct polyc_pointer_t {

			std::uintptr_t abs;
			std::uint8_t mutator;
			bool is_crypted;
			std::size_t pointer_table_index;
			std::size_t length;
		};

#pragma endregion

#pragma region Globals

		inline std::mutex					pcXOR_mtx;

		inline bool							_polycXOR_initialized = false;

		inline std::vector<polyc_pointer_t> _polycXOR_pointer_table;

		inline std::vector<std::uintptr_t>	_polycXOR_subroutine_safecall_table;

		inline std::uint8_t					qsub0_mutator = __TIME__[7];
		inline std::uint8_t					qsub1_mutator = __TIME__[6];
		inline std::uint8_t					qsub2_mutator = __TIME__[5];
		inline std::uint8_t					qsub3_mutator = __TIME__[4];
		inline std::uint8_t					qsub4_mutator = __TIME__[3];
		inline std::uint8_t					qsub5_mutator = __TIME__[2];
		inline std::uint8_t					qsub6_mutator = __TIME__[1];
		inline std::uint8_t					qsub7_mutator = __TIME__[0];
		inline std::uint8_t					qsub8_mutator = ~__TIME__[7];

		inline std::uint8_t					_polycXOR_pointer_table_key = __TIME__[7];

#pragma endregion

#pragma region Seeding Values

#pragma region Raw Arrays

		inline std::uintptr_t pXOR_ciph_x[16];
		inline std::uintptr_t pXOR_ciph_y[16];
		inline std::uintptr_t pXOR_ciph_z[16];

#pragma endregion

#pragma region Used Indice(s)

		inline std::uint8_t pXOR_indice_map_x[4];
		inline std::uint8_t pXOR_indice_map_y[8];
		inline std::uint8_t pXOR_indice_map_z[12];

#pragma endregion

#pragma endregion

#pragma region Rolling Addition / Subtraction (Junk Code Generation + WEAK Encryption && Confusion)

		static __compelled_inline imut std::uint8_t rol_add(imut std::uint8_t base, imut std::uint8_t modifier) nex {

			static imut imutexpr std::uint8_t maximum = 0xFFui8;

			imut std::uint8_t remaining = maximum - base;

			if (modifier <= remaining)
				return base + modifier;

			return (modifier - remaining) - 1;
		}

		static __compelled_inline imut std::uint8_t rol_sub(imut std::uint8_t base, imut std::uint8_t modifier) nex {

			static imut imutexpr std::uint8_t maximum = 0xFFui8;

			return modifier > base ? maximum - ((modifier - base) - 1) : base - modifier;
		}

#pragma endregion

#pragma region Confusion Subroutines

		/*

			The Below Symbols must be Symbolically Compiled as to retrieve a function pointer, Optimizations are disabled for the varying subroutines and Function Inlining is explicitly disabled, as well being marked volatile

			The Net Affect of these Subroutines, and their random Ordering, Equates to a Polymorphic Algorithm - Meaning the Algorithm itself Changes Per-Application

		*/

		static __symbolic imut bool __regcall internal_do_algo_subroutine_0(c_void data, imut std::size_t length, imut bool crypted) nex {

			if (crypted)
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_add(reinterpret_cast<std::uint8_t*>(data)[i], qsub0_mutator);
			else
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_sub(reinterpret_cast<std::uint8_t*>(data)[i], qsub0_mutator);

			return true;
		}

		static __symbolic imut bool __regcall internal_do_algo_subroutine_1(c_void data, imut std::size_t length, imut bool crypted) nex {

			internal_do_algo_subroutine_0(data, length, crypted);

			if (crypted)
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_sub(reinterpret_cast<std::uint8_t*>(data)[i], qsub1_mutator);
			else
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_add(reinterpret_cast<std::uint8_t*>(data)[i], qsub1_mutator);

			return true;
		}

		static __symbolic imut bool __regcall internal_do_algo_subroutine_2(c_void data, imut std::size_t length, imut bool crypted) nex {

			internal_do_algo_subroutine_0(data, length, crypted);
			internal_do_algo_subroutine_1(data, length, crypted);

			if (crypted)
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_add(reinterpret_cast<std::uint8_t*>(data)[i], qsub2_mutator);
			else
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_sub(reinterpret_cast<std::uint8_t*>(data)[i], qsub2_mutator);

			return true;
		}

		static __symbolic imut bool __regcall internal_do_algo_subroutine_3(c_void data, imut std::size_t length, imut bool crypted) nex {

			internal_do_algo_subroutine_0(data, length, crypted);
			internal_do_algo_subroutine_1(data, length, crypted);
			internal_do_algo_subroutine_2(data, length, crypted);

			if (crypted)
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_sub(reinterpret_cast<std::uint8_t*>(data)[i], qsub3_mutator);
			else
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_add(reinterpret_cast<std::uint8_t*>(data)[i], qsub3_mutator);

			return true;
		}

		static __symbolic imut bool __regcall internal_do_algo_subroutine_4(c_void data, imut std::size_t length, imut bool crypted) nex {

			internal_do_algo_subroutine_0(data, length, crypted);
			internal_do_algo_subroutine_1(data, length, crypted);
			internal_do_algo_subroutine_2(data, length, crypted);
			internal_do_algo_subroutine_3(data, length, crypted);

			if (crypted)
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_add(reinterpret_cast<std::uint8_t*>(data)[i], qsub4_mutator);
			else
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_sub(reinterpret_cast<std::uint8_t*>(data)[i], qsub4_mutator);

			return true;
		}

		static __symbolic imut bool __regcall internal_do_algo_subroutine_5(c_void data, imut std::size_t length, imut bool crypted) nex {

			internal_do_algo_subroutine_0(data, length, crypted);
			internal_do_algo_subroutine_1(data, length, crypted);
			internal_do_algo_subroutine_2(data, length, crypted);
			internal_do_algo_subroutine_3(data, length, crypted);
			internal_do_algo_subroutine_4(data, length, crypted);

			if (crypted)
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_sub(reinterpret_cast<std::uint8_t*>(data)[i], qsub5_mutator);
			else
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_add(reinterpret_cast<std::uint8_t*>(data)[i], qsub5_mutator);

			return true;
		}

		static __symbolic imut bool __regcall internal_do_algo_subroutine_6(c_void data, imut std::size_t length, imut bool crypted) nex {

			internal_do_algo_subroutine_0(data, length, crypted);
			internal_do_algo_subroutine_1(data, length, crypted);
			internal_do_algo_subroutine_2(data, length, crypted);
			internal_do_algo_subroutine_3(data, length, crypted);
			internal_do_algo_subroutine_4(data, length, crypted);
			internal_do_algo_subroutine_5(data, length, crypted);

			if (crypted)
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_add(reinterpret_cast<std::uint8_t*>(data)[i], qsub6_mutator);
			else
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_sub(reinterpret_cast<std::uint8_t*>(data)[i], qsub6_mutator);

			return true;
		}

		static __symbolic imut bool __regcall internal_do_algo_subroutine_7(c_void data, imut std::size_t length, imut bool crypted) nex {

			internal_do_algo_subroutine_0(data, length, crypted);
			internal_do_algo_subroutine_1(data, length, crypted);
			internal_do_algo_subroutine_2(data, length, crypted);
			internal_do_algo_subroutine_3(data, length, crypted);
			internal_do_algo_subroutine_4(data, length, crypted);
			internal_do_algo_subroutine_5(data, length, crypted);
			internal_do_algo_subroutine_6(data, length, crypted);

			if (crypted)
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_sub(reinterpret_cast<std::uint8_t*>(data)[i], qsub7_mutator);
			else
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_add(reinterpret_cast<std::uint8_t*>(data)[i], qsub7_mutator);

			return true;
		}

		static __symbolic imut bool __regcall internal_do_algo_subroutine_8(c_void data, imut std::size_t length, imut bool crypted) nex {

			internal_do_algo_subroutine_0(data, length, crypted);
			internal_do_algo_subroutine_1(data, length, crypted);
			internal_do_algo_subroutine_2(data, length, crypted);
			internal_do_algo_subroutine_3(data, length, crypted);
			internal_do_algo_subroutine_4(data, length, crypted);
			internal_do_algo_subroutine_5(data, length, crypted);
			internal_do_algo_subroutine_6(data, length, crypted);
			internal_do_algo_subroutine_7(data, length, crypted);

			if (crypted)
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_add(reinterpret_cast<std::uint8_t*>(data)[i], qsub8_mutator);
			else
				for (std::size_t i = 0; i < length; ++i)
					reinterpret_cast<std::uint8_t*>(data)[i] = rol_sub(reinterpret_cast<std::uint8_t*>(data)[i], qsub8_mutator);

			return true;
		}

#pragma endregion

#pragma region Subroutine FN Prototype

		typedef bool(__regcall* _algo_subroutine_prototype)(c_void, imut std::size_t, imut bool);

#pragma endregion

#pragma region Confusion Subroutine Wrappers

		static __compelled_inline imut bool __regcall internal_do_algo_region_subroutine_byref(polyc_pointer_t* pointer_entry, imut std::uintptr_t offset, imut std::size_t length) nex {

			if (!pointer_entry)
				return false;

			std::uintptr_t pointer_abs_cpy = pointer_entry->abs;

			__XORWORD__(pointer_abs_cpy, _polycXOR_pointer_table_key);								//	Decrypt pointer to data before calling subroutine

			std::uintptr_t subroutine_addr_cpy = _polycXOR_subroutine_safecall_table[pointer_entry->mutator];	//	Copy heap allocated encrypted pointer to the stack (pointer to subroutine)

			__XORWORD__(subroutine_addr_cpy, _polycXOR_pointer_table_key);								//	Decrypt pointer ONLY on the stack

			bool result = reinterpret_cast<_algo_subroutine_prototype>(subroutine_addr_cpy)(reinterpret_cast<c_void>(pointer_abs_cpy + offset), pointer_entry->length, pointer_entry->is_crypted);

			VOLATILE_NULL(pointer_abs_cpy);

			VOLATILE_NULL(subroutine_addr_cpy);

			pointer_entry->is_crypted = pointer_entry->is_crypted ? false : true;

			return result;
		}

		static __compelled_inline imut bool __regcall internal_do_algo_subroutine_byref(polyc_pointer_t* pointer_entry) nex {

			return internal_do_algo_region_subroutine_byref(pointer_entry, 0, pointer_entry->length);
		}

#pragma endregion

#pragma region Pseudo-Ctor

		static __symbolic imut bool __stackcall polyc_init() nex {

			std::lock_guard<std::mutex> lock(pcXOR_mtx);

			if (_polycXOR_initialized)
				return false;

			/* Provide a Proper Pseudo-Random Seed to rand()  */
			srand(
				std::time(nullptr) ^ BYTE_SET ^ QCTIME_SEED // Inverse the bits, then xor by compile-time constant
			);

			/* Determine Algorithm key value(s) */
			for (std::size_t i = 0; i < 16; ++i) {

				// | BIT_SCRAMBLE is Used to Produce / Garauntee a High Degree of Entropy among the Algorithm key(s)
				pXOR_ciph_x[i] = ((static_cast<uintptr_t>(std::time(nullptr) % __RAND__(UINT16_MAX * 3u, 1u)) ^ 3000u) * 30000u) | BIT_SCRAMBLE;

				pXOR_ciph_y[i] = ((static_cast<uintptr_t>(std::time(nullptr) % __RAND__(UINT16_MAX * 6u, 1u)) ^ 6000u) * 60000u) | BIT_SCRAMBLE;

				pXOR_ciph_z[i] = ((static_cast<uintptr_t>(std::time(nullptr) % __RAND__(UINT16_MAX * 9u, 1u)) ^ 9000u) * 90000u) | BIT_SCRAMBLE;
			}

			/* Determine Indices in x vector to use */
			for (auto x = 0; x < sizeof(pXOR_indice_map_x); ++x)
				pXOR_indice_map_x[x] = static_cast<char>(std::time(nullptr) % static_cast<std::uint8_t>(__RAND__(16, 1)));

			/* Determine Indices in y vector to use */
			for (auto y = 0; y < sizeof(pXOR_indice_map_y); ++y)
				pXOR_indice_map_y[y] = static_cast<char>(std::time(nullptr) % static_cast<std::uint8_t>(__RAND__(16, 1)));

			/* Determine Indices in z vector to use */
			for (auto z = 0; z < sizeof(pXOR_indice_map_z); ++z)
				pXOR_indice_map_z[z] = static_cast<char>(std::time(nullptr) % static_cast<std::uint8_t>(__RAND__(16, 1)));

			qsub0_mutator ^= static_cast<std::uint8_t>(__RAND__(255, 1));
			qsub1_mutator ^= static_cast<std::uint8_t>(__RAND__(255, 1));
			qsub2_mutator ^= static_cast<std::uint8_t>(__RAND__(255, 1));
			qsub3_mutator ^= static_cast<std::uint8_t>(__RAND__(255, 1));
			qsub4_mutator ^= static_cast<std::uint8_t>(__RAND__(255, 1));
			qsub5_mutator ^= static_cast<std::uint8_t>(__RAND__(255, 1));
			qsub6_mutator ^= static_cast<std::uint8_t>(__RAND__(255, 1));
			qsub7_mutator ^= static_cast<std::uint8_t>(__RAND__(255, 1));
			qsub8_mutator ^= static_cast<std::uint8_t>(__RAND__(255, 1));

			_polycXOR_pointer_table_key ^= static_cast<std::uint8_t>(std::chrono::high_resolution_clock().now().time_since_epoch().count());

			auto subroutine0_addr = reinterpret_cast<std::uintptr_t>(&internal_do_algo_subroutine_0);
			auto subroutine1_addr = reinterpret_cast<std::uintptr_t>(&internal_do_algo_subroutine_1);
			auto subroutine2_addr = reinterpret_cast<std::uintptr_t>(&internal_do_algo_subroutine_2);
			auto subroutine3_addr = reinterpret_cast<std::uintptr_t>(&internal_do_algo_subroutine_3);
			auto subroutine4_addr = reinterpret_cast<std::uintptr_t>(&internal_do_algo_subroutine_4);
			auto subroutine5_addr = reinterpret_cast<std::uintptr_t>(&internal_do_algo_subroutine_5);
			auto subroutine6_addr = reinterpret_cast<std::uintptr_t>(&internal_do_algo_subroutine_6);
			auto subroutine7_addr = reinterpret_cast<std::uintptr_t>(&internal_do_algo_subroutine_7);
			auto subroutine8_addr = reinterpret_cast<std::uintptr_t>(&internal_do_algo_subroutine_8);

			__XORWORD__(subroutine0_addr, _polycXOR_pointer_table_key);
			__XORWORD__(subroutine1_addr, _polycXOR_pointer_table_key);
			__XORWORD__(subroutine2_addr, _polycXOR_pointer_table_key);
			__XORWORD__(subroutine3_addr, _polycXOR_pointer_table_key);
			__XORWORD__(subroutine4_addr, _polycXOR_pointer_table_key);
			__XORWORD__(subroutine5_addr, _polycXOR_pointer_table_key);
			__XORWORD__(subroutine6_addr, _polycXOR_pointer_table_key);
			__XORWORD__(subroutine7_addr, _polycXOR_pointer_table_key);
			__XORWORD__(subroutine8_addr, _polycXOR_pointer_table_key);

			_polycXOR_subroutine_safecall_table.push_back(subroutine0_addr);
			_polycXOR_subroutine_safecall_table.push_back(subroutine1_addr);
			_polycXOR_subroutine_safecall_table.push_back(subroutine2_addr);
			_polycXOR_subroutine_safecall_table.push_back(subroutine3_addr);
			_polycXOR_subroutine_safecall_table.push_back(subroutine4_addr);
			_polycXOR_subroutine_safecall_table.push_back(subroutine5_addr);
			_polycXOR_subroutine_safecall_table.push_back(subroutine6_addr);
			_polycXOR_subroutine_safecall_table.push_back(subroutine7_addr);
			_polycXOR_subroutine_safecall_table.push_back(subroutine8_addr);

			return (_polycXOR_initialized = true);
		}

#pragma endregion

#pragma region Pointer Table Search

		static __compelled_inline polyc_pointer_t* __regcall get_pointer_table_entry_by_abs(imut c_void abs) nex {

			if (!abs)
				return nullptr;

			std::uintptr_t ptr = 0x0u;

			for (auto& pointer_entry : _polycXOR_pointer_table) {

				// Copy Encrypted Pointer to Stack
				ptr = pointer_entry.abs;

				__XORWORD__(ptr, _polycXOR_pointer_table_key);

				if (reinterpret_cast<c_void>(ptr) == abs) {

					// Wipe Local Copy
					VOLATILE_NULL(ptr);

					return &pointer_entry;
				}
			}

			VOLATILE_NULL(ptr);

			return nullptr;
		}

#pragma endregion

#pragma region Pointer Table Manipulation

		static __symbolic imut bool __regcall unregister_polyc_pointer(imut c_void abs) nex {

			if (!abs || !_polycXOR_pointer_table.size())
				return false;

			static polyc_pointer_t* existing_entry = nullptr;

			if ((existing_entry = get_pointer_table_entry_by_abs(abs)) == nullptr)
				return false;

			if (_polycXOR_pointer_table.size() - 1 > existing_entry->pointer_table_index)	// Perform table relocations if necessary
				for (std::size_t i = (existing_entry->pointer_table_index + 1); i < _polycXOR_pointer_table.size(); ++i)
					--_polycXOR_pointer_table[i].pointer_table_index;

			_polycXOR_pointer_table.erase(_polycXOR_pointer_table.begin() + existing_entry->pointer_table_index);

			return true;
		}

		static __symbolic polyc_pointer_t* __regcall register_polyc_pointer(c_void abs, imut std::size_t length) nex {

			if (!abs)
				return nullptr;

			static polyc_pointer_t* existing_entry = nullptr;

			if ((existing_entry = get_pointer_table_entry_by_abs(abs)) != nullptr)
				return existing_entry;

			polyc_pointer_t pointer_entry{

				reinterpret_cast<std::uintptr_t>(abs),
				// Below is an annoying ternary expression with the sole intention of including a chance of subroutine0 and subroutine8 mutators both being selected given a roughly equivalent chance
				std::chrono::high_resolution_clock::now().time_since_epoch().count() % 2 ? static_cast<std::uint8_t>((std::chrono::high_resolution_clock::now().time_since_epoch().count() % 9) - 1) : static_cast<std::uint8_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count() % 9),

				false,

				_polycXOR_pointer_table.size(),

				length
			};

			__XORWORD__(pointer_entry.abs, _polycXOR_pointer_table_key);

			_polycXOR_pointer_table.push_back(pointer_entry);

			// Wipe Pointer Copy on Stack
			RtlZeroMemory(&pointer_entry, sizeof(polyc_pointer_t));

			return &_polycXOR_pointer_table[_polycXOR_pointer_table.size() - 1];
		}

#pragma endregion

#pragma region Algorithm

		// TODO: Optimize this algorithm to operate on larger block sizes
		static __compelled_inline imut bool __regcall polycXOR_algo_region(

			c_void				abs,

			imut std::uintptr_t offset,

			imut std::size_t	length,

			imut bool			execute_subroutine = true

		) nex {

			if (!_polycXOR_initialized)
				polyc_init();

			std::lock_guard<std::mutex> lock(pcXOR_mtx);

			if (!abs || !length)
				return false;

			polyc_pointer_t* algo_pointer_entry = nullptr;

			if (execute_subroutine) {

				algo_pointer_entry = register_polyc_pointer(abs, length);	//	This fn allocated a pointer table entry, or returns the existing one (if applicable)

				if (!algo_pointer_entry->is_crypted)
					if (!internal_do_algo_region_subroutine_byref(algo_pointer_entry, offset, length))	//	We have to manually dictate the execution of this subroutine as it doesn't utilize a rolling algorithm.
						return false;

			}

			auto data_c = reinterpret_cast<std::uint8_t*>(abs);

			/* iterate each individual byte of data in the source */
			for (std::size_t i = 0; i < length; ++i) {

				/* run our first  XOR pass on the data */
				for (std::size_t x = 0; x < sizeof(pXOR_indice_map_x); ++x)
					__XORBYTE__(data_c[offset + i], pXOR_ciph_x[pXOR_indice_map_x[x]]);

				/* run our second XOR pass on the data */
				for (std::size_t y = 0; y < sizeof(pXOR_indice_map_y); ++y)
					__XORBYTE__(data_c[offset + i], pXOR_ciph_y[pXOR_indice_map_y[y]]);

				/* run our third XOR pass on the data */
				for (std::size_t z = 0; z < sizeof(pXOR_indice_map_z); ++z)
					__XORBYTE__(data_c[offset + i], pXOR_ciph_z[pXOR_indice_map_z[z]]);

			}

			if (execute_subroutine)																//	Safety check to ensure this data is manipulated using a further subroutine 
				if (algo_pointer_entry->is_crypted)												//	Check if the entry is was crypted, this means the XOR (decryption) subroutine has completed and we now need to realign our data to match the inverse subroutine algorithm
					if (!internal_do_algo_region_subroutine_byref(algo_pointer_entry, offset, length))  //  This function automatically toggles the [ is_crypted ] field when executed
						return false;

			return true;
		}

		// TODO: Optimize this algorithm to operate on larger block sizes
		static __compelled_inline imut bool __regcall polycXOR_algo(c_void abs, imut size_t length, imut bool execute_subroutine = true) nex {

			return polycXOR_algo_region(abs, 0, length, execute_subroutine);
		}

#pragma endregion

	}

	/*
		polyc128 is a Rough Equivalent of AES-128 in it's Base, Keystream-only Cipher mode, as well as Being Highly Optimized for SSE Intrinsics.

		This Algorithm, in it's more Complex Modalities, Provides Objectively Stronger Encryption than AES-XXX Due to it's Plaintext Mutations Prior to the actual Stream Cipher Application -

		Take the Control-Flow Confusion into Account and the Chances of anyone Reversing Data Encrypted with this Algorithm are Astronomically Low

		[Key + IV]
		   ↓
		[Key Schedule (9 × 32-bit)]
		   ↓
		[get_keystream_block(index)]
		   ├── Pulls 4 words from keyschedule
		   ├── Applies index × 32767 to word[0] (4 Billion++ Unique Keystream Probabilities from this Offseting Factor Alone)
		   ├── Chains bitwise rotation + XOR
		   ↓
		[128-bit keystream block]
		   ↓
		[Plaintext Block]
		   ├── (Optional) Byte Offset Mutation
		   ├── (Optional) Circular Rotation
		   ├── (Optional) S-Box Substitution
		   ├── (Optional) Modular Inverse Mutation
		   ↓
		[XOR with keystream block]
		   ↓
		[Ciphertext Block]
	*/
	namespace polyc128 {

#pragma region POLYC128 Cipher Modes

		/*
			streamonly : The Cipher only uses the 128-bit Keystream Product for the specified 128-bit Plaintext Block to Modulate Input (Strong Alone, but the Weakest Strength)

			stream_offset_mutation : The Cipher uses per-byte Offset Mutation, to Alter the Plaintext, BEFORE the 128-bit Keystream Block is Applied to the Corresponding 128-bit Plaintext Block (Small Performance Hit, Stronger Encryption)

			stream_offset_bitrotator_mutation : The Cipher Applies the Aforementioned Offset Mutation, next Applies a Circular-Bitwise Rotation per-byte(Rotation According to Block Index), lastly Applying the 128-bit Keystream Product for the 128-bit Block
		*/

		typedef enum polyc_cipher_mode128 : std::uint16_t {

			streamonly = 0,

			stream_offset_mutation = 1,

			stream_offset_bitrotator_mutation = 2,

			stream_offset_bitrotator_sbox_mutation = 3,

			stream_offset_bitrotator_sbox_invmod_mutation = 4
		};

#pragma endregion

#pragma region Globals

		std::recursive_mutex pc128_mtx;

#pragma region Cipher Globals

		inline bool								_is_polyc128_instantiated = false;

		inline polyc_cipher_mode128				_cipher_mode128 = streamonly;

		alignas(0x10) inline std::uint32_t		_key_schedule128[9];

#pragma endregion

#pragma endregion

#pragma region polyc128 Initialization Wrapper

		// Pre-Declaration Prototypes
		static __symbolic void __stackcall toggle_fn_ptr_states(polyc128::polyc_cipher_mode128 mode = stream_offset_bitrotator_sbox_invmod_mutation) nex;

		static __symbolic imut __m128i __regcall get_keystream_block(imut std::size_t block_index) nex;

		static __compelled_inline imut bool __regcall polyc128_expand_key(
			
			imut c_void key, 
			
			imut c_void iv, 
			
			imut bool wipe_key = false, 
			
			imut bool	wipe_iv = false
) nex;

		struct _auto_init_polyc128 {

			alignas(0x10) static std::uint8_t secure_rdata256[sizeof(__m128i) * 2];

			static __compelled_inline imut __m128i __stackcall generate_secure_rand128(std::uint32_t seed) nex {

#ifdef _M_X64
				MAKERD64();
#else
				MAKERD32();
#endif

				alignas(0x10) std::uint32_t gen128[4]{

					r() ^ seed,
					r() ^ (seed * INT16_MAX),
					r() ^ (seed * UINT16_MAX),
					r() ^ (seed * INT32_MAX)
				};

				polycXOR::polycXOR_algo(gen128, sizeof(gen128));
				polycXOR::unregister_polyc_pointer(gen128);

				gen128[0] = rol_shl(gen128[0], __TIME__[7]);
				gen128[1] = rol_shr(gen128[1], __TIME__[6]);
				gen128[2] = rol_shl(gen128[2], __TIME__[5]);
				gen128[3] = rol_shr(gen128[3], __TIME__[4]);

				crc32 crc;

				imut auto quickcrc = [&crc](std::uint32_t& val) -> std::uint32_t {

					imut std::uint32_t hash = crc.update_crc(reinterpret_cast<std::uint8_t*>(&val), sizeof(std::uint32_t));

					crc.reset_crc();

					return hash;
				};

				gen128[0] = quickcrc(gen128[0]);
				gen128[1] = quickcrc(gen128[1]);
				gen128[2] = quickcrc(gen128[2]);
				gen128[3] = quickcrc(gen128[3]);

				__m128i ret128 = _mm_load_si128(reinterpret_cast<__m128i*>(gen128));

				SECURE_ZERO_MEMORY(gen128, sizeof(gen128));

				return ret128;
			}

			__compelled_inline __stackcall _auto_init_polyc128() nex {

				std::lock_guard<std::recursive_mutex> lock(pc128_mtx);

				static std::once_flag flag;

				std::call_once(

					flag,

					// Initialize Encrypted State for all Sensitive Globals, Regardless of Target Stream Version
					[]() {

						polyc128::toggle_fn_ptr_states();

						std::random_device r;

						imut __m128i rkey128				= generate_secure_rand128(r() * INT16_MAX);

						imut __m128i riv128					= generate_secure_rand128(r() * UINT16_MAX);

						_mm_store_si128(reinterpret_cast<__m128i*>(secure_rdata256), rkey128);
						_mm_store_si128(reinterpret_cast<__m128i*>(secure_rdata256 + sizeof(__m128i)), riv128);

						polyc128_expand_key(secure_rdata256, secure_rdata256 + sizeof(__m128i));

						SECURE_ZERO_MEMORY(secure_rdata256, sizeof(secure_rdata256));

						polyc128::_is_polyc128_instantiated	= true;
					}
				);
			}
		};

#pragma endregion

#pragma region Algorithm Constants

#pragma region Substitution Tables (S-Table)

		inline std::uint8_t s_table[256]{

			0xBD, 0x47, 0xBB, 0x14, 0x6C, 0xED, 0x1C, 0x0B,
			0x8D, 0xBA, 0x09, 0xF9, 0x31, 0x15, 0xB8, 0x24,
			0xF7, 0x2D, 0xF2, 0xC1, 0x1A, 0x57, 0xE8, 0xE7,
			0x7E, 0xB3, 0xB9, 0x3E, 0x10, 0x79, 0x9A, 0x20,
			0x3B, 0x12, 0x7D, 0x89, 0xE9, 0x18, 0xB7, 0xD7,
			0xE2, 0x8E, 0xE0, 0x9D, 0xA2, 0x3C, 0x1F, 0x91,
			0x83, 0xC8, 0xA9, 0x01, 0xFB, 0xD8, 0xCB, 0x8B,
			0x8C, 0x48, 0x72, 0x2A, 0x92, 0x5E, 0x5F, 0xAE,
			0x81, 0xAB, 0x37, 0x67, 0xFE, 0xC6, 0x16, 0xA1,
			0xB5, 0x22, 0xBF, 0x7A, 0x6B, 0xFC, 0xC4, 0x43,
			0xC9, 0x53, 0xCF, 0x8A, 0x68, 0x98, 0x4D, 0x9C,
			0x86, 0xF3, 0x4A, 0x5C, 0x9F, 0x1B, 0xFD, 0xD9,
			0x8F, 0xB2, 0xF8, 0xC5, 0xE4, 0x75, 0xD4, 0x4E,
			0x78, 0xA6, 0x69, 0xBE, 0xE6, 0x90, 0x0D, 0x28,
			0x3F, 0xDB, 0x2C, 0x0A, 0x07, 0x99, 0x2B, 0x4C,
			0x7B, 0xCC, 0x4B, 0x54, 0xE3, 0x5D, 0x11, 0xD2,
			0x80, 0x50, 0xAF, 0x03, 0x62, 0xEC, 0x02, 0xF4,
			0x94, 0xCA, 0x59, 0x51, 0x00, 0x3D, 0x95, 0xDF,
			0xFF, 0x93, 0x6E, 0x64, 0x82, 0xC2, 0x88, 0x30,
			0x25, 0x55, 0xDE, 0x52, 0xBC, 0x84, 0xB0, 0xCD,
			0x2F, 0x39, 0x4F, 0x73, 0x6D, 0xA7, 0x6A, 0x46,
			0x42, 0x36, 0x29, 0x2E, 0x5A, 0x08, 0x34, 0x19,
			0x60, 0x96, 0x32, 0x58, 0xF0, 0x7F, 0xEF, 0x21,
			0xC3, 0x26, 0x85, 0x97, 0x77, 0x04, 0xDA, 0x76,
			0xD5, 0xC7, 0x17, 0xD3, 0x65, 0xD1, 0xD6, 0x3A,
			0x06, 0x27, 0x40, 0x0E, 0x0C, 0xAA, 0x5B, 0x56,
			0xFA, 0xF5, 0x23, 0xA8, 0xEA, 0x6F, 0x45, 0xD0,
			0xB6, 0xC0, 0xB1, 0xE1, 0xA3, 0x49, 0x44, 0xF6,
			0x38, 0x33, 0x87, 0xA0, 0x0F, 0x7C, 0xE5, 0xCE,
			0x1E, 0x35, 0xAC, 0x13, 0x66, 0xDC, 0xB4, 0x63,
			0x05, 0xAD, 0x74, 0x71, 0xA5, 0x1D, 0x9E, 0x41,
			0xF1, 0x61, 0xEE, 0xDD, 0x9B, 0xA4, 0x70, 0xEB
		};

		inline std::uint8_t inverse_s_table[256] = {

			0x8C, 0x33, 0x86, 0x83, 0xBD, 0xF0, 0xC8, 0x74,
			0xAD, 0x0A, 0x73, 0x07, 0xCC, 0x6E, 0xCB, 0xE4,
			0x1C, 0x7E, 0x21, 0xEB, 0x03, 0x0D, 0x46, 0xC2,
			0x25, 0xAF, 0x14, 0x5D, 0x06, 0xF5, 0xE8, 0x2E,
			0x1F, 0xB7, 0x49, 0xD2, 0x0F, 0x98, 0xB9, 0xC9,
			0x6F, 0xAA, 0x3B, 0x76, 0x72, 0x11, 0xAB, 0xA0,
			0x97, 0x0C, 0xB2, 0xE1, 0xAE, 0xE9, 0xA9, 0x42,
			0xE0, 0xA1, 0xC7, 0x20, 0x2D, 0x8D, 0x1B, 0x70,
			0xCA, 0xF7, 0xA8, 0x4F, 0xDE, 0xD6, 0xA7, 0x01,
			0x39, 0xDD, 0x5A, 0x7A, 0x77, 0x56, 0x67, 0xA2,
			0x81, 0x8B, 0x9B, 0x51, 0x7B, 0x99, 0xCF, 0x15,
			0xB3, 0x8A, 0xAC, 0xCE, 0x5B, 0x7D, 0x3D, 0x3E,
			0xB0, 0xF9, 0x84, 0xEF, 0x93, 0xC4, 0xEC, 0x43,
			0x54, 0x6A, 0xA6, 0x4C, 0x04, 0xA4, 0x92, 0xD5,
			0xFE, 0xF3, 0x3A, 0xA3, 0xF2, 0x65, 0xBF, 0xBC,
			0x68, 0x1D, 0x4B, 0x78, 0xE5, 0x22, 0x18, 0xB5,
			0x80, 0x40, 0x94, 0x30, 0x9D, 0xBA, 0x58, 0xE2,
			0x96, 0x23, 0x53, 0x37, 0x38, 0x08, 0x29, 0x60,
			0x6D, 0x2F, 0x3C, 0x91, 0x88, 0x8E, 0xB1, 0xBB,
			0x55, 0x75, 0x1E, 0xFC, 0x57, 0x2B, 0xF6, 0x5C,
			0xE3, 0x47, 0x2C, 0xDC, 0xFD, 0xF4, 0x69, 0xA5,
			0xD3, 0x32, 0xCD, 0x41, 0xEA, 0xF1, 0x3F, 0x82,
			0x9E, 0xDA, 0x61, 0x19, 0xEE, 0x48, 0xD8, 0x26,
			0x0E, 0x1A, 0x09, 0x02, 0x9C, 0x00, 0x6B, 0x4A,
			0xD9, 0x13, 0x95, 0xB8, 0x4E, 0x63, 0x45, 0xC1,
			0x31, 0x50, 0x89, 0x36, 0x79, 0x9F, 0xE7, 0x52,
			0xD7, 0xC5, 0x7F, 0xC3, 0x66, 0xC0, 0xC6, 0x27,
			0x35, 0x5F, 0xBE, 0x71, 0xED, 0xFB, 0x9A, 0x8F,
			0x2A, 0xDB, 0x28, 0x7C, 0x64, 0xE6, 0x6C, 0x17,
			0x16, 0x24, 0xD4, 0xFF, 0x85, 0x05, 0xFA, 0xB6,
			0xB4, 0xF8, 0x12, 0x59, 0x87, 0xD1, 0xDF, 0x10,
			0x62, 0x0B, 0xD0, 0x34, 0x4D, 0x5E, 0x44, 0x90
		};


#pragma endregion

#pragma region Inverse Multiplication Modulo 256 Lookup Tables

		inline std::uint8_t mod_inverse_multipliers[128] = {

			0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F,
			0x11, 0x13, 0x15, 0x17, 0x19, 0x1B, 0x1D, 0x1F,
			0x21, 0x23, 0x25, 0x27, 0x29, 0x2B, 0x2D, 0x2F,
			0x31, 0x33, 0x35, 0x37, 0x39, 0x3B, 0x3D, 0x3F,
			0x41, 0x43, 0x45, 0x47, 0x49, 0x4B, 0x4D, 0x4F,
			0x51, 0x53, 0x55, 0x57, 0x59, 0x5B, 0x5D, 0x5F,
			0x61, 0x63, 0x65, 0x67, 0x69, 0x6B, 0x6D, 0x6F,
			0x71, 0x73, 0x75, 0x77, 0x79, 0x7B, 0x7D, 0x7F,
			0x81, 0x83, 0x85, 0x87, 0x89, 0x8B, 0x8D, 0x8F,
			0x91, 0x93, 0x95, 0x97, 0x99, 0x9B, 0x9D, 0x9F,
			0xA1, 0xA3, 0xA5, 0xA7, 0xA9, 0xAB, 0xAD, 0xAF,
			0xB1, 0xB3, 0xB5, 0xB7, 0xB9, 0xBB, 0xBD, 0xBF,
			0xC1, 0xC3, 0xC5, 0xC7, 0xC9, 0xCB, 0xCD, 0xCF,
			0xD1, 0xD3, 0xD5, 0xD7, 0xD9, 0xDB, 0xDD, 0xDF,
			0xE1, 0xE3, 0xE5, 0xE7, 0xE9, 0xEB, 0xED, 0xEF,
			0xF1, 0xF3, 0xF5, 0xF7, 0xF9, 0xFB, 0xFD, 0xFF
		};

		static std::uint8_t mod_inverse_mod256[128] = {

			0x01, 0xAB, 0xCD, 0xB7, 0x39, 0xA3, 0xC5, 0xEF,
			0xF1, 0x1B, 0x3D, 0xA7, 0x29, 0x13, 0x35, 0xDF,
			0xE1, 0x8B, 0xAD, 0x97, 0x19, 0x83, 0xA5, 0xCF,
			0xD1, 0xFB, 0x1D, 0x87, 0x09, 0xF3, 0x15, 0xBF,
			0xC1, 0x6B, 0x8D, 0x77, 0xF9, 0x63, 0x85, 0xAF,
			0xB1, 0xDB, 0xFD, 0x67, 0xE9, 0xD3, 0xF5, 0x9F,
			0xA1, 0x4B, 0x6D, 0x57, 0xD9, 0x43, 0x65, 0x8F,
			0x91, 0xBB, 0xDD, 0x47, 0xC9, 0xB3, 0xD5, 0x7F,
			0x81, 0x2B, 0x4D, 0x37, 0xB9, 0x23, 0x45, 0x6F,
			0x71, 0x9B, 0xBD, 0x27, 0xA9, 0x93, 0xB5, 0x5F,
			0x61, 0x0B, 0x2D, 0x17, 0x99, 0x03, 0x25, 0x4F,
			0x51, 0x7B, 0x9D, 0x07, 0x89, 0x73, 0x95, 0x3F,
			0x41, 0xEB, 0x0D, 0xF7, 0x79, 0xE3, 0x05, 0x2F,
			0x31, 0x5B, 0x7D, 0xE7, 0x69, 0x53, 0x75, 0x1F,
			0x21, 0xCB, 0xED, 0xD7, 0x59, 0xC3, 0xE5, 0x0F,
			0x11, 0x3B, 0x5D, 0xC7, 0x49, 0x33, 0x55, 0xFF
		};

#pragma endregion

#pragma endregion

#pragma region polyc-128 Algorithm Misc Functions

		static __compelled_inline void __fastcall polyc128_set_cipher_mode(

			imut polyc_cipher_mode128 mode

		) nex {

			_cipher_mode128 = mode;
		}

#pragma endregion

#pragma region Keystream-Generation && Mutation-Table Lookups

		typedef imut __m128i (__regcall* ks_block_proto)(imut std::size_t block_index);

		static __compelled_inline imut std::uint8_t& __regcall get_invmod_mutator8(imut std::size_t& block_index, imut bool is_encryption) nex {

			return is_encryption ? mod_inverse_multipliers[block_index % 128] : mod_inverse_mod256[block_index % 128];
		}

		// Removed Conditionals for whole-Block Processing
		static __compelled_inline __m128i __regcall sbox_substitute_block(

			__m128i		block,

			imut bool	is_encryption

		) nex {

			alignas(0x10) std::uint8_t	plaintext_ui8[sizeof(__m128i)];

			_mm_store_si128(reinterpret_cast<__m128i*>(plaintext_ui8), block);

			imut std::uint8_t* table = is_encryption ? s_table : inverse_s_table;

			return _mm_set_epi8(

				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[15]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[14]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[13]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[12]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[11]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[10]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[9]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[8]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[7]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[6]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[5]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[4]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[3]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[2]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[1]],
				table[reinterpret_cast<std::uint8_t*>(plaintext_ui8)[0]]
			);
		}

		static __compelled_inline void __regcall sbox_substitute(

			c_void				data,

			imut std::size_t&	len,

			imut bool			is_encryption

		) nex {

			if (!data || !len)
				return;

			imut std::uint8_t* table = is_encryption ? s_table : inverse_s_table;

			reinterpret_cast<std::uint8_t*>(data)[0] = table[reinterpret_cast<std::uint8_t*>(data)[0]];

			if (len < 2)
				return;
			reinterpret_cast<std::uint8_t*>(data)[1] = table[reinterpret_cast<std::uint8_t*>(data)[1]];
			if (len < 3)
				return;
			reinterpret_cast<std::uint8_t*>(data)[2] = table[reinterpret_cast<std::uint8_t*>(data)[2]];
			if (len < 4)
				return;
			reinterpret_cast<std::uint8_t*>(data)[3] = table[reinterpret_cast<std::uint8_t*>(data)[3]];
			if (len < 5)
				return;
			reinterpret_cast<std::uint8_t*>(data)[4] = table[reinterpret_cast<std::uint8_t*>(data)[4]];
			if (len < 6)
				return;
			reinterpret_cast<std::uint8_t*>(data)[5] = table[reinterpret_cast<std::uint8_t*>(data)[5]];
			if (len < 7)
				return;
			reinterpret_cast<std::uint8_t*>(data)[6] = table[reinterpret_cast<std::uint8_t*>(data)[6]];
			if (len < 8)
				return;
			reinterpret_cast<std::uint8_t*>(data)[7] = table[reinterpret_cast<std::uint8_t*>(data)[7]];
			if (len < 9)
				return;
			reinterpret_cast<std::uint8_t*>(data)[8] = table[reinterpret_cast<std::uint8_t*>(data)[8]];
			if (len < 10)
				return;
			reinterpret_cast<std::uint8_t*>(data)[9] = table[reinterpret_cast<std::uint8_t*>(data)[9]];
			if (len < 11)
				return;
			reinterpret_cast<std::uint8_t*>(data)[10] = table[reinterpret_cast<std::uint8_t*>(data)[10]];
			if (len < 12)
				return;
			reinterpret_cast<std::uint8_t*>(data)[11] = table[reinterpret_cast<std::uint8_t*>(data)[11]];
			if (len < 13)
				return;
			reinterpret_cast<std::uint8_t*>(data)[12] = table[reinterpret_cast<std::uint8_t*>(data)[12]];
			if (len < 14)
				return;
			reinterpret_cast<std::uint8_t*>(data)[13] = table[reinterpret_cast<std::uint8_t*>(data)[13]];
			if (len < 15)
				return;
			reinterpret_cast<std::uint8_t*>(data)[14] = table[reinterpret_cast<std::uint8_t*>(data)[14]];
			if (len < 16)
				return;
			reinterpret_cast<std::uint8_t*>(data)[15] = table[reinterpret_cast<std::uint8_t*>(data)[15]];
		}

#pragma endregion

#pragma region polyc-128 Plaintext-Mutation Routines

		template<typename T>
		static __compelled_inline imut T __regcall sbox_word(imut T word) nex {

			T output = T(0x0u);

			for (std::size_t i = 0; i < sizeof(T); ++i) {

				imut std::uint8_t original = word >> (i * 8) & 0xFF;

				output |= static_cast<T>(s_table[original]) << (i * 8);
			}

			return output;
		}

		typedef imut __m128i(__fpcall* im_mutator128_proto)(imut __m128i, imut std::size_t&, imut bool);

		// Performs Modular Inverse Multiplication, Dependent on Block Index (From Statically Defined Tables Containing Valid Multipliers and Inverse Mod256 Multipliers)
		static __symbolic imut __m128i __fpcall apply_IM_mutator128(

			imut __m128i		plaintext128,

			imut std::size_t&	block_index,

			imut bool			is_encryption

		) nex {

			alignas(0x10) std::uint8_t	plaintext_ui8[sizeof(__m128i)];

			_mm_store_si128(reinterpret_cast<__m128i*>(plaintext_ui8), plaintext128);

			std::uint8_t				multiplier = get_invmod_mutator8(block_index, is_encryption);

			// Unroll Loop for Performance - We are already Nested Inside a Loop in Caller
			plaintext_ui8[0] *= multiplier;
			plaintext_ui8[1] *= multiplier;
			plaintext_ui8[2] *= multiplier;
			plaintext_ui8[3] *= multiplier;
			plaintext_ui8[4] *= multiplier;
			plaintext_ui8[5] *= multiplier;
			plaintext_ui8[6] *= multiplier;
			plaintext_ui8[7] *= multiplier;
			plaintext_ui8[8] *= multiplier;
			plaintext_ui8[9] *= multiplier;
			plaintext_ui8[10] *= multiplier;
			plaintext_ui8[11] *= multiplier;
			plaintext_ui8[12] *= multiplier;
			plaintext_ui8[13] *= multiplier;
			plaintext_ui8[14] *= multiplier;
			plaintext_ui8[15] *= multiplier;

			VOLATILE_NULL(multiplier);

			return _mm_load_si128(reinterpret_cast<__m128i*>(plaintext_ui8));
		}

		typedef imut __m128i(__fpcall* sb_mutator128_proto)(imut __m128i, imut bool);

		static __symbolic imut __m128i __fpcall apply_SB_mutator128(

			imut __m128i plaintext128,

			imut bool		is_encryption

		) nex {

			return sbox_substitute_block(plaintext128, is_encryption);
		}

		typedef __m128i(__fpcall* sh_mutator128_proto)(imut __m128i, imut __m128i, imut bool);

		static __symbolic imut __m128i __fpcall apply_SH_mutator128(

			imut __m128i		plaintext128,

			imut __m128i		ks_block128,

			imut bool			is_encryption

		) nex {

			alignas(0x10) std::uint8_t plaintext_ui8[sizeof(__m128i)], mutagen_ui8[sizeof(__m128i)];

			_mm_store_si128(reinterpret_cast<__m128i*>(plaintext_ui8), plaintext128);
			_mm_store_si128(reinterpret_cast<__m128i*>(mutagen_ui8), ks_block128);

			imut auto lambda_sh_fn = is_encryption ? lambda_rol_shl_byte : lambda_rol_shr_byte;

			// Retrieve Pseudo-fn Pointer to Lower Codesize without Using Loops
			imut std::uint8_t(__regcall * rol_fn)(std::uint8_t, std::uint16_t) = is_encryption ? &rol_shl<std::uint8_t, std::uint16_t> : &rol_shr<std::uint8_t, std::uint16_t>;

			plaintext_ui8[0] = lambda_sh_fn(plaintext_ui8[0], mutagen_ui8[0]);
			plaintext_ui8[1] = lambda_sh_fn(plaintext_ui8[1], mutagen_ui8[1]);
			plaintext_ui8[2] = lambda_sh_fn(plaintext_ui8[2], mutagen_ui8[2]);
			plaintext_ui8[3] = lambda_sh_fn(plaintext_ui8[3], mutagen_ui8[3]);
			plaintext_ui8[4] = lambda_sh_fn(plaintext_ui8[4], mutagen_ui8[4]);
			plaintext_ui8[5] = lambda_sh_fn(plaintext_ui8[5], mutagen_ui8[5]);
			plaintext_ui8[6] = lambda_sh_fn(plaintext_ui8[6], mutagen_ui8[6]);
			plaintext_ui8[7] = lambda_sh_fn(plaintext_ui8[7], mutagen_ui8[7]);
			plaintext_ui8[8] = lambda_sh_fn(plaintext_ui8[8], mutagen_ui8[8]);
			plaintext_ui8[9] = lambda_sh_fn(plaintext_ui8[9], mutagen_ui8[9]);
			plaintext_ui8[10] = lambda_sh_fn(plaintext_ui8[10], mutagen_ui8[10]);
			plaintext_ui8[11] = lambda_sh_fn(plaintext_ui8[11], mutagen_ui8[11]);
			plaintext_ui8[12] = lambda_sh_fn(plaintext_ui8[12], mutagen_ui8[12]);
			plaintext_ui8[13] = lambda_sh_fn(plaintext_ui8[13], mutagen_ui8[13]);
			plaintext_ui8[14] = lambda_sh_fn(plaintext_ui8[14], mutagen_ui8[14]);
			plaintext_ui8[15] = lambda_sh_fn(plaintext_ui8[15], mutagen_ui8[15]);

			SECURE_ZERO_MEMORY(mutagen_ui8, sizeof(mutagen_ui8));

			imut __m128i rcode =  _mm_load_si128(reinterpret_cast<__m128i*>(plaintext_ui8));

			SECURE_ZERO_MEMORY(plaintext_ui8, sizeof(plaintext_ui8));

			return rcode;
		}

		typedef __m128i(__fpcall* of_mutator128_proto)(imut __m128i, imut __m128i, imut bool);

		static __symbolic imut __m128i __fpcall apply_OFS_mutator128(

			imut __m128i		plaintext128,

			imut __m128i		ks_block128,

			imut bool			is_encryption

		) nex {

			alignas(0x10) std::uint8_t	plaintext_ui8[sizeof(__m128i)], mutagen_ui8[sizeof(__m128i)];

			_mm_store_si128(reinterpret_cast<__m128i*>(plaintext_ui8), plaintext128);
			_mm_store_si128(reinterpret_cast<__m128i*>(mutagen_ui8), ks_block128);

#define DO_BYTE_OFFSET(_OPERATOR_)							\
			plaintext_ui8[0]  _OPERATOR_ mutagen_ui8[0];	\
			plaintext_ui8[1]  _OPERATOR_ mutagen_ui8[1];	\
			plaintext_ui8[2]  _OPERATOR_ mutagen_ui8[2];	\
			plaintext_ui8[3]  _OPERATOR_ mutagen_ui8[3];	\
			plaintext_ui8[4]  _OPERATOR_ mutagen_ui8[4];	\
			plaintext_ui8[5]  _OPERATOR_ mutagen_ui8[5];	\
			plaintext_ui8[6]  _OPERATOR_ mutagen_ui8[6];	\
			plaintext_ui8[7]  _OPERATOR_ mutagen_ui8[7];	\
			plaintext_ui8[8]  _OPERATOR_ mutagen_ui8[8];	\
			plaintext_ui8[9]  _OPERATOR_ mutagen_ui8[9];	\
			plaintext_ui8[10] _OPERATOR_ mutagen_ui8[10];	\
			plaintext_ui8[11] _OPERATOR_ mutagen_ui8[11];	\
			plaintext_ui8[12] _OPERATOR_ mutagen_ui8[12];	\
			plaintext_ui8[13] _OPERATOR_ mutagen_ui8[13];	\
			plaintext_ui8[14] _OPERATOR_ mutagen_ui8[14];	\
			plaintext_ui8[15] _OPERATOR_ mutagen_ui8[15];

			if (is_encryption) {

				DO_BYTE_OFFSET(+= );

				goto do_ret;
			}

			DO_BYTE_OFFSET(-= );

#undef DO_BYTE_OFFSET

			SECURE_ZERO_MEMORY(mutagen_ui8, sizeof(mutagen_ui8));

			do_ret :

			imut __m128i rcode = _mm_load_si128(reinterpret_cast<__m128i*>(plaintext_ui8));

			SECURE_ZERO_MEMORY(plaintext_ui8, sizeof(plaintext_ui8));

			return rcode;
		}

		typedef void(__regcall* im_mutator_proto)(c_void, imut std::size_t&, imut std::size_t&, imut bool);

		static __symbolic void __regcall apply_IM_mutator_range(

			c_void				plaintext,

			imut std::size_t&	block_index,

			imut std::size_t&	len,

			imut bool			is_encryption

		) nex {

			if (!plaintext || !len)
				return;

			std::uint8_t multiplier = get_invmod_mutator8(block_index, is_encryption);

			reinterpret_cast<std::uint8_t*>(plaintext)[0] *= multiplier;

			if (len < 2)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[1] *= multiplier;
			if (len < 3)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[2] *= multiplier;
			if (len < 4)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[3] *= multiplier;
			if (len < 5)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[4] *= multiplier;
			if (len < 6)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[5] *= multiplier;
			if (len < 7)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[6] *= multiplier;
			if (len < 8)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[7] *= multiplier;
			if (len < 9)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[8] *= multiplier;
			if (len < 10)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[9] *= multiplier;
			if (len < 11)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[10] *= multiplier;
			if (len < 12)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[11] *= multiplier;
			if (len < 13)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[12] *= multiplier;
			if (len < 14)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[13] *= multiplier;
			if (len < 15)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[14] *= multiplier;
			if (len < 16)
				goto cleanup;
			reinterpret_cast<std::uint8_t*>(plaintext)[15] *= multiplier;

		cleanup:

			VOLATILE_NULL(multiplier);
		}

		typedef void(__regcall* sb_mutator_proto)(c_void, imut std::size_t&, imut bool);

		// Basic Function Wrapper / Indirection to fit Naming Scheme
		static __symbolic void __regcall apply_SB_mutator_range(

			c_void				plaintext,

			imut std::size_t&	len,

			imut bool			is_encryption

		) nex {

			sbox_substitute(plaintext, len, is_encryption);
		}

		typedef void(__regcall* sh_mutator_proto)(c_void, imut __m128i, imut std::uintptr_t&, imut std::size_t&, imut bool);

		static __symbolic void __regcall apply_SH_mutator_range(

			c_void					plaintext,

			imut __m128i			ks_block128,

			imut std::uintptr_t&	block_offset,

			imut std::size_t&		len,

			imut bool				is_encryption

		) nex {

			if (!plaintext || !len)
				return;

			alignas(0x10) std::uint8_t	mutagen_ui8[sizeof(__m128i)];

			_mm_store_si128(reinterpret_cast<__m128i*>(mutagen_ui8), ks_block128);

			imut auto		lamda_sh_fn = is_encryption ? lambda_rol_shl_byte : lambda_rol_shr_byte;

			/*
				Since our input array has a maximum fixed length, we can Unroll the Loop and Save Loop Overhead
			*/
			reinterpret_cast<std::uint8_t*>(plaintext)[0] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[0], mutagen_ui8[0 + block_offset]);
			if (len < 2)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[1] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[1], mutagen_ui8[1 + block_offset]);
			if (len < 3)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[2] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[2], mutagen_ui8[2 + block_offset]);
			if (len < 4)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[3] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[3], mutagen_ui8[3 + block_offset]);
			if (len < 5)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[4] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[4], mutagen_ui8[4 + block_offset]);
			if (len < 6)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[5] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[5], mutagen_ui8[5 + block_offset]);
			if (len < 7)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[6] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[6], mutagen_ui8[6 + block_offset]);
			if (len < 8)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[7] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[7], mutagen_ui8[7 + block_offset]);
			if (len < 9)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[8] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[8], mutagen_ui8[8 + block_offset]);
			if (len < 10)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[9] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[9], mutagen_ui8[9 + block_offset]);
			if (len < 11)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[10] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[10], mutagen_ui8[10 + block_offset]);
			if (len < 12)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[11] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[11], mutagen_ui8[11 + block_offset]);
			if (len < 13)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[12] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[12], mutagen_ui8[12 + block_offset]);
			if (len < 14)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[13] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[13], mutagen_ui8[13 + block_offset]);
			if (len < 15)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[14] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[14], mutagen_ui8[14 + block_offset]);
			if (len < 16)
				return;
			reinterpret_cast<std::uint8_t*>(plaintext)[15] = lamda_sh_fn(reinterpret_cast<std::uint8_t*>(plaintext)[15], mutagen_ui8[15 + block_offset]);

			SECURE_ZERO_MEMORY(mutagen_ui8, sizeof(mutagen_ui8));
		}

		typedef void(__regcall* of_mutator_proto)(c_void, imut __m128i, imut std::uintptr_t, imut std::size_t&, imut bool);

		static __symbolic void __regcall apply_OFS_mutator_range(

			c_void				plaintext,

			imut __m128i		ks_block128,

			imut std::uintptr_t block_offset,

			imut std::size_t&	len,

			imut bool			is_encryption

		) nex {

			if (!plaintext || !len)
				return;

			alignas(0x10) std::uint8_t	mutagen_ui8[sizeof(__m128i)];

			_mm_store_si128(reinterpret_cast<__m128i*>(mutagen_ui8), ks_block128);

#define DO_CONDITIONAL_BYTE_OFFSET(_OPERATOR_)															\
			reinterpret_cast<std::uint8_t*>(plaintext)[0]  _OPERATOR_ mutagen_ui8[0 + block_offset];	\
			if (len < 2)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[1]  _OPERATOR_ mutagen_ui8[1 + block_offset];	\
			if (len < 3)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[2]  _OPERATOR_ mutagen_ui8[2 + block_offset];	\
			if (len < 4)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[3]  _OPERATOR_ mutagen_ui8[3 + block_offset];	\
			if (len < 5)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[4]  _OPERATOR_ mutagen_ui8[4 + block_offset];	\
			if (len < 6)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[5]  _OPERATOR_ mutagen_ui8[5 + block_offset];	\
			if (len < 7)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[6]  _OPERATOR_ mutagen_ui8[6 + block_offset];	\
			if (len < 8)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[7]  _OPERATOR_ mutagen_ui8[7 + block_offset];	\
			if (len < 9)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[8]  _OPERATOR_ mutagen_ui8[8 + block_offset];	\
			if (len < 10)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[9]  _OPERATOR_ mutagen_ui8[9 + block_offset];	\
			if (len < 11)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[10] _OPERATOR_ mutagen_ui8[10 + block_offset];	\
			if (len < 12)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[11] _OPERATOR_ mutagen_ui8[11 + block_offset];	\
			if (len < 13)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[12] _OPERATOR_ mutagen_ui8[12 + block_offset];	\
			if (len < 14)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[13] _OPERATOR_ mutagen_ui8[13 + block_offset];	\
			if (len < 15)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[14] _OPERATOR_ mutagen_ui8[14 + block_offset];	\
			if (len < 16)																				\
				return;																					\
			reinterpret_cast<std::uint8_t*>(plaintext)[15] _OPERATOR_ mutagen_ui8[15 + block_offset];

			if (is_encryption) {

				DO_CONDITIONAL_BYTE_OFFSET(+=);

				return;
			}

			DO_CONDITIONAL_BYTE_OFFSET(-=);

#undef DO_CONDITIONAL_BYTE_OFFSET

		}

#pragma endregion

#pragma region Keystream Generation

		static __symbolic imut __m128i __regcall get_keystream_block(imut std::size_t block_index) nex {

#ifdef _MSC_VER

			_ReadWriteBarrier();

#endif

			static const constexpr auto BARE = 1u;
			static const constexpr auto SPLIT = 2u;
			static const constexpr auto TRI = 3u;
			static const constexpr auto PENTA = 5u;
			static const constexpr auto HEXA = 6u;
			static const constexpr auto HEPTA = 7u;
			static const constexpr auto ENNEA = 9u;
			static const constexpr auto DODECA = 12u;

			const std::size_t vblock_idx_bare = block_index + BARE;
			const std::size_t vblock_idx_tri = block_index + TRI;
			const std::size_t vblock_idx_hexa = block_index + HEXA;
			const std::size_t vblock_idx_ennea = block_index + ENNEA;
			const std::size_t vblock_idx_dodeca = block_index + DODECA;
			const std::size_t vblock_idx_bare_mtri = vblock_idx_bare % TRI;
			const std::size_t vblock_idx_bare_mennea = vblock_idx_bare % ENNEA;
			const std::size_t vblock_idx_hexa_mennea = vblock_idx_hexa % ENNEA;
			const std::size_t vblock_idx_ennea_mennea = vblock_idx_ennea % ENNEA;
			const std::size_t vblock_idx_dodeca_mennea = vblock_idx_dodeca % ENNEA;
			const std::size_t vblock_idx_bare_mhepta = vblock_idx_bare % HEPTA;
			const std::size_t vblock_idx_bare_mpenta = vblock_idx_bare % PENTA;
			const std::size_t vblock_idx_tri_xennea = vblock_idx_tri * ENNEA;
			const std::size_t vblock_idx_hexa_xhexa = vblock_idx_hexa * HEXA;
			const std::size_t vblock_idx_ennea_xtri = vblock_idx_ennea * TRI;

			static const constexpr std::uint16_t VMAX_MULROT = INT16_MAX;
			static const constexpr std::uint16_t VMAX_MULROT_DX2 = VMAX_MULROT / SPLIT;

			// MSVC Corrupts the Entire Algorithm and Fails to Properly Instantiate this Array in Release Mode if it isn't Declared Volatile;; (Thanks M$)
			alignas(0x10) noregister std::uint32_t bX[4]{

				// Addition of Non-Linear Entropy to bX[FIRST]
				_key_schedule128[vblock_idx_bare_mtri]			^	sbox_word(rol_shr(sbox_word((_key_schedule128[vblock_idx_bare_mennea] * vblock_idx_tri) ^ vblock_idx_bare), vblock_idx_tri)),
				_key_schedule128[vblock_idx_hexa_mennea]		^   _key_schedule128[vblock_idx_bare_mhepta]	* vblock_idx_hexa,
				_key_schedule128[vblock_idx_ennea_mennea]		^	_key_schedule128[vblock_idx_bare_mpenta]	* vblock_idx_ennea,
				_key_schedule128[vblock_idx_dodeca_mennea]		^	_key_schedule128[vblock_idx_bare_mtri]		* vblock_idx_dodeca
			};

			/*
				block_index * 32767 % 2³² = 4, 294, 967, 296 Garaunteed Unique 128 - bit Keystream Output blocks per Given Key / IV from this Math Operation Alone;
				Subsequent Word-Chaining Likely Extends this by Several Multpiles
			*/
			bX[0] += vblock_idx_bare * VMAX_MULROT;

			bX[0] ^= vblock_idx_bare * VMAX_MULROT_DX2;

			bX[1] ^= rol_shr(bX[0], (std::uint32_t)(vblock_idx_tri * ENNEA));

			bX[2] ^= rol_shl(bX[1], (std::uint32_t)(vblock_idx_hexa * HEXA));

			bX[3] ^= rol_shr(bX[2], (std::uint32_t)(vblock_idx_ennea * TRI));

			return _mm_load_si128(reinterpret_cast<const __m128i*>(volatile_cast<__m128*>(reinterpret_cast<noregister __m128*>(bX))));
		}

#pragma endregion

#pragma region Function Indirection / Confusion Globals

		inline bool								_pointer_tables_state = false;

		// Pointer to Keyschedule shall be appended to this table as Opposed to Creating a Singular Global Pointing to it.
		inline std::uintptr_t					_cipher_table_pointers[5]{

			(std::uintptr_t)polyc128::_key_schedule128,

			(std::uintptr_t)polyc128::s_table,
			(std::uintptr_t)polyc128::inverse_s_table,

			(std::uintptr_t)polyc128::mod_inverse_multipliers,
			(std::uintptr_t)polyc128::mod_inverse_mod256
		};

		// get_keystream_block, Whilst not part of Plaintext Mutation Phase technically, shall be the last entry appended to this array
		inline std::uintptr_t					_mutation_applicator_pointers[9]{

			(std::uintptr_t)polyc128::apply_OFS_mutator128,
			(std::uintptr_t)polyc128::apply_OFS_mutator_range,

			(std::uintptr_t)polyc128::apply_SH_mutator128,
			(std::uintptr_t)polyc128::apply_SH_mutator_range,

			(std::uintptr_t)polyc128::apply_SB_mutator128,
			(std::uintptr_t)polyc128::apply_SB_mutator_range,

			(std::uintptr_t)polyc128::apply_IM_mutator128,
			(std::uintptr_t)polyc128::apply_IM_mutator_range,

			(std::uintptr_t)polyc128::get_keystream_block
		};

#pragma endregion

#pragma region polyc128 Function Indirections / Function Pointer Encryptions

		static __symbolic void __stackcall toggle_fn_ptr_states(polyc128::polyc_cipher_mode128 mode) nex {

			std::lock_guard<std::recursive_mutex> lock(pc128_mtx);

			// If Encrypted, Decrypt the Pointer Tables Before that which they Point towards
			if (_pointer_tables_state) {

				// Encrypt the Table itself
				polycXOR::polycXOR_algo(&_cipher_table_pointers[0], sizeof(_cipher_table_pointers));

				// Simply Run the Cipher on the Pointer Table to the Mutation Subroutines - Not going through the Trouble of Determining FN size in memory and also Encrypting the Functions Themselves
				polycXOR::polycXOR_algo(&_mutation_applicator_pointers[0], sizeof(_mutation_applicator_pointers));
			}

			// Cipher the Actual Tables Pointed to by the Varying Table Indexes
			polycXOR::polycXOR_algo((c_void)_cipher_table_pointers[0], sizeof(_key_schedule128));

			if (mode == stream_offset_bitrotator_mutation)
				goto do_end;

			polycXOR::polycXOR_algo((c_void)_cipher_table_pointers[1], sizeof(s_table));
			polycXOR::polycXOR_algo((c_void)_cipher_table_pointers[2], sizeof(inverse_s_table));

			if (mode == stream_offset_bitrotator_sbox_mutation)
				goto do_end;

			polycXOR::polycXOR_algo((c_void)_cipher_table_pointers[3], sizeof(mod_inverse_multipliers));
			polycXOR::polycXOR_algo((c_void)_cipher_table_pointers[4], sizeof(mod_inverse_mod256));

		do_end:

			// If Decrypted, now Obfuscate the Pointer Tables 
			if (!_pointer_tables_state) {

				polycXOR::polycXOR_algo(&_cipher_table_pointers[0], sizeof(_cipher_table_pointers));

				polycXOR::polycXOR_algo(&_mutation_applicator_pointers[0], sizeof(_mutation_applicator_pointers));
			}

			_pointer_tables_state = _pointer_tables_state ? false : true;
		};



#pragma endregion

#pragma region polyc128 Keyschedule Generation

		static __compelled_inline imut bool __regcall polyc128_expand_key(

			imut c_void key,

			imut c_void iv,

			imut bool	wipe_key,

			imut bool	wipe_iv

		) nex {

			if (!key || !iv)
				return false;

			std::lock_guard<std::recursive_mutex> lock(pc128_mtx);

			// We Need SBox Decrypted as well as Keyschedule
			toggle_fn_ptr_states(stream_offset_bitrotator_sbox_mutation);

			// Initialize the First Key, as the First Sub-UWORD32 of the 128-bit Key
			_key_schedule128[0] = reinterpret_cast<std::uint32_t*>(key)[0];

			// Warmup First Key in Schedule, ensure it is Imprinted by the Entire IV, but Inverse the IV to Preserve Entropy when using Actual IV in Subseuent Loops (As Well, Shift Right to Accomodate for Subseuent l-shift Entropy)
			// Also, in the case of Keys Containing Repeat-Entropy (E.G 0xFFFFFFFFFFFF), Utilize Rolling Addition to Offset the Negating Affect on Key Entropy this (Could) have
			for (std::size_t i = 0; i < 4; ++i)
				_key_schedule128[0] ^= polycXOR::rol_add(rol_shr(~reinterpret_cast<std::uint32_t*>(iv)[i], (std::uint32_t)((i + 1) * (i + 1))), polycXOR::rol_add(_key_schedule128[0] % reinterpret_cast<std::uint32_t*>(iv)[i], i % 2 ? 0xF0F0F0F0 : 0x0F0F0F0F));

			for (std::size_t i = 1; i < 9; ++i) {

				// Initialize the Current Key Schedule Entry by Chaining the Previous, XOR this with a Pseudo-Random Key Subword Dictated by the Current Key Schedule Index
				_key_schedule128[i] =
					reinterpret_cast<std::uint32_t*>(key)[i - 1]
					^
					reinterpret_cast<std::uint32_t*>(key)[((i + 12) * (i + 12)) % 4];

				for (std::size_t x = 0; x < 4; ++x) {

					// Create Pseudo-Key using Byte-Table Substitution
					_key_schedule128[i] = sbox_word(_key_schedule128[i]);

					// Imprint Key with a Permutation of it's own Index in the Schedule (shl), next an IV segment with a Permutation of the Key Subword Index(x) (shr), next a Plaintext IV segment Corresponding w/ the Parent Schedule Index
					// And Last but not least, Imprint and Chain the Entropy using the Previous Key Schedule Entry
					_key_schedule128[i] = (
						rol_shl(_key_schedule128[i], (std::uint32_t)((i + 3) * (x + 3)))
						^
						rol_shr(reinterpret_cast<std::uint32_t*>(iv)[x], (std::uint32_t)((i + 6) * (x + 6)))
						)
						^
						reinterpret_cast<std::uint32_t*>(iv)[i % 4]
						^
						_key_schedule128[i - 1];

					// Create a Pseudo-IV using Byte-Substitution
					imut std::uint32_t pseudo_iv = sbox_word(reinterpret_cast<std::uint32_t*>(iv)[x]);

					// Last, XOR the Current Key Schedule Entry, with a Further Permutation (shl) of the Substituted IV, To further offput Repeat-Entropy, Utilize Rolling Subtraction between the Pseudo-IV and Key Schedule Entry
					_key_schedule128[i] ^= polycXOR::rol_sub(rol_shl(pseudo_iv, (std::uint32_t)(i * 9)), _key_schedule128[i]);
				}
			}

			toggle_fn_ptr_states(stream_offset_bitrotator_sbox_mutation);

			if (wipe_key)
				RtlZeroMemory(key, sizeof(__m128i));
			if (wipe_iv)
				RtlZeroMemory(iv, sizeof(__m128i));

			return true;
		}

#pragma endregion

#pragma region polyc-128 Cipher Routines

		/*
			decrypt_range Is Defined as the Inverse of encrypt_range
		*/
		static __compelled_inline imut bool __regcall polyc128_decrypt_range(

			c_void				dst,

			imut c_void			src,

			imut std::uintptr_t offset,

			imut std::size_t	len,

			c_void				key = nullptr,

			c_void				iv = nullptr,

			imut bool			wipe_key = false,

			imut bool			wipe_iv = false

		) nex {

#pragma region Argument Safety Guard

			if (!src || !dst || !len)
				return false;

#pragma endregion 

#pragma region  Prologue / Local Instantiation

			std::lock_guard<std::recursive_mutex> lock(pc128_mtx);

			if (key && iv)
				polyc128_expand_key(key, iv);

			if (!_is_polyc128_instantiated)
				static _auto_init_polyc128 _init_polyc128;

			imut std::uint8_t* in = reinterpret_cast<std::uint8_t*>(src);

			std::uint8_t* out = reinterpret_cast<std::uint8_t*>(dst);

			imut std::size_t			block_index = offset / sizeof(__m128i);

			imut std::uintptr_t			block_offset = offset % sizeof(__m128i);

			std::size_t					block_counter = block_index;

			std::size_t					iterator = 0;

			alignas(0x10) std::uint8_t	key_block_ui8[sizeof(__m128i)];

			alignas(0x10) std::uint8_t	plaintext_offset_block_ui8[sizeof(__m128)];

			if (_pointer_tables_state)
				toggle_fn_ptr_states(_cipher_mode128);

#pragma endregion

#pragma region Alignment / Offset Correction (Partial Block Decryption)

			if (block_offset) {

				imut __m128i		first_key_block = reinterpret_cast<ks_block_proto>(_mutation_applicator_pointers[8])(block_index);

				_mm_store_si128(reinterpret_cast<__m128i*>(key_block_ui8), first_key_block);

				imut std::size_t	chunk_size = std::min(static_cast<std::size_t>(sizeof(__m128i) - block_offset), len);

				std::memcpy(plaintext_offset_block_ui8, &in[offset], chunk_size);

				for (std::size_t i = 0; i < chunk_size; ++i)
					plaintext_offset_block_ui8[i] ^= key_block_ui8[block_offset + i];

				switch (_cipher_mode128) {

					case polyc_cipher_mode128::stream_offset_mutation: {

						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, first_key_block, block_offset, chunk_size, false);
						break;
					}

					case polyc_cipher_mode128::stream_offset_bitrotator_mutation: {

						reinterpret_cast<sh_mutator_proto>(_mutation_applicator_pointers[3])(plaintext_offset_block_ui8, first_key_block, block_offset, chunk_size, false);
						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, first_key_block, block_offset, chunk_size, false);
						break;
					}

					case polyc_cipher_mode128::stream_offset_bitrotator_sbox_mutation: {

						reinterpret_cast<sh_mutator_proto>(_mutation_applicator_pointers[3])(plaintext_offset_block_ui8, first_key_block, block_offset, chunk_size, false);
						reinterpret_cast<sb_mutator_proto>(_mutation_applicator_pointers[5])(plaintext_offset_block_ui8, chunk_size, false);
						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, first_key_block, block_offset, chunk_size, false);
						break;
					}

					case polyc_cipher_mode128::stream_offset_bitrotator_sbox_invmod_mutation: {

						reinterpret_cast<sh_mutator_proto>(_mutation_applicator_pointers[3])(plaintext_offset_block_ui8, first_key_block, block_offset, chunk_size, false);
						reinterpret_cast<sb_mutator_proto>(_mutation_applicator_pointers[5])(plaintext_offset_block_ui8, chunk_size, false);
						reinterpret_cast<im_mutator_proto>(_mutation_applicator_pointers[7])(plaintext_offset_block_ui8, block_index, chunk_size, false);
						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, first_key_block, block_offset, chunk_size, false);
						break;
					}

					default: {
						break;
					}
				}

				for (std::size_t i = 0; i < chunk_size; ++i)
					out[i] = plaintext_offset_block_ui8[i];

				iterator += chunk_size;

				++block_counter;
			}

#pragma endregion 

#pragma region Aligned Block Decryption Loop

			std::size_t				block_count = (len - iterator) / sizeof(__m128i);

			for (std::int64_t i = 0; i < (std::int64_t)block_count; ++i) {

				imut std::size_t	iter_block_index = block_counter + i;

				// Retrieve the Correponding KeyStream Block as Per Data Index / Offset (128-bit Keystream && Data Blocks Corresponding)
				imut __m128i		keystream_block = reinterpret_cast<ks_block_proto>(_mutation_applicator_pointers[8])(iter_block_index);

				imut __m128i		ciphertext128 = _mm_loadu_si128(reinterpret_cast<imut __m128i*>(in + offset + iterator + (i * sizeof(__m128i))));

				// Apply Exclusive Or / XOR to the Data Block with it's Corresponding Keystream Block to Produce the 1. Shift-Mutated Data, or 2.Mutated (Wrapping / Rolling Offset) Data, or 3. Plaintext Data
				imut __m128i		x_text128 = _mm_xor_si128(ciphertext128, keystream_block);

				__m128i				plaintext128;

				switch (_cipher_mode128) {

					case polyc_cipher_mode128::stream_offset_mutation: {

						// plaintext_offset_block_ui8 Now Contains Mutated / Wrapping Offset Data, We Inverse the Mutator (Subtract the Offsets, instead of Add) to Retrieve Original Data
						plaintext128 = reinterpret_cast<of_mutator128_proto>(_mutation_applicator_pointers[0])(x_text128, keystream_block, false);
						break;
					}
					case polyc_cipher_mode128::stream_offset_bitrotator_mutation: {

						// Perform Inverse Wrapping Bit Rotation(shift-right) with Corresponding Shift-Block Descriptor, to get Wrapping Offset-Mutated Data
						imut __m128i as_mutatedtext128 = reinterpret_cast<sh_mutator128_proto>(_mutation_applicator_pointers[2])(x_text128, keystream_block, false);
						// plaintext_offset_block_ui8 Now Contains Mutated / Wrapping Offset Data, We Inverse the Offset Mutator to Retrieve Original Data
						plaintext128 = reinterpret_cast<of_mutator128_proto>(_mutation_applicator_pointers[0])(as_mutatedtext128, keystream_block, false);
						break;
					}
					case polyc_cipher_mode128::stream_offset_bitrotator_sbox_mutation: {

						imut __m128i sb_mutatedtext128 = reinterpret_cast<sh_mutator128_proto>(_mutation_applicator_pointers[2])(x_text128, keystream_block, false);
						imut __m128i as_mutatedtext128 = reinterpret_cast<sb_mutator128_proto>(_mutation_applicator_pointers[4])(sb_mutatedtext128, false);
						plaintext128 = reinterpret_cast<of_mutator128_proto>(_mutation_applicator_pointers[0])(as_mutatedtext128, keystream_block, false);
						break;
					}
					case polyc_cipher_mode128::stream_offset_bitrotator_sbox_invmod_mutation: {

						imut __m128i sb_mutatedtext128 = reinterpret_cast<sh_mutator128_proto>(_mutation_applicator_pointers[2])(x_text128, keystream_block, false);
						imut __m128i im_mutatedtext128 = reinterpret_cast<sb_mutator128_proto>(_mutation_applicator_pointers[4])(sb_mutatedtext128, false);
						imut __m128i as_mutatedtext128 = reinterpret_cast<im_mutator128_proto>(_mutation_applicator_pointers[6])(im_mutatedtext128, iter_block_index, false);
						plaintext128 = reinterpret_cast<of_mutator128_proto>(_mutation_applicator_pointers[0])(as_mutatedtext128, keystream_block, false);
						break;
					}
					default: {

						plaintext128 = x_text128;
						break;
					}
				}

				_mm_storeu_si128(

					reinterpret_cast<__m128i*>(out + iterator + (i * sizeof(__m128i))),

					plaintext128
				);
			}

			iterator += block_count * sizeof(__m128i);
			block_counter += block_count;

#pragma endregion

#pragma region Tail Offset Decryption (Partial Decryption)

			// Handle small Tail case (Size < 0x10 bytes)
			if (iterator < len) {

				__m128i				last_key_block = reinterpret_cast<ks_block_proto>(_mutation_applicator_pointers[8])(block_counter);

				_mm_store_si128(reinterpret_cast<__m128i*>(key_block_ui8), last_key_block);

				imut std::size_t	tail_size = len - iterator;

				std::memcpy(plaintext_offset_block_ui8, in + offset + iterator, tail_size);

				for (std::size_t i = 0; i < tail_size; ++i)
					plaintext_offset_block_ui8[i] ^= key_block_ui8[i];

				switch (_cipher_mode128) {

					case polyc_cipher_mode128::stream_offset_mutation: {

						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, last_key_block, 0, tail_size, false);
						break;
					}
					case polyc_cipher_mode128::stream_offset_bitrotator_mutation: {

						reinterpret_cast<sh_mutator_proto>(_mutation_applicator_pointers[3])(plaintext_offset_block_ui8, last_key_block, 0u, tail_size, false);
						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, last_key_block, 0, tail_size, false);
						break;
					}
					case polyc_cipher_mode128::stream_offset_bitrotator_sbox_mutation: {

						reinterpret_cast<sh_mutator_proto>(_mutation_applicator_pointers[3])(plaintext_offset_block_ui8, last_key_block, 0u, tail_size, false);
						reinterpret_cast<sb_mutator_proto>(_mutation_applicator_pointers[5])(plaintext_offset_block_ui8, tail_size, false);
						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, last_key_block, 0, tail_size, false);
						break;
					}
					case polyc_cipher_mode128::stream_offset_bitrotator_sbox_invmod_mutation: {

						reinterpret_cast<sh_mutator_proto>(_mutation_applicator_pointers[3])(plaintext_offset_block_ui8, last_key_block, 0u, tail_size, false);
						reinterpret_cast<sb_mutator_proto>(_mutation_applicator_pointers[5])(plaintext_offset_block_ui8, tail_size, false);
						reinterpret_cast<im_mutator_proto>(_mutation_applicator_pointers[7])(plaintext_offset_block_ui8, block_counter, tail_size, false);
						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, last_key_block, 0, tail_size, false);
						break;
					}
					default: {
						break;
					}
				}

				for (std::size_t i = 0; i < tail_size; ++i)
					out[iterator + i] = plaintext_offset_block_ui8[i];
			}

#pragma endregion

#pragma region Epilogue

			toggle_fn_ptr_states(_cipher_mode128);

			RtlZeroMemory(plaintext_offset_block_ui8, sizeof(__m128i));

			RtlZeroMemory(key_block_ui8, sizeof(__m128i));

			return true;

#pragma endregion

		}

		static __compelled_inline imut bool __regcall polyc128_decrypt(

			c_void				dst,

			imut c_void			src,

			imut std::size_t	len,

			c_void				key = nullptr,

			c_void				iv = nullptr,

			imut bool			wipe_key = false,

			imut bool			wipe_iv = false

		) nex {

			return polyc128_decrypt_range(

				dst,

				src,

				0,

				len,

				key,

				iv,

				wipe_key,

				wipe_iv
			);
		}

		static __compelled_inline imut bool __regcall polyc128_encrypt_range(

			c_void				dst,

			imut c_void			src,

			imut std::uintptr_t offset,

			imut std::size_t	len,

			c_void				key = nullptr,

			c_void				iv = nullptr,

			imut bool			wipe_key = false,

			imut bool			wipe_iv = false

		) nex {

#pragma region Argument Safety Guard

			if (!src || !dst || !len)
				return false;

#pragma endregion 

#pragma region Prologue / Local Instantiation

			std::lock_guard<std::recursive_mutex> lock(pc128_mtx);

			if (key && iv)
				polyc128_expand_key(key, iv);

			if (!_is_polyc128_instantiated)
				static _auto_init_polyc128 _init_polyc128;

			imut std::uint8_t* in = reinterpret_cast<std::uint8_t*>(src);

			std::uint8_t* out = reinterpret_cast<std::uint8_t*>(dst);

			imut std::size_t			block_index = offset / sizeof(__m128i);

			imut std::uintptr_t			block_offset = offset % sizeof(__m128i);

			std::size_t					block_counter = block_index;

			std::size_t					iterator = 0;

			alignas(0x10) std::uint8_t	key_block_ui8[sizeof(__m128i)];

			alignas(0x10) std::uint8_t	plaintext_offset_block_ui8[sizeof(__m128)];

			if (_pointer_tables_state)
				toggle_fn_ptr_states(_cipher_mode128);

#pragma endregion

#pragma region Alignment / Offset Correction (Partial Block Encryption)

			if (block_offset) {

				imut __m128i		first_key_block = reinterpret_cast<ks_block_proto>(_mutation_applicator_pointers[8])(block_index);

				_mm_store_si128((__m128i*)key_block_ui8, first_key_block);

				imut std::size_t	chunk_size = std::min(static_cast<std::size_t>(sizeof(__m128i) - block_offset), len);

				std::memcpy(plaintext_offset_block_ui8, &in[offset], chunk_size);

				switch (_cipher_mode128) {

					case polyc_cipher_mode128::stream_offset_mutation: {

						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, first_key_block, block_offset, chunk_size, true);
						break;
					}
					case polyc_cipher_mode128::stream_offset_bitrotator_mutation: {

						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, first_key_block, block_offset, chunk_size, true);
						reinterpret_cast<sh_mutator_proto>(_mutation_applicator_pointers[3])(plaintext_offset_block_ui8, first_key_block, block_offset, chunk_size, true);
						break;
					}
					case polyc_cipher_mode128::stream_offset_bitrotator_sbox_mutation: {

						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, first_key_block, block_offset, chunk_size, true);
						reinterpret_cast<sb_mutator_proto>(_mutation_applicator_pointers[5])(plaintext_offset_block_ui8, chunk_size, true);
						reinterpret_cast<sh_mutator_proto>(_mutation_applicator_pointers[3])(plaintext_offset_block_ui8, first_key_block, block_offset, chunk_size, true);
						break;
					}
					case polyc_cipher_mode128::stream_offset_bitrotator_sbox_invmod_mutation: {

						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, first_key_block, block_offset, chunk_size, true);
						reinterpret_cast<im_mutator_proto>(_mutation_applicator_pointers[7])(plaintext_offset_block_ui8, block_index, chunk_size, true);
						reinterpret_cast<sb_mutator_proto>(_mutation_applicator_pointers[5])(plaintext_offset_block_ui8, chunk_size, true);
						reinterpret_cast<sh_mutator_proto>(_mutation_applicator_pointers[3])(plaintext_offset_block_ui8, first_key_block, block_offset, chunk_size, true);
						break;
					}
					default: {
						break;
					}
				}

				for (std::size_t i = 0; i < chunk_size; ++i)
					out[i] = plaintext_offset_block_ui8[i] ^ key_block_ui8[block_offset + i];

				iterator += chunk_size;

				++block_counter;
			}

#pragma endregion

#pragma region Aligned Block Encryption Loop

			std::size_t				block_count = (len - iterator) / sizeof(__m128i);

			for (std::int64_t i = 0; i < (std::int64_t)block_count; ++i) {

				imut std::size_t	iter_block_index = block_counter + i;

				imut __m128i		keystream_block = reinterpret_cast<ks_block_proto>(_mutation_applicator_pointers[8])(iter_block_index);

				imut __m128i		plaintext128 = _mm_loadu_si128(reinterpret_cast<imut __m128i*>(in + offset + iterator + (i * sizeof(__m128i))));

				__m128i				x_text128;

				switch (_cipher_mode128) {

					// We Offset the Plaintext Data (Weak / Minor Encryption), Prior to Strongly Encrypting it, As Extra Assurance that the Original Entropy May NOT Reflect in the Output of the Cipher
					case polyc_cipher_mode128::stream_offset_mutation: {

						x_text128 = reinterpret_cast<of_mutator128_proto>(_mutation_applicator_pointers[0])(plaintext128, keystream_block, true);
						break;
					}
																	 // To Make the Cipher Stronger, We next Perform a Circular/Wrapping Bit Rotation/Mutation on the Offset-Mutated Data, before performing Strong Encryption with the Keystream
					case polyc_cipher_mode128::stream_offset_bitrotator_mutation: {

						imut __m128i as_mutatedtext128 = reinterpret_cast<of_mutator128_proto>(_mutation_applicator_pointers[0])(plaintext128, keystream_block, true);
						x_text128 = reinterpret_cast<sh_mutator128_proto>(_mutation_applicator_pointers[2])(as_mutatedtext128, keystream_block, true);
						break;
					}
																				// The next Step Up in the Cipher - In this Mode, we do the same As the Previous Case; Except that, latter to Offset Mutation, we then Apply a Static Byte-Substitution box to the Offset Data,
																				// Which is the Circularly Bitwise Rotated Dependent on Block Index in the Stream
					case polyc_cipher_mode128::stream_offset_bitrotator_sbox_mutation: {

						imut __m128i as_mutatedtext128 = reinterpret_cast<of_mutator128_proto>(_mutation_applicator_pointers[0])(plaintext128, keystream_block, true);
						imut __m128i sb_mutatedtext128 = reinterpret_cast<sb_mutator128_proto>(_mutation_applicator_pointers[4])(as_mutatedtext128, true);
						x_text128 = reinterpret_cast<sh_mutator128_proto>(_mutation_applicator_pointers[2])(sb_mutatedtext128, keystream_block, true);

						break;
					}
					case polyc_cipher_mode128::stream_offset_bitrotator_sbox_invmod_mutation: {

						imut __m128i as_mutatedtext128 = reinterpret_cast<of_mutator128_proto>(_mutation_applicator_pointers[0])(plaintext128, keystream_block, true);
						imut __m128i im_mutatedtext128 = reinterpret_cast<im_mutator128_proto>(_mutation_applicator_pointers[6])(as_mutatedtext128, iter_block_index, true);
						imut __m128i sb_mutatedtext128 = reinterpret_cast<sb_mutator128_proto>(_mutation_applicator_pointers[4])(im_mutatedtext128, true);
						x_text128 = reinterpret_cast<sh_mutator128_proto>(_mutation_applicator_pointers[2])(sb_mutatedtext128, keystream_block, true);
						break;
					}
					default: {

						x_text128 = plaintext128;
						break;
					}
				}

				// Apply the Corresponding 128-bit Keystream Cipher Block to the 128-bit Plaintext (Or Mutated Text) Block
				imut __m128i ciphertext128 = _mm_xor_si128(x_text128, keystream_block);

				_mm_storeu_si128(reinterpret_cast<__m128i*>(out + iterator + (i * sizeof(__m128i))), ciphertext128);
			}

			iterator += block_count * sizeof(__m128i);

			block_counter += block_count;

#pragma endregion

#pragma region Tail Offset Encryption (Partial Encryption)

			// Handle small Tail case (Size < 0x10 bytes)
			if (iterator < len) {

				__m128i				last_key_block = reinterpret_cast<ks_block_proto>(_mutation_applicator_pointers[8])(block_counter);

				_mm_store_si128((__m128i*)key_block_ui8, last_key_block);

				imut std::size_t	tail_size = len - iterator;

				std::memcpy(plaintext_offset_block_ui8, in + offset + iterator, tail_size);

				switch (_cipher_mode128) {

					case polyc_cipher_mode128::stream_offset_mutation: {

						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, last_key_block, 0, tail_size, true);
						break;
					}
					case polyc_cipher_mode128::stream_offset_bitrotator_mutation: {

						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, last_key_block, 0, tail_size, true);
						reinterpret_cast<sh_mutator_proto>(_mutation_applicator_pointers[3])(plaintext_offset_block_ui8, last_key_block, 0u, tail_size, true);
						break;
					}
					case polyc_cipher_mode128::stream_offset_bitrotator_sbox_mutation: {

						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, last_key_block, 0, tail_size, true);
						reinterpret_cast<sb_mutator_proto>(_mutation_applicator_pointers[5])(plaintext_offset_block_ui8, tail_size, true);
						reinterpret_cast<sh_mutator_proto>(_mutation_applicator_pointers[3])(plaintext_offset_block_ui8, last_key_block, 0u, tail_size, true);
						break;
					}
					case polyc_cipher_mode128::stream_offset_bitrotator_sbox_invmod_mutation: {

						reinterpret_cast<of_mutator_proto>(_mutation_applicator_pointers[1])(plaintext_offset_block_ui8, last_key_block, 0, tail_size, true);
						reinterpret_cast<im_mutator_proto>(_mutation_applicator_pointers[7])(plaintext_offset_block_ui8, block_counter, tail_size, true);
						reinterpret_cast<sb_mutator_proto>(_mutation_applicator_pointers[5])(plaintext_offset_block_ui8, tail_size, true);
						reinterpret_cast<sh_mutator_proto>(_mutation_applicator_pointers[3])(plaintext_offset_block_ui8, last_key_block, 0u, tail_size, true);
						break;
					}
					default: {
						break;
					}
				}

				for (std::size_t i = 0; i < tail_size; ++i)
					out[iterator + i] = plaintext_offset_block_ui8[i] ^ key_block_ui8[i];
			}

#pragma endregion

#pragma region Epilogue

			toggle_fn_ptr_states(_cipher_mode128);

			RtlZeroMemory(plaintext_offset_block_ui8, sizeof(__m128i));

			RtlZeroMemory(key_block_ui8, sizeof(__m128i));

			return true;

#pragma endregion

		}

		static __compelled_inline imut bool __regcall polyc128_encrypt(

			c_void				dst,

			imut c_void			src,

			imut std::size_t	len,

			c_void				key = nullptr,

			c_void				iv = nullptr,

			imut bool			wipe_key = false,

			imut bool			wipe_iv = false

		) nex {

			return polyc128_encrypt_range(

				dst,

				src,

				0,

				len,

				key,

				iv,

				wipe_key,

				wipe_iv
			);
		}

#pragma endregion

	};

#pragma region Static Instancing

#pragma region polyc128 Algorithm Mode Macro Wrapper

	struct _auto_set_polyc128_mode {

		__compelled_inline __stackcall _auto_set_polyc128_mode(qengine::polyc128::polyc_cipher_mode128 mode) nex {

			static std::once_flag flag;

			std::call_once(

				flag,

				// Initialize Encrypted State for all Sensitive Globals, Regardless of Target Stream Version
				[mode]() {

					qengine::polyc128::_cipher_mode128 = mode;
				}
			);
		}
	};


// These are Defined from (most_performant && least_secure -> (least_performant && most_secure)) (for an Overwhelming Majority of Cases, LIGHTWEIGHT is Plenty Secure, on Par with AES-128 (CTR) )
#define QSET_POLYC128_MODE_LIGHT		inline _auto_set_polyc128_mode _qeng_autoinit_modality0(qengine::polyc128::polyc_cipher_mode128::streamonly);

#define QSET_POLYC128_MODE_MEDIUM		inline _auto_set_polyc128_mode _qeng_autoinit_modality1(qengine::polyc128::polyc_cipher_mode128::stream_offset_mutation);

#define QSET_POLYC128_MODE_HIGH			inline _auto_set_polyc128_mode _qeng_autoinit_modality2(qengine::polyc128::polyc_cipher_mode128::stream_offset_bitrotator_mutation);

#define QSET_POLYC128_MODE_VERYHIGH		inline _auto_set_polyc128_mode _qeng_autoinit_modality3(qengine::polyc128::polyc_cipher_mode128::stream_offset_bitrotator_sbox_mutation);

#define QSET_POLYC128_MODE_EXTREME		inline _auto_set_polyc128_mode _qeng_autoinit_modality4(qengine::polyc128::polyc_cipher_mode128::stream_offset_bitrotator_sbox_invmod_mutation);

#pragma endregion

#pragma region polyc128 AutoInit

	alignas(0x10) std::uint8_t				polyc128::_auto_init_polyc128::secure_rdata256[sizeof(__m128i) * 2];

#pragma endregion

#pragma endregion

#pragma endregion

	inline polyc128::_auto_init_polyc128	_polyc_auto_instantiator;
}

#pragma optimize("", on)

#pragma region Preprocessor

#pragma pack(pop)

#pragma endregion

#pragma region Header Guard

#endif

#pragma endregion