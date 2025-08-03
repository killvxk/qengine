#pragma region Header Guard

#ifndef QCRITICAL_H
#define QCRITICAL_H

#pragma endregion

#pragma region Imports

#include <tuple>
#include <concepts>
#include <type_traits>

#include "../qbase/qdef.hpp"

#pragma endregion

#pragma region Namespacing

namespace qengine {

	namespace qcritical {

		#pragma endregion

#pragma region Conditional Descriptor

		enum condition_t {

			GREATERTHAN,
			GREATERTHANOREQUALTO,
			LESSTHAN,
			LESSTHANOREQUALTO,
			NOTEQUALTO,
			EQUALTO
		};

#pragma endregion

#pragma region Templatized Comparison Scramblers

		template<typename T>
		struct is_cmut : std::false_type {};

		template<typename T>
		struct is_cmut<cmut<T>> : std::true_type {};

		// Helper variable template for convenience
		template<typename T>
		inline constexpr bool is_cmut_v = is_cmut<T>::value;

#define QCUMBERSOME_COMPARE_F32_MEMORY(_FLOAT1_, _FLOAT2_) qengine::qcritical::cumbersome_compare_integral_memory(std::bit_cast<std::uint32_t>((float)_FLOAT1_), std::bit_cast<std::uint32_t>((float)_FLOAT2_))
#define QCUMBERSOME_COMPARE_F64_MEMORY(_FLOAT1_, _FLOAT2_) qengine::qcritical::cumbersome_compare_integral_memory(std::bit_cast<std::uint64_t>((double)_FLOAT1_), std::bit_cast<std::uint64_t>((double)_FLOAT2_))

		/* Scrambled Comparison Operation */
		template<std::integral T, std::integral T2>
		static __compelled_inline imut bool __regcall cumbersome_compare_integral_memory(T word1, T2 word2) nex {

			cmut<bool> same = cmut<bool>(true).get();
			
			if (sizeof(decltype(word1)) != sizeof(decltype(word2))) {
				/* Align Bits of Smaller word type to the larger one */
				using c_type = std::conditional_t<(sizeof(T) > sizeof(T2)), T, T2>;

				c_type word_c = (sizeof(decltype(word1)) > sizeof(decltype(word2)) ? static_cast<decltype(word_c)>(word2) : static_cast<decltype(word_c)>(word1));

				if (sizeof(decltype(word1)) > sizeof(decltype(word2)))
					for (std::size_t i = 0; i < sizeof(decltype(word1)); ++i)
						if (same.get())
							same.set(cmut<std::uint8_t>(((word1 >> (i * 8)) & 0xFF)).get() == (cmut<std::uint8_t>(((word_c >> (i * 8)) & 0xFF)).get()));
						else
							continue;
				else
					for (std::size_t i = 0; i < sizeof(decltype(word2)); ++i)
						if (same.get())
							same.set((cmut<std::uint8_t>(((word2 >> (i * 8)) & 0xFF)).get() == cmut<std::uint8_t>(((word_c >> (i * 8)) & 0xFF)).get()));
						else
							continue;
			}
			else {
				for (std::size_t i = 0; i < sizeof(decltype(word1)); ++i)
					if (same.get())
						same.set((cmut<std::uint8_t>(((word1 >> (i * 8)) & 0xFF)).get() == cmut<std::uint8_t>(((word2 >> (i * 8)) & 0xFF)).get()));
					else
						continue;
			}

			return same.get();
		}

		template<typename... args, typename... args2, typename T, typename T2>
		__inlineable void __regcall SCRAMBLE_CRITICAL_CONDITION(

			void(*callback)(args...), 

			void(*callback_two)(args2...),

			imut std::tuple<args...>	args_one,

			imut std::tuple<args2...>	args_two,

			T							condition_one,

			T2							condition_two,

			noregister condition_t		condition = EQUALTO
		) {

			cmut<bool> evaluation = cmut<bool>(false).get();

			if constexpr (!std::is_same_v<T, std::string> && !std::is_same_v<T2, std::string> && !std::is_same_v<T, std::wstring> && !std::is_same_v<T2, std::wstring>) {

				if constexpr(std::is_integral_v<T> && std::is_integral_v<T2>) {

					switch (condition) {

						case condition_t::EQUALTO: {

							evaluation = cumbersome_compare_integral_memory(condition_one, condition_two);
							break;
						}
						case condition_t::GREATERTHAN: {

							evaluation = cmut<T>(condition_one).get() > cmut<T2>(condition_two).get();
							break;
						}
						case condition_t::GREATERTHANOREQUALTO: {

							if constexpr ((std::is_signed<T>::value && !std::is_signed<T2>::value) || (std::is_signed<T2>::value && !std::is_signed<T>::value)) {

								evaluation = cmut<T>(condition_one).get() >= cmut<T2>(condition_two).get();
							}
							else {

								evaluation = cumbersome_compare_integral_memory(condition_one, condition_two); // inlined scrambling

								if (!evaluation) // condition one failed, they are not equal. check if second part of condition is true
									evaluation = condition_one > condition_two;
							}
							break;
						}

						case condition_t::LESSTHAN: {

							evaluation = cmut<T>(condition_one).get() < cmut<T2>(condition_two).get();
							break;
						}
						case condition_t::LESSTHANOREQUALTO: {

							if constexpr (std::is_signed<T>::value && !std::is_signed<T2>::value) { // special condition here as a signed int can appear the same as an un signed int for example in memory but hold different values

								evaluation = cmut<T>(condition_one).get() <= cmut<T2>(condition_two).get();
							}
							else {

								evaluation = cumbersome_compare_integral_memory(condition_one, condition_two); // Ensure some Form of Difference Exists (&& CF-Confusion from Inlining)

								if (!evaluation) // Condition Check one Failed, they are not Equal. Check if Second part of Condition is true
									evaluation = cmut<T>(condition_one).get() < cmut<T2>(condition_two).get();
							}
							break;
						}
						case condition_t::NOTEQUALTO: {

							evaluation = cumbersome_compare_integral_memory(condition_one, condition_two) ? false : true; /* arguments are raw / integral */
							break;
						}
						default: {
							break;
						}
					}
				}
				else {

					switch (condition) {

						case condition_t::EQUALTO: {

							if		constexpr(std::is_same_v<T, float> && std::is_same_v<T2, float>)
								evaluation = QCUMBERSOME_COMPARE_F32_MEMORY(condition_one, condition_two);
							else
								evaluation = QCUMBERSOME_COMPARE_F64_MEMORY(condition_one, condition_two);
							break;
						}
						case condition_t::GREATERTHAN: {

							evaluation = cmut<T>(condition_one).get() > cmut<T2>(condition_two).get();
							break;
						}
						case condition_t::GREATERTHANOREQUALTO: {

							if		constexpr ((std::is_signed<T>::value && !std::is_signed<T2>::value) || (std::is_signed<T2>::value && !std::is_signed<T>::value)) {

								evaluation = cmut<T>(condition_one).get() >= cmut<T2>(condition_two).get();
							}
							else {

								if	constexpr(std::is_same_v<T, float> && std::is_same_v<T2, float>)
									evaluation = QCUMBERSOME_COMPARE_F32_MEMORY(condition_one, condition_two);
								else
									evaluation = QCUMBERSOME_COMPARE_F64_MEMORY(condition_one, condition_two);

								if (!evaluation) // condition one failed, they are not equal. check if second part of condition is true
									evaluation = condition_one > condition_two;
							}
							break;
						}

						case condition_t::LESSTHAN: {

							evaluation = cmut<T>(condition_one).get() < cmut<T2>(condition_two).get();
							break;
						}
						case condition_t::LESSTHANOREQUALTO: {

							if (std::is_signed<T>::value && !std::is_signed<T2>::value) { // special condition here as a signed int can appear the same as an un signed int for example in memory but hold different values

								evaluation = cmut<T>(condition_one).get() <= cmut<T2>(condition_two).get();
							}
							else {

								if	constexpr(std::is_same_v<T, float> && std::is_same_v<T2, float>)
									evaluation = QCUMBERSOME_COMPARE_F32_MEMORY(condition_one, condition_two);
								else
									evaluation = QCUMBERSOME_COMPARE_F64_MEMORY(condition_one, condition_two);

								if (!evaluation) // Condition Check one Failed, they are not Equal. Check if Second part of Condition is true
									evaluation = cmut<T>(condition_one).get() < cmut<T2>(condition_two).get();
							}
							break;
						}
						case condition_t::NOTEQUALTO: {

							if	constexpr(std::is_same_v<T, float> && std::is_same_v<T2, float>)
								evaluation = QCUMBERSOME_COMPARE_F32_MEMORY(condition_one, condition_two);
							else
								evaluation = QCUMBERSOME_COMPARE_F64_MEMORY(condition_one, condition_two);
							break;
						}
						default: {
							break;
						}
					}
				}
			}
			else {

				if (condition == condition_t::EQUALTO) {

					if		constexpr (std::is_same_v<T, std::string> && std::is_same_v<T2, std::string>)
						evaluation = accelmem::a_memcmp(static_cast<std::string>(condition_one).data(), static_cast<std::string>(condition_two).data(), static_cast<std::string>(condition_one).size()) ? false : true;
					else if constexpr (std::is_same_v<T, std::wstring> && std::is_same_v<T2, std::wstring>)
						evaluation = accelmem::a_memcmp(static_cast<std::wstring>(condition_one).data(), static_cast<std::wstring>(condition_two).data(), static_cast<std::wstring>(condition_one).size() * sizeof(wchar_t)) ? false : true;
				}
				else if (condition == condition_t::NOTEQUALTO) {

					if		constexpr (std::is_same_v<T, std::string> && std::is_same_v<T2, std::string>)
						evaluation = accelmem::a_memcmp(static_cast<std::string>(condition_one).data(), static_cast<std::string>(condition_two).data(), static_cast<std::string>(condition_one).size()) ? true : false;
					else if constexpr (std::is_same_v<T, std::wstring> && std::is_same_v<T2, std::wstring>)
						evaluation = accelmem::a_memcmp(static_cast<std::wstring>(condition_one).data(), static_cast<std::wstring>(condition_two).data(), static_cast<std::wstring>(condition_one).size() * sizeof(wchar_t)) ? true : false;
				}
			}

			if (cumbersome_compare_integral_memory(evaluation.get(), true))
				std::apply(callback, args_one);
			else
				std::apply(callback_two, args_two);
		}

#pragma endregion

#pragma region Namespacing

	}
}

#pragma endregion

#pragma region Header Guard

#endif

#pragma endregion