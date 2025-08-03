#ifndef QEXCEPT_H
#define QEXCEPT_H

#include <string>

namespace qengine {

	namespace qexcept {
#pragma region Interface Prototype

		struct qexcept_t {

			std::string message;

			std::uint32_t id;

			bool iserror;
		};

#pragma endregion

#pragma region Memory Exceptions

#pragma region Preset Exceptions

		enum qexcept_mem_e {

			BAD_ALLOC,

			BAD_ACCESS,

			BAD_PTR,

			MEMORY_ALTERATION,

			THREAD_VIOLATION,

			ACCESS_VIOLATION,

			HOOK_DETECTED,

			FN_HASH_CORRUPT
		};

		static constexpr const char* qexcept_mem_str[8]{

			"BAD_ALLOC",

			"BAD_ACCESS",

			"BAD_PTR",

			"MEMORY_ALTERATION",

			"THREAD_VIOLATION",

			"ACCESS_VIOLATION",

			"HOOK_DETECTED",

			"FN_HASH_CORRUPT"
		};

#pragma endregion

#pragma region Memory Exception Prototype

		struct qexcept_mem : qexcept_t {

			inline qexcept_mem(qexcept_mem_e except_t) noexcept {

				message = std::string(qexcept_mem_str[except_t]) ;

				id = except_t;

				// Unnecessary placeholder switch statement, but it's here for future expansion
				switch (except_t) {

					case BAD_ALLOC: {

						iserror = true;
						break;
					}
					case BAD_ACCESS: {

						iserror = true;
						break;
					}
					case ACCESS_VIOLATION: {

						iserror = true;
						break;
					}
					case THREAD_VIOLATION: {

						iserror = true;
						break;
					}
					case HOOK_DETECTED: {

						iserror = true;
						break;
					}
					case FN_HASH_CORRUPT: {

						iserror = true;
						break;
					}
					default: {

						iserror = false;
						break;
					}
				}
			}
		};

#pragma endregion

#pragma region Memory Exception Presets

		struct q_badalloc : qexcept_mem {

			q_badalloc() : qexcept_mem(qexcept_mem_e::BAD_ALLOC) {  }
		};

		struct q_rogueaccess : qexcept_mem {

			std::uintptr_t original_hash;

			std::uintptr_t altered_hash;

			q_rogueaccess(std::uintptr_t oldhash, std::uintptr_t newhash) : qexcept_mem(qexcept_mem_e::MEMORY_ALTERATION) { original_hash = oldhash; altered_hash = newhash; };
		};

#pragma endregion

#pragma endregion
	}
}

#endif