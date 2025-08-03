#pragma region Header Guard

#ifndef QGEN_H
#define QGEN_H

#pragma endregion

#pragma region Imports

#include <random>
#include <chrono>
#include <climits>
#include <unordered_map>

#pragma region qengine

#include "../qbase/qdef.hpp"
#include "../qimport/qimport.hpp"

#pragma endregion

#pragma region ASMJIT

// If your bin folder outputs a static library, you don't need it. this seems to cause an unnecessary binary output in some cases.
#define ASMJIT_STATIC

#include "../extern/asmjit/asmjit.h"

#pragma endregion

#pragma endregion

#pragma region Preprocessor

#ifdef NDEBUG

#ifdef _WIN64

#pragma comment(lib, "asmjit64.lib")

#else

#pragma comment(lib, "asmjit32.lib")

#endif

#else

#ifdef _WIN64

#pragma comment(lib, "asmjit_d64.lib")

#else

#pragma comment(lib, "asmjit_d32.lib")

#endif

#endif

#pragma endregion

namespace qengine {

	namespace qmorph{

		namespace qgen {

	#pragma region Opcode Descriptor(s)

			enum asm_register64 {
				RAX, RBX, RCX, RDX, RSI, RDI,
				R8, R9, R10, R11, R12, R13, R14, R15
			};

			enum asm_register32 {
				EAX, EBX, ECX, EDX, ESI, EDI
			};

			enum asm_preamble {
				MOV, PUSH, POP, CALL,
				OR, XOR, AND, SUB, INC, DEC, JMP,
				ADD, SHL, ROR, BSWAP
			};

#pragma endregion

			// Max Reasonable 
			alignas(0x10) inline std::uint8_t insn_data_buffer[0x20];

			// Maximum Carryover Length in case of Severe Misalignment is PAGE_SIZE - 1 , most Systems have Maximum Pagesize of 4096 bytes
			alignas(0x10) inline std::uint8_t insn_output_buffer[0xFFF];

			class asm_generator {

			private:

				static __inlineable asmjit::x86::Gp generate_random_register64() noexcept {

					std::default_random_engine eng(std::time(nullptr));
					std::uniform_int_distribution<int> dist(0, 13);          // 14 regs

					switch (static_cast<asm_register64>(dist(eng))) {

						case RAX:  return asmjit::x86::rax;
						case RBX:  return asmjit::x86::rbx;
						case RCX:  return asmjit::x86::rcx;
						case RDX:  return asmjit::x86::rdx;
						case RSI:  return asmjit::x86::rsi;
						case RDI:  return asmjit::x86::rdi;
						case R8:   return asmjit::x86::r8;
						case R9:   return asmjit::x86::r9;
						case R10:  return asmjit::x86::r10;
						case R11:  return asmjit::x86::r11;
						case R12:  return asmjit::x86::r12;
						case R13:  return asmjit::x86::r13;
						case R14:  return asmjit::x86::r14;
						case R15:  return asmjit::x86::r15;
						default:   return asmjit::x86::rax;   // never hit
					}
				}

				static inline asmjit::x86::Gp generate_random_register32() noexcept {

					using namespace asmjit;

					static std::default_random_engine eng(
						std::time(nullptr));

					static std::uniform_int_distribution<int> dist(0, 4);
					switch (dist(eng)) {

						case EAX: return x86::eax;
						case EBX: return x86::ebx;
						case ECX: return x86::ecx;
						case EDX: return x86::edx;
						default:  return x86::esi;
					}
				}

				static __compelled_inline imut std::size_t __regcall generate_insn(
					
					asm_preamble insn_t
				
				) noexcept {

					using namespace asmjit;

					// RNG for immediates
					static std::default_random_engine eng(std::time(nullptr));
					static std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);

					JitRuntime rt;
					CodeHolder code;
					code.init(rt.environment());

					x86::Assembler a(&code);

						// -------------------------------------------------------------------
						switch (insn_t) {
						case MOV:
	#ifdef _WIN64
							a.mov(generate_random_register64(), generate_random_register64());
	#else
							a.mov(generate_random_register32(), imm(dist(eng)));
	#endif
							break;

						case PUSH:
							a.push(imm(dist(eng)));
							break;

						case POP:
	#ifdef _WIN64
							a.pop(generate_random_register64());
	#else
							a.pop(generate_random_register32());
	#endif
							break;

						case CALL:
							a.call(imm(dist(eng)));           // wrapped in imm()
							break;

						case OR:
	#ifdef _WIN64
							a.or_(generate_random_register64(), generate_random_register64());
	#else
							a.or_(generate_random_register32(), generate_random_register32());
	#endif
							break;

						case XOR:
	#ifdef _WIN64
							a.xor_(generate_random_register64(), generate_random_register64());
	#else
							a.xor_(generate_random_register32(), generate_random_register32());
	#endif
							break;

						case AND:
	#ifdef _WIN64
							a.and_(generate_random_register64(), generate_random_register64());
	#else
							a.and_(generate_random_register32(), generate_random_register32());
	#endif
							break;

						case SUB:
	#ifdef _WIN64
							a.sub(generate_random_register64(), generate_random_register64());
	#else
							a.sub(generate_random_register32(), generate_random_register32());
	#endif
							break;

						case JMP:                             // register‑indirect jmp
	#ifdef _WIN64
							a.jmp(generate_random_register64());
	#else
							a.jmp(generate_random_register32());
	#endif
							break;

						case ADD:
	#ifdef _WIN64
							a.add(generate_random_register64(), generate_random_register64());
	#else
							a.add(generate_random_register32(), generate_random_register32());
	#endif
							break;

						case SHL:
	#ifdef _WIN64
							a.shl(generate_random_register64(), 1);
	#else
							a.shl(generate_random_register32(), 1);
	#endif
							break;

						case ROR:
	#ifdef _WIN64
							a.ror(generate_random_register64(), 1);
	#else
							a.ror(generate_random_register32(), 1);
	#endif
							break;

						case BSWAP:
	#ifdef _WIN64
							a.bswap(generate_random_register64());
	#else
							a.bswap(generate_random_register32());
	#endif
							break;

						case INC:

	#ifdef _WIN64
							a.inc(generate_random_register64());
	#else
							a.inc(generate_random_register32());
	#endif
						case DEC:

	#ifdef _WIN64
							a.dec(generate_random_register64());
	#else
							a.dec(generate_random_register32());
	#endif

						default: break;
					}

					// -------------------------------------------------------------------
					void* fn = nullptr;

					if (rt.add(&fn, &code) != asmjit::kErrorOk)
						return NULL;

					accelmem::a_memcpy(insn_data_buffer, fn, code.codeSize());

					return code.codeSize();
				}

			public:

				static __inlineable imut std::size_t __regcall generate_assembly(uint32_t length) noexcept {

					// Ensure Length <= Output Buffer Size ;; Sometimes in DEBUG Builds, the Interrupt Region Lengths Return as Longer than they Should be Able to
					if (!length || length > sizeof(insn_output_buffer))
						return 0;

#pragma region RNG Locals

					std::default_random_engine engine_r(std::time(nullptr));

					std::uniform_int_distribution<short> distributor_o(0, 14);

#pragma endregion

					intptr_t last_insn_index = -1;

					size_t bytes_written = static_cast<size_t>(0);

					do {

						auto remaining = length - bytes_written;

						asm_preamble insn;

						std::pair<char, char> insn_size_data;

						auto word_r = distributor_o(engine_r);

						if (remaining >= 7) {
							if (word_r >= 10)			insn = MOV;
							else if (word_r >= 7)       insn = PUSH;
							else                        insn = CALL;
						}
						else if (remaining >= 3) {
							if (word_r >= 14)			insn = POP;
							else if (word_r == 13)      insn = XOR;
							else if (word_r == 12)      insn = AND;
							else if (word_r == 11)      insn = SUB;
							else if (word_r == 10)      insn = INC;
							else if (word_r == 9)       insn = DEC;
							else if (word_r == 8)       insn = JMP;
							else if (word_r == 7)       insn = OR;
							else if (word_r == 6)       insn = ADD;
							else if (word_r == 5)       insn = SHL;
							else if (word_r == 4)       insn = ROR;
							else                        insn = BSWAP;  // 3,2,1,0 fall here
						}
						else { // Fill remaining padding with NOP instructions

							// Safe Enough, yet Approximate Size for Amo0unt of NOP insns we would need Anyways
							alignas(0x10) static imut imutexpr std::uint8_t alloc_nop[0x3]{ 0x90u, 0x90u, 0x90u };

							accelmem::a_memcpy(insn_output_buffer + bytes_written, alloc_nop, remaining);

							goto do_ret; // this may throw compile-time errors with C++ 20 bcuz gotos r scary

							break;
						}

						imut std::size_t alloc_insn_sz = generate_insn(insn);

						accelmem::a_memcpy(insn_output_buffer + bytes_written, insn_data_buffer, alloc_insn_sz);

						bytes_written += alloc_insn_sz;

					} while (bytes_written < length);

				do_ret:

					SECURE_ZERO_MEMORY(insn_data_buffer, sizeof(insn_data_buffer));

					return bytes_written;
				}
			};

#pragma region Namespacing

		}
	}
}

#pragma endregion

#pragma region Header Guard

#endif

#pragma endregion