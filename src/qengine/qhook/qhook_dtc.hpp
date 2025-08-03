#pragma region Header Guard

#ifndef QHOOK_DTC_H
#define QHOOK_DTC_H

#pragma endregion

#pragma region Imports

#pragma region Operating System

#define NOMINMAX

#include <windows.h>

#pragma endregion

#pragma region std

#include <vector>
#include <cstdint>

#pragma endregion

#pragma region qengine

#include "../extern/ghostmut/gmutveh.hxx"

#pragma endregion

#pragma endregion

namespace qengine {

	namespace qhook {

		struct qhook_detection_t {

			bool is_hook;

			std::size_t hook_length;

			std::uintptr_t hook_address;

			std::vector<std::uint8_t> hook_data;
		};

		inline MODULEINFO qmodule_information {};

		inline bool is_qmodule_information_init = false;

		class qhook_dtc_util {
			
			public:


			/* TODO: Remove Heap / Operator New* Allocation for Return T */
			static __symbolic qhook_detection_t* __regcall analyze_fn_hook_presence(

				imut c_void fn_address,

				imut std::size_t fn_length

			) noexcept { // return nullptr if no hook detected

				if (!fn_address || !fn_length )
					return nullptr;

				if (!is_qmodule_information_init && !GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &qmodule_information, sizeof(MODULEINFO)))
					return nullptr;

				is_qmodule_information_init = true;

				csh handle;

				if( (cs_open(CS_ARCH_X86, qcs_mode, &handle) != CS_ERR_OK) || !handle )
					return nullptr;

				cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

				cs_insn* instructions = nullptr;

				auto disasm_count = cs_disasm(handle, static_cast<std::uint8_t*>(fn_address), fn_length, reinterpret_cast<std::uintptr_t>(fn_address), static_cast<std::size_t>(fn_length * 16), &instructions);

				if (!disasm_count)
					return nullptr;

				for (size_t i = 0; i < disasm_count; ++i) {
					
					if (instructions[i].id == X86_INS_JMP || instructions[i].id == X86_INS_CALL) { // if immediate check if address is in valid module address space, if regiter check last mov to register

						if (instructions[i].detail->x86.operands[0].type == X86_OP_IMM) { // jmp / call immediate address, check if in module address space
							
							imut auto& operand_address = instructions[i].detail->x86.operands[0].imm;

							if (operand_address < reinterpret_cast<std::uintptr_t>(qmodule_information.lpBaseOfDll) || operand_address > ( reinterpret_cast<std::uintptr_t>(qmodule_information.lpBaseOfDll) + qmodule_information.SizeOfImage) ) {

								auto* hook_o = new qhook_detection_t{
									true,
									static_cast<std::size_t>(instructions[i].size),
									static_cast<std::uintptr_t>(instructions[i].address)
								};

								for (size_t i = 0; i < instructions[i].size; ++i)
									hook_o->hook_data.push_back(instructions[i].bytes[i]);

								return hook_o;
							}

						}
						else if (instructions[i].detail->x86.operands[0].type = X86_OP_REG) { // jmp / call to register val, check for last write to register
							
							if (!i)
								continue;
							
							for (std::intptr_t x = i - 1; x > -1; --x) {

								if (instructions[x].id == X86_INS_MOV || instructions[x].id == X86_INS_MOVABS || instructions[x].id == X86_INS_MOVZX || instructions[x].id == X86_INS_MOVSX) { // mov reg jmp reg hook detected

									if (( instructions[x].detail->x86.operands[0].type == X86_OP_REG ) && instructions[x].detail->x86.operands[1].type == X86_OP_IMM) { // immediate mov into register

										if (instructions[x].detail->x86.operands[0].reg == instructions[i].detail->x86.operands[0].reg) {

											imut auto& operand_address = instructions[x].detail->x86.operands[1].imm;

											if (operand_address < reinterpret_cast<std::uintptr_t>(qmodule_information.lpBaseOfDll) || operand_address >(reinterpret_cast<std::uintptr_t>(qmodule_information.lpBaseOfDll) + qmodule_information.SizeOfImage)) { // mov reg jmp reg hook detected

												auto* hook_o = new qhook_detection_t{
													true,
													static_cast<std::size_t>(instructions[i].address + instructions[i].size) - static_cast<std::size_t>(instructions[x].address),
													static_cast<std::uintptr_t>(instructions[x].address)
												};

												for (auto y = instructions[x].address; y < instructions[i].address + instructions[i].size; ++y)
													hook_o->hook_data.push_back(*reinterpret_cast<std::uint8_t*>(y));

												return hook_o;
											}
										}
									}
								}

								// You need to get context() and watch rip / eip in feature to track the hook and dump the malicious code
								// It doesn't look like i properly checked for the possibility of a push imm32 instruction for 32-bit applications
								else if (instructions[x].id == X86_INS_POP) { // check if top of stack popped into our register

									if (instructions[x].detail->x86.operands[0].type == X86_OP_REG && (instructions[x].detail->x86.operands[0].reg == instructions[i].detail->x86.operands[0].reg) ) { // pop value off stack into same register, scan for last push

										if (!x)
											continue;

										for (std::intptr_t y = x - 1; y > -1; --y) { // scan for push

											if (instructions[y].id == X86_INS_PUSH && instructions[y].detail->x86.operands[0].type == X86_OP_REG) { // register pushed onto stack

												for (std::intptr_t z = y - 1; z > -1; --z) {

													if ((instructions[z].id == X86_INS_MOV) && instructions[z].detail->x86.operands[0].type == X86_OP_REG && instructions[z].detail->x86.operands[0].reg == instructions[y].detail->x86.operands[0].reg && instructions[z].detail->x86.operands[1].type == X86_OP_IMM) { // mov operation of naddress into register, any deeper recursion in the hook than this and our detection fails

														imut auto& operand_address = instructions[z].detail->x86.operands[1].imm;

														if (operand_address < reinterpret_cast<uintptr_t>(qmodule_information.lpBaseOfDll) || operand_address >(reinterpret_cast<uintptr_t>(qmodule_information.lpBaseOfDll) + qmodule_information.SizeOfImage)) { // mov reg jmp reg hook detected

															auto* hook_o = new qhook_detection_t{
																true,
																static_cast<std::size_t>(instructions[i].address + instructions[i].size) - static_cast<size_t>(instructions[z].address),
																static_cast<std::uintptr_t>(instructions[z].address)
															};

															for (auto w = instructions[y].address; w < instructions[i].address + instructions[i].size; ++w)
																hook_o->hook_data.push_back(*reinterpret_cast<std::uint8_t*>(w));

															return hook_o;
														}
													}
												}
											}
										}
									}
								}
							}
						}

					}
					else if(instructions[i].id == X86_INS_RET) { // Check last address pushed to stack
						
						if (!i)
							return nullptr;

						for (intptr_t x = i - 1; x > -1; --x) {

							if (instructions[x].id == X86_INS_PUSH && instructions[x].detail->x86.operands[0].type == X86_OP_REG) { // register pushed onto stack, look for mov into register

								if (!x)
									continue;

								for (intptr_t y = x - 1; y > -1; --y) {

									if ((instructions[y].id == X86_INS_MOV || instructions[y].id == X86_INS_MOVABS) && (instructions[y].detail->x86.operands[0].type == X86_OP_REG) && instructions[y].detail->x86.operands[1].type == X86_OP_IMM) { // mov operation of naddress into register, any deeper recursion in the hook than this and our detection fails

										imut auto& operand_address = instructions[y].detail->x86.operands[1].imm;

										if (operand_address < reinterpret_cast<uintptr_t>(qmodule_information.lpBaseOfDll) || operand_address >(reinterpret_cast<uintptr_t>(qmodule_information.lpBaseOfDll) + qmodule_information.SizeOfImage)) { // mov reg jmp reg hook detected

											auto* hook_o = new qhook_detection_t{
												true,
												static_cast<std::size_t>(instructions[i].address + instructions[i].size) - static_cast<std::size_t>(instructions[y].address),
												static_cast<std::uintptr_t>(instructions[y].address)
											};

											for (auto z = instructions[y].address; z < instructions[i].address + instructions[i].size; ++z)
												hook_o->hook_data.push_back(*reinterpret_cast<std::uint8_t*>(z));

											return hook_o;
										}
									}
								}
							}
						}
					}
				}

				if(disasm_count)
					cs_free(instructions, disasm_count);

				return nullptr;
			}

			/*
				For x64 Builds -> Your Function must Qualify as Non-Leaf, if it does not, use one of the following Macros within the Function Body:  FORCE_PDFN  OR FORCE_NLEAF()
			*/
			static __symbolic std::size_t __regcall qanalyze_fn_length(imut c_void fn_address) noexcept {
				
				if (!fn_address)
					return NULL;

				return pdfn::get_function_length(fn_address);
			}
		
		};
	}
}

#endif