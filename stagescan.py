import pefile
import mmap
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import os

INSTRUCTIONS = [] # i hate the upper snake case but i also hate warnings

def find_this_random_string_that_lets_us_get_internal_studio(pe, input_data):
    target_string = b"VoiceChatEnableApiSecurityCheck"
    string_addr = None

    for section in pe.sections:
        if section.Name.decode().strip('\x00') in [".rdata", ".data"]:
            start = section.PointerToRawData
            size = section.SizeOfRawData
            end = start + size
            section_data = input_data[start:end]

            index = section_data.find(target_string)
            if index != -1:
                string_addr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + index
                break
    return string_addr

def get_jz_that_controls_internal_studio(random_string_internal_studio):
    identifier_function = None
    patch_addr = None

    for i, insn in enumerate(INSTRUCTIONS):
        for op in insn.operands:
            if op.type == 1:
                if op.mem.base == 0x8:
                    if op.mem.displacement == random_string_internal_studio and insn.mnemonic != 'lea':
                        for back in range(i - 1, -1, -1):
                            prev_insn = INSTRUCTIONS[back]
                            if prev_insn.mnemonic == 'call':
                                if back > 0 and INSTRUCTIONS[back - 1].mnemonic == 'lea':
                                    continue
                                identifier_function = prev_insn.address
                                break
                        if identifier_function:
                            break

    if identifier_function:
        for i, insn in enumerate(INSTRUCTIONS):
            if insn.mnemonic == 'call' and insn.address == identifier_function:
                prev_insn = INSTRUCTIONS[i - 1]
                if prev_insn.mnemonic == 'je':
                    patch_addr = prev_insn.address
                    break
    else:
        print("Error: Could not find the identifier function. Please report to https://github.com/7ap/internal-studio-patcher/issues")
        exit(1)

    return patch_addr

def start(input_data, output_path):
    pe = pefile.PE(data=input_data)

    str_addr = find_this_random_string_that_lets_us_get_internal_studio(pe, input_data)
    if not str_addr:
        print("Error: Could not find the string to get internal studio. Please report to https://github.com/7ap/internal-studio-patcher/issues")
        exit(1)

    text_section = None
    for section in pe.sections:
        if section.Name.decode().strip('\x00') == ".text":
            text_section = section
            break

    if not text_section:
        print(".text section missing. This should never happen.")
        exit(1)

    text_start = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress
    text_size = text_section.SizeOfRawData
    text_bytes = input_data[text_section.PointerToRawData:text_section.PointerToRawData + text_size]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for insn in md.disasm(text_bytes, text_start):
        INSTRUCTIONS.append(insn)
      
    patch_addr = get_jz_that_controls_internal_studio(str_addr)
    if patch_addr:
        offset = text_section.PointerToRawData + (patch_addr - text_start)
        insn_len = next((insn.size for insn in INSTRUCTIONS if insn.address == patch_addr), 0)
        
        input_data[offset:offset + insn_len] = b'\x90' * insn_len

        with open(output_path, 'wb') as f:
            f.write(input_data)
    else:
        print("Error: Could not find the address to patch. Please report to https://github.com/7ap/internal-studio-patcher/issues")
        exit(1)
