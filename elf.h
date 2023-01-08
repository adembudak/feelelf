#pragma once

#include <cstdint>
#include <string_view>

namespace elf {

using Elf32_Addr = std::uint32_t;
using Elf32_Off = std::uint32_t;
using Elf32_Section = std::uint16_t;
using Elf32_Versym = std::uint16_t;
using Elf_byte = unsigned char;
using Elf32_Half = std::uint16_t;
using Elf32_Sword = std::int32_t;
using Elf32_Word = std::uint32_t;

constexpr std::size_t ei_nident = 16; // Size of e_ident[]

struct Elf32_header_t {
  Elf_byte e_ident[ei_nident]; // ELF identification
  Elf32_Half type;             // object file type
  Elf32_Half machine;          // architecture
  Elf32_Word version;          // object file version
  Elf32_Addr entry;            // entry point, virtual address to transfer control
  Elf32_Off phoff;             // program header table offset, 0 if no program header
  Elf32_Off shoff;             // section header table offset, 0 if no section header
  Elf32_Word flags;            // processor specific flags
  Elf32_Half ehsize;           // ELF header size in bytes
  Elf32_Half phentsize;        // program header table size in bytes
  Elf32_Half phnum;            // number of entries in program header
  Elf32_Half shentsize;        // section header table size in bytes
  Elf32_Half shnum;            // number of entries in section header
  Elf32_Half shstrndx;         // section header table index
};

bool init(Elf32_header_t &header, const char *file) noexcept;
std::string_view decode_data(Elf32_header_t &header) noexcept;
std::string_view decode_class(Elf32_header_t &header) noexcept;
std::size_t decode_file_vesion(Elf32_header_t &header) noexcept;
std::string_view decode_os_abi(Elf32_header_t &header) noexcept;

struct Elf32_Section_Header {
  Elf32_Word name;  // name of the section
  Elf32_Word type;  // section type
  Elf32_Word flags; //
  Elf32_Addr addr;
  Elf32_Off offset;
  Elf32_Word size;
  Elf32_Word link;
  Elf32_Word info;
  Elf32_Word addralign;
  Elf32_Word entsize;
};
}
