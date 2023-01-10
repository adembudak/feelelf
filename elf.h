#pragma once

#include <cstdint>
#include <string_view>

namespace elf {

using Elf_byte = unsigned char;

using Elf32_Half = std::uint16_t;
using Elf32_Sword = std::int32_t;
using Elf32_Word = std::uint32_t;

using Elf32_SXword = std::int64_t;
using Elf32_Xword = std::uint64_t;

using Elf32_Addr = std::uint32_t;
using Elf32_Off = std::uint32_t;
using Elf32_Section = std::uint16_t;
using Elf32_Versym = std::uint16_t;

using Elf64_Half = std::uint16_t;
using Elf64_Sword = std::int32_t;
using Elf64_Word = std::uint32_t;

using Elf64_SXword = std::int64_t;
using Elf64_Xword = std::uint64_t;

using Elf64_Addr = std::uint64_t;
using Elf64_Off = std::uint64_t;
using Elf64_Section = std::uint16_t;
using Elf64_Versym = std::uint16_t;

constexpr std::size_t i_mag0 = 0;    // File identitfication, 0x7f
constexpr std::size_t i_mag1 = 1;    // File identitfication, 'E'
constexpr std::size_t i_mag2 = 2;    // File identitfication, 'L'
constexpr std::size_t i_mag3 = 3;    // File identitfication, 'F'
constexpr std::size_t i_class = 4;   // File class
constexpr std::size_t i_data = 5;    // Data encoding
constexpr std::size_t i_version = 6; // ELF spec version
constexpr std::size_t i_osabi = 7;
constexpr std::size_t i_abiversion = 8;
constexpr std::size_t i_pad = 9;     // padding bytes, set to 0, reserved for future use
constexpr std::size_t i_nident = 16; // Size of e_ident[]

struct Elf64_header_t {
  Elf_byte ident[i_nident]; // ELF identification
  Elf64_Half type;          // object file type
  Elf64_Half machine;       // architecture
  Elf64_Word version;       // object file version
  Elf64_Addr entry;         // entry point, virtual address to transfer control
  Elf64_Off phoff;          // program header table offset, 0 if no program header
  Elf64_Off shoff;          // section header table offset, 0 if no section header
  Elf64_Word flags;         // processor specific flags
  Elf64_Half ehsize;        // ELF header size in bytes
  Elf64_Half phentsize;     // program header table size in bytes
  Elf64_Half phnum;         // number of entries in program header
  Elf64_Half shentsize;     // section header table size in bytes
  Elf64_Half shnum;         // number of entries in section header
  Elf64_Half shstrndx;      // section header table index
};

bool init(Elf64_header_t &header, const char *file) noexcept;
std::string_view decode_data(Elf64_header_t &header) noexcept;
std::string_view decode_class(Elf64_header_t &header) noexcept;
std::size_t decode_file_version(Elf64_header_t &header) noexcept;
std::string_view decode_os_abi(Elf64_header_t &header) noexcept;
std::string_view decode_machine(Elf64_header_t &header) noexcept;
std::string_view decode_type(Elf64_header_t &header) noexcept;

struct Elf32_Section_Header {
  Elf64_Word name;  // name of the section
  Elf64_Word type;  // section type
  Elf64_Word flags; //
  Elf64_Addr addr;
  Elf64_Off offset;
  Elf64_Word size;
  Elf64_Word link;
  Elf64_Word info;
  Elf64_Word addralign;
  Elf64_Word entsize;
};
}
