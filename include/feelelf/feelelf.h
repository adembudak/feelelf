#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <variant>
#include <vector>

namespace feelelf {

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

inline constexpr std::size_t i_mag0{0};       // File identitfication, 0x7f
inline constexpr std::size_t i_mag1{1};       // File identitfication, 'E'
inline constexpr std::size_t i_mag2{2};       // File identitfication, 'L'
inline constexpr std::size_t i_mag3{3};       // File identitfication, 'F'
inline constexpr std::size_t i_class{4};      // File class
inline constexpr std::size_t i_data{5};       // Data encoding
inline constexpr std::size_t i_version{6};    // ELF spec version
inline constexpr std::size_t i_osabi{7};      // OS ABI
inline constexpr std::size_t i_abiversion{8}; // ABI version
inline constexpr std::size_t i_pad{9};        // [9, 16) padding bytes, set to 0, reserved for future use
inline constexpr std::size_t i_nident{16};    // Size of e_ident[]

struct Elf32_Header_t {
  Elf_byte ident[i_nident]; // ELF identification
  Elf32_Half type;          // object file type
  Elf32_Half machine;       // architecture
  Elf32_Word version;       // object file version
  Elf32_Addr entryPoint;    // entry point, virtual address to transfer control
  Elf32_Off phOffset;       // program header table offset, 0 if no program header
  Elf32_Off shOffset;       // section header table offset, 0 if no section header
  Elf32_Word flags;         // processor specific flags
  Elf32_Half size;          // ELF header size in bytes
  Elf32_Half phEntrySize;   // program header table size in bytes
  Elf32_Half phNumber;      // number of entries in program header
  Elf32_Half shEntrySize;   // section header table size in bytes
  Elf32_Half shNumber;      // number of entries in section header
  Elf32_Half shStringIndex; // section header table index
};

struct Elf64_Header_t {
  Elf_byte ident[i_nident];
  Elf64_Half type;
  Elf64_Half machine;
  Elf64_Word version;
  Elf64_Addr entryPoint;
  Elf64_Off phOffset;
  Elf64_Off shOffset;
  Elf64_Word flags;
  Elf64_Half size;
  Elf64_Half phEntrySize;
  Elf64_Half phNumber;
  Elf64_Half shEntrySize;
  Elf64_Half shNumber;
  Elf64_Half shStringIndex;
};
using Elf_Header_t = std::variant<Elf32_Header_t, Elf64_Header_t>;

struct Elf32_Program_Header_t {
  Elf32_Word type;   // segment type
  Elf32_Off offset;  // segment file offset
  Elf32_Addr vaddr;  // segment virtual address
  Elf32_Addr paddr;  // segment physical address
  Elf32_Word filesz; // segment size in file
  Elf32_Word memsz;  // segment size in memory
  Elf32_Word flags;  // segment flags
  Elf32_Word align;  // segment alignment
};

struct Elf64_Program_Header_t {
  Elf64_Word type;
  Elf64_Word flags;
  Elf64_Off offset;
  Elf64_Addr vaddr;
  Elf64_Addr paddr;
  Elf64_Xword filesz;
  Elf64_Xword memsz;
  Elf64_Xword align;
};
using Program_Header_t = std::variant<Elf32_Program_Header_t, Elf64_Program_Header_t>;

struct Elf32_Section_Header_t {
  Elf32_Word name;      // section name (string table index)
  Elf32_Word type;      // section type
  Elf32_Word flags;     // section flags
  Elf32_Addr addr;      // section virtual addr at execution
  Elf32_Off offset;     // section file offset
  Elf32_Word size;      // section size in bytes
  Elf32_Word link;      // link to another section
  Elf32_Word info;      // additional section information
  Elf32_Word addralign; // section alignment
  Elf32_Word entsize;   // entry size if section holds table
};

struct Elf64_Section_Header_t {
  Elf64_Word name;
  Elf64_Word type;
  Elf64_Xword flags;
  Elf64_Addr addr;
  Elf64_Off offset;
  Elf64_Xword size;
  Elf64_Word link;
  Elf64_Word info;
  Elf64_Xword addralign;
  Elf64_Xword entsize;
};
using Section_Header_t = std::variant<Elf32_Section_Header_t, Elf64_Section_Header_t>;

struct Elf32_Symbol_t {
  Elf32_Word name;  // symbol name (string tbl index)
  Elf32_Addr value; // symbol value
  Elf32_Word size;  // symbol size
  Elf_byte info;    // symbol type and binding
  Elf_byte other;   // symbol Visibility
  Elf32_Half shndx; // section index
};

struct Elf64_Symbol_t {
  Elf64_Word name;
  Elf_byte info;
  Elf_byte other;
  Elf32_Half shndx;
  Elf64_Addr value;
  Elf64_Off size;
};
using Symbol_t = std::variant<Elf32_Symbol_t, Elf64_Symbol_t>;

class FileHeader {
  Elf_Header_t elf_header;
  std::vector<Program_Header_t> program_headers;
  std::vector<Section_Header_t> section_headers;

public:
  [[nodiscard]] auto open(const char *file) noexcept -> bool;
  auto decode() noexcept -> void;

  // clang-format off
  [[nodiscard]] auto identificationArray() noexcept -> std::span<Elf_byte> const; // ident
  [[nodiscard]] auto fileClass()        noexcept -> std::string_view const; // ident[i_class]
  [[nodiscard]] auto fileDataEncoding() noexcept -> std::string_view const; // ident[i_data]
  [[nodiscard]] auto fileVersion()      noexcept -> std::string_view const; // ident[i_version]
  [[nodiscard]] auto osABI()            noexcept -> std::string_view const; // ident[i_osabi]
  [[nodiscard]] auto ABIVersion()       noexcept -> int;                    // ident[i_abiversion]

  [[nodiscard]] auto type()                noexcept -> std::string_view const;
  [[nodiscard]] auto machine()             noexcept -> std::string_view const;
  [[nodiscard]] auto version()             noexcept -> int const;
  [[nodiscard]] auto entryPoint()          noexcept -> int const;
  [[nodiscard]] auto programHeaderOffset() noexcept -> std::size_t const;
  [[nodiscard]] auto sectionHeaderOffset() noexcept -> std::size_t const;

  [[nodiscard]] auto programHeaders()    noexcept -> const decltype(program_headers) &;
  [[nodiscard]] auto sectionHeaders()    noexcept -> const decltype(section_headers) &;

  [[nodiscard]] auto programHeaderType(const std::size_t phType) noexcept -> std::string_view const;
  [[nodiscard]] auto programHeaderFlag(const std::size_t phFlag) noexcept -> std::string_view const;

  [[nodiscard]] auto flags()             noexcept -> int const;
  [[nodiscard]] auto headerSize()        noexcept -> int const;

  [[nodiscard]] auto programHeaderSize() noexcept -> int const;
  [[nodiscard]] auto numProgramHeaders() noexcept -> int const;

  [[nodiscard]] auto sectionHeaderEntrySize() noexcept -> std::size_t const;
  [[nodiscard]] auto numSectionHeaders() noexcept -> int const;
  [[nodiscard]] auto sectionHeaderStringTableIndex() noexcept -> int const;

  [[nodiscard]] auto sectionHeaderType(const std::size_t shType) noexcept -> std::string_view const;
  [[nodiscard]] auto sectionHeaderName(const std::size_t shName) noexcept -> std::string_view const;
  [[nodiscard]] auto sectionHeaderFlags(const std::size_t shFlags) noexcept -> std::string_view const;

private:
  [[nodiscard]] auto hasProgramHeaders() noexcept -> bool const;
  [[nodiscard]] auto hasSectionHeaders() noexcept -> bool const;
  [[nodiscard]] auto isELF() noexcept -> bool const;
  [[nodiscard]] auto is64bit() noexcept -> bool const;
};

static_assert(std::copyable<FileHeader>);
static_assert(std::movable<FileHeader>);
static_assert(std::semiregular<FileHeader>);

} // naemspace feelelf
