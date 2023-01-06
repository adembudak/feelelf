// ELF header parser based on: man 5 elf

#include <CLI/CLI.hpp>
#include <fmt/format.h>

#include <cstdint>

using Elf32_Addr = std::uint32_t;
using Elf32_Off = std::uint32_t;
using Elf32_Section = std::uint16_t;
using Elf32_Versym = std::uint16_t;
using Elf_byte = unsigned char;
using Elf32_Half = std::uint16_t;
using Elf32_Sword = std::int32_t;
using Elf32_Word = std::uint32_t;

// elements of Elf32_header_t.e_ident array
constexpr std::size_t EI_MAG0 = 0; // File identitfication, 0x7f
constexpr std::size_t EI_MAG1 = 1; // File identitfication, 'E'
constexpr std::size_t EI_MAG2 = 2; // File identitfication, 'L'
constexpr std::size_t EI_MAG3 = 3; // File identitfication, 'F'

constexpr std::size_t EI_CLASS = 4; // File class
enum EI_CLASS : std::size_t {
  ELFCLASSNONE = 0, // Invalid class
  ELFCLASS32 = 1,   // 32-bit objects, machines with virtual address spaces up to 4Gb
  ELFCLASS64 = 2    // 64-bit objects
};

constexpr std::size_t EI_DATA = 5; // Data encoding
enum EI_DATA : std::size_t {
  ELFDATANONE = 0, // Invalid data encoding
  ELFDATA2LSB = 1, // 2's complement little endian: 0x0102 -> 0x02 0x01
  ELFDATA2MSB = 2  // 2's complement big endian   : 0x0102 -> 0x01 0x02
};

constexpr std::size_t EI_VERSION = 6; // ELF spec version

constexpr std::size_t EI_OSABI = 7;
enum e_osabi {
  ELFOSABI_NONE = 0,  // Same as ELFOSABI_SYSV
  ELFOSABI_SYSV,      // UNIX System V ABI
  ELFOSABI_HPUX,      // HP-UX ABI
  ELFOSABI_NETBSD,    // NetBSD ABI
  ELFOSABI_LINUX,     // Linux ABI
  ELFOSABI_SOLARIS,   // Solaris ABI
  ELFOSABI_IRIX,      // IRIX ABI
  ELFOSABI_FREEBSD,   // FreeBSD ABI
  ELFOSABI_TRU64,     // TRU64 UNIX ABI
  ELFOSABI_ARM,       // ARM architecture ABI
  ELFOSABI_STANDALONE // Stand-alone (embedded) ABI
};

constexpr std::size_t EI_ABIVERSION = 8;
constexpr std::size_t EI_PAD = 9;     // padding bytes, set to 0, reserved for future use
constexpr std::size_t EI_NIDENT = 16; // Size of e_ident[]

enum e_type_ : Elf32_Half {
  ET_NONE = 0,        // No file type
  ET_REL = 1,         // Relocatible file
  ET_EXEC = 2,        // Executable file
  ET_DYN = 3,         // Shared object file
  ET_CORE = 4,        // Core file
  ET_LOPROC = 0xff00, // Processor specific
  ET_HIPROC = 0xffff  // Processor specific
};

enum e_machine_ : Elf32_Half {
  EM_NONE = 0,    // An unknown machine
  EM_M32,         // AT&T WE 32100
  EM_SPARC,       // Sun Microsystems SPARC
  EM_386,         // Intel 80386
  EM_68K,         // Motorola 68000
  EM_88K,         // Motorola 88000
  EM_860,         // Intel 80860
  EM_MIPS,        // MIPS RS3000 (big-endian only)
  EM_PARISC,      // HP/PA
  EM_SPARC32PLUS, // SPARC with enhanced instruction set
  EM_PPC,         // PowerPC
  EM_PPC64,       // PowerPC 64-bit
  EM_S390,        // IBM S/390
  EM_ARM,         // Advanced RISC Machines
  EM_SH,          // Renesas SuperH
  EM_SPARCV9,     // SPARC v9 64-bit
  EM_IA_64,       // Intel Itanium
  EM_X86_64,      // AMD x86-64
  EM_VAX          // DEC Vax
};

enum e_version_ : Elf32_Word { // file version
  EV_NONE = 0,                 // Invalid version
  EV_CURRENT = 1               // Current version
};

struct Elf32_header_t {
  Elf_byte e_ident[EI_NIDENT]; // ELF identification
  e_type_ e_type;              // object file type
  e_machine_ e_machine;        // architecture
  e_version_ e_version;        // object file version
  Elf32_Addr e_entry;          // entry point, virtual address to transfer control
  Elf32_Off e_phoff;           // program header table offset, 0 if no program header
  Elf32_Off e_shoff;           // section header table offset, 0 if no section header
  Elf32_Word e_flags;          // processor specific flags
  Elf32_Half e_ehsize;         // ELF header size in bytes
  Elf32_Half e_phentsize;      // program header table size in bytes
  Elf32_Half e_phnum;          // number of entries in program header
  Elf32_Half e_shentsize;      // section header table size in bytes
  Elf32_Half e_shnum;          // number of entries in section header
  Elf32_Half e_shstrndx;       // section header table index
} Elf32_Ehdr;

struct Elf32_program_header_t {
  uint32_t p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  uint32_t p_filesz;
  uint32_t p_memsz;
  uint32_t p_flags;
  uint32_t p_align;
} Elf32_Phdr;

enum p_type_ { // what are the values of this enumerators?
  PT_NULL,
  PT_LOAD,
  PT_DYNAMIC,
  PT_INTERP,
  PT_NOTE,
  PT_SHLIB,
  PT_PHDR,
  PT_LOPROC,
  PT_HIPROC,
  PT_GNU_STACK
};

enum e_flags : Elf32_Word {};

struct Elf32_Section_Header {
  Elf32_Word sh_name;  // name of the section
  Elf32_Word sh_type;  // section type
  Elf32_Word sh_flags; //
  Elf32_Addr sh_addr;
  Elf32_Off sh_offset;
  Elf32_Word sh_size;
  Elf32_Word sh_link;
  Elf32_Word sh_info;
  Elf32_Word sh_addralign;
  Elf32_Word sh_entsize;
} Elf32_Shdr;

// special section indexes
constexpr std::size_t SHN_UNDEF = 0;
constexpr std::size_t SHN_LORESERVE = 0xff00;
constexpr std::size_t SHN_LOPROC = 0xff00;
constexpr std::size_t SHN_HIPROC = 0xff1f;
constexpr std::size_t SHN_ABS = 0xfff1;
constexpr std::size_t SHN_COMMON = 0xfff2;
constexpr std::size_t SHN_HIRESERVE = 0xffff;

int main(int argc, const char *argv[]) {
  Elf32_header_t Elf32_Ehdr;
  // Elf32_Ehdr.e_ident[EI_MAG0] == 0x7f;
  // Elf32_Ehdr.e_ident[EI_MAG1] == 'E';
  // Elf32_Ehdr.e_ident[EI_MAG2] == 'L';
  // Elf32_Ehdr.e_ident[EI_MAG3] == 'F';
}

/*
- iABI object file format, the ELF (Executable and Linking Format)
- object file types: relocatible file, executible file, shared object file
- object files created by the assembler and link editor

        Linking View                 Execution View
  +--------------------------+  +--------------------------+
  |       ELF header         |  |      ELF header          |
  |---------------------------  |---------------------------
  |Program header table (opt)|  | Program header table     |
  |--------------------------|  |--------------------------|
  |       Section 1          |  |                          |
  |--------------------------|  |       Segment 1          |
  |           ...            |  |                          |
  |--------------------------|  |--------------------------|
  |       Section N          |  |                          |
  |--------------------------|  |       Segment 2          |
  |        ...               |  |       ...                |
  |--------------------------|  |--------------------------|
  |   Section header table   |  |  Section header table    |
  |                          |  |          (opt)           |
  +--------------------------+  +--------------------------+
*/
