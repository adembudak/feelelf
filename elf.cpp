#include "elf.h"

#include <cstdint>
#include <fstream>
#include <string_view>

namespace elf {

namespace {
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
constexpr std::size_t EI_PAD = 9; // padding bytes, set to 0, reserved for future use

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

////////////////////////////////
// special section indexes
constexpr std::size_t SHN_UNDEF = 0;
constexpr std::size_t SHN_LORESERVE = 0xff00;
constexpr std::size_t SHN_LOPROC = 0xff00;
constexpr std::size_t SHN_HIPROC = 0xff1f;
constexpr std::size_t SHN_ABS = 0xfff1;
constexpr std::size_t SHN_COMMON = 0xfff2;
constexpr std::size_t SHN_HIRESERVE = 0xffff;
}

bool init(Elf32_header_t &header, const char *file) noexcept {
  std::ifstream fin;

  fin.open(file);
  fin.read((char *)header.e_ident, EI_NIDENT);
  if(header.e_ident[EI_MAG0] != 0x7f || //
     header.e_ident[EI_MAG1] != 'E' ||  //
     header.e_ident[EI_MAG2] != 'L' ||  //
     header.e_ident[EI_MAG3] != 'F')    //
    return false;

  fin >> header.e_type;
  fin >> header.e_machine;
  fin >> header.e_version;
  fin >> header.e_entry;
  fin >> header.e_phoff;
  fin >> header.e_shoff;
  fin >> header.e_flags;

  fin >> header.e_ehsize;
  fin >> header.e_phentsize;
  fin >> header.e_phnum;

  fin >> header.e_shentsize;
  fin >> header.e_shnum;
  fin >> header.e_shstrndx;

  fin.close();

  return true;
}

std::string_view decode_data(Elf32_header_t &header) noexcept {
  switch(header.e_ident[EI_DATA]) {
  case EI_DATA::ELFDATANONE: return "None";
  case EI_DATA::ELFDATA2LSB: return "2's complement, little endian";
  case EI_DATA::ELFDATA2MSB: return "2's complement, big endian";
  }
}

std::string_view decode_class(Elf32_header_t &header) noexcept {
  switch(header.e_ident[EI_CLASS]) {
  case EI_CLASS::ELFCLASSNONE: return "None";
  case EI_CLASS::ELFCLASS32: return "ELF32";
  case EI_CLASS::ELFCLASS64: return "ELF64";
  }
}
}
