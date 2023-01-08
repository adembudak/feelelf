#include "elf.h"
// #include <elf.h>

#include <cstdint>
#include <fstream>
#include <string_view>

namespace elf {

// elements of Elf32_header_t.e_ident array
constexpr std::size_t i_mag0 = 0; // File identitfication, 0x7f
constexpr std::size_t i_mag1 = 1; // File identitfication, 'E'
constexpr std::size_t i_mag2 = 2; // File identitfication, 'L'
constexpr std::size_t i_mag3 = 3; // File identitfication, 'F'

constexpr std::size_t i_class = 4; // File class
enum class_ : std::size_t {
  classNone = 0, // Invalid class
  class32 = 1,   // 32-bit objects, machines with virtual address spaces up to 4Gb
  class64 = 2    // 64-bit objects
};

constexpr std::size_t i_data = 5; // Data encoding
enum data : std::size_t {
  dataNone = 0, // Invalid data encoding
  data2lsb = 1, // 2's complement little endian: 0x0102 -> 0x02 0x01
  data2msb = 2  // 2's complement big endian   : 0x0102 -> 0x01 0x02
};

constexpr std::size_t i_version = 6; // ELF spec version

constexpr std::size_t i_osabi = 7;
enum osabi {
  none = 0,        // UNIX System V ABI
  sysv = 0,        // Alias
  hpux = 1,        // HP-UX
  netbsd = 2,      // NetBSD
  gnu = 3,         // Object uses GNU ELF extensions
  linux = 3,       // Compatibility alias
  solaris = 6,     // Sun Solaris
  aix = 7,         // IBM AIX
  irix = 8,        // SGI Irix
  freebsd = 9,     // FreeBSD
  tru64 = 10,      // Compaq TRU64 UNIX
  modesto = 11,    // Novell Modesto
  openbsd = 12,    // OpenBSD
  arm_aeabi = 64,  // ARM EABI
  arm = 97,        // ARM
  standalone = 255 // Standalone (embedded) application
};

constexpr std::size_t i_abiversion = 8;
constexpr std::size_t i_pad = 9; // padding bytes, set to 0, reserved for future use
                                 //
enum class type : Elf32_Half {
  typeNone = 0,    // No file type
  rel = 1,         // Relocatible file
  exec = 2,        // Executable file
  dyn = 3,         // Shared object file
  core = 4,        // Core file
  loproc = 0xff00, // Processor specific
  hiproc = 0xffff  // Processor specific
};

enum class machine : Elf32_Half {
  machineNone = 0, // An unknown machine
  m32,             // AT&T WE 32100
  sparc,           // Sun Microsystems SPARC
  _386,            // Intel 80386
  _68k,            // Motorola 68000
  _88k,            // Motorola 88000
  _860,            // Intel 80860
  mips,            // MIPS RS3000 (big-endian only)
  parisc,          // HP/PA
  sparc32plus,     // SPARC with enhanced instruction set
  ppc,             // PowerPC
  ppc64,           // PowerPC 64-bit
  s390,            // IBM S/390
  arm,             // Advanced RISC Machines
  sh,              // Renesas SuperH
  sparcv9,         // SPARC v9 64-bit
  ia_64,           // Intel Itanium
  x86_64,          // AMD x86-64
  vax              // DEC Vax
};

enum version : Elf32_Word { // file version
  versionNone = 0,          // Invalid version
  current = 1               // Current version
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

enum class p_type { // what are the values of this enumerators?
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

bool init(Elf32_header_t &header, const char *file) noexcept {
  std::ifstream fin;

  fin.open(file);

  fin.read((char *)header.e_ident, ei_nident);
  if(header.e_ident[i_mag0] != 0x7f || //
     header.e_ident[i_mag1] != 'E' ||  //
     header.e_ident[i_mag2] != 'L' ||  //
     header.e_ident[i_mag3] != 'F')    //
    return false;

  fin >> header.type;
  fin >> header.machine;
  fin >> header.version;
  fin >> header.entry;
  fin >> header.phoff;
  fin >> header.shoff;
  fin >> header.flags;

  fin >> header.ehsize;
  fin >> header.phentsize;
  fin >> header.phnum;

  fin >> header.shentsize;
  fin >> header.shnum;
  fin >> header.shstrndx;

  fin.close();

  return true;
}

std::string_view decode_data(Elf32_header_t &header) noexcept {
  switch(header.e_ident[i_data]) {
  case data::dataNone: return "None";
  case data::data2lsb: return "2's complement, little endian";
  case data::data2msb: return "2's complement, big endian";
  }
}

std::string_view decode_class(Elf32_header_t &header) noexcept {
  switch(header.e_ident[i_class]) {
  case class_::classNone: return "None";
  case class_::class32: return "ELF32";
  case class_::class64: return "ELF64";
  }
}

std::size_t decode_file_vesion(Elf32_header_t &header) noexcept {
  return header.e_ident[i_version];
}

std::string_view decode_os_abi(Elf32_header_t &header) noexcept {
  switch(header.e_ident[i_osabi]) {
  case osabi::sysv: return "UNIX System V ABI";
  case osabi::hpux: return "HP-UX";
  case osabi::netbsd: return "NetBSD";
  case osabi::gnu: return "Object uses GNU ELF extensions";
  // case osabi::linux: return "Compatibility alias";
  case osabi::solaris: return "Sun Solaris";
  case osabi::aix: return "IBM AIX";
  case osabi::irix: return "SGI Irix";
  case osabi::freebsd: return "FreeBSD";
  case osabi::tru64: return "Compaq TRU64 UNIX";
  case osabi::modesto: return "Novell Modesto";
  case osabi::openbsd: return "OpenBSD";
  case osabi::arm_aeabi: return "ARM EABI";
  case osabi::arm: return "ARM";
  case osabi::standalone: return "Standalone (embedded) application";
  }
}

} // namespace elf
