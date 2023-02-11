#include <feelelf/feelelf.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <string_view>
#include <vector>

namespace feelelf {

// clang-format off
template <class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template <class... Ts> overloaded(Ts...) -> overloaded<Ts...>;
// clang-format on

std::ifstream fin;

auto FileHeader::open(const char *file) noexcept -> bool {
  fin.open(file, std::ios::binary);

  if(!isELF()) return false;

  if(is64bit()) elf_header = Elf64_Header_t{};
  else elf_header = Elf32_Header_t{};

  return true;
}

auto FileHeader::decode() noexcept -> void {
  fin.seekg(0);
  // clang-format off
  std::visit(
    overloaded{
      [&](Elf32_Header_t &x32) {
            fin.read(reinterpret_cast<char *>(&x32), sizeof(decltype(x32)));

            program_headers.resize(x32.phNumber, Elf32_Program_Header_t{});
            section_headers.resize(x32.shNumber, Elf32_Section_Header_t{});
      },
      [&](Elf64_Header_t &x64) {
            fin.read(reinterpret_cast<char *>(&x64), sizeof(decltype(x64)));

            program_headers.resize(x64.phNumber, Elf64_Program_Header_t{});
            section_headers.resize(x64.shNumber, Elf64_Section_Header_t{});
      }
    }, elf_header);
  // clang-format on
}

auto FileHeader::identificationArray() const noexcept -> std::span<const Elf_byte> {
  if(auto x64 = std::get_if<Elf64_Header_t>(&elf_header)) //
    return x64->ident;
  return std::get<Elf32_Header_t>(elf_header).ident;
}

auto FileHeader::fileClass() const noexcept -> std::string_view {
  auto classData = std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.ident[i_class]; },
                                         [](const Elf64_Header_t &x64) { return x64.ident[i_class]; }},
                              elf_header);
  switch(classData) {
  case 0: return "None";  // Invalid class
  case 1: return "ELF32"; // 32-bit objects, machines with virtual address spaces up to 4Gb
  case 2: return "ELF64"; // 64-bit objects
  }
}

auto FileHeader::fileDataEncoding() const noexcept -> std::string_view {
  auto encodingData = std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.ident[i_data]; },
                                            [](const Elf64_Header_t &x64) { return x64.ident[i_data]; }},
                                 elf_header);

  switch(encodingData) {
  case 0: return "None";
  case 1: return "2's complement, little endian"; // 0x0102 -> 0x02 0x01
  case 2: return "2's complement, big endian";    // 0x0102 -> 0x01 0x02
  }
}

auto FileHeader::fileVersion() const noexcept -> std::string_view {
  auto versionData = std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.ident[i_version]; },
                                           [](const Elf64_Header_t &x64) { return x64.ident[i_version]; }},
                                elf_header);

  switch(versionData) {
  case 0: return "0 (Invalid)";
  case 1: return "1 (Current)";
  }
}

auto FileHeader::osABI() const noexcept -> std::string_view {
  auto osABI = std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.ident[i_osabi]; },
                                     [](const Elf64_Header_t &x64) { return x64.ident[i_osabi]; }},
                          elf_header);
  switch(osABI) {
  case 0: return "UNIX System V ABI";
  case 1: return "HP-UX";
  case 2: return "NetBSD";
  case 3: return "Object uses GNU ELF extensions";
  // case osabi::linux: return "Compatibility alias";
  case 6: return "Sun Solaris";
  case 7: return "IBM AIX";
  case 8: return "SGI Irix";
  case 9: return "FreeBSD";
  case 10: return "Compaq TRU64 UNIX";
  case 11: return "Novell Modesto";
  case 12: return "OpenBSD";
  case 64: return "ARM EABI";
  case 97: return "ARM";
  case 255: return "Standalone (embedded) application";
  }
}

auto FileHeader::ABIVersion() const noexcept -> int {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.ident[i_abiversion]; },
                               [](const Elf64_Header_t &x64) { return x64.ident[i_abiversion]; }},
                    elf_header);
}

auto FileHeader::type() const noexcept -> std::string_view {
  auto fileType = std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.type; },
                                        [](const Elf64_Header_t &x64) { return x64.type; }},
                             elf_header);
  switch(fileType) {
  case 0: return "No file type";
  case 1: return "Relocatible file";
  case 2: return "Executable file";
  case 3: return "Shared object file";
  case 4: return "Core file";
  }

  if(fileType >= 0xff00 && fileType <= 0xffff) {
    return "Processor specific";
  }
}

auto FileHeader::machine() const noexcept -> std::string_view {
  auto machine = std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.machine; },
                                       [](const Elf64_Header_t &x64) { return x64.machine; }},
                            elf_header);
  switch(machine) {
  case 0: return "An unknown machine";
  case 1: return "AT&T WE 32100";
  case 2: return "Sun Microsystems SPARC";
  case 3: return "Intel 80386";
  case 4: return "Motorola 68000";
  case 5: return "Motorola 88000";
  case 7: return "Intel 80860";
  case 8: return "MIPS RS3000 (big-endian only)";
  case 15: return "HP/PA";
  case 18: return "SPARC with enhanced instruction set";
  case 20: return "PowerPC";
  case 21: return "PowerPC 64-bit";
  case 22: return "IBM S/390";
  case 40: return "Advanced RISC Machines";
  case 42: return "Renesas SuperH";
  case 43: return "SPARC v9 64-bit";
  case 50: return "Intel Itanium";
  case 62: return "AMD x86-64";
  case 75: return "DEC Vax";
  }
}

auto FileHeader::version() const noexcept -> std::size_t {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.version; },
                               [](const Elf64_Header_t &x64) { return x64.version; }},
                    elf_header);
}

auto FileHeader::entryPoint() const noexcept -> std::size_t {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) -> std::size_t { return x32.entryPoint; },
                               [](const Elf64_Header_t &x64) -> std::size_t { return x64.entryPoint; }},
                    elf_header);
}

auto FileHeader::programHeaderOffset() const noexcept -> std::size_t {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) -> std::size_t { return x32.phOffset; },
                               [](const Elf64_Header_t &x64) -> std::size_t { return x64.phOffset; }},
                    elf_header);
}

auto FileHeader::sectionHeaderOffset() const noexcept -> std::size_t {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) -> std::size_t { return x32.shOffset; },
                               [](const Elf64_Header_t &x64) -> std::size_t { return x64.shOffset; }},
                    elf_header);
}

// clang-format off
auto FileHeader::programHeaders() noexcept -> const decltype(program_headers) & {
  if(programHeaderOffset() != 0) { // no program header if the offset is 0
    fin.seekg(programHeaderOffset());

    for(auto &ph : program_headers)
      std::visit(overloaded{[](Elf32_Program_Header_t &x32) { fin.read(reinterpret_cast<char *>(&x32), sizeof(decltype(x32))); },
                            [](Elf64_Program_Header_t &x64) { fin.read(reinterpret_cast<char *>(&x64), sizeof(decltype(x64))); }}, ph);
  }

  return program_headers;
}

auto FileHeader::sectionHeaders() noexcept -> decltype(section_headers) const & {
  if(sectionHeaderOffset() != 0) {
    fin.seekg(sectionHeaderOffset());

    for(auto &sh : section_headers)
      std::visit(overloaded{[](Elf32_Section_Header_t &x32) { fin.read(reinterpret_cast<char *>(&x32), sizeof(decltype(x32))); },
                            [](Elf64_Section_Header_t &x64) { fin.read(reinterpret_cast<char *>(&x64), sizeof(decltype(x64))); }}, sh);
  }

  return section_headers;
}

auto FileHeader::symbols() noexcept -> std::vector<Symbol_t> const {
  std::vector<Symbol_t> symbols;

  auto symbol_section = std::ranges::find_if(sectionHeaders(), [](const auto &section) {
    return std::visit(overloaded{[](const Elf32_Section_Header_t &x32) { return x32.type; },
                                 [](const Elf64_Section_Header_t &x64) { return x64.type; }}, section) == 2;
  });

  if(symbol_section != section_headers.end()) {
    std::visit(overloaded{
                 [&](const Elf32_Section_Header_t &x32) {
                       fin.seekg(x32.offset);
                       const int size = x32.size / x32.entsize;

                       Elf32_Symbol_t symbol{};
                       for(int i = 0; i < size; ++i) {
                         fin.read(reinterpret_cast<char *>(&symbol), sizeof(decltype(symbol)));
                         symbols.push_back(symbol);
                       }
                     }, 
                  [&](const Elf64_Section_Header_t &x64) {
                        fin.seekg(x64.offset);
                        const int size = x64.size / x64.entsize;

                        Elf64_Symbol_t symbol{};
                        for(int i = 0; i < size; ++i) {
                          fin.read(reinterpret_cast<char *>(&symbol), sizeof(decltype(symbol)));
                          symbols.push_back(symbol);
                        }
                  }}, *symbol_section);
  }
  return symbols;
}

auto FileHeader::flags() const noexcept -> int {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.flags; },
                               [](const Elf64_Header_t &x64) { return x64.flags; }}, elf_header);
}

auto FileHeader::headerSize() const noexcept -> int {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.size; },
                               [](const Elf64_Header_t &x64) { return x64.size; }}, elf_header);
}

auto FileHeader::programHeaderSize() const noexcept -> int {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.phEntrySize; },
                               [](const Elf64_Header_t &x64) { return x64.phEntrySize; }}, elf_header);
}

auto FileHeader::numProgramHeaders() const noexcept -> int {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.phNumber; },
                               [](const Elf64_Header_t &x64) { return x64.phNumber; }}, elf_header);
}

auto FileHeader::sectionHeaderEntrySize() const noexcept -> std::size_t {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.shEntrySize; },
                               [](const Elf64_Header_t &x64) { return x64.shEntrySize; }}, elf_header);
}

auto FileHeader::numSectionHeaders() const noexcept -> int {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.shNumber; },
                               [](const Elf64_Header_t &x64) { return x64.shNumber; }}, elf_header);
}

auto FileHeader::sectionHeaderStringTableIndex() const noexcept -> int {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.shStringIndex; },
                               [](const Elf64_Header_t &x64) { return x64.shStringIndex; }}, elf_header);
}

auto FileHeader::isELF() const noexcept -> bool {
  const std::array<Elf_byte, 4> identification_bytes{0x7f, 'E', 'L', 'F'};

  fin.seekg(0);

  std::array<Elf_byte, 4> buf{};
  fin.read(reinterpret_cast<char *>(buf.data()), std::size(buf) * sizeof(Elf_byte));

  return identification_bytes == buf;
}

auto FileHeader::is64bit() const noexcept -> bool {
  fin.seekg(4);

  Elf_byte temp;
  fin.read(reinterpret_cast<char *>(&temp), sizeof(Elf_byte));

  return temp == 2;
}

std::string shNameStr;
auto FileHeader::getSectionHeaderName(const std::size_t shName) const noexcept -> std::string_view {
  const auto offset =
      std::visit(overloaded{[shName](const Elf32_Section_Header_t &x32) -> std::size_t { return x32.offset + shName; },
                            [shName](const Elf64_Section_Header_t &x64) -> std::size_t { return x64.offset + shName; }}, section_headers[sectionHeaderStringTableIndex()]);

  fin.seekg(offset);

  shNameStr.clear();
  std::getline(fin, shNameStr, '\0');

  return shNameStr.c_str();
}

std::string symNameStr;
auto FileHeader::getSymbolName(const std::size_t symName) noexcept -> std::string_view {
  std::size_t sectionTableIndex = 0;

  const auto sections = sectionHeaders();
  for(std::size_t i = 0; i < sections.size(); ++i) {
      const auto name = std::visit(overloaded{[](const Elf32_Section_Header_t &x32) -> std::size_t { return x32.name; },
                                              [](const Elf64_Section_Header_t &x64) -> std::size_t { return x64.name; }}, sections[i]);

      if(getSectionHeaderName(name) == ".strtab")  {
        sectionTableIndex = i; 
        break;
      }
  }

  const auto offset =
      std::visit(overloaded{[symName](const Elf32_Section_Header_t &x32) -> std::size_t { return x32.offset + symName; },
                            [symName](const Elf64_Section_Header_t &x64) -> std::size_t { return x64.offset + symName; }}, section_headers[sectionTableIndex]);

  fin.seekg(offset);

  std::getline(fin, symNameStr, '\0');

  return symNameStr.c_str();
}

auto getProgramHeaderType(const std::size_t phType) noexcept -> std::string_view {
  switch(phType) {
  case 0: return "NULL";    // program header table entry
  case 1: return "LOAD";    // loadable program segment
  case 2: return "DYNAMIC"; // dynamic linking informatio
  case 3: return "INTERP";  // program interpreter
  case 4: return "NOTE";    // auxiliary information
  case 5: return "SHLIB";   // reserved
  case 6: return "PHDR";    // entry for header table its
  case 7: return "TLS";     // thread-local storage segme
  case 8: return "NUM";     // number of defined types
  }

  if(phType >= 0x60000000 && phType <= 0x6fffffff) { // start-end of OS-specific
    switch(phType) {
    case 0x6474e550: return "GNU_EH_FRAME"; // GCC .eh_frame_hdr segment
    case 0x6474e551: return "GNU_STACK";    // indicates stack executabil
    case 0x6474e552: return "GNU_RELRO";    // read-only after relocation
    }

    if(phType >= 0x6ffffffa && phType <= 0x6fffffff) { // [LOSUNW, HISUNW]
      switch(phType) {
      case 0x6ffffffa: return "SUNWBSS";   // Sun Specific segment
      case 0x6ffffffb: return "SUNWSTACK"; // stack segment
      }
    }
    return "LOOS";
  }

  if(phType >= 0x70000000 && phType <= 0x7fff'ffff) { // start-end of processor-specific
    return "processor specific";
  }
}

std::string phFlagStr;
auto getProgramHeaderFlag(const std::size_t phFlag) noexcept -> std::string_view {
  phFlagStr.clear();

  if(phFlag & (1 << 0)) phFlagStr.push_back('X');
  if(phFlag & (1 << 1)) phFlagStr.push_back('W');
  if(phFlag & (1 << 2)) phFlagStr.push_back('R');
  // if(phFlags & 0x0ff00000) REVISIT: handle OS-specific
  // if(phFlags & 0xf0000000) REVISIT: handle processor-specific

  return phFlagStr.c_str();
}

auto getSectionHeaderType(const std::size_t shType) noexcept -> std::string_view {
  switch(shType) {
  case 0:  return "NULL";          // Section header table entry unused
  case 1:  return "PROGBITS";      // Program data
  case 2:  return "SYMTAB";        // Symbol table
  case 3:  return "STRTAB";        // String table
  case 4:  return "RELA";          // Relocation entries with addends
  case 5:  return "HASH";          // Symbol hash table
  case 6:  return "DYNAMIC";       // Dynamic linking information
  case 7:  return "NOTE";          // Notes
  case 8:  return "NOBITS";        // Program space with no data (bss)
  case 9:  return "REL";           // Relocation entries, no addends
  case 10: return "SHLIB";         // Reserved
  case 11: return "DYNSYM";        // Dynamic linker symbol table
  case 14: return "INIT_ARRAY";    // Array of constructors
  case 15: return "FINI_ARRAY";    // Array of destructors
  case 16: return "PREINIT_ARRAY"; // Array of pre-constructors
  case 17: return "GROUP";         // Section group
  case 18: return "SYMTAB_SHNDX";  // Extended section indeces
  case 19: return "NUM";           // Number of defined types.
  }
               
  if(shType >= 0x60000000 && shType <= 0x6fffffff) { // [start-end] OS-specific
    switch(shType) {
    case 0x6ffffff5: return "GNU_ATTRIBUTES"; // Object attributes.
    case 0x6ffffff6: return "GNU_HASH";       // GNU-style hash table.
    case 0x6ffffff7: return "GNU_LIBLIST";    // Prelink library list
    case 0x6ffffff8: return "CHECKSUM";       // Checksum for DSO content.
    }

    if(shType >= 0x6ffffffa && shType <= 0x6fffffff) { // [start-end] Sun-specific
      switch(shType) {
      case 0x6ffffffa: return "SUNW_move";    //
      case 0x6ffffffb: return "SUNW_COMDAT";  //
      case 0x6ffffffc: return "SUNW_syminfo"; //
      case 0x6ffffffd: return "GNU_verdef";   // Version definition section.
      case 0x6ffffffe: return "GNU_verneed";  // Version needs section.
      case 0x6fffffff: return "GNU_versym";   // Version symbol table.
      }
    }
  }

  if(shType >= 0x70000000 && shType <= 0x7fffffff) { // [start-end] processor specific
    return "processor specific";
  }

  if(shType >= 0x80000000 && shType <= 0x8fffffff) { // [start-end] processor specific
    return "application specific";
  }
}

std::string shFlagsStr;
auto getSectionHeaderFlag(const std::size_t shFlag) noexcept -> std::string_view {
  shFlagsStr.clear();
  if(shFlag & (1 << 0)) shFlagsStr.push_back('W');    // writable
  if(shFlag & (1 << 1)) shFlagsStr.push_back('A');    // occupies memory during execution
  if(shFlag & (1 << 2)) shFlagsStr.push_back('X');    // executable
  if(shFlag & (1 << 4)) shFlagsStr.push_back('M');    // might be merged
  if(shFlag & (1 << 5)) shFlagsStr.push_back('S');    // contains nul-terminated strings
  if(shFlag & (1 << 6)) shFlagsStr.push_back('I');    // sh_info contains SHT index
  if(shFlag & (1 << 7)) shFlagsStr.push_back('L');    // preserve order after combining
  if(shFlag & (1 << 8)) shFlagsStr.push_back('O');    // non-standard OS specific handling required
  if(shFlag & (1 << 9)) shFlagsStr.push_back('G');    // section is member of a group
  if(shFlag & (1 << 10)) shFlagsStr.push_back('T');   // section hold thread-local data
  if(shFlag & (1 << 11)) shFlagsStr.push_back('C');   // section with compressed data
  if(shFlag == 0x0ff00000) shFlagsStr.push_back('o'); // OS-specific
  if(shFlag == 0xf0000000) shFlagsStr.push_back('p'); // processor-specific
  if(shFlag & (1 << 30)) shFlagsStr.push_back('?');   // (Revisit '?') special ordering requirement (Solaris)
  if(shFlag & (1 << 31)) shFlagsStr.push_back('E');   // excluded unless referenced or allocated (Solaris)
  return shFlagsStr.c_str();
}

auto getSymbolType(const Elf_byte symInfo) noexcept -> std::string_view {
  switch(symInfo & 0b1111) {
  case 0: return "NOTYPE";  // symbol type is unspecified
  case 1: return "OBJECT";  // symbol is a data object
  case 2: return "FUNC";    // symbol is a code object
  case 3: return "SECTION"; // symbol associated with a section
  case 4: return "FILE";    // symbol's name is file name
  case 5: return "COMMON";  // symbol is a common data object
  case 6: return "TLS";     // symbol is thread-local data object
  case 7: return "NUM";     // number of defined types
  }

  if(symInfo >= 10 && symInfo <= 12) { // [start, end] OS-specific
    switch(symInfo) {
    case 10: return "GNU_IFUNC"; // symbol is indirect code object
    }
  }

  if(symInfo >= 13 && symInfo <= 15) { // [start, end] processor-specific
    return "processor-specific";
  }
}

auto getSymbolBind(const Elf_byte symInfo) noexcept -> std::string_view {
  switch(symInfo >> 4) {
  case 0: return "LOCAL";  // local symbol
  case 1: return "GLOBAL"; // global symbol
  case 2: return "WEAK";   // weak symbol
  case 3: return "NUM";    // number of defined types.
  }

  if(symInfo >= 10 && symInfo <= 12) { // [start, end] OS-specific
    switch(symInfo) {
    case 10: return "GNU_UNIQUE"; // Unique symbol.
    }
  }

  if(symInfo >= 13 && symInfo <= 15) { // [start, end] processor-specific
    return "";
  }
}

auto getSymbolVisibility(const Elf_byte symOther) noexcept -> std::string_view {
  switch(symOther & 0b11) {
  case 0: return "DEFAULT";   // default symbol visibility rules
  case 1: return "INTERNAL";  // processor specific hidden class
  case 2: return "HIDDEN";    // sym unavailable in other modules
  case 3: return "PROTECTED"; // not preemptible, not exported
  }
}

} // namespace feelelf
