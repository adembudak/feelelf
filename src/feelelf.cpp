#include <feelelf/feelelf.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <map>
#include <sstream>
#include <string_view>
#include <vector>

namespace feelelf {

namespace {
std::string_view i386_relocation_symbols(unsigned int type);
std::string_view amd64_relocation_symbols(unsigned int type);
std::string_view aarch64_relocation_symbols(unsigned int type);
}

// clang-format off
template <class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template <class... Ts> overloaded(Ts...) -> overloaded<Ts...>;
// clang-format on

std::ifstream fin;

auto FileHeader::open(const char *file) noexcept -> bool {
  if(fin.is_open()) fin.close();

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
      [&](Elf32_Header_t &elf_header) {
            fin.read(reinterpret_cast<char *>(&elf_header), sizeof(Elf32_Header_t)); // read ELF header

            if(const auto shOffset = elf_header.shOffset; shOffset != 0) {
              fin.seekg(shOffset + (elf_header.shStringIndex * elf_header.shEntrySize)); // seek to shstrtab section to get section names

              Elf32_Section_Header_t shstrtab;
              fin.read(reinterpret_cast<char *>(&shstrtab), sizeof(Elf32_Section_Header_t));

              fin.seekg(shOffset); // seek back to section offset and get sections to map as, [name] -> section

              for(std::size_t i = 0; i < elf_header.shNumber; ++i) {
                Elf32_Section_Header_t section;
                fin.read(reinterpret_cast<char *>(&section), sizeof(Elf32_Section_Header_t)); // read section

                auto position_before_reading_section_name = fin.tellg(); // push read pointer to a variable

                auto sectionNameOffset = shstrtab.offset + section.name;
                fin.seekg(sectionNameOffset); // seek section name
                std::string sectionName;
                std::getline(fin, sectionName, '\0');

                section_headers[sectionName] = section;
                fin.seekg(position_before_reading_section_name); // pop read pointer back
              }
            }

            if(auto phOffset = elf_header.phOffset; phOffset != 0) { // no program header if the offset is 0
              program_headers.resize(elf_header.phNumber, Elf32_Program_Header_t{});

              fin.seekg(phOffset);

              for(auto &ph : program_headers)
                fin.read(reinterpret_cast<char *>(&std::get<Elf32_Program_Header_t>(ph)), sizeof(Elf32_Program_Header_t));
            }

      },
      [&](Elf64_Header_t &elf_header) {
            fin.read(reinterpret_cast<char *>(&elf_header), sizeof(Elf64_Header_t));

            if(const auto shOffset = elf_header.shOffset; shOffset != 0) {
              fin.seekg(shOffset + (elf_header.shStringIndex * elf_header.shEntrySize));

              Elf64_Section_Header_t shstrtab;
              fin.read(reinterpret_cast<char *>(&shstrtab), sizeof(Elf64_Section_Header_t));

              fin.seekg(shOffset);

              for(std::size_t i = 0; i < elf_header.shNumber; ++i) {
                Elf64_Section_Header_t section;
                fin.read(reinterpret_cast<char *>(&section), sizeof(Elf64_Section_Header_t));

                auto position_before_reading_section_name = fin.tellg();

                auto sectionNameOffset = shstrtab.offset + section.name;
                fin.seekg(sectionNameOffset);
                std::string sectionName;
                std::getline(fin, sectionName, '\0');

                section_headers[sectionName] = section;
                fin.seekg(position_before_reading_section_name);
              }
            }

            if(auto phOffset = elf_header.phOffset; phOffset != 0) {
              program_headers.resize(elf_header.phNumber, Elf64_Program_Header_t{});

              fin.seekg(phOffset);

              for(auto &ph : program_headers)
                fin.read(reinterpret_cast<char *>(&std::get<Elf64_Program_Header_t>(ph)), sizeof(Elf64_Program_Header_t));
            }
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
auto FileHeader::programHeaders() const noexcept -> const decltype(program_headers) & {
  return program_headers;
}

auto FileHeader::sectionHeaders() const noexcept -> const decltype(section_headers) & {
  return section_headers;
}

auto FileHeader::symbols() const noexcept -> const std::vector<Symbol_t> {
  std::vector<Symbol_t> symbols;

  std::visit(
         overloaded{
           [&](const Elf32_Section_Header_t &x32) {
                 fin.seekg(x32.offset);
                 const auto size = x32.size / x32.entsize;
  
                 Elf32_Symbol_t symbol{};
                 for(int i = 0; i < size; ++i) {
                   fin.read(reinterpret_cast<char *>(&symbol), sizeof(decltype(symbol)));
                   symbols.push_back(symbol);
                 }
           }, 
           [&](const Elf64_Section_Header_t &x64) {
                 fin.seekg(x64.offset);
                 const auto size = x64.size / x64.entsize;
  
                 Elf64_Symbol_t symbol{};
                 for(int i = 0; i < size; ++i) {
                   fin.read(reinterpret_cast<char *>(&symbol), sizeof(decltype(symbol)));
                   symbols.push_back(symbol);
                 }
           }
         }, section_headers.find(".symtab")->second);

  return symbols;
}


auto FileHeader::dynamicSymbols() const noexcept -> const std::vector<Symbol_t> {
  std::vector<Symbol_t> dynSymbols;

  if(section_headers.contains(".dynsym")) {
    std::visit(
           overloaded{
             [&](const Elf32_Section_Header_t &x32) {
                   fin.seekg(x32.offset);
                   const auto size = x32.size / x32.entsize;
    
                   Elf32_Symbol_t symbol{};
                   for(int i = 0; i < size; ++i) {
                     fin.read(reinterpret_cast<char *>(&symbol), sizeof(decltype(symbol)));
                     dynSymbols.push_back(symbol);
                   }
             }, 
             [&](const Elf64_Section_Header_t &x64) {
                   fin.seekg(x64.offset);
                   const auto size = x64.size / x64.entsize;
    
                   Elf64_Symbol_t symbol{};
                   for(int i = 0; i < size; ++i) {
                     fin.read(reinterpret_cast<char *>(&symbol), sizeof(decltype(symbol)));
                     dynSymbols.push_back(symbol);
                   }
             }
           }, section_headers.find(".dynsym")->second);
  }

  return dynSymbols;
}

auto FileHeader::notes() const noexcept -> const std::map<std::string, std::tuple<std::string, std::size_t, std::string>> {
  std::map<std::string, std::tuple<std::string, std::size_t, std::string>> things;

  for(const auto &[name, section] : section_headers) {
    if(name.starts_with(".note")) {
      auto offset = 
        std::visit(overloaded{[](const Elf32_Section_Header_t &x32) -> std::size_t { return x32.offset; },
                              [](const Elf64_Section_Header_t &x64) -> std::size_t { return x64.offset; }}, section);
      fin.seekg(offset);

      Elf32_Note_header_t note;
      fin.read(reinterpret_cast<char*>(&note), sizeof(decltype(note)));

      std::string noteName;
      std::getline(fin, noteName, '\0');

      std::vector<Elf32_Word> desc_words(note.desc_sz / sizeof(Elf32_Word), Elf32_Word{});
      for(auto &word : desc_words)
        fin.read(reinterpret_cast<char *>(&word), sizeof(Elf32_Word));

      // clang-format on
      std::ostringstream sout;
      if(note.type == 1) { // description words:
        // word 0: OS descriptor
        // word 1: major version of the ABI
        // word 2: minor version of the ABI
        // word 3: subminor version of the ABI

        sout << "NT_GNU_ABI_TAG\n";
        sout << "OS: ";

        switch(desc_words[0]) {
        case 0: sout << "Linux, "; break;
        case 1: sout << "GNU, "; break;
        case 2: sout << "Solaris2, "; break;
        case 3: sout << "FreeBSD, "; break;
        }

        sout << "ABI: " << desc_words[1] << '.' << desc_words[2] << '.' << desc_words[3];
        sout << '\n';
      }

      else if(note.type == 2) {
        sout << "NT_GNU_HWCAP"; // Synthetic hwcap information.
        // word 0: number of entries
        // word 1: bitmask of enabled entries
        // Then follow variable-length entries, one byte followed by a '\0'-terminated hwcap name string.
        // The byte gives the bit number to test if enabled, (1U << bit) & bitmask.
        std::vector<Elf_byte> entries(desc_words[0], Elf_byte{});
        const auto bitmask = desc_words[1];
        for(int i = 0; const auto entry : entries) {
          [[maybe_unused]] auto _ = (1U << i) & bitmask; // REVISIT, implement this
        }
      }

      else if(note.type == 3) {
        sout << "NT_GNU_BUILD_ID\n";
        sout << "Build ID: ";
        for(auto word : desc_words)
          sout << std::hex << word;
        sout << '\n';
      }

      else if(note.type == 4) {
        sout << "NT_GNU_GOLD_VERSION\n";
      }

      else if(note.type == 5) {
        sout << "NT_GNU_PROPERTY_TYPE_0\n";
      }

      else {
        sout << "Unknown note type: " << '(' << "0x" << std::hex << note.type << ')' << '\n';
        for(auto word : desc_words)
          sout << std::hex << word << ' ';
        sout << '\n';
      }

      things[name] = std::make_tuple(noteName, note.desc_sz, sout.str());
    }
  }

  return things;
}

// clang-format off
auto FileHeader::relocations() const noexcept
  -> const std::map<
                    std::pair<std::string, std::size_t>, 
                    std::vector<std::tuple<std::size_t, std::size_t, std::string_view, std::size_t, std::string>>
                   > {

  std::map<std::pair<std::string, std::size_t>, std::vector<std::tuple<std::size_t, std::size_t, std::string_view, std::size_t, std::string>>> things;

  for(const auto &[sectionName, section] : section_headers) {
    if(sectionName.starts_with(".rel")) {
      const auto &rel_section = std::get<Elf32_Section_Header_t>(section);
      fin.seekg(rel_section.offset);

      std::vector<std::tuple<std::size_t, std::size_t, std::string_view, std::size_t, std::string>> entries;

      const auto n_entry = rel_section.size / rel_section.entsize;
      for(int i = 0; i < n_entry; ++i) {
        Elf32_Rel rel{};
        fin.read(reinterpret_cast<char *>(&rel), sizeof(Elf32_Rel));

        entries.push_back(std::make_tuple(rel.offset, rel.info, i386_relocation_symbols(rel.info & 0xff), 0, ""));
      }

      things[std::make_pair(sectionName, rel_section.offset)] = std::move(entries);
    }
  }

  return things;
}

// clang-format off
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

auto FileHeader::getSymbolName(const std::size_t name) const noexcept -> std::string {
  const auto offset =
      std::visit(overloaded{[](const Elf32_Section_Header_t &x32) -> std::size_t { return x32.offset; },
                            [](const Elf64_Section_Header_t &x64) -> std::size_t { return x64.offset; }}, section_headers.find(".strtab")->second);

  fin.seekg(offset + name);

  std::string symNameStr;
  std::getline(fin, symNameStr, '\0');

  return symNameStr;
}

auto FileHeader::getDynamicSymbolName(const std::size_t name) const noexcept -> std::string {
  const auto offset =
      std::visit(overloaded{[](const Elf32_Section_Header_t &x32) -> std::size_t { return x32.offset; },
                            [](const Elf64_Section_Header_t &x64) -> std::size_t { return x64.offset; }}, section_headers.find(".dynstr")->second);

  fin.seekg(offset + name);

  std::string dynSymNameStr;
  std::getline(fin, dynSymNameStr, '\0');

  return dynSymNameStr;
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

namespace {
std::string_view amd64_relocation_symbols(unsigned int type) {
  switch(type) {
  case 0: return "R_X86_64_NONE";
  case 1: return "R_X86_64_64";
  case 2: return "R_X86_64_PC32";
  case 3: return "R_X86_64_GOT32";
  case 4: return "R_X86_64_PLT32";
  case 5: return "R_X86_64_COPY";
  case 6: return "R_X86_64_GLOB_DAT";
  case 7: return "R_X86_64_JUMP_SLOT";
  case 8: return "R_X86_64_RELATIVE";
  case 9: return "R_X86_64_GOTPCREL";
  case 10: return "R_X86_64_32";
  case 11: return "R_X86_64_32S";
  case 12: return "R_X86_64_16";
  case 13: return "R_X86_64_PC16";
  case 14: return "R_X86_64_8";
  case 15: return "R_X86_64_PC8";
  case 16: return "R_X86_64_DTPMOD64";
  case 17: return "R_X86_64_DTPOFF64";
  case 18: return "R_X86_64_TPOFF64";
  case 19: return "R_X86_64_TLSGD";
  case 20: return "R_X86_64_TLSLD";
  case 21: return "R_X86_64_DTPOFF32";
  case 22: return "R_X86_64_GOTTPOFF";
  case 23: return "R_X86_64_TPOFF32";
  case 24: return "R_X86_64_PC64";
  case 25: return "R_X86_64_GOTOFF64";
  case 26: return "R_X86_64_GOTPC32";
  case 27: return "R_X86_64_GOT64";
  case 28: return "R_X86_64_GOTPCREL64";
  case 29: return "R_X86_64_GOTPC64";
  case 30: return "R_X86_64_GOTPLT64";
  case 31: return "R_X86_64_PLTOFF64";
  case 32: return "R_X86_64_SIZE32";
  case 33: return "R_X86_64_SIZE64";
  case 34: return "R_X86_64_GOTPC32_TLSDESC";
  case 35: return "R_X86_64_TLSDESC_CALL";
  case 36: return "R_X86_64_TLSDESC";
  case 37: return "R_X86_64_IRELATIVE";
  case 38: return "R_X86_64_RELATIVE64";
  case 39: return "Reserved R_X86_64_PC32_BND";
  case 40: return "Reserved R_X86_64_PLT32_BND";
  case 41: return "R_X86_64_GOTPCRELX";
  case 42: return "R_X86_64_REX_GOTPCRELX";
  case 43: return "R_X86_64_NUM";
  default: return "Unknown";
  }
}

std::string_view i386_relocation_symbols(unsigned int type) {
  switch(type) {
  case 0: return "R_386_NONE";
  case 1: return "R_386_32";
  case 2: return "R_386_PC32";
  case 3: return "R_386_GOT32";
  case 4: return "R_386_PLT32";
  case 5: return "R_386_COPY";
  case 6: return "R_386_GLOB_DAT";
  case 7: return "R_386_JMP_SLOT";
  case 8: return "R_386_RELATIVE";
  case 9: return "R_386_GOTOFF";
  case 10: return "R_386_GOTPC";
  case 11: return "R_386_32PLT";
  case 14: return "R_386_TLS_TPOFF";
  case 15: return "R_386_TLS_IE";
  case 16: return "R_386_TLS_GOTIE";
  case 17: return "R_386_TLS_LE";
  case 18: return "R_386_TLS_GD";
  case 19: return "R_386_TLS_LDM";
  case 20: return "R_386_16";
  case 21: return "R_386_PC16";
  case 22: return "R_386_8";
  case 23: return "R_386_PC8";
  case 24: return "R_386_TLS_GD_32";
  case 25: return "R_386_TLS_GD_PUSH";
  case 26: return "R_386_TLS_GD_CALL";
  case 27: return "R_386_TLS_GD_POP";
  case 28: return "R_386_TLS_LDM_32";
  case 29: return "R_386_TLS_LDM_PUSH";
  case 30: return "R_386_TLS_LDM_CALL";
  case 31: return "R_386_TLS_LDM_POP";
  case 32: return "R_386_TLS_LDO_32";
  case 33: return "R_386_TLS_IE_32";
  case 34: return "R_386_TLS_LE_32";
  case 35: return "R_386_TLS_DTPMOD32";
  case 36: return "R_386_TLS_DTPOFF32";
  case 37: return "R_386_TLS_TPOFF32";
  case 38: return "R_386_SIZE32";
  case 39: return "R_386_TLS_GOTDESC";
  case 40: return "R_386_TLS_DESC_CALL";
  case 41: return "R_386_TLS_DESC";
  case 42: return "R_386_IRELATIVE";
  case 43: return "R_386_GOT32X";
  case 44: return "R_386_NUM";
  default: return "Unknown";
  }
}

std::string_view aarch64_relocation_symbols(unsigned int type) {
  switch(type) {
  case 0: return "R_AARCH64_NONE";
  case 1: return "R_AARCH64_P32_ABS32";
  case 180: return "R_AARCH64_P32_COPY";
  case 181: return "R_AARCH64_P32_GLOB_DAT";
  case 182: return "R_AARCH64_P32_JUMP_SLOT";
  case 183: return "R_AARCH64_P32_RELATIVE";
  case 184: return "R_AARCH64_P32_TLS_DTPMOD";
  case 185: return "R_AARCH64_P32_TLS_DTPREL";
  case 186: return "R_AARCH64_P32_TLS_TPREL";
  case 187: return "R_AARCH64_P32_TLSDESC";
  case 188: return "R_AARCH64_P32_IRELATIVE";
  case 257: return "R_AARCH64_ABS64";
  case 258: return "R_AARCH64_ABS32";
  case 259: return "R_AARCH64_ABS16";
  case 260: return "R_AARCH64_PREL64";
  case 261: return "R_AARCH64_PREL32";
  case 262: return "R_AARCH64_PREL16";
  case 263: return "R_AARCH64_MOVW_UABS_G0";
  case 264: return "R_AARCH64_MOVW_UABS_G0_NC";
  case 265: return "R_AARCH64_MOVW_UABS_G1";
  case 266: return "R_AARCH64_MOVW_UABS_G1_NC";
  case 267: return "R_AARCH64_MOVW_UABS_G2";
  case 268: return "R_AARCH64_MOVW_UABS_G2_NC";
  case 269: return "R_AARCH64_MOVW_UABS_G3";
  case 270: return "R_AARCH64_MOVW_SABS_G0";
  case 271: return "R_AARCH64_MOVW_SABS_G1";
  case 272: return "R_AARCH64_MOVW_SABS_G2";
  case 273: return "R_AARCH64_LD_PREL_LO19";
  case 274: return "R_AARCH64_ADR_PREL_LO21";
  case 275: return "R_AARCH64_ADR_PREL_PG_HI21";
  case 276: return "R_AARCH64_ADR_PREL_PG_HI21_NC";
  case 277: return "R_AARCH64_ADD_ABS_LO12_NC";
  case 278: return "R_AARCH64_LDST8_ABS_LO12_NC";
  case 279: return "R_AARCH64_TSTBR14";
  case 280: return "R_AARCH64_CONDBR19";
  case 282: return "R_AARCH64_JUMP26";
  case 283: return "R_AARCH64_CALL26";
  case 284: return "R_AARCH64_LDST16_ABS_LO12_NC";
  case 285: return "R_AARCH64_LDST32_ABS_LO12_NC";
  case 286: return "R_AARCH64_LDST64_ABS_LO12_NC";
  case 287: return "R_AARCH64_MOVW_PREL_G0";
  case 288: return "R_AARCH64_MOVW_PREL_G0_NC";
  case 289: return "R_AARCH64_MOVW_PREL_G1";
  case 290: return "R_AARCH64_MOVW_PREL_G1_NC";
  case 291: return "R_AARCH64_MOVW_PREL_G2";
  case 292: return "R_AARCH64_MOVW_PREL_G2_NC";
  case 293: return "R_AARCH64_MOVW_PREL_G3";
  case 299: return "R_AARCH64_LDST128_ABS_LO12_NC";
  case 300: return "R_AARCH64_MOVW_GOTOFF_G0";
  case 301: return "R_AARCH64_MOVW_GOTOFF_G0_NC";
  case 302: return "R_AARCH64_MOVW_GOTOFF_G1";
  case 303: return "R_AARCH64_MOVW_GOTOFF_G1_NC";
  case 304: return "R_AARCH64_MOVW_GOTOFF_G2";
  case 305: return "R_AARCH64_MOVW_GOTOFF_G2_NC";
  case 306: return "R_AARCH64_MOVW_GOTOFF_G3";
  case 307: return "R_AARCH64_GOTREL64";
  case 308: return "R_AARCH64_GOTREL32";
  case 309: return "R_AARCH64_GOT_LD_PREL19";
  case 310: return "R_AARCH64_LD64_GOTOFF_LO15";
  case 311: return "R_AARCH64_ADR_GOT_PAGE";
  case 312: return "R_AARCH64_LD64_GOT_LO12_NC";
  case 313: return "R_AARCH64_LD64_GOTPAGE_LO15";
  case 512: return "R_AARCH64_TLSGD_ADR_PREL21";
  case 513: return "R_AARCH64_TLSGD_ADR_PAGE21";
  case 514: return "R_AARCH64_TLSGD_ADD_LO12_NC";
  case 515: return "R_AARCH64_TLSGD_MOVW_G1";
  case 516: return "R_AARCH64_TLSGD_MOVW_G0_NC";
  case 517: return "R_AARCH64_TLSLD_ADR_PREL21";
  case 518: return "R_AARCH64_TLSLD_ADR_PAGE21";
  case 519: return "R_AARCH64_TLSLD_ADD_LO12_NC";
  case 520: return "R_AARCH64_TLSLD_MOVW_G1";
  case 521: return "R_AARCH64_TLSLD_MOVW_G0_NC";
  case 522: return "R_AARCH64_TLSLD_LD_PREL19";
  case 523: return "R_AARCH64_TLSLD_MOVW_DTPREL_G2";
  case 524: return "R_AARCH64_TLSLD_MOVW_DTPREL_G1";
  case 525: return "R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC";
  case 526: return "R_AARCH64_TLSLD_MOVW_DTPREL_G0";
  case 527: return "R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC";
  case 528: return "R_AARCH64_TLSLD_ADD_DTPREL_HI12";
  case 529: return "R_AARCH64_TLSLD_ADD_DTPREL_LO12";
  case 530: return "R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC";
  case 531: return "R_AARCH64_TLSLD_LDST8_DTPREL_LO12";
  case 532: return "R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC";
  case 533: return "R_AARCH64_TLSLD_LDST16_DTPREL_LO12";
  case 534: return "R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC";
  case 535: return "R_AARCH64_TLSLD_LDST32_DTPREL_LO12";
  case 536: return "R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC";
  case 537: return "R_AARCH64_TLSLD_LDST64_DTPREL_LO12";
  case 538: return "R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC";
  case 539: return "R_AARCH64_TLSIE_MOVW_GOTTPREL_G1";
  case 540: return "R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC";
  case 541: return "R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21";
  case 542: return "R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC";
  case 543: return "R_AARCH64_TLSIE_LD_GOTTPREL_PREL19";
  case 544: return "R_AARCH64_TLSLE_MOVW_TPREL_G2";
  case 545: return "R_AARCH64_TLSLE_MOVW_TPREL_G1";
  case 546: return "R_AARCH64_TLSLE_MOVW_TPREL_G1_NC";
  case 547: return "R_AARCH64_TLSLE_MOVW_TPREL_G0";
  case 548: return "R_AARCH64_TLSLE_MOVW_TPREL_G0_NC";
  case 549: return "R_AARCH64_TLSLE_ADD_TPREL_HI12";
  case 550: return "R_AARCH64_TLSLE_ADD_TPREL_LO12";
  case 551: return "R_AARCH64_TLSLE_ADD_TPREL_LO12_NC";
  case 552: return "R_AARCH64_TLSLE_LDST8_TPREL_LO12";
  case 553: return "R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC";
  case 554: return "R_AARCH64_TLSLE_LDST16_TPREL_LO12";
  case 555: return "R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC";
  case 556: return "R_AARCH64_TLSLE_LDST32_TPREL_LO12";
  case 557: return "R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC";
  case 558: return "R_AARCH64_TLSLE_LDST64_TPREL_LO12";
  case 559: return "R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC";
  case 560: return "R_AARCH64_TLSDESC_LD_PREL19";
  case 561: return "R_AARCH64_TLSDESC_ADR_PREL21";
  case 562: return "R_AARCH64_TLSDESC_ADR_PAGE21";
  case 563: return "R_AARCH64_TLSDESC_LD64_LO12";
  case 564: return "R_AARCH64_TLSDESC_ADD_LO12";
  case 565: return "R_AARCH64_TLSDESC_OFF_G1";
  case 566: return "R_AARCH64_TLSDESC_OFF_G0_NC";
  case 567: return "R_AARCH64_TLSDESC_LDR";
  case 568: return "R_AARCH64_TLSDESC_ADD";
  case 569: return "R_AARCH64_TLSDESC_CALL";
  case 570: return "R_AARCH64_TLSLE_LDST128_TPREL_LO12";
  case 571: return "R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC";
  case 572: return "R_AARCH64_TLSLD_LDST128_DTPREL_LO12";
  case 573: return "R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC";
  case 1024: return "R_AARCH64_COPY";
  case 1025: return "R_AARCH64_GLOB_DAT";
  case 1026: return "R_AARCH64_JUMP_SLOT";
  case 1027: return "R_AARCH64_RELATIVE";
  case 1028: return "R_AARCH64_TLS_DTPMOD";
  case 1029: return "R_AARCH64_TLS_DTPREL";
  case 1030: return "R_AARCH64_TLS_TPREL";
  case 1031: return "R_AARCH64_TLSDESC";
  case 1032: return "R_AARCH64_IRELATIVE";
  default: return "Unknown";
  }
}
}

} // namespace feelelf
