#include <feelelf/feelelf.h>

#include <CLI/CLI.hpp>

#include <fmt/core.h>
#include <fmt/ranges.h>

#include <filesystem>
#include <vector>

int main(int argc, const char *argv[]) {
  namespace fs = std::filesystem;
  using namespace fmt::literals;

  std::vector<fs::path> elf_files;

  bool show_fileheader = false;
  bool show_segments = false;
  bool show_sections = false;
  bool show_symbols = false;
  bool show_headers = false;

  CLI::App app{{}, "readelf"};
  try {
    app.set_help_flag("-H, --help", "Display this information");
    app.set_version_flag("-v,--version", "readelf version: 0.0.1", "Display version number of feelelf");

    app.add_flag("-h,--file-header", show_fileheader, "Display the ELF file header");

    app.add_flag("-l,--program-headers", show_segments, "Display the ELF file header");
    app.add_flag("--segments", show_segments, "An alias for --program-headers");

    app.add_flag("-S,--section-headers", show_sections, "Display the sections' header");
    app.add_flag("--sections", show_sections, "An alias for --section-headers");

    app.add_flag("-s,--syms", show_symbols, "Display the symbol table");
    app.add_flag("--symbols", show_symbols, "An alias for --syms");

    app.add_flag("-e,--headers", show_headers, "Equivalent to: -h -l -s");

    app.add_option("elf-file(s)", elf_files)->option_text(" ... ");

    app.parse(argc, argv);
  }
  catch(CLI::ParseError &e) {
    return app.exit(e);
  }

  if(show_headers) {
    show_fileheader = show_segments = show_sections = true;
  }

  feelelf::FileHeader header;

  for(const auto &p : elf_files) {
    if(!fs::exists(p)) {
      fmt::print("readelf: Error: '{}': No such file\n", p.c_str());
      continue;
    }

    bool is_good = header.open(p.c_str());

    if(!is_good) {
      fmt::print("readelf: Error: Not an ELF file - it has the wrong magic bytes at the start\n");
      continue;
    }

    header.decode();

    if(show_fileheader) {
      fmt::print("ELF Header:\n");
      fmt::print("  {:<8} {:02x}\n", "Magic:", fmt::join(header.identificationArray(), " "));
      fmt::print("  {:<34} {}\n", "Class:", header.fileClass());
      fmt::print("  {:<34} {}\n", "Data:", header.fileDataEncoding());
      fmt::print("  {:<34} {}\n", "Version:", header.fileVersion());
      fmt::print("  {:<34} {}\n", "OS/ABI:", header.osABI());
      fmt::print("  {:<34} {}\n", "ABI Version:", header.ABIVersion());
      fmt::print("  {:<34} {}\n", "Type:", header.type());
      fmt::print("  {:<34} {}\n", "Machine:", header.machine());
      fmt::print("  {:<34} {:#x}\n", "Version:", header.version());
      fmt::print("  {:<34} {:#x}\n", "Entry point address:", header.entryPoint());
      fmt::print("  {:<34} {}\n", "Start of program headers:", header.programHeaderOffset());
      fmt::print("  {:<34} {}\n", "Start of section headers:", header.sectionHeaderOffset());
      fmt::print("  {:<34} {:#x}\n", "Flags:", header.flags());
      fmt::print("  {:<34} {} (bytes)\n", "Size of this header:", header.headerSize());
      fmt::print("  {:<34} {} (bytes)\n", "Size of program headers:", header.programHeaderSize());
      fmt::print("  {:<34} {}\n", "Number of program headers:", header.numProgramHeaders());
      fmt::print("  {:<34} {} (bytes)\n", "Size of section headers:", header.sectionHeaderEntrySize());
      fmt::print("  {:<34} {}\n", "Number of section headers:", header.numSectionHeaders());
      fmt::print("  {:<34} {}\n\n", "Section header string table index:", header.sectionHeaderStringTableIndex());
    }

    if(show_segments) {
      if(!show_fileheader) {
        fmt::print("\nElf file type is {}\n", header.fileClass());
        fmt::print("Entry point {:#x}\n", header.entryPoint());
        fmt::print("There are {} program headers, starting at offset {}\n\n", header.numProgramHeaders(),
                   header.programHeaderOffset());
      }
      fmt::print("Program Headers:\n");
      if(!header.programHeaders().empty()) {

        if(std::holds_alternative<feelelf::Elf32_Program_Header_t>(header.programHeaders()[0])) {
          fmt::print("{:^14} {:^8} {:^10} {:^10} {:^7} {:^7} {:^6} {:<8}\n", "Type", "Offset", "VirtAddr", "PhysAddr",
                     "FileSiz", "MemSiz", "Flags", "Align");

          for(const auto &o : header.programHeaders()) {
            auto x86 = std::get<feelelf::Elf32_Program_Header_t>(o);
            fmt::print("{:<14} {:#08x} {:#010x} {:#010x} {:#07x} {:#07x} {:<6} {:#0x}\n",
                       feelelf::getProgramHeaderType(x86.type), x86.offset, x86.vaddr, x86.paddr, x86.filesz, x86.memsz,
                       feelelf::getProgramHeaderFlag(x86.flags), x86.align);
          }
        }

        else {

          fmt::print("{:^14} {:^16} {:^16} {:^16} {:^16} {:^16} {:<7} {:<8}\n", "Type", "Offset", "VirtAddr",
                     "PhysAddr", "FileSize", "MemSize", "Flags", "Align");

          for(const auto &o : header.programHeaders()) {
            auto x64 = std::get<feelelf::Elf64_Program_Header_t>(o);
            fmt::print("{:<14} {:#016x} {:#016x} {:#016x} {:#016x} {:#016x} {:<7} {:#0x}\n",
                       feelelf::getProgramHeaderType(x64.type), x64.offset, x64.vaddr, x64.paddr, x64.filesz, x64.memsz,
                       feelelf::getProgramHeaderFlag(x64.flags), x64.align);
          }
        }
      }
    }

    if(show_sections) {
      fmt::print("\nThere are {} section headers, starting at offset {:#0x}:\n\n", header.numSectionHeaders(),
                 header.sectionHeaderOffset());

      fmt::print("Section Headers:\n");

      if(std::holds_alternative<feelelf::Elf32_Section_Header_t>(header.sectionHeaders()[0])) {
        fmt::print("  {} {:<18} {:<15} {:<8} {:<6} {:<6} {:<9} {:<5} {:<4} {:<4} {}\n", "[Nr]", "Name", "Type",
                   "Address", "Offset", "Size", "EntrySize", "Flags", "Link", "Info", "Align");

        for(int i = 0; const auto &o : header.sectionHeaders()) {
          auto x86 = std::get<feelelf::Elf32_Section_Header_t>(o);
          fmt::print("  [{num:>2}] {name:<18} {type:<15} {address:>08x} {offset:>06x} {size:>06x} "
                     "{entrySize:<9x} {flags:<5} {link:<4} {info:<4} {align}\n",
                     "num"_a = i++, "name"_a = header.getSectionHeaderName(x86.name),
                     "type"_a = feelelf::getSectionHeaderType(x86.type), "address"_a = x86.addr,
                     "offset"_a = x86.offset, "size"_a = x86.size, "entrySize"_a = x86.entsize,
                     "flags"_a = feelelf::getSectionHeaderFlag(x86.flags), "link"_a = x86.link, "info"_a = x86.info,
                     "align"_a = x86.addralign);
        }

      } else {
        fmt::print("  {} {:<18} {:<15} {:<16} {:<8} {:<16} {:<16} {:<5} {:<4} {:<4} {}\n", //
                   "[Nr]", "Name", "Type", "Address", "Offset", "Size", "EntrySize", "Flags", "Link", "Info", "Align");

        for(int i = 0; const auto &o : header.sectionHeaders()) {
          auto x64 = std::get<feelelf::Elf64_Section_Header_t>(o);
          fmt::print("  [{num:>2}] {name:<18} {type:<15} {address:>016x} {offset:>08x} {size:>016x} "
                     "{entrySize:>016x} {flags:<5} {link:<4} {info:<4} {align}\n",
                     "num"_a = i++, "name"_a = header.getSectionHeaderName(x64.name),
                     "type"_a = feelelf::getSectionHeaderType(x64.type), "address"_a = x64.addr,
                     "offset"_a = x64.offset, "size"_a = x64.size, "entrySize"_a = x64.entsize,
                     "flags"_a = feelelf::getSectionHeaderFlag(x64.flags), "link"_a = x64.link, "info"_a = x64.info,
                     "align"_a = x64.addralign);
        }
      }

      fmt::print("\nKey to Flags:\n"
                 "  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),\n"
                 "  L (link order), O (extra OS processing required), G (group), T (TLS),\n"
                 "  C (compressed), x (unknown), o (OS specific), E (exclude),\n"
                 "  p (processor specific)\n");
    }

    if(show_symbols) {
      const auto symbols = header.symbols();

      if(!std::empty(symbols)) {
        if(std::holds_alternative<feelelf::Elf32_Symbol_t>(symbols[0])) {

          fmt::print("{num:>8} {value:^9} {size:>4} {type:^7} {bind:<5} {vis:^10} {index:>5} {name}\n",
                     "num"_a = "Num:", "value"_a = "Value", "size"_a = "Size", "type"_a = "Type", "bind"_a = "Bind",
                     "vis"_a = "Visibility", "index"_a = "Index", "name"_a = "Name");

          for(int i = 0; const auto &sym : symbols) {
            const auto x86 = std::get<feelelf::Elf32_Symbol_t>(sym);
            fmt::print("{num:>7}: {value:<08x} {size:>5} {type:<7} {binding:<6} {visibility:<9} {index:<5} "
                       "{name} \n",
                       "num"_a = i++, "value"_a = x86.value, "size"_a = x86.size,
                       "type"_a = feelelf::getSymbolType(x86.info), "binding"_a = feelelf::getSymbolBind(x86.info),
                       "visibility"_a = feelelf::getSymbolVisibility(x86.other), "index"_a = x86.shndx,
                       "name"_a = header.getSymbolName(x86.name));
          }
        }

        else {
          fmt::print("{num:>8} {value:^17} {size:>4} {type:^6} {bind:^6} {vis:<8} {index:>5} {name}\n",
                     "num"_a = "Num:", "value"_a = "Value", "size"_a = "Size", "type"_a = "Type", "bind"_a = "Bind",
                     "vis"_a = "Visibility", "index"_a = "Index", "name"_a = "Name");

          for(int i = 0; const auto &sym : symbols) {
            const auto x64 = std::get<feelelf::Elf64_Symbol_t>(sym);
            fmt::print("{num:>7}: {value:>016x} {size:>5} {type:<7} {binding:<6} {visibility:<9} {index:<5} {name}\n",
                       "num"_a = i++, "value"_a = x64.value, "size"_a = x64.size,
                       "type"_a = feelelf::getSymbolType(x64.info), "binding"_a = feelelf::getSymbolBind(x64.info),
                       "visibility"_a = feelelf::getSymbolVisibility(x64.other), "index"_a = x64.shndx,
                       "name"_a = header.getSymbolName(x64.name));
          }
        }
      }
    }
  }
}
