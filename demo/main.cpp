#include <feelelf/feelelf.h>

#include <CLI/CLI.hpp>

#include <fmt/format.h>
#include <fmt/ranges.h>

#include <filesystem>
#include <vector>

int main(int argc, const char *argv[]) {
  namespace fs = std::filesystem;
  using namespace fmt::literals;

  std::vector<fs::path> files;

  bool show_header = false;
  bool show_segments = false;
  bool show_sections = false;

  CLI::App app{{}, "FeelELF"};
  try {
    app.set_help_flag("-H, --help", "Display this information");
    app.set_version_flag("-v,--version", "readelf version: 0.0.1", "Display version number of feelelf");

    app.add_flag("-h,--file-header", show_header, "Display the ELF file header");
    app.add_flag("-l,--program-headers,--segments", show_segments, "Display the ELF file header");
    app.add_flag("-S,--section-headers,--sections", show_sections, "Display the sections' header");
    app.add_option("elf-files", files);

    app.parse(argc, argv);
  }
  catch(CLI::ParseError &e) {
    return app.exit(e);
  }

  feelelf::FileHeader header;

  for(const auto &p : files) {
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

    if(show_header) {
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
      fmt::print("  {:<34} {}\n\n",
                 "Section header string table index:", header.sectionHeaderStringTableIndex());
    }

    if(show_segments) {
      if(!show_header) {
        fmt::print("\nElf file type is {}\n", header.fileClass());
        fmt::print("Entry point {:#x}\n", header.entryPoint());
        fmt::print("There are {} program headers, starting at offset {}\n\n", header.numProgramHeaders(),
                   header.programHeaderOffset());
      }
      fmt::print("Program Headers:\n");
      if(!header.programHeaders().empty()) {

        if(std::holds_alternative<feelelf::Elf64_Program_Header_t>(header.programHeaders()[0])) {

          fmt::print("{:^14} {:^16} {:^16} {:^16} {:^16} {:^16} {:<7} {:<8}\n", "Type", "Offset", "VirtAddr",
                     "PhysAddr", "FileSize", "MemSize", "Flags", "Align");

          for(const auto &o : header.programHeaders()) {
            auto x64 = std::get<feelelf::Elf64_Program_Header_t>(o);
            fmt::print("{:<14} {:#016x} {:#016x} {:#016x} {:#016x} {:#016x} {:<7} {:#0x}\n",
                       header.programHeaderType(x64.type), x64.offset, x64.vaddr, x64.paddr, x64.filesz,
                       x64.memsz, header.programHeaderFlag(x64.flags), x64.align);
          }
        }

        else {

          fmt::print("{:^14} {:^8} {:^10} {:^10} {:^7} {:^7} {:^6} {:<8}\n", "Type", "Offset", "VirtAddr",
                     "PhysAddr", "FileSiz", "MemSiz", "Flags", "Align");

          for(const auto &o : header.programHeaders()) {
            auto x86 = std::get<feelelf::Elf32_Program_Header_t>(o);
            fmt::print("{:<14} {:#08x} {:#010x} {:#010x} {:#07x} {:#07x} {:<6} {:#0x}\n",
                       header.programHeaderType(x86.type), x86.offset, x86.vaddr, x86.paddr, x86.filesz,
                       x86.memsz, header.programHeaderFlag(x86.flags), x86.align);
          }
        }
      }
    }

    if(show_sections) {
      fmt::print("There are {} section headers, starting at offset {:#0x}:\n\n", header.numSectionHeaders(),
                 header.sectionHeaderOffset());

      fmt::print("Section Headers:\n");

      if(std::holds_alternative<feelelf::Elf64_Section_Header_t>(header.sectionHeaders()[0])) {
        fmt::print("  {} {:<17} {:<15} {:<16} {:<8} {:<16} {:<16} {:<5} {:<4} {:<4} {}\n", //
                   "[Nr]", "Name", "Type", "Address", "Offset", "Size", "EntrySize", "Flags", "Link", "Info",
                   "Align");

        for(int i = 0; const auto &o : header.sectionHeaders()) {
          auto x64 = std::get<feelelf::Elf64_Section_Header_t>(o);
          fmt::print("  [{num:>2}] {name:<17} {type:<15} {address:>016x} {offset:>08x} {size:>016x} "
                     "{entrySize:>016x} {flags:<5} {link:<4} {info:<4} {align}\n",
                     "num"_a = i++, "name"_a = header.sectionHeaderName(x64.name),
                     "type"_a = header.sectionHeaderType(x64.type), "address"_a = x64.addr,
                     "offset"_a = x64.offset, "size"_a = x64.size, "entrySize"_a = x64.entsize,
                     "flags"_a = x64.flags, "link"_a = x64.link, "info"_a = x64.info,
                     "align"_a = x64.addralign);
        }

      } else {
        fmt::print("  {} {:<17} {:<15} {:<8} {:<6} {:<6} {:<9} {:<5} {:<4} {:<4} {}\n", "[Nr]", "Name",
                   "Type", "Address", "Offset", "Size", "EntrySize", "Flags", "Link", "Info", "Align");

        for(int i = 0; const auto &o : header.sectionHeaders()) {
          auto x86 = std::get<feelelf::Elf32_Section_Header_t>(o);
          fmt::print("  [{num:>2}] {name:<17} {type:<15} {address:>08x} {offset:>06x} {size:>06x} "
                     "{entrySize:<9x} {flags:<5} {link:<4} {info:<4} {align}\n",
                     "num"_a = i++, "name"_a = header.sectionHeaderName(x86.name),
                     "type"_a = header.sectionHeaderType(x86.type), "address"_a = x86.addr,
                     "offset"_a = x86.offset, "size"_a = x86.size, "entrySize"_a = x86.entsize,
                     "flags"_a = x86.flags, "link"_a = x86.link, "info"_a = x86.info,
                     "align"_a = x86.addralign);
        }
      }
    }
  }
}
