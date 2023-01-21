#include <feelelf/feelelf.h>

#include <CLI/CLI.hpp>

#include <fmt/format.h>
#include <fmt/ranges.h>

#include <filesystem>
#include <vector>

int main(int argc, const char *argv[]) {
  namespace fs = std::filesystem;
  std::vector<fs::path> files;

  bool show_header = false;
  bool show_segments = false;

  bool show_help = false;
  bool show_version = false;

  CLI::App app{{}, "FeelELF"};
  try {
    app.add_flag("-H,--file-header", show_header, "Display the ELF file header");
    app.add_flag("-l,--program-headers,--segments", show_segments, "Display the ELF file header");
    app.add_option("elf-files", files);

    app.add_flag("-v,--version", show_version, "Display version number of feelelf");

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
      fmt::print("  {:<34} {} (bytes)\n", "Size of section headers:", header.sectionHeaderSize());
      fmt::print("  {:<34} {}\n", "Number of section headers:", header.numSectionHeaders());
      fmt::print("  {:<34} {}\n\n", "Section header string table index:", header.sectionHeaderStringTable());
    }

    if(show_segments) {
      if(!show_header) {
        fmt::print("\nElf file type is {}\n", header.fileClass());
        fmt::print("Entry point {:#x}\n", header.entryPoint());
        fmt::print("There are {} program headers, starting at offset {}\n\n", header.numProgramHeaders(),
                   header.programHeaderOffset());
      }
      fmt::print("Program Headers:\n");

      fmt::print("{:^14} {:^16} {:^16} {:^16} {:^16} {:^16} {:^8} {:<8}\n", "Type", "Offset", "FileSize",
                 "VirtAddr", "MemSize", "PhysAddr", "Flags", "Align");

      for(const auto &o : header.programHeaders()) {
        if(auto x64 = std::get_if<feelelf::Elf64_Program_Header_t>(&o))
          fmt::print("{:<14} {:#016x} {:#016x} {:#016x} {:#016x} {:#016x} {:<16} {:#016x}\n",
                     header.programHeaderType(o), //
                     x64->offset,                 //
                     x64->filesz,                 //
                     x64->vaddr,                  //
                     x64->memsz,                  //
                     x64->paddr,                  //
                     header.programHeaderFlag(o), //
                     x64->align);

        else if(auto x86 = std::get_if<feelelf::Elf32_Program_Header_t>(&o))
          fmt::print("{:<14} {:#016x} {:#016x} {:#016x} {:#016x} {:#016x} {:<16} {:#016x}\n",
                     header.programHeaderType(o), //
                     x86->offset,                 //
                     x86->filesz,                 //
                     x86->vaddr,                  //
                     x86->memsz,                  //
                     x86->paddr,                  //
                     header.programHeaderFlag(o), //
                     x86->align);
      }
    }

    if(show_version) fmt::print("feelelf 0.0.1\n");
  }
}
