#include "elf.h"

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

  elf::Elf64_header_t elf64_header;

  for(const auto &p : files) {
    bool is_good = elf::init(elf64_header, p.c_str());

    if(!fs::exists(p)) continue;
    if(!is_good) continue;

    if(show_header) {
      fmt::print("ELF Header:\n");
      fmt::print("  {:<8} {:02x}\n", "Magic:", fmt::join(elf64_header.ident, " "));
      fmt::print("  {:<34} {}\n", "Class:", elf::decode_class(elf64_header));
      fmt::print("  {:<34} {}\n", "Data:", elf::decode_data(elf64_header));
      fmt::print("  {:<34} {}\n", "Version:", elf::decode_file_version(elf64_header));
      fmt::print("  {:<34} {}\n", "OS/ABI:", decode_os_abi(elf64_header));
      fmt::print("  {:<34} {}\n", "ABI Version:", elf64_header.ident[elf::i_abiversion]);
      fmt::print("  {:<34} {}\n", "Type:", elf::decode_filetype(elf64_header));
      fmt::print("  {:<34} {}\n", "Machine:", decode_machine(elf64_header));
      fmt::print("  {:<34} {:#x}\n", "Version:", elf64_header.version);
      fmt::print("  {:<34} {:#x}\n", "Entry point address:", elf64_header.entry);
      fmt::print("  {:<34} {}\n", "Start of program headers:", elf64_header.phoff);
      fmt::print("  {:<34} {}\n", "Start of section headers:", elf64_header.shoff);
      fmt::print("  {:<34} {:#x}\n", "Flags:", elf64_header.flags);
      fmt::print("  {:<34} {} (bytes)\n", "Size of this header:", elf64_header.ehsize);
      fmt::print("  {:<34} {} (bytes)\n", "Size of program headers:", elf64_header.phentsize);
      fmt::print("  {:<34} {}\n", "Number of program headers:", elf64_header.phnum);
      fmt::print("  {:<34} {} (bytes)\n", "Size of section headers:", elf64_header.shentsize);
      fmt::print("  {:<34} {}\n", "Number of section headers:", elf64_header.shnum);
      fmt::print("  {:<34} {}\n\n", "Section header string table index:", elf64_header.shstrndx);
    }

    if(show_segments) {
      if(!show_header) {
        fmt::print("\nElf file type is {}\n", elf::decode_class(elf64_header));
        fmt::print("Entry point {:#x}\n", elf64_header.entry);
        fmt::print("There are {} program headers, starting at offset {}\n\n", elf64_header.phnum,
                   elf64_header.phoff);
      }
      fmt::print("Program Headers:\n");
      fmt::print("Type           Offset             FileSize           VirtAddr           MemSize            "
                 "PhysAddr           Flags Align\n");
      const auto oo = elf::decode_program_headers(elf64_header, p.c_str());
      for(const auto &o : oo) {
        fmt::print("{}\n", elf::decode_program_header_type(o));
      }
    }

    if(show_version) {
      fmt::print("feelelf 0.0.1\n");
    }
  }
}
