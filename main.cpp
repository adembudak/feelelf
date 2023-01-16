// ELF header parser based on: man 5 elf

#include "elf.h"

#include <CLI/CLI.hpp>

#include <fmt/format.h>
#include <fmt/ranges.h>

#include <ranges>
#include <vector>

int main(int argc, const char *argv[]) {
  bool header{};
  bool segments{};
  std::vector<std::filesystem::path> files;

  CLI::App app{{}, "FeelELF"};
  app.add_flag("--file-header", header, "Display the ELF file header");
  app.add_flag("-l,--program-headers,--segments", segments, "Display the ELF file header");
  app.add_option("elf-files", files);
  CLI11_PARSE(app, argc, argv);

  elf::Elf64_header_t elf64_header;

  for(const auto &p : files | std::views::filter([](auto &p) { return exists(p); })) {
    bool is_good = elf::init(elf64_header, p.c_str());

    if(header & is_good) {
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

    if(segments) {
      fmt::print("Segments\n");
    }
  }
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
