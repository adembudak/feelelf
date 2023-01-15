// ELF header parser based on: man 5 elf

#include "elf.h"

#include <CLI/CLI.hpp>

#include <fmt/format.h>
#include <fmt/ranges.h>


int main(int argc, const char *argv[]) {
  elf::Elf64_header_t elf64_header;

  bool ret = elf::init(elf64_header, argv[1]);

  fmt::print("Magic:                             {:x}\n", fmt::join(elf64_header.ident, " "));
  fmt::print("Class:                             {}\n", elf::decode_class(elf64_header));
  fmt::print("Data:                              {}\n", elf::decode_data(elf64_header));
  fmt::print("Version:                           {}\n", elf::decode_file_version(elf64_header));
  fmt::print("OS/ABI:                            {}\n", decode_os_abi(elf64_header));
  fmt::print("ABI Version:                       {}\n", elf64_header.ident[elf::i_abiversion]);
  fmt::print("Type:                              {}\n", elf::decode_type(elf64_header));
  fmt::print("Machine:                           {}\n", decode_machine(elf64_header));
  fmt::print("Version:                           {}\n", elf64_header.version);
  fmt::print("Entry point address:               {}\n", elf64_header.entry);
  fmt::print("Start of program headers:          {}\n", elf64_header.phoff);
  fmt::print("Start of section headers:          {}\n", elf64_header.shoff);
  fmt::print("Flags:                             {}\n", elf64_header.flags);
  fmt::print("Size of this header:               {}\n", elf64_header.ehsize);
  fmt::print("Size of program headers:           {}\n", elf64_header.phentsize);
  fmt::print("Number of program headers:         {}\n", elf64_header.phnum);
  fmt::print("Size of section headers:           {}\n", elf64_header.shentsize);
  fmt::print("Number of section headers:         {}\n", elf64_header.shnum);
  fmt::print("Section header string table index: {}\n", elf64_header.shstrndx);
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
