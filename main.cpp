// ELF header parser based on: man 5 elf

#include "elf.h"

#include <CLI/CLI.hpp>

#include <fmt/format.h>
#include <fmt/ranges.h>

#include <cassert>

int main(int argc, const char *argv[]) {
  elf::Elf64_header_t elf64_header;

  bool ret = elf::init(elf64_header, argv[1]);
  assert(ret);

  fmt::print("Magic:          {:x}\n", fmt::join(elf64_header.ident, " "));
  fmt::print("Class:          {}\n", elf::decode_class(elf64_header));        // ELF64
  fmt::print("Data:           {}\n", elf::decode_data(elf64_header));         // 2's complement, little endian
  fmt::print("Version:        {}\n", elf::decode_file_version(elf64_header)); // 1 (current)
  fmt::print("OS/ABI:         {}\n", decode_os_abi(elf64_header));            // UNIX - GNU
  fmt::print("ABI Version:    {}\n", elf64_header.ident[elf::i_abiversion]);  // 0
  fmt::print("Type:           {}\n", elf::decode_type(elf64_header));         // EXEC (Executable file)
  fmt::print("Machine:        {} {}\n", decode_machine(elf64_header), elf64_header.machine);
  // fmt::print("Version:        {}\n", elf64_Ehdr.version); // 0x1
  /*
  fmt::print("Entry point address: {:X}\n", elf64_Ehdr.e_entry); // 0x40de00
  fmt::print("Start of program headers: {}");          // 64 (bytes into file)
  fmt::print("Start of section headers: {}");          // 1106752 (bytes into file)
  fmt::print("Flags: {}");                             // 0x0
  fmt::print("Size of this header: {}");               // 64 (bytes)
  fmt::print("Size of program headers: {}");           // 56 (bytes)
  fmt::print("Number of program headers: {}");         // 11
  fmt::print("Size of section headers: {}");           // 64 (bytes)
  fmt::print("Number of section headers: {}");         // 39
  fmt::print("Section header string table index: {}"); // 38
  */
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
