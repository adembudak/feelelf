#include <feelelf/feelelf.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <ranges>
#include <string_view>
#include <vector>

namespace feelelf {

// clang-format off
template <class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template <class... Ts> overloaded(Ts...) -> overloaded<Ts...>;
// clang-format on

enum machine : Elf64_Half {
  machineNone = 0,     // No machine
  m32 = 1,             // AT&T WE 32100
  sparc = 2,           // SUN SPARC
  _386 = 3,            // Intel 80386
  _68k = 4,            // Motorola m68k family
  _88k = 5,            // Motorola m88k family
  iamcu = 6,           // Intel MCU
  _860 = 7,            // Intel 80860
  mips = 8,            // MIPS R3000 big-endian
  s370 = 9,            // IBM System/370
  mips_rs3_le = 10,    // MIPS R3000 little-endian
  reserved11 = 11,     // reserved = 11-14
  reserved12 = 12,     // reserved = 11-14
  reserved13 = 13,     // reserved = 11-14
  reserved14 = 14,     // reserved = 11-14
  parisc = 15,         // HPPA
  reserved16 = 16,     // reserved = 16
  vpp500 = 17,         // Fujitsu VPP500
  sparc32plus = 18,    // Sun's "v8plus"
  _960 = 19,           // Intel 80960
  ppc = 20,            // PowerPC
  ppc64 = 21,          // PowerPC 64-bit
  s390 = 22,           // IBM S390
  spu = 23,            // IBM SPU/SPC
  reserved24 = 24,     // reserved = 24-35
  reserved25 = 25,     // reserved = 24-35
  reserved26 = 26,     // reserved = 24-35
  reserved27 = 27,     // reserved = 24-35
  reserved28 = 28,     // reserved = 24-35
  reserved29 = 29,     // reserved = 24-35
  reserved30 = 30,     // reserved = 24-35
  reserved31 = 31,     // reserved = 24-35
  reserved32 = 32,     // reserved = 24-35
  reserved33 = 33,     // reserved = 24-35
  reserved34 = 34,     // reserved = 24-35
  reserved35 = 35,     // reserved = 24-35
  v800 = 36,           // NEC V800 series
  fr20 = 37,           // Fujitsu FR20
  rh32 = 38,           // TRW RH-32
  rce = 39,            // Motorola RCE
  arm = 40,            // ARM
  fake_alpha = 41,     // Digital Alpha
  sh = 42,             // Hitachi SH
  sparcv9 = 43,        // SPARC v9 64-bit
  tricore = 44,        // Siemens Tricore
  arc = 45,            // Argonaut RISC Core
  h8_300 = 46,         // Hitachi H8/300
  h8_300h = 47,        // Hitachi H8/300H
  h8s = 48,            // Hitachi H8S
  h8_500 = 49,         // Hitachi H8/500
  ia_64 = 50,          // Intel Merced
  mips_x = 51,         // Stanford MIPS-X
  coldfire = 52,       // Motorola Coldfire
  _68hc12 = 53,        // Motorola M68HC12
  mma = 54,            // Fujitsu MMA Multimedia Accelerator
  pcp = 55,            // Siemens PCP
  ncpu = 56,           // Sony nCPU embeeded RISC
  ndr1 = 57,           // Denso NDR1 microprocessor
  starcore = 58,       // Motorola Start*Core processor
  me16 = 59,           // Toyota ME16 processor
  st100 = 60,          // STMicroelectronic ST100 processor
  tinyj = 61,          // Advanced Logic Corp. Tinyj emb.fam
  x86_64 = 62,         // AMD x86-64 architecture
  pdsp = 63,           // Sony DSP Processor
  pdp10 = 64,          // Digital PDP-10
  pdp11 = 65,          // Digital PDP-11
  fx66 = 66,           // Siemens FX66 microcontroller
  st9plus = 67,        // STMicroelectronics ST9+ 8/16 mc
  st7 = 68,            // STmicroelectronics ST7 8 bit mc
  _68hc16 = 69,        // Motorola MC68HC16 microcontroller
  _68hc11 = 70,        // Motorola MC68HC11 microcontroller
  _68hc08 = 71,        // Motorola MC68HC08 microcontroller
  _68hc05 = 72,        // Motorola MC68HC05 microcontroller
  svx = 73,            // Silicon Graphics SVx
  st19 = 74,           // STMicroelectronics ST19 8 bit mc
  vax = 75,            // Digital VAX
  cris = 76,           // Axis Communications 32-bit emb.proc
  javelin = 77,        // Infineon Technologies 32-bit emb.proc
  firepath = 78,       // Element 14 64-bit DSP Processor
  zsp = 79,            // LSI Logic 16-bit DSP Processor
  mmix = 80,           // Donald Knuth's educational 64-bit proc
  huany = 81,          // Harvard University machine-independent object files
  prism = 82,          // SiTera Prism
  avr = 83,            // Atmel AVR 8-bit microcontroller
  fr30 = 84,           // Fujitsu FR30
  d10v = 85,           // Mitsubishi D10V
  d30v = 86,           // Mitsubishi D30V
  v850 = 87,           // NEC v850
  m32r = 88,           // Mitsubishi M32R
  mn10300 = 89,        // Matsushita MN10300
  mn10200 = 90,        // Matsushita MN10200
  pj = 91,             // picoJava
  openrisc = 92,       // OpenRISC 32-bit embedded processor
  arc_compact = 93,    // ARC International ARCompact
  xtensa = 94,         // Tensilica Xtensa Architecture
  videocore = 95,      // Alphamosaic VideoCore
  tmm_gpp = 96,        // Thompson Multimedia General Purpose Proc
  ns32k = 97,          // National Semi. 32000
  tpc = 98,            // Tenor Network TPC
  snp1k = 99,          // Trebia SNP 1000
  st200 = 100,         // STMicroelectronics ST200
  ip2k = 101,          // Ubicom IP2xxx
  max = 102,           // MAX processor
  cr = 103,            // National Semi. CompactRISC
  f2mc16 = 104,        // Fujitsu F2MC16
  msp430 = 105,        // Texas Instruments msp430
  blackfin = 106,      // Analog Devices Blackfin DSP
  se_c33 = 107,        // Seiko Epson S1C33 family
  sep = 108,           // Sharp embedded microprocessor
  arca = 109,          // Arca RISC
  unicore = 110,       // PKU-Unity & MPRC Peking Uni. mc series
  excess = 111,        // eXcess configurable cpu
  dxp = 112,           // Icera Semi. Deep Execution Processor
  altera_nios2 = 113,  // Altera Nios II
  crx = 114,           // National Semi. CompactRISC CRX
  xgate = 115,         // Motorola XGATE
  c166 = 116,          // Infineon C16x/XC16x
  m16c = 117,          // Renesas M16C
  dspic30f = 118,      // Microchip Technology dsPIC30F
  ce = 119,            // Freescale Communication Engine RISC
  m32c = 120,          // Renesas M32C
  reserved121 = 121,   // reserved = 121-130
  reserved122 = 122,   // reserved = 121-130
  reserved123 = 123,   // reserved = 121-130
  reserved124 = 124,   // reserved = 121-130
  reserved125 = 125,   // reserved = 121-130
  reserved126 = 126,   // reserved = 121-130
  reserved127 = 127,   // reserved = 121-130
  reserved128 = 128,   // reserved = 121-130
  reserved129 = 129,   // reserved = 121-130
  reserved130 = 130,   // reserved = 121-130
  tsk3000 = 131,       // Altium TSK3000
  rs08 = 132,          // Freescale RS08
  sharc = 133,         // Analog Devices SHARC family
  ecog2 = 134,         // Cyan Technology eCOG2
  score7 = 135,        // Sunplus S+core7 RISC
  dsp24 = 136,         // New Japan Radio (NJR) 24-bit DSP
  videocore3 = 137,    // Broadcom VideoCore III
  latticemico32 = 138, // RISC for Lattice FPGA
  se_c17 = 139,        // Seiko Epson C17
  ti_c6000 = 140,      // Texas Instruments TMS320C6000 DSP
  ti_c2000 = 141,      // Texas Instruments TMS320C2000 DSP
  ti_c5500 = 142,      // Texas Instruments TMS320C55x DSP
  ti_arp32 = 143,      // Texas Instruments App. Specific RISC
  ti_pru = 144,        // Texas Instruments Prog. Realtime Unit
  reserved145 = 145,   // reserved = 145-159
  reserved146 = 146,   // reserved = 145-159
  reserved147 = 147,   // reserved = 145-159
  reserved148 = 148,   // reserved = 145-159
  reserved149 = 149,   // reserved = 145-159
  reserved150 = 150,   // reserved = 145-159
  reserved151 = 151,   // reserved = 145-159
  reserved152 = 152,   // reserved = 145-159
  reserved153 = 153,   // reserved = 145-159
  reserved154 = 154,   // reserved = 145-159
  reserved155 = 155,   // reserved = 145-159
  reserved156 = 156,   // reserved = 145-159
  reserved157 = 157,   // reserved = 145-159
  reserved158 = 158,   // reserved = 145-159
  reserved159 = 159,   // reserved = 145-159
  mmdsp_plus = 160,    // STMicroelectronics 64bit VLIW DSP
  cypress_m8c = 161,   // Cypress M8C
  r32c = 162,          // Renesas R32C
  trimedia = 163,      // NXP Semi. TriMedia
  qdsp6 = 164,         // QUALCOMM DSP6
  _8051 = 165,         // Intel 8051 and variants
  stxp7x = 166,        // STMicroelectronics STxP7x
  nds32 = 167,         // Andes Tech. compact code emb. RISC
  ecog1x = 168,        // Cyan Technology eCOG1X
  maxq30 = 169,        // Dallas Semi. MAXQ30 mc
  ximo16 = 170,        // New Japan Radio (NJR) 16-bit DSP
  manik = 171,         // M2000 Reconfigurable RISC
  craynv2 = 172,       // Cray NV2 vector architecture
  rx = 173,            // Renesas RX
  metag = 174,         // Imagination Tech. META
  mcst_elbrus = 175,   // MCST Elbrus
  ecog16 = 176,        // Cyan Technology eCOG16
  cr16 = 177,          // National Semi. CompactRISC CR16
  etpu = 178,          // Freescale Extended Time Processing Unit
  sle9x = 179,         // Infineon Tech. SLE9X
  l10m = 180,          // Intel L10M
  k10m = 181,          // Intel K10M
  reserved182 = 182,   // reserved = 182
  aarch64 = 183,       // ARM AARCH64
  reserved184 = 184,   // reserved = 184
  avr32 = 185,         // Amtel 32-bit microprocessor
  stm8 = 186,          // STMicroelectronics STM8
  tile64 = 187,        // Tileta TILE64
  tilepro = 188,       // Tilera TILEPro
  microblaze = 189,    // Xilinx MicroBlaze
  cuda = 190,          // NVIDIA CUDA
  tilegx = 191,        // Tilera TILE-Gx
  cloudshield = 192,   // CloudShield
  corea_1st = 193,     // KIPO-KAIST Core-A 1st gen.
  corea_2nd = 194,     // KIPO-KAIST Core-A 2nd gen.
  arc_compact2 = 195,  // Synopsys ARCompact V2
  open8 = 196,         // Open8 RISC
  rl78 = 197,          // Renesas RL78
  videocore5 = 198,    // Broadcom VideoCore V
  _78kor = 199,        // Renesas 78KOR
  _56800ex = 200,      // Freescale 56800EX DSC
  ba1 = 201,           // Beyond BA1
  ba2 = 202,           // Beyond BA2
  xcore = 203,         // XMOS xCORE
  mchp_pic = 204,      // Microchip 8-bit PIC(r)
  reserved205 = 205,   // reserved = 205-209
  reserved206 = 206,   // reserved = 205-209
  reserved207 = 207,   // reserved = 205-209
  reserved208 = 208,   // reserved = 205-209
  reserved209 = 209,   // reserved = 205-209
  km32 = 210,          // KM211 KM32
  kmx32 = 211,         // KM211 KMX32
  emx16 = 212,         // KM211 KMX16
  emx8 = 213,          // KM211 KMX8
  kvarc = 214,         // KM211 KVARC
  cdp = 215,           // Paneve CDP
  coge = 216,          // Cognitive Smart Memory Processor
  cool = 217,          // Bluechip CoolEngine
  norc = 218,          // Nanoradio Optimized RISC
  csr_kalimba = 219,   // CSR Kalimba
  z80 = 220,           // Zilog Z80
  visium = 221,        // Controls and Data Services VISIUMcore
  ft32 = 222,          // FTDI Chip FT32
  moxie = 223,         // Moxie processor
  amdgpu = 224,        // AMD GPU
  reserved225 = 225,   // reserved 225-242
  reserved226 = 226,   // reserved 225-242
  reserved227 = 227,   // reserved 225-242
  reserved228 = 228,   // reserved 225-242
  reserved229 = 229,   // reserved 225-242
  reserved230 = 230,   // reserved 225-242
  reserved231 = 231,   // reserved 225-242
  reserved232 = 232,   // reserved 225-242
  reserved233 = 233,   // reserved 225-242
  reserved234 = 234,   // reserved 225-242
  reserved235 = 235,   // reserved 225-242
  reserved236 = 236,   // reserved 225-242
  reserved237 = 237,   // reserved 225-242
  reserved238 = 238,   // reserved 225-242
  reserved239 = 239,   // reserved 225-242
  reserved240 = 240,   // reserved 225-242
  reserved241 = 241,   // reserved 225-242
  reserved242 = 242,   // reserved 225-242
  riscv = 243,         // RISC-V
  bpf = 247,           // Linux BPF -- in-kernel virtual machine
  csky = 252,          // C-SKY
  num = 253
};

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
            fin.read(reinterpret_cast<char*>(&x32),  sizeof(decltype(x32)));

            program_headers.resize(x32.phNumber);
            std::ranges::fill(program_headers, Elf32_Program_Header_t{});

            section_headers.resize(x32.shNumber);
            std::ranges::fill(section_headers, Elf32_Section_Header_t{});
      },
      [&](Elf64_Header_t &x64) {
            fin.read(reinterpret_cast<char *>(&x64), sizeof(decltype(x64)));

            program_headers.resize(x64.phNumber);
            std::ranges::fill(program_headers, Elf64_Program_Header_t{});

            section_headers.resize(x64.shNumber);
            std::ranges::fill(section_headers, Elf64_Section_Header_t{});
      }
    }, elf_header);
  // clang-format on
}

auto FileHeader::identificationArray() noexcept -> std::span<Elf_byte> const {
  if(auto x64 = std::get_if<Elf64_Header_t>(&elf_header)) //
    return x64->ident;
  return std::get<Elf32_Header_t>(elf_header).ident;
}

auto FileHeader::fileClass() noexcept -> std::string_view const {
  auto classData = std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.ident[i_class]; },
                                         [](const Elf64_Header_t &x64) { return x64.ident[i_class]; }},
                              elf_header);
  switch(classData) {
  case 0: return "None";  // Invalid class
  case 1: return "ELF32"; // 32-bit objects, machines with virtual address spaces up to 4Gb
  case 2: return "ELF64"; // 64-bit objects
  }
}

auto FileHeader::fileDataEncoding() noexcept -> std::string_view const {
  auto encodingData = std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.ident[i_data]; },
                                            [](const Elf64_Header_t &x64) { return x64.ident[i_data]; }},
                                 elf_header);

  switch(encodingData) {
  case 0: return "None";
  case 1: return "2's complement, little endian"; // 0x0102 -> 0x02 0x01
  case 2: return "2's complement, big endian";    // 0x0102 -> 0x01 0x02
  }
}

auto FileHeader::fileVersion() noexcept -> std::string_view const {
  auto versionData = std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.ident[i_version]; },
                                           [](const Elf64_Header_t &x64) { return x64.ident[i_version]; }},
                                elf_header);

  switch(versionData) {
  case 0: return "0 (Invalid)";
  case 1: return "1 (Current)";
  }
}

auto FileHeader::osABI() noexcept -> std::string_view const {
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

auto FileHeader::ABIVersion() noexcept -> int {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.ident[i_abiversion]; },
                               [](const Elf64_Header_t &x64) { return x64.ident[i_abiversion]; }},
                    elf_header);
}

auto FileHeader::type() noexcept -> std::string_view const {
  auto fileType = std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.type; },
                                        [](const Elf64_Header_t &x64) { return x64.type; }},
                             elf_header);
  switch(fileType) {
  case 0: return "No file type";
  case 1: return "Relocatible file";
  case 2: return "Executable file";
  case 3: return "Shared object file";
  case 4: return "Core file";
  case 0xff00: return "Processor specific";
  case 0xffff: return "Processor specific";
  }
}

auto FileHeader::machine() noexcept -> std::string_view const {
  auto machine = std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.machine; },
                                       [](const Elf64_Header_t &x64) { return x64.machine; }},
                            elf_header);
  switch(machine) {
  case machine::machineNone: return "An unknown machine";
  case machine::m32: return "AT&T WE 32100";
  case machine::sparc: return "Sun Microsystems SPARC";
  case machine::_386: return "Intel 80386";
  case machine::_68k: return "Motorola 68000";
  case machine::_88k: return "Motorola 88000";
  case machine::_860: return "Intel 80860";
  case machine::mips: return "MIPS RS3000 (big-endian only)";
  case machine::parisc: return "HP/PA";
  case machine::sparc32plus: return "SPARC with enhanced instruction set";
  case machine::ppc: return "PowerPC";
  case machine::ppc64: return "PowerPC 64-bit";
  case machine::s390: return "IBM S/390";
  case machine::arm: return "Advanced RISC Machines";
  case machine::sh: return "Renesas SuperH";
  case machine::sparcv9: return "SPARC v9 64-bit";
  case machine::ia_64: return "Intel Itanium";
  case machine::x86_64: return "AMD x86-64";
  case machine::vax: return "DEC Vax";
  }
}

auto FileHeader::version() noexcept -> int const {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.version; },
                               [](const Elf64_Header_t &x64) { return x64.version; }},
                    elf_header);
}

auto FileHeader::entryPoint() noexcept -> int const {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) -> int { return x32.entryPoint; },
                               [](const Elf64_Header_t &x64) -> int { return x64.entryPoint; }},
                    elf_header);
}

auto FileHeader::programHeaderOffset() noexcept -> std::size_t const {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) -> size_t { return x32.phOffset; },
                               [](const Elf64_Header_t &x64) -> size_t { return x64.phOffset; }},
                    elf_header);
}

auto FileHeader::sectionHeaderOffset() noexcept -> std::size_t const {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) -> std::size_t { return x32.shOffset; },
                               [](const Elf64_Header_t &x64) -> std::size_t { return x64.shOffset; }},
                    elf_header);
}

// clang-format off
auto FileHeader::programHeaders() noexcept -> const decltype(program_headers) & {
  fin.seekg(programHeaderOffset());

  for(auto &ph : program_headers) {
    std::visit(overloaded{[](Elf32_Program_Header_t &x86) { fin.read(reinterpret_cast<char *>(&x86), sizeof(decltype(x86))); },
                          [](Elf64_Program_Header_t &x64) { fin.read(reinterpret_cast<char *>(&x64), sizeof(decltype(x64))); }},
               ph);
  }

  return program_headers;
}

auto FileHeader::sectionHeaders() noexcept -> const decltype(section_headers) & {
  fin.seekg(sectionHeaderOffset());

  for(auto &sh : section_headers) {
    std::visit(
      overloaded{[](Elf32_Section_Header_t &x86) { fin.read(reinterpret_cast<char *>(&x86), sizeof(decltype(x86))); },
                 [](Elf64_Section_Header_t &x64) { fin.read(reinterpret_cast<char *>(&x64), sizeof(decltype(x64))); }},
        sh);
  }

  return section_headers;
}
// clang-format on

auto FileHeader::getProgramHeaderType(const std::size_t i) noexcept -> std::string_view const {
  // clang-format off
  switch(i) {
  case 0: return "NULL";                  // program header table entry
  case 1: return "LOAD";                  // loadable program segment
  case 2: return "DYNAMIC";               // dynamic linking informatio
  case 3: return "INTERP";                // program interpreter
  case 4: return "NOTE";                  // auxiliary information
  case 5: return "SHLIB";                 // reserved
  case 6: return "PHDR";                  // entry for header table its
  case 7: return "TLS";                   // thread-local storage segme
  case 8: return "NUM";                   // number of defined types
  case 0x60000000: return "LOOS";         // start of OS-specific
  case 0x6474e550: return "GNU_EH_FRAME"; // GCC .eh_frame_hdr segment
  case 0x6474e551: return "GNU_STACK";    // indicates stack executabil
  case 0x6474e552: return "GNU_RELRO";    // read-only after relocation
  // case 0x6ffffffa: return "LOSUNW";    //
  case 0x6ffffffa: return "SUNWBSS";      // Sun Specific segment
  case 0x6ffffffb: return "SUNWSTACK";    // stack segment
  //case 0x6fffffff: return "HISUNW";     //
  case 0x6FFfffff: return "HIOS";         // end of OS-specific
  case 0x70000000: return "LOPROC";       // start of processor-specific
  case 0x7fffffff: return "HIPROC";       // end of processor-specific
  }
}

std::string phFlagStr;
[[nodiscard]] auto FileHeader::getProgramHeaderFlag(const std::size_t phFlag) noexcept -> std::string_view const {
  phFlagStr.clear();

  if(phFlag & (1 << 0)) phFlagStr.push_back('X');
  if(phFlag & (1 << 1)) phFlagStr.push_back('W');
  if(phFlag & (1 << 2)) phFlagStr.push_back('R');
  // if(phFlags & 0x0ff00000) REVISIT: handle OS-specific
  // if(phFlags & 0xf0000000) REVISIT: handle processor-specific

  return phFlagStr.c_str();
}

auto FileHeader::flags() noexcept -> int const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.flags; },
                               [](const Elf32_Header_t &x32) { return x32.flags; }},
                    elf_header);
}

auto FileHeader::headerSize() noexcept -> int const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.size; },
                               [](const Elf32_Header_t &x32) { return x32.size; }},
                    elf_header);
}

auto FileHeader::programHeaderSize() noexcept -> int const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.phEntrySize; },
                               [](const Elf32_Header_t &x32) { return x32.phEntrySize; }},
                    elf_header);
}

auto FileHeader::numProgramHeaders() noexcept -> int const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.phNumber; },
                               [](const Elf32_Header_t &x32) { return x32.phNumber; }},
                    elf_header);
}

auto FileHeader::sectionHeaderEntrySize() noexcept -> std::size_t const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.shEntrySize; },
                               [](const Elf32_Header_t &x32) { return x32.shEntrySize; }},
                    elf_header);
}

auto FileHeader::numSectionHeaders() noexcept -> int const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.shNumber; },
                               [](const Elf32_Header_t &x32) { return x32.shNumber; }},
                    elf_header);
}

auto FileHeader::sectionHeaderStringTableIndex() noexcept -> int const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.shStringIndex; },
                               [](const Elf32_Header_t &x32) { return x32.shStringIndex; }},
                    elf_header);
}

auto FileHeader::hasProgramHeaders() noexcept -> bool const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.phOffset == 0; },
                               [](const Elf32_Header_t &x32) { return x32.phOffset == 0; }},
                    elf_header);
}

auto FileHeader::hasSectionHeaders() noexcept -> bool const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.shOffset == 0; },
                               [](const Elf32_Header_t &x32) { return x32.shOffset == 0; }},
                    elf_header);
}

constexpr Elf_byte identification_bytes[]{0x7f, 'E', 'L', 'F'};

auto FileHeader::isELF() noexcept -> bool const {
  fin.seekg(0);

  Elf_byte temp[4]{};
  fin.read(reinterpret_cast<char *>(temp), std::size(temp) * sizeof(Elf_byte));

  return std::ranges::equal(temp, identification_bytes);
}

auto FileHeader::is64bit() noexcept -> bool const {
  fin.seekg(4);
  Elf_byte temp;
  fin.read(reinterpret_cast<char *>(&temp), sizeof(Elf_byte));
  return temp == 2;
}

// Legal values for sh_type (section type).
auto FileHeader::getSectionHeaderType(const std::size_t shType) noexcept -> std::string_view const {
  // clang-format off
  switch(shType) {
  case 0:          return "NULL";           // Section header table entry unused
  case 1:          return "PROGBITS";       // Program data
  case 2:          return "SYMTAB";         // Symbol table
  case 3:          return "STRTAB";         // String table
  case 4:          return "RELA";           // Relocation entries with addends
  case 5:          return "HASH";           // Symbol hash table
  case 6:          return "DYNAMIC";        // Dynamic linking information
  case 7:          return "NOTE";           // Notes
  case 8:          return "NOBITS";         // Program space with no data (bss)
  case 9:          return "REL";            // Relocation entries, no addends
  case 10:         return "SHLIB";          // Reserved
  case 11:         return "DYNSYM";         // Dynamic linker symbol table
  case 14:         return "INIT_ARRAY";     // Array of constructors
  case 15:         return "FINI_ARRAY";     // Array of destructors
  case 16:         return "PREINIT_ARRAY";  // Array of pre-constructors
  case 17:         return "GROUP";          // Section group
  case 18:         return "SYMTAB_SHNDX";   // Extended section indeces
  case 19:         return "NUM";            // Number of defined types.
  case 0x60000000: return "LOOS";           // Start OS-specific.
  case 0x6ffffff5: return "GNU_ATTRIBUTES"; // Object attributes.
  case 0x6ffffff6: return "GNU_HASH";       // GNU-style hash table.
  case 0x6ffffff7: return "GNU_LIBLIST";    // Prelink library list
  case 0x6ffffff8: return "CHECKSUM";       // Checksum for DSO content.
  case 0x6ffffffa: return "LOSUNW";         // Sun-specific low bound.
//case 0x6ffffffa: return "SUNW_move";      //
  case 0x6ffffffb: return "SUNW_COMDAT";    //
  case 0x6ffffffc: return "SUNW_syminfo";   //
  case 0x6ffffffd: return "GNU_verdef";     // Version definition section.
  case 0x6ffffffe: return "GNU_verneed";    // Version needs section.
  case 0x6fffffff: return "GNU_versym";     // Version symbol table.
//case 0x6fffffff: return "HISUNW";         // Sun-specific high bound.
//case 0x6fffffff: return "HIOS";           // End OS-specific type
  case 0x70000000: return "LOPROC";         // Start of processor-specific
  case 0x7fffffff: return "HIPROC";         // End of processor-specific
  case 0x80000000: return "LOUSER";         // Start of application-specific
  case 0x8fffffff: return "HIUSER";         // End of application-specific
  }
  // clang-format on
}

std::string shNameStr;
auto FileHeader::getSectionHeaderName(const std::size_t shName) noexcept -> std::string_view const {
  const auto offset = std::visit(
      overloaded{[shName](const Elf32_Section_Header_t &x86) -> std::size_t { return x86.offset + shName; },
                 [shName](const Elf64_Section_Header_t &x64) -> std::size_t { return x64.offset + shName; }},
      section_headers[sectionHeaderStringTableIndex()]);

  fin.seekg(offset);

  shNameStr.clear();
  std::getline(fin, shNameStr, '\0');

  return shNameStr.c_str();
}

std::string shFlagsStr;
auto FileHeader::getSectionHeaderFlags(const std::size_t shFlags) noexcept -> std::string_view const {
  shFlagsStr.clear();
  if(shFlags & (1 << 0)) shFlagsStr.push_back('W');    // writable
  if(shFlags & (1 << 1)) shFlagsStr.push_back('A');    // occupies memory during execution
  if(shFlags & (1 << 2)) shFlagsStr.push_back('X');    // executable
  if(shFlags & (1 << 4)) shFlagsStr.push_back('M');    // might be merged
  if(shFlags & (1 << 5)) shFlagsStr.push_back('S');    // contains nul-terminated strings
  if(shFlags & (1 << 6)) shFlagsStr.push_back('I');    // sh_info contains SHT index
  if(shFlags & (1 << 7)) shFlagsStr.push_back('L');    // preserve order after combining
  if(shFlags & (1 << 8)) shFlagsStr.push_back('O');    // non-standard OS specific handling required
  if(shFlags & (1 << 9)) shFlagsStr.push_back('G');    // section is member of a group
  if(shFlags & (1 << 10)) shFlagsStr.push_back('T');   // section hold thread-local data
  if(shFlags & (1 << 11)) shFlagsStr.push_back('C');   // section with compressed data
  if(shFlags == 0x0ff00000) shFlagsStr.push_back('o'); // OS-specific
  if(shFlags == 0xf0000000) shFlagsStr.push_back('p'); // processor-specific
  if(shFlags & (1 << 30)) shFlagsStr.push_back('?');   // (Revisit '?') special ordering requirement (Solaris)
  if(shFlags & (1 << 31)) shFlagsStr.push_back('E');   // excluded unless referenced or allocated (Solaris)
  return shFlagsStr.c_str();
}

} // namespace readelf
