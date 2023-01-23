#include <feelelf/feelelf.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <string_view>
#include <vector>

namespace feelelf {

// clang-format off
template <class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template <class... Ts> overloaded(Ts...) -> overloaded<Ts...>;
// clang-format on

// elements of Elf64_header_t.e_ident array
enum class_ : std::size_t {
  classNone = 0, // Invalid class
  class32 = 1,   // 32-bit objects, machines with virtual address spaces up to 4Gb
  class64 = 2    // 64-bit objects
};

enum data : std::size_t {
  dataNone = 0, // Invalid data encoding
  data2lsb = 1, // 2's complement little endian: 0x0102 -> 0x02 0x01
  data2msb = 2  // 2's complement big endian   : 0x0102 -> 0x01 0x02
};

enum version : Elf64_Word { // file version
  versionNone = 0,          // Invalid version
  current = 1               // Current version
};

enum osabi {
  osNone = 0,      // UNIX System V ABI
  sysv = 0,        // Alias
  hpux = 1,        // HP-UX
  netbsd = 2,      // NetBSD
  gnu = 3,         // Object uses GNU ELF extensions
  linux = 3,       // Compatibility alias
  solaris = 6,     // Sun Solaris
  aix = 7,         // IBM AIX
  irix = 8,        // SGI Irix
  freebsd = 9,     // FreeBSD
  tru64 = 10,      // Compaq TRU64 UNIX
  modesto = 11,    // Novell Modesto
  openbsd = 12,    // OpenBSD
  arm_aeabi = 64,  // ARM EABI
  arm_ = 97,       // ARM
  standalone = 255 // Standalone (embedded) application
};

enum type : Elf64_Half {
  typeNone = 0,    // No file type
  rel = 1,         // Relocatible file
  exec = 2,        // Executable file
  dyn = 3,         // Shared object file
  core = 4,        // Core file
  loproc = 0xff00, // Processor specific
  hiproc = 0xffff  // Processor specific
};

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

// Legal values for pType (segment type)
enum pType {
  pNull = 0,                 // program header table entry unused
  load = 1,                  // loadable program segment
  dynamic = 2,               // dynamic linking information
  interp = 3,                // program interpreter
  note = 4,                  // auxiliary information
  shlib = 5,                 // reserved
  phdr = 6,                  // entry for header table itself
  tls = 7,                   // thread-local storage segment
  num_ = 8,                  // number of defined types
  loos = 0x60000000,         // start of OS-specific
  gnu_eh_frame = 0x6474e550, // GCC .eh_frame_hdr segment
  gnu_stack = 0x6474e551,    // indicates stack executability
  gnu_relro = 0x6474e552,    // read-only after relocation
  losunw = 0x6ffffffa,       //
  sunwbss = 0x6ffffffa,      // Sun Specific segment
  sunwstack = 0x6ffffffb,    // stack segment
  hisunw = 0x6fffffff,       //
  hios = 0x6FFfffff,         // end of OS-specific
  loproc_ = 0x70000000,      // start of processor-specific
  hiproc_ = 0x7fffffff       // end of processor-specific
};

// Legal values for p_flags (segment flags)
enum pFlag {
  x = (1 << 0),             // Segment is executable
  w = (1 << 1),             // Segment is writable
  r = (1 << 2),             // Segment is readable
  rw = (1 << 2) | (1 << 1), // Segment is readable/writable
  re = (1 << 2) | (1 << 0), // Segment is readable/executable
  maskOS = 0x0ff00000,      // OS-specific
  maskProc = 0xf0000000     // Processor-specific
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
            fin.read(reinterpret_cast<char *>(&x32.ident), i_nident);
            fin.read(reinterpret_cast<char *>(&x32.type), sizeof(decltype(x32.type)));
            fin.read(reinterpret_cast<char *>(&x32.machine), sizeof(decltype(x32.machine)));
            fin.read(reinterpret_cast<char *>(&x32.version), sizeof(decltype(x32.version)));
            fin.read(reinterpret_cast<char *>(&x32.entry), sizeof(decltype(x32.entry)));
            fin.read(reinterpret_cast<char *>(&x32.phoff), sizeof(decltype(x32.phoff)));
            fin.read(reinterpret_cast<char *>(&x32.shoff), sizeof(decltype(x32.shoff)));
            fin.read(reinterpret_cast<char *>(&x32.flags), sizeof(decltype(x32.flags)));

            fin.read(reinterpret_cast<char *>(&x32.ehsize), sizeof(decltype(x32.ehsize)));
            fin.read(reinterpret_cast<char *>(&x32.phentsize), sizeof(decltype(x32.phentsize)));
            fin.read(reinterpret_cast<char *>(&x32.phnum), sizeof(decltype(x32.phnum)));

            program_headers.resize(x32.phnum);
            std::ranges::fill(program_headers, Elf32_Program_Header_t{});

            fin.read(reinterpret_cast<char *>(&x32.shentsize), sizeof(decltype(x32.shentsize)));
            fin.read(reinterpret_cast<char *>(&x32.shnum), sizeof(decltype(x32.shnum)));
            fin.read(reinterpret_cast<char *>(&x32.shstrndx), sizeof(decltype(x32.shstrndx)));
      },
      [&](Elf64_Header_t &x64) {
            fin.read(reinterpret_cast<char *>(&x64.ident), i_nident);
            fin.read(reinterpret_cast<char *>(&x64.type), sizeof(decltype(x64.type)));
            fin.read(reinterpret_cast<char *>(&x64.machine), sizeof(decltype(x64.machine)));
            fin.read(reinterpret_cast<char *>(&x64.version), sizeof(decltype(x64.version)));
            fin.read(reinterpret_cast<char *>(&x64.entry), sizeof(decltype(x64.entry)));
            fin.read(reinterpret_cast<char *>(&x64.phoff), sizeof(decltype(x64.phoff)));
            fin.read(reinterpret_cast<char *>(&x64.shoff), sizeof(decltype(x64.shoff)));
            fin.read(reinterpret_cast<char *>(&x64.flags), sizeof(decltype(x64.flags)));

            fin.read(reinterpret_cast<char *>(&x64.ehsize), sizeof(decltype(x64.ehsize)));
            fin.read(reinterpret_cast<char *>(&x64.phentsize), sizeof(decltype(x64.phentsize)));
            fin.read(reinterpret_cast<char *>(&x64.phnum), sizeof(decltype(x64.phnum)));

            program_headers.resize(x64.phnum);
            std::ranges::fill(program_headers, Elf64_Program_Header_t{});

            fin.read(reinterpret_cast<char *>(&x64.shentsize), sizeof(decltype(x64.shentsize)));
            fin.read(reinterpret_cast<char *>(&x64.shnum), sizeof(decltype(x64.shnum)));
            fin.read(reinterpret_cast<char *>(&x64.shstrndx), sizeof(decltype(x64.shstrndx)));
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
  case class_::classNone: return "None";
  case class_::class32: return "ELF32";
  case class_::class64: return "ELF64";
  }
}

auto FileHeader::fileDataEncoding() noexcept -> std::string_view const {
  auto encodingData = std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.ident[i_data]; },
                                            [](const Elf64_Header_t &x64) { return x64.ident[i_data]; }},
                                 elf_header);

  switch(encodingData) {
  case data::dataNone: return "None";
  case data::data2lsb: return "2's complement, little endian";
  case data::data2msb: return "2's complement, big endian";
  }
}

auto FileHeader::fileVersion() noexcept -> std::string_view const {
  auto versionData = std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.ident[i_version]; },
                                           [](const Elf64_Header_t &x64) { return x64.ident[i_version]; }},
                                elf_header);

  switch(versionData) {
  case version::versionNone: return "0 (Invalid)";
  case version::current: return "1 (Current)";
  }
}

auto FileHeader::osABI() noexcept -> std::string_view const {
  auto osABI = std::visit(overloaded{[](const Elf32_Header_t &x32) { return x32.ident[i_osabi]; },
                                     [](const Elf64_Header_t &x64) { return x64.ident[i_osabi]; }},
                          elf_header);
  switch(osABI) {
  case osabi::sysv: return "UNIX System V ABI";
  case osabi::hpux: return "HP-UX";
  case osabi::netbsd: return "NetBSD";
  case osabi::gnu: return "Object uses GNU ELF extensions";
  // case osabi::linux: return "Compatibility alias";
  case osabi::solaris: return "Sun Solaris";
  case osabi::aix: return "IBM AIX";
  case osabi::irix: return "SGI Irix";
  case osabi::freebsd: return "FreeBSD";
  case osabi::tru64: return "Compaq TRU64 UNIX";
  case osabi::modesto: return "Novell Modesto";
  case osabi::openbsd: return "OpenBSD";
  case osabi::arm_aeabi: return "ARM EABI";
  case osabi::arm_: return "ARM";
  case osabi::standalone: return "Standalone (embedded) application";
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
  case type::typeNone: return "No file type";
  case type::rel: return "Relocatible file";
  case type::exec: return "Executable file";
  case type::dyn: return "Shared object file";
  case type::core: return "Core file";
  case type::loproc: return "Processor specific";
  case type::hiproc: return "Processor specific";
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
  return std::visit(overloaded{[](const Elf32_Header_t &x32) -> int { return x32.entry; },
                               [](const Elf64_Header_t &x64) -> int { return x64.entry; }},
                    elf_header);
}

auto FileHeader::programHeaderOffset() noexcept -> int const {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) -> int { return x32.phoff; },
                               [](const Elf64_Header_t &x64) -> int { return x64.phoff; }},
                    elf_header);
}

auto FileHeader::sectionHeaderOffset() noexcept -> int const {
  return std::visit(overloaded{[](const Elf32_Header_t &x32) -> int { return x32.shoff; },
                               [](const Elf64_Header_t &x64) -> int { return x64.shoff; }},
                    elf_header);
}

// clang-format off
auto FileHeader::programHeaders() noexcept -> const decltype(program_headers) & {
  fin.seekg(programHeaderOffset());

struct El{
  Elf64_Word type;
  Elf64_Word flags;
  Elf64_Off offset;
  Elf64_Addr vaddr;
  Elf64_Addr paddr;
  Elf64_Xword filesz;
  Elf64_Xword memsz;
  Elf64_Xword align;
};

  for(auto &ph : program_headers) {
    std::visit( //
      overloaded{
        [](Elf32_Program_Header_t &x86) {
             fin.read(reinterpret_cast<char *>(&x86.type), sizeof(decltype(x86.type)));
             fin.read(reinterpret_cast<char *>(&x86.offset), sizeof(decltype(x86.offset)));
             fin.read(reinterpret_cast<char *>(&x86.vaddr), sizeof(decltype(x86.vaddr)));
             fin.read(reinterpret_cast<char *>(&x86.paddr), sizeof(decltype(x86.paddr)));
             fin.read(reinterpret_cast<char *>(&x86.filesz), sizeof(decltype(x86.filesz)));
             fin.read(reinterpret_cast<char *>(&x86.memsz), sizeof(decltype(x86.memsz)));
             fin.read(reinterpret_cast<char *>(&x86.flags), sizeof(decltype(x86.flags)));
             fin.read(reinterpret_cast<char *>(&x86.align), sizeof(decltype(x86.align)));
        },

        [](Elf64_Program_Header_t &x64) {
             fin.read(reinterpret_cast<char *>(&x64.type), sizeof(decltype(x64.type)));
             fin.read(reinterpret_cast<char *>(&x64.flags), sizeof(decltype(x64.flags)));
             fin.read(reinterpret_cast<char *>(&x64.offset), sizeof(decltype(x64.offset)));
             fin.read(reinterpret_cast<char *>(&x64.vaddr), sizeof(decltype(x64.vaddr)));
             fin.read(reinterpret_cast<char *>(&x64.paddr), sizeof(decltype(x64.paddr)));
             fin.read(reinterpret_cast<char *>(&x64.filesz), sizeof(decltype(x64.filesz)));
             fin.read(reinterpret_cast<char *>(&x64.memsz), sizeof(decltype(x64.memsz)));
             fin.read(reinterpret_cast<char *>(&x64.align), sizeof(decltype(x64.align)));
        }
      }, ph);
  }

  return program_headers;
}

auto FileHeader::sectionHeaders() noexcept -> const decltype(section_headers) & {
  fin.seekg(sectionHeaderOffset());
  section_headers.resize(numSectionHeaders());

  for(auto &sh : section_headers) {
    std::visit(
      overloaded{
        [](Elf32_Section_Header_t &x86) {
             fin.read(reinterpret_cast<char *>(&x86.name), sizeof(decltype(x86.name)));
             fin.read(reinterpret_cast<char *>(&x86.type), sizeof(decltype(x86.type)));
             fin.read(reinterpret_cast<char *>(&x86.flags), sizeof(decltype(x86.flags)));
             fin.read(reinterpret_cast<char *>(&x86.addr), sizeof(decltype(x86.addr)));
             fin.read(reinterpret_cast<char *>(&x86.offset), sizeof(decltype(x86.offset)));
             fin.read(reinterpret_cast<char *>(&x86.size), sizeof(decltype(x86.size)));
             fin.read(reinterpret_cast<char *>(&x86.link), sizeof(decltype(x86.link)));
             fin.read(reinterpret_cast<char *>(&x86.info), sizeof(decltype(x86.info)));
             fin.read(reinterpret_cast<char *>(&x86.addralign), sizeof(decltype(x86.addralign)));
             fin.read(reinterpret_cast<char *>(&x86.entsize), sizeof(decltype(x86.entsize)));
        },
        [](Elf64_Section_Header_t &x64) {
             fin.read(reinterpret_cast<char *>(&x64.name), sizeof(decltype(x64.name)));
             fin.read(reinterpret_cast<char *>(&x64.type), sizeof(decltype(x64.type)));
             fin.read(reinterpret_cast<char *>(&x64.flags), sizeof(decltype(x64.flags)));
             fin.read(reinterpret_cast<char *>(&x64.addr), sizeof(decltype(x64.addr)));
             fin.read(reinterpret_cast<char *>(&x64.offset), sizeof(decltype(x64.offset)));
             fin.read(reinterpret_cast<char *>(&x64.size), sizeof(decltype(x64.size)));
             fin.read(reinterpret_cast<char *>(&x64.link), sizeof(decltype(x64.link)));
             fin.read(reinterpret_cast<char *>(&x64.info), sizeof(decltype(x64.info)));
             fin.read(reinterpret_cast<char *>(&x64.addralign), sizeof(decltype(x64.addralign)));
             fin.read(reinterpret_cast<char *>(&x64.entsize), sizeof(decltype(x64.entsize)));
        }
      }, sh);
  }

  return section_headers;
}
// clang-format on

auto FileHeader::programHeaderType(const Program_Header_t &ph) noexcept -> std::string_view const {

  auto phType = std::visit(overloaded{[](const Elf32_Program_Header_t &x32) { return x32.type; },
                                      [](const Elf64_Program_Header_t &x64) { return x64.type; }},
                           ph);
  // clang-format off
  switch(phType) {
  case pType::pNull:        return "NULL";
  case pType::load:         return "LOAD";
  case pType::dynamic:      return "DYNAMIC";
  case pType::interp:       return "INTERP";
  case pType::note:         return "NOTE";
  case pType::shlib:        return "SHLIB";
  case pType::phdr:         return "PHDR";
  case pType::tls:          return "TLS";
  case pType::num_:         return "NUM";
  case pType::loos:         return "LOOS";
  case pType::gnu_eh_frame: return "GNU_EH_FRAME";
  case pType::gnu_stack:    return "GNU_STACK";
  case pType::gnu_relro:    return "GNU_RELRO";
  case pType::losunw:       return "LOSUNW";
//case pType::sunwbss:      return "SUNWBSS";
  case pType::sunwstack:    return "SUNWSTACK";
//case pType::hisunw:       return "HISUNW";
  case pType::hios:         return "HIOS";
  case pType::loproc_:      return "LOPROC";
  case pType::hiproc_:      return "HIPROC";
  }
  // clang-format on
}

[[nodiscard]] auto FileHeader::programHeaderFlag(const Program_Header_t &ph) noexcept
    -> std::string_view const {

  auto phFlag = std::visit(overloaded{[](const Elf32_Program_Header_t &x32) { return x32.flags; },
                                      [](const Elf64_Program_Header_t &x64) { return x64.flags; }},
                           ph);

  switch(phFlag) {
  case pFlag::x: return "X";
  case pFlag::w: return "W";
  case pFlag::r: return "R";
  case pFlag::rw: return "RW";
  case pFlag::re: return "R E";
  case pFlag::maskOS: return "MASKOS";
  case pFlag::maskProc: return "MASKProc";
  default: return "unknown";
  }
}

auto FileHeader::flags() noexcept -> int const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.flags; },
                               [](const Elf32_Header_t &x32) { return x32.flags; }},
                    elf_header);
}

auto FileHeader::headerSize() noexcept -> int const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.ehsize; },
                               [](const Elf32_Header_t &x32) { return x32.ehsize; }},
                    elf_header);
}

auto FileHeader::programHeaderSize() noexcept -> int const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.phentsize; },
                               [](const Elf32_Header_t &x32) { return x32.phentsize; }},
                    elf_header);
}

auto FileHeader::numProgramHeaders() noexcept -> int const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.phnum; },
                               [](const Elf32_Header_t &x32) { return x32.phnum; }},
                    elf_header);
}

auto FileHeader::sectionHeaderSize() noexcept -> int const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.shentsize; },
                               [](const Elf32_Header_t &x32) { return x32.shentsize; }},
                    elf_header);
}

auto FileHeader::numSectionHeaders() noexcept -> int const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.shnum; },
                               [](const Elf32_Header_t &x32) { return x32.shnum; }},
                    elf_header);
}

auto FileHeader::sectionHeaderStringTable() noexcept -> int const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.shstrndx; },
                               [](const Elf32_Header_t &x32) { return x32.shstrndx; }},
                    elf_header);
}

auto FileHeader::hasProgramHeaders() noexcept -> bool const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.phoff == 0; },
                               [](const Elf32_Header_t &x32) { return x32.phoff == 0; }},
                    elf_header);
}

auto FileHeader::hasSectionHeaders() noexcept -> bool const {
  return std::visit(overloaded{[](const Elf64_Header_t &x64) { return x64.shoff == 0; },
                               [](const Elf32_Header_t &x32) { return x32.shoff == 0; }},
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
  return temp == class_::class64;
}

} // namespace readelf
