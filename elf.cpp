#include "elf.h"

#include <cstdint>
#include <fstream>
#include <string_view>

namespace elf {

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
  none = 0,        // UNIX System V ABI
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

bool init(Elf64_header_t &header, const char *file) noexcept {
  std::ifstream fin{file, std::ios::binary};
  if(!fin.good()) return false;

  fin.read(reinterpret_cast<char *>(header.ident), i_nident);

  if(header.ident[i_mag0] != 0x7f || //
     header.ident[i_mag1] != 'E' ||  //
     header.ident[i_mag2] != 'L' ||  //
     header.ident[i_mag3] != 'F')    //
    return false;

  fin.read(reinterpret_cast<char *>(&header.type), sizeof(decltype(header.type)));
  fin.read(reinterpret_cast<char *>(&header.machine), sizeof(decltype(header.machine)));
  fin.read(reinterpret_cast<char *>(&header.version), sizeof(decltype(header.version)));
  fin.read(reinterpret_cast<char *>(&header.entry), sizeof(decltype(header.entry)));
  fin.read(reinterpret_cast<char *>(&header.phoff), sizeof(decltype(header.phoff)));
  fin.read(reinterpret_cast<char *>(&header.shoff), sizeof(decltype(header.shoff)));
  fin.read(reinterpret_cast<char *>(&header.flags), sizeof(decltype(header.flags)));

  fin.read(reinterpret_cast<char *>(&header.ehsize), sizeof(decltype(header.ehsize)));
  fin.read(reinterpret_cast<char *>(&header.phentsize), sizeof(decltype(header.phentsize)));
  fin.read(reinterpret_cast<char *>(&header.phnum), sizeof(decltype(header.phnum)));

  fin.read(reinterpret_cast<char *>(&header.shentsize), sizeof(decltype(header.shentsize)));
  fin.read(reinterpret_cast<char *>(&header.shnum), sizeof(decltype(header.shnum)));
  fin.read(reinterpret_cast<char *>(&header.shstrndx), sizeof(decltype(header.shstrndx)));

  return true;
}

std::string_view decode_data(Elf64_header_t &header) noexcept {
  switch(header.ident[i_data]) {
  case data::dataNone: return "None";
  case data::data2lsb: return "2's complement, little endian";
  case data::data2msb: return "2's complement, big endian";
  }
}

std::string_view decode_class(Elf64_header_t &header) noexcept {
  switch(header.ident[i_class]) {
  case class_::classNone: return "None";
  case class_::class32: return "ELF32";
  case class_::class64: return "ELF64";
  }
}

std::string_view decode_file_version(Elf64_header_t &header) noexcept {
  switch(header.ident[i_version]) {
  case version::versionNone: return "0 (Invalid)";
  case version::current: return "1 (Current)";
  }
}

std::string_view decode_os_abi(Elf64_header_t &header) noexcept {
  switch(header.ident[i_osabi]) {
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

std::string_view decode_machine(Elf64_header_t &header) noexcept {
  switch(header.machine) {
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

std::string_view decode_filetype(Elf64_header_t &header) noexcept {
  switch(header.type) {
  case type::typeNone: return "No file type";
  case type::rel: return "Relocatible file";
  case type::exec: return "Executable file";
  case type::dyn: return "Shared object file";
  case type::core: return "Core file";
  case type::loproc: return "Processor specific";
  case type::hiproc: return "Processor specific";
  }
}

} // namespace elf
