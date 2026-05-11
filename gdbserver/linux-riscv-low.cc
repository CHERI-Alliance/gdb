/* GNU/Linux/RISC-V specific low level interface, for the remote server
   for GDB.
   Copyright (C) 2020-2025 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */


#include "linux-low.h"
#include "tdesc.h"
#include "elf/common.h"
#include "elf/riscv.h"
#include "nat/riscv-linux-tdesc.h"
#include "opcode/riscv.h"

#include "nat/gdb_ptrace.h"
#include "asm/ptrace.h"

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <limits.h>

/* Work around glibc header breakage causing ELF_NFPREG not to be usable.  */
#ifndef NFPREG
# define NFPREG 33
#endif

#ifdef __CHERI__
#define REGSET_LEN_64BIT  16

#define RISCV_GREGS_NUM  32

#define RISCV_PTRACE_PCC_IDX 0
#define RISCV_PTRACE_DDC_IDX 32
#define RISCV_PTRACE_TAG_IDX 33
static_assert(RISCV_PTRACE_TAG_IDX < ELF_NGREG);
#else
#define REGSET_LEN_64BIT  8
#endif

/* Linux target op definitions for the RISC-V architecture.  */

class riscv_target : public linux_process_target
{
public:

  const regs_info *get_regs_info () override;

  int breakpoint_kind_from_pc (CORE_ADDR *pcptr) override;

  const gdb_byte *sw_breakpoint_from_kind (int kind, int *size) override;

  bool supports_qxfer_capability () override;

  int qxfer_capability (const CORE_ADDR address, unsigned char *readbuf,
			unsigned const char *writebuf,
			CORE_ADDR offset, int len) override;

protected:

  void low_arch_setup () override;

  bool low_cannot_fetch_register (int regno) override;

  bool low_cannot_store_register (int regno) override;

  bool low_fetch_register (regcache *regcache, int regno) override;

  bool low_supports_breakpoints () override;

  CORE_ADDR low_get_pc (regcache *regcache) override;

  void low_set_pc (regcache *regcache, CORE_ADDR newpc) override;

  bool low_breakpoint_at (CORE_ADDR pc) override;

  const struct link_map_offsets *low_fetch_linkmap_offsets (int is_elf64) override;

  int low_auxv_wordsize (int pid, const int is_elf64) override;

  int low_get_auxv (int pid, int wordsize, CORE_ADDR match, CORE_ADDR *valp) override;
};

/* Return non-zero if HEADER is a CHERI ELF file,
   and -1 if the file is not a valid file.  */

static int
elf_cheri_header_p (const Elf64_Ehdr *header)
{
  unsigned int e_machine;
  unsigned int e_flags;

  if (header->e_ident[EI_MAG0] == ELFMAG0
      && header->e_ident[EI_MAG1] == ELFMAG1
      && header->e_ident[EI_MAG2] == ELFMAG2
      && header->e_ident[EI_MAG3] == ELFMAG3
      && header->e_machine == EM_RISCV)
      return header->e_flags & EF_RISCV_CHERIABI ?
             1 : 0;

  return -1;
}

/* Return non-zero if FILE is a CHERI ELF file,
   zero if the file is not a CHERI ELF file,
   and -1 if the file is not accessible or doesn't exist.  */

static int
elf_cheri_file_p (const char *file)
{
  Elf64_Ehdr header;
  int fd;

  fd = open (file, O_RDONLY);
  if (fd < 0)
    return -1;

  if (read (fd, &header, sizeof (header)) != sizeof (header))
    {
      close (fd);
      return 0;
    }
  close (fd);

  return elf_cheri_header_p (&header);
}

/* Accepts an integer PID; Returns true if the executable PID is
   running is a CHERI ELF file.  */

int
linux_pid_exe_is_elf_cheri_file (int pid)
{
  char file[PATH_MAX];

  sprintf (file, "/proc/%d/exe", pid);
  return elf_cheri_file_p (file);
}

/* The singleton target ops object.  */

static riscv_target the_riscv_target;

bool
riscv_target::low_cannot_fetch_register (int regno)
{
  gdb_assert_not_reached ("linux target op low_cannot_fetch_register "
			  "is not implemented by the target");
}

bool
riscv_target::low_cannot_store_register (int regno)
{
  gdb_assert_not_reached ("linux target op low_cannot_store_register "
			  "is not implemented by the target");
}

/* Implementation of linux target ops method "low_arch_setup".  */

void
riscv_target::low_arch_setup ()
{
  static const char *expedite_regs[] = { "sp", "pc", NULL };

  const riscv_gdbarch_features features
    = riscv_linux_read_features (current_thread->id.lwp ());
  target_desc_up tdesc = riscv_create_target_description (features);

  if (tdesc->expedite_regs.empty ())
    {
      init_target_desc (tdesc.get (), expedite_regs, GDB_OSABI_LINUX);
      gdb_assert (!tdesc->expedite_regs.empty ());
    }

  current_process ()->tdesc = tdesc.release ();
}


static const struct link_map_offsets lmo_cheri_64bit_offsets =
  {
    0,     /* r_version offset. */
    16,    /* r_debug.r_map offset.  */
    64,    /* r_debug_extended.r_next.  */
    0,     /* l_addr offset in link_map.  */
    16,    /* l_name offset in link_map.  */
    32,    /* l_ld offset in link_map.  */
    48,    /* l_next offset in link_map.  */
    64     /* l_prev offset in link_map.  */
  };

const struct link_map_offsets *
riscv_target::low_fetch_linkmap_offsets (int is_elf64)
{
  if (is_elf64)
    {
      int pid = current_thread->id.pid ();

      if (linux_pid_exe_is_elf_cheri_file(pid) > 0)
	return &lmo_cheri_64bit_offsets;
    }

  return linux_process_target::low_fetch_linkmap_offsets (is_elf64);
}

int
riscv_target::low_auxv_wordsize (int pid, const int is_elf64)
{
  if (is_elf64)
    {
      gdb_byte data[2 * 8];
      int offset = 0;

      while (the_target->read_auxv (pid, offset, data, sizeof (data))
             == sizeof (data))
        {
          CORE_ADDR *entry_type = (CORE_ADDR *) data;

          if (*entry_type > AT_MINSIGSTKSZ)
            return 16;

          if (*entry_type == AT_NULL)
            break;

          offset += sizeof (data);
        }
    }

  return linux_process_target::low_auxv_wordsize (pid, is_elf64);
}

int
riscv_target::low_get_auxv (int pid, int wordsize, CORE_ADDR match,
			      CORE_ADDR *valp)
{
  if (wordsize == 16)
    {
      gdb_byte data [2 * 16];
      int offset = 0;

      while (the_target->read_auxv (pid, offset, data, sizeof (data))
	     == sizeof (data))
	{
	  uint64_t *data_p = (uint64_t *) data;
	  if (data_p[0] == match)
	    {
	      *valp = data_p[2];
	      return 1;
	    }

	  offset += sizeof (data);
	}

      return 0;
    }

  return linux_process_target::low_get_auxv (pid, wordsize, match, valp);
}

/* Collect GPRs from REGCACHE into BUF.  */

static void
riscv_fill_gregset (struct regcache *regcache, void *buf)
{
#ifdef __CHERI__
  const struct target_desc *tdesc = regcache->tdesc;
  elf_gregset_t *regset = (elf_gregset_t *) buf;
  uint8_t *tags = (uint8_t *)(*regset + RISCV_PTRACE_TAG_IDX);

#define SET_TAG(IDX, VAL) do { \
  if (VAL) \
    tags[(IDX) / 8] |= (1U << ((IDX) % 8)); \
  else \
    tags[(IDX) / 8] &= ~(1U << ((IDX) % 8)); \
} while (0)

  int cnull_regno = find_regno (tdesc, "cnull");

  collect_register_by_name (regcache, "pcc", *regset + RISCV_PTRACE_PCC_IDX);
  SET_TAG(RISCV_PTRACE_PCC_IDX, regcache_get_tag_by_name (regcache, "pcc"));

  collect_register_by_name (regcache, "ddc", *regset + RISCV_PTRACE_DDC_IDX);
  SET_TAG(RISCV_PTRACE_DDC_IDX, regcache_get_tag_by_name (regcache, "ddc"));

  for (int i = 1; i < RISCV_GREGS_NUM; i++) {
    collect_register (regcache, cnull_regno + i, *regset + i);
    SET_TAG(i, regcache_get_tag (regcache, cnull_regno + i));
  }
#else
  const struct target_desc *tdesc = regcache->tdesc;
  elf_gregset_t *regset = (elf_gregset_t *) buf;
  int regno = find_regno (tdesc, "zero");
  int i;

  collect_register_by_name (regcache, "pc", *regset);
  for (i = 1; i < ARRAY_SIZE (*regset); i++)
    collect_register (regcache, regno + i, *regset + i);
#endif
}

/* Supply GPRs from BUF into REGCACHE.  */

static void
riscv_store_gregset (struct regcache *regcache, const void *buf)
{
#ifdef __CHERI__
  const elf_gregset_t *regset = (const elf_gregset_t *) buf;
  const struct target_desc *tdesc = regcache->tdesc;
  const uint8_t *tags = (uint8_t *)(*regset + RISCV_PTRACE_TAG_IDX);
#define GET_TAG(IDX) (!!(tags[(IDX) / 8] & (1U << ((IDX) % 8))))

  int zero_regno = find_regno (tdesc, "zero");
  int cnull_regno = find_regno (tdesc, "cnull");

  supply_register_by_name (regcache, "pc", *regset + RISCV_PTRACE_PCC_IDX);
  supply_register_zeroed (regcache, zero_regno);

  supply_register_by_name (regcache, "pcc", *regset + RISCV_PTRACE_PCC_IDX);
  regcache_set_tag_by_name (regcache, "pcc", GET_TAG(RISCV_PTRACE_PCC_IDX));

  supply_register_by_name (regcache, "ddc", *regset + RISCV_PTRACE_DDC_IDX);
  regcache_set_tag_by_name (regcache, "ddc", GET_TAG(RISCV_PTRACE_DDC_IDX));

  supply_register_zeroed (regcache, cnull_regno);

  for (int i = 1; i < RISCV_GREGS_NUM; i++) {
    supply_register(regcache, zero_regno + i, *regset + i);
    supply_register(regcache, cnull_regno + i, *regset + i);
    regcache_set_tag (regcache, cnull_regno + i, GET_TAG(i));
  }
#else
  const elf_gregset_t *regset = (const elf_gregset_t *) buf;
  const struct target_desc *tdesc = regcache->tdesc;
  int regno = find_regno (tdesc, "zero");
  int i;

  supply_register_by_name (regcache, "pc", *regset);
  supply_register_zeroed (regcache, regno);
  for (i = 1; i < ARRAY_SIZE (*regset); i++)
    supply_register (regcache, regno + i, *regset + i);
#endif
}

/* Collect FPRs from REGCACHE into BUF.  */

static void
riscv_fill_fpregset (struct regcache *regcache, void *buf)
{
  const struct target_desc *tdesc = regcache->tdesc;
  int regno = find_regno (tdesc, "ft0");
  int flen = register_size (regcache->tdesc, regno);
  gdb_byte *regbuf = (gdb_byte *) buf;
  int i;

  for (i = 0; i < ELF_NFPREG - 1; i++, regbuf += flen)
    collect_register (regcache, regno + i, regbuf);
  collect_register_by_name (regcache, "fcsr", regbuf);
}

/* Supply FPRs from BUF into REGCACHE.  */

static void
riscv_store_fpregset (struct regcache *regcache, const void *buf)
{
  const struct target_desc *tdesc = regcache->tdesc;
  int regno = find_regno (tdesc, "ft0");
  int flen = register_size (regcache->tdesc, regno);
  const gdb_byte *regbuf = (const gdb_byte *) buf;
  int i;

  for (i = 0; i < ELF_NFPREG - 1; i++, regbuf += flen)
    supply_register (regcache, regno + i, regbuf);
  supply_register_by_name (regcache, "fcsr", regbuf);
}

/* RISC-V/Linux regsets.  FPRs are optional and come in different sizes,
   so define multiple regsets for them marking them all as OPTIONAL_REGS
   rather than FP_REGS, so that "regsets_fetch_inferior_registers" picks
   the right one according to size.  */
static struct regset_info riscv_regsets[] = {
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_PRSTATUS,
    sizeof (elf_gregset_t), GENERAL_REGS,
    riscv_fill_gregset, riscv_store_gregset },
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_FPREGSET,
    sizeof (struct __riscv_mc_q_ext_state), OPTIONAL_REGS,
    riscv_fill_fpregset, riscv_store_fpregset },
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_FPREGSET,
    sizeof (struct __riscv_mc_d_ext_state), OPTIONAL_REGS,
    riscv_fill_fpregset, riscv_store_fpregset },
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_FPREGSET,
    sizeof (struct __riscv_mc_f_ext_state), OPTIONAL_REGS,
    riscv_fill_fpregset, riscv_store_fpregset },
  NULL_REGSET
};

/* RISC-V/Linux regset information.  */
static struct regsets_info riscv_regsets_info =
  {
    riscv_regsets, /* regsets */
    0, /* num_regsets */
    NULL, /* disabled_regsets */
  };

/* Definition of linux_target_ops data member "regs_info".  */
static struct regs_info riscv_regs =
  {
    NULL, /* regset_bitmap */
    NULL, /* usrregs */
    &riscv_regsets_info,
  };

/* Implementation of linux target ops method "get_regs_info".  */

const regs_info *
riscv_target::get_regs_info ()
{
  return &riscv_regs;
}

/* Implementation of linux target ops method "low_fetch_register".  */

bool
riscv_target::low_fetch_register (regcache *regcache, int regno)
{
  const struct target_desc *tdesc = regcache->tdesc;

  if (regno != find_regno (tdesc, "zero"))
    return false;
  supply_register_zeroed (regcache, regno);
  return true;
}

bool
riscv_target::low_supports_breakpoints ()
{
  return true;
}

/* Implementation of linux target ops method "low_get_pc".  */

CORE_ADDR
riscv_target::low_get_pc (regcache *regcache)
{
  elf_gregset_t regset;

  if (sizeof (regset[0]) == REGSET_LEN_64BIT)
    return linux_get_pc_64bit (regcache);
  else
    return linux_get_pc_32bit (regcache);
}

/* Implementation of linux target ops method "low_set_pc".  */

void
riscv_target::low_set_pc (regcache *regcache, CORE_ADDR newpc)
{
  elf_gregset_t regset;

  if (sizeof (regset[0]) == REGSET_LEN_64BIT)
    linux_set_pc_64bit (regcache, newpc);
  else
    linux_set_pc_32bit (regcache, newpc);
}

/* Correct in either endianness.  */
static const uint16_t riscv_ibreakpoint[] = { 0x0073, 0x0010 };
static const uint16_t riscv_cbreakpoint = 0x9002;

/* Implementation of target ops method "breakpoint_kind_from_pc".  */

int
riscv_target::breakpoint_kind_from_pc (CORE_ADDR *pcptr)
{
  union
    {
      gdb_byte bytes[2];
      uint16_t insn;
    }
  buf;

  if (target_read_memory (*pcptr, buf.bytes, sizeof (buf.insn)) == 0
      && riscv_insn_length (buf.insn == sizeof (riscv_ibreakpoint)))
    return sizeof (riscv_ibreakpoint);
  else
    return sizeof (riscv_cbreakpoint);
}

/* Implementation of target ops method "sw_breakpoint_from_kind".  */

const gdb_byte *
riscv_target::sw_breakpoint_from_kind (int kind, int *size)
{
  *size = kind;
  switch (kind)
    {
      case sizeof (riscv_ibreakpoint):
	return (const gdb_byte *) &riscv_ibreakpoint;
      default:
	return (const gdb_byte *) &riscv_cbreakpoint;
    }
}

/* Implementation of linux target ops method "low_breakpoint_at".  */

bool
riscv_target::low_breakpoint_at (CORE_ADDR pc)
{
  union
    {
      gdb_byte bytes[2];
      uint16_t insn;
    }
  buf;

  if (target_read_memory (pc, buf.bytes, sizeof (buf.insn)) == 0
      && (buf.insn == riscv_cbreakpoint
	  || (buf.insn == riscv_ibreakpoint[0]
	      && target_read_memory (pc + sizeof (buf.insn), buf.bytes,
				     sizeof (buf.insn)) == 0
	      && buf.insn == riscv_ibreakpoint[1])))
    return true;
  else
    return false;
}

bool
riscv_target::supports_qxfer_capability ()
{
#ifdef __CHERI__
  return true;
#else
  return false;
#endif
}

int
riscv_target::qxfer_capability (const CORE_ADDR address,
				unsigned char *readbuf,
				unsigned const char *writebuf,
				CORE_ADDR offset, int len)
{
#ifdef __CHERI__
  if (readbuf != nullptr)
    {
      int tid = current_thread->id.lwp ();
      struct user_cap ucap;

      if (ptrace (PTRACE_PEEKCAP, tid, address, (PTRACE_TYPE_ARG3) &ucap) == 0)
        {
          memcpy (readbuf, &ucap.tag, 1);
          memcpy (readbuf + 1, &ucap.val, sizeof(ucap.val));

          return sizeof (ucap.val) + 1;
	}
    }
#endif
  return 0;
}


/* The linux target ops object.  */

linux_process_target *the_linux_target = &the_riscv_target;

/* Initialize the RISC-V/Linux target.  */

void
initialize_low_arch ()
{
  initialize_regsets_info (&riscv_regsets_info);
}
