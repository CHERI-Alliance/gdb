/* Simulator instruction semantics for m32r.

This file is machine generated.

Copyright (C) 1996, 1997 Free Software Foundation, Inc.

This file is part of the GNU Binutils and/or GDB, the GNU debugger.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

#include "sim-main.h"
#include "mem-ops.h"
#include "sem-ops.h"
#include "decode.h"
#include "cpu-sim.h"

/* Perform add: add $dr,$sr.  */
CIA
SEM_FN_NAME (add) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = ADDSI (* FLD (f_r1), * FLD (f_r2));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform add3: add3 $dr,$sr,$slo16.  */
CIA
SEM_FN_NAME (add3) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_1.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = ADDSI (* FLD (f_r2), FLD (f_simm16));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform and: and $dr,$sr.  */
CIA
SEM_FN_NAME (and) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = ANDSI (* FLD (f_r1), * FLD (f_r2));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform and3: and3 $dr,$sr,$uimm16.  */
CIA
SEM_FN_NAME (and3) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_2.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = ANDSI (* FLD (f_r2), FLD (f_uimm16));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform or: or $dr,$sr.  */
CIA
SEM_FN_NAME (or) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = ORSI (* FLD (f_r1), * FLD (f_r2));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform or3: or3 $dr,$sr,$ulo16.  */
CIA
SEM_FN_NAME (or3) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_3.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = ORSI (* FLD (f_r2), FLD (f_uimm16));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform xor: xor $dr,$sr.  */
CIA
SEM_FN_NAME (xor) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = XORSI (* FLD (f_r1), * FLD (f_r2));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform xor3: xor3 $dr,$sr,$uimm16.  */
CIA
SEM_FN_NAME (xor3) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_2.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = XORSI (* FLD (f_r2), FLD (f_uimm16));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform addi: addi $dr,$simm8.  */
CIA
SEM_FN_NAME (addi) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_4.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = ADDSI (* FLD (f_r1), FLD (f_simm8));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform addv: addv $dr,$sr.  */
CIA
SEM_FN_NAME (addv) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
do {
  BI temp1;SI temp0;
temp0 = ADDSI (* FLD (f_r1), * FLD (f_r2));
temp1 = ADDOFSI (* FLD (f_r1), * FLD (f_r2), 0);
* FLD (f_r1) = temp0;
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
CPU (h_cond) = temp1;
  TRACE_RESULT (current_cpu, "h_cond", 'x', temp1);
} while (0);
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform addv3: addv3 $dr,$sr,$simm16.  */
CIA
SEM_FN_NAME (addv3) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_5.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
do {
  BI temp1;SI temp0;
temp0 = ADDSI (* FLD (f_r2), FLD (f_simm16));
temp1 = ADDOFSI (* FLD (f_r2), FLD (f_simm16), 0);
* FLD (f_r1) = temp0;
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
CPU (h_cond) = temp1;
  TRACE_RESULT (current_cpu, "h_cond", 'x', temp1);
} while (0);
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform addx: addx $dr,$sr.  */
CIA
SEM_FN_NAME (addx) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
do {
  BI temp1;SI temp0;
temp0 = ADDCSI (* FLD (f_r1), * FLD (f_r2), CPU (h_cond));
temp1 = ADDCFSI (* FLD (f_r1), * FLD (f_r2), CPU (h_cond));
* FLD (f_r1) = temp0;
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
CPU (h_cond) = temp1;
  TRACE_RESULT (current_cpu, "h_cond", 'x', temp1);
} while (0);
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform bc8: bc $disp8.  */
CIA
SEM_FN_NAME (bc8) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_6.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
if (CPU (h_cond))
{
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp8));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform bc24: bc $disp24.  */
CIA
SEM_FN_NAME (bc24) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_7.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
if (CPU (h_cond))
{
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp24));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform beq: beq $src1,$src2,$disp16.  */
CIA
SEM_FN_NAME (beq) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_8.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
if (EQSI (* FLD (f_r1), * FLD (f_r2)))
{
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp16));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform beqz: beqz $src2,$disp16.  */
CIA
SEM_FN_NAME (beqz) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_9.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
if (EQSI (* FLD (f_r2), 0))
{
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp16));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform bgez: bgez $src2,$disp16.  */
CIA
SEM_FN_NAME (bgez) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_9.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
if (GESI (* FLD (f_r2), 0))
{
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp16));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform bgtz: bgtz $src2,$disp16.  */
CIA
SEM_FN_NAME (bgtz) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_9.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
if (GTSI (* FLD (f_r2), 0))
{
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp16));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform blez: blez $src2,$disp16.  */
CIA
SEM_FN_NAME (blez) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_9.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
if (LESI (* FLD (f_r2), 0))
{
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp16));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform bltz: bltz $src2,$disp16.  */
CIA
SEM_FN_NAME (bltz) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_9.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
if (LTSI (* FLD (f_r2), 0))
{
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp16));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform bnez: bnez $src2,$disp16.  */
CIA
SEM_FN_NAME (bnez) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_9.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
if (NESI (* FLD (f_r2), 0))
{
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp16));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform bl8: bl $disp8.  */
CIA
SEM_FN_NAME (bl8) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_6.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
{
CPU (h_gr[14]) = ADDSI (ANDSI (CPU (pc), -4), 4);
  TRACE_RESULT (current_cpu, "h_gr[14]", 'x', ADDSI (ANDSI (CPU (pc), -4), 4));
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp8));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform bl24: bl $disp24.  */
CIA
SEM_FN_NAME (bl24) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_7.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
{
CPU (h_gr[14]) = ADDSI (CPU (pc), 4);
  TRACE_RESULT (current_cpu, "h_gr[14]", 'x', ADDSI (CPU (pc), 4));
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp24));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform bnc8: bnc $disp8.  */
CIA
SEM_FN_NAME (bnc8) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_6.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
if (NOTBI (CPU (h_cond)))
{
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp8));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform bnc24: bnc $disp24.  */
CIA
SEM_FN_NAME (bnc24) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_7.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
if (NOTBI (CPU (h_cond)))
{
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp24));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform bne: bne $src1,$src2,$disp16.  */
CIA
SEM_FN_NAME (bne) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_8.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
if (NESI (* FLD (f_r1), * FLD (f_r2)))
{
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp16));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform bra8: bra $disp8.  */
CIA
SEM_FN_NAME (bra8) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_6.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp8));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform bra24: bra $disp24.  */
CIA
SEM_FN_NAME (bra24) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_7.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
  new_pc = SEM_BRANCH_VIA_CACHE (sem_arg, FLD (f_disp24));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform cmp: cmp $src1,$src2.  */
CIA
SEM_FN_NAME (cmp) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
CPU (h_cond) = LTSI (* FLD (f_r1), * FLD (f_r2));
  TRACE_RESULT (current_cpu, "h_cond", 'x', LTSI (* FLD (f_r1), * FLD (f_r2)));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform cmpi: cmpi $src2,$simm16.  */
CIA
SEM_FN_NAME (cmpi) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_11.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
CPU (h_cond) = LTSI (* FLD (f_r2), FLD (f_simm16));
  TRACE_RESULT (current_cpu, "h_cond", 'x', LTSI (* FLD (f_r2), FLD (f_simm16)));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform cmpu: cmpu $src1,$src2.  */
CIA
SEM_FN_NAME (cmpu) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
CPU (h_cond) = LTUSI (* FLD (f_r1), * FLD (f_r2));
  TRACE_RESULT (current_cpu, "h_cond", 'x', LTUSI (* FLD (f_r1), * FLD (f_r2)));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform cmpui: cmpui $src2,$uimm16.  */
CIA
SEM_FN_NAME (cmpui) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_12.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
CPU (h_cond) = LTUSI (* FLD (f_r2), FLD (f_uimm16));
  TRACE_RESULT (current_cpu, "h_cond", 'x', LTUSI (* FLD (f_r2), FLD (f_uimm16)));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform div: div $dr,$sr.  */
CIA
SEM_FN_NAME (div) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_13.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
if (NESI (* FLD (f_r2), 0))
{
* FLD (f_r1) = DIVSI (* FLD (f_r1), * FLD (f_r2));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform divu: divu $dr,$sr.  */
CIA
SEM_FN_NAME (divu) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_13.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
if (NESI (* FLD (f_r2), 0))
{
* FLD (f_r1) = UDIVSI (* FLD (f_r1), * FLD (f_r2));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform rem: rem $dr,$sr.  */
CIA
SEM_FN_NAME (rem) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_13.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
if (NESI (* FLD (f_r2), 0))
{
* FLD (f_r1) = MODSI (* FLD (f_r1), * FLD (f_r2));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform remu: remu $dr,$sr.  */
CIA
SEM_FN_NAME (remu) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_13.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
if (NESI (* FLD (f_r2), 0))
{
* FLD (f_r1) = UMODSI (* FLD (f_r1), * FLD (f_r2));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform jl: jl $sr.  */
CIA
SEM_FN_NAME (jl) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_14.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
do {
  SI temp1;SI temp0;
temp0 = ADDSI (ANDSI (CPU (pc), -4), 4);
temp1 = * FLD (f_r2);
CPU (h_gr[14]) = temp0;
  TRACE_RESULT (current_cpu, "h_gr[14]", 'x', temp0);
  new_pc = SEM_BRANCH_VIA_ADDR (sem_arg, temp1);
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
} while (0);
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform jmp: jmp $sr.  */
CIA
SEM_FN_NAME (jmp) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_14.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
  new_pc = SEM_BRANCH_VIA_ADDR (sem_arg, * FLD (f_r2));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform ld: ld $dr,@$sr.  */
CIA
SEM_FN_NAME (ld) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = GETMEMSI (current_cpu, * FLD (f_r2));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform ld-d: ld $dr,@($slo16,$sr).  */
CIA
SEM_FN_NAME (ld_d) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_1.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = GETMEMSI (current_cpu, ADDSI (* FLD (f_r2), FLD (f_simm16)));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform ldb: ldb $dr,@$sr.  */
CIA
SEM_FN_NAME (ldb) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = EXTQISI (GETMEMQI (current_cpu, * FLD (f_r2)));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform ldb-d: ldb $dr,@($slo16,$sr).  */
CIA
SEM_FN_NAME (ldb_d) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_1.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = EXTQISI (GETMEMQI (current_cpu, ADDSI (* FLD (f_r2), FLD (f_simm16))));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform ldh: ldh $dr,@$sr.  */
CIA
SEM_FN_NAME (ldh) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = EXTHISI (GETMEMHI (current_cpu, * FLD (f_r2)));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform ldh-d: ldh $dr,@($slo16,$sr).  */
CIA
SEM_FN_NAME (ldh_d) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_1.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = EXTHISI (GETMEMHI (current_cpu, ADDSI (* FLD (f_r2), FLD (f_simm16))));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform ldub: ldub $dr,@$sr.  */
CIA
SEM_FN_NAME (ldub) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = ZEXTQISI (GETMEMQI (current_cpu, * FLD (f_r2)));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform ldub-d: ldub $dr,@($slo16,$sr).  */
CIA
SEM_FN_NAME (ldub_d) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_1.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = ZEXTQISI (GETMEMQI (current_cpu, ADDSI (* FLD (f_r2), FLD (f_simm16))));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform lduh: lduh $dr,@$sr.  */
CIA
SEM_FN_NAME (lduh) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = ZEXTHISI (GETMEMHI (current_cpu, * FLD (f_r2)));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform lduh-d: lduh $dr,@($slo16,$sr).  */
CIA
SEM_FN_NAME (lduh_d) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_1.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = ZEXTHISI (GETMEMHI (current_cpu, ADDSI (* FLD (f_r2), FLD (f_simm16))));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform ld-plus: ld $dr,@$sr+.  */
CIA
SEM_FN_NAME (ld_plus) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
do {
  SI temp1;SI temp0;
temp0 = GETMEMSI (current_cpu, * FLD (f_r2));
temp1 = ADDSI (* FLD (f_r2), 4);
* FLD (f_r1) = temp0;
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
* FLD (f_r2) = temp1;
  TRACE_RESULT (current_cpu, "sr", 'x', * FLD (f_r2));
} while (0);
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform ld24: ld24 $dr,$uimm24.  */
CIA
SEM_FN_NAME (ld24) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_15.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = FLD (f_uimm24);
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform ldi8: ldi $dr,$simm8.  */
CIA
SEM_FN_NAME (ldi8) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_4.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = FLD (f_simm8);
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform ldi16: ldi $dr,$slo16.  */
CIA
SEM_FN_NAME (ldi16) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_16.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = FLD (f_simm16);
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform lock: lock $dr,@$sr.  */
CIA
SEM_FN_NAME (lock) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
do_lock (current_cpu, * FLD (f_r1), * FLD (f_r2));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform machi: machi $src1,$src2.  */
CIA
SEM_FN_NAME (machi) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
CPU (h_accum) = SRADI (SHLDI (ADDDI (CPU (h_accum), MULDI (EXTSIDI (ANDSI (* FLD (f_r1), 0xffff0000)), EXTHIDI (TRUNCSIHI (SRASI (* FLD (f_r2), 16))))), 8), 8);
  TRACE_RESULT (current_cpu, "h_accum", 'D', SRADI (SHLDI (ADDDI (CPU (h_accum), MULDI (EXTSIDI (ANDSI (* FLD (f_r1), 0xffff0000)), EXTHIDI (TRUNCSIHI (SRASI (* FLD (f_r2), 16))))), 8), 8));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform maclo: maclo $src1,$src2.  */
CIA
SEM_FN_NAME (maclo) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
CPU (h_accum) = SRADI (SHLDI (ADDDI (CPU (h_accum), MULDI (EXTSIDI (SHLSI (* FLD (f_r1), 16)), EXTHIDI (TRUNCSIHI (* FLD (f_r2))))), 8), 8);
  TRACE_RESULT (current_cpu, "h_accum", 'D', SRADI (SHLDI (ADDDI (CPU (h_accum), MULDI (EXTSIDI (SHLSI (* FLD (f_r1), 16)), EXTHIDI (TRUNCSIHI (* FLD (f_r2))))), 8), 8));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform macwhi: macwhi $src1,$src2.  */
CIA
SEM_FN_NAME (macwhi) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
CPU (h_accum) = SRADI (SHLDI (ADDDI (CPU (h_accum), MULDI (EXTSIDI (* FLD (f_r1)), EXTHIDI (TRUNCSIHI (SRASI (* FLD (f_r2), 16))))), 8), 8);
  TRACE_RESULT (current_cpu, "h_accum", 'D', SRADI (SHLDI (ADDDI (CPU (h_accum), MULDI (EXTSIDI (* FLD (f_r1)), EXTHIDI (TRUNCSIHI (SRASI (* FLD (f_r2), 16))))), 8), 8));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform macwlo: macwlo $src1,$src2.  */
CIA
SEM_FN_NAME (macwlo) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
CPU (h_accum) = SRADI (SHLDI (ADDDI (CPU (h_accum), MULDI (EXTSIDI (* FLD (f_r1)), EXTHIDI (TRUNCSIHI (* FLD (f_r2))))), 8), 8);
  TRACE_RESULT (current_cpu, "h_accum", 'D', SRADI (SHLDI (ADDDI (CPU (h_accum), MULDI (EXTSIDI (* FLD (f_r1)), EXTHIDI (TRUNCSIHI (* FLD (f_r2))))), 8), 8));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform mul: mul $dr,$sr.  */
CIA
SEM_FN_NAME (mul) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = MULSI (* FLD (f_r1), * FLD (f_r2));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform mulhi: mulhi $src1,$src2.  */
CIA
SEM_FN_NAME (mulhi) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
CPU (h_accum) = SRADI (SHLDI (MULDI (EXTSIDI (ANDSI (* FLD (f_r1), 0xffff0000)), EXTHIDI (TRUNCSIHI (SRASI (* FLD (f_r2), 16)))), 16), 16);
  TRACE_RESULT (current_cpu, "h_accum", 'D', SRADI (SHLDI (MULDI (EXTSIDI (ANDSI (* FLD (f_r1), 0xffff0000)), EXTHIDI (TRUNCSIHI (SRASI (* FLD (f_r2), 16)))), 16), 16));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform mullo: mullo $src1,$src2.  */
CIA
SEM_FN_NAME (mullo) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
CPU (h_accum) = SRADI (SHLDI (MULDI (EXTSIDI (SHLSI (* FLD (f_r1), 16)), EXTHIDI (TRUNCSIHI (* FLD (f_r2)))), 16), 16);
  TRACE_RESULT (current_cpu, "h_accum", 'D', SRADI (SHLDI (MULDI (EXTSIDI (SHLSI (* FLD (f_r1), 16)), EXTHIDI (TRUNCSIHI (* FLD (f_r2)))), 16), 16));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform mulwhi: mulwhi $src1,$src2.  */
CIA
SEM_FN_NAME (mulwhi) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
CPU (h_accum) = SRADI (SHLDI (MULDI (EXTSIDI (* FLD (f_r1)), EXTHIDI (TRUNCSIHI (SRASI (* FLD (f_r2), 16)))), 8), 8);
  TRACE_RESULT (current_cpu, "h_accum", 'D', SRADI (SHLDI (MULDI (EXTSIDI (* FLD (f_r1)), EXTHIDI (TRUNCSIHI (SRASI (* FLD (f_r2), 16)))), 8), 8));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform mulwlo: mulwlo $src1,$src2.  */
CIA
SEM_FN_NAME (mulwlo) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
CPU (h_accum) = SRADI (SHLDI (MULDI (EXTSIDI (* FLD (f_r1)), EXTHIDI (TRUNCSIHI (* FLD (f_r2)))), 8), 8);
  TRACE_RESULT (current_cpu, "h_accum", 'D', SRADI (SHLDI (MULDI (EXTSIDI (* FLD (f_r1)), EXTHIDI (TRUNCSIHI (* FLD (f_r2)))), 8), 8));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform mv: mv $dr,$sr.  */
CIA
SEM_FN_NAME (mv) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = * FLD (f_r2);
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform mvfachi: mvfachi $dr.  */
CIA
SEM_FN_NAME (mvfachi) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_17.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = TRUNCDISI (SRADI (CPU (h_accum), 32));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform mvfaclo: mvfaclo $dr.  */
CIA
SEM_FN_NAME (mvfaclo) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_17.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = TRUNCDISI (CPU (h_accum));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform mvfacmi: mvfacmi $dr.  */
CIA
SEM_FN_NAME (mvfacmi) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_17.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = TRUNCDISI (SRADI (CPU (h_accum), 16));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform mvfc: mvfc $dr,$scr.  */
CIA
SEM_FN_NAME (mvfc) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_18.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = h_cr_get (FLD (f_r2));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform mvtachi: mvtachi $src1.  */
CIA
SEM_FN_NAME (mvtachi) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_19.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
CPU (h_accum) = ORDI (ANDDI (CPU (h_accum), MAKEDI (0, 0xffffffff)), SHLDI (EXTSIDI (* FLD (f_r1)), 32));
  TRACE_RESULT (current_cpu, "h_accum", 'D', ORDI (ANDDI (CPU (h_accum), MAKEDI (0, 0xffffffff)), SHLDI (EXTSIDI (* FLD (f_r1)), 32)));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform mvtaclo: mvtaclo $src1.  */
CIA
SEM_FN_NAME (mvtaclo) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_19.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
CPU (h_accum) = ORDI (ANDDI (CPU (h_accum), MAKEDI (0xffffffff, 0)), EXTSIDI (* FLD (f_r1)));
  TRACE_RESULT (current_cpu, "h_accum", 'D', ORDI (ANDDI (CPU (h_accum), MAKEDI (0xffffffff, 0)), EXTSIDI (* FLD (f_r1))));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform mvtc: mvtc $sr,$dcr.  */
CIA
SEM_FN_NAME (mvtc) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_20.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
h_cr_set (FLD (f_r1), * FLD (f_r2));
  TRACE_RESULT (current_cpu, "dcr", 'x', h_cr_get (FLD (f_r1)));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform neg: neg $dr,$sr.  */
CIA
SEM_FN_NAME (neg) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = NEGSI (* FLD (f_r2));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform nop: nop.  */
CIA
SEM_FN_NAME (nop) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_21.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
PROFILE_COUNT_FILLNOPS (current_cpu, abuf->addr);
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform not: not $dr,$sr.  */
CIA
SEM_FN_NAME (not) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = INVSI (* FLD (f_r2));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform rac: rac.  */
CIA
SEM_FN_NAME (rac) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_21.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
{
  DI tmp_tmp1;
tmp_tmp1 = ANDDI (CPU (h_accum), MAKEDI (16777215, 0xffffffff));
if (ANDIFSI (GEDI (tmp_tmp1, MAKEDI (16383, 0xffff8000)), LEDI (tmp_tmp1, MAKEDI (8388607, 0xffffffff))))
{
  tmp_tmp1 = MAKEDI (16383, 0xffff8000);
} else {
if (ANDIFSI (GEDI (tmp_tmp1, MAKEDI (8388608, 0)), LEDI (tmp_tmp1, MAKEDI (16760832, 0))))
{
  tmp_tmp1 = MAKEDI (16760832, 0);
} else {
  tmp_tmp1 = ANDDI (ADDDI (CPU (h_accum), MAKEDI (0, 16384)), MAKEDI (16777215, 0xffff8000));
}
}
  tmp_tmp1 = SHLDI (tmp_tmp1, 1);
CPU (h_accum) = SRADI (SHLDI (tmp_tmp1, 7), 7);
  TRACE_RESULT (current_cpu, "h_accum", 'D', SRADI (SHLDI (tmp_tmp1, 7), 7));
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform rach: rach.  */
CIA
SEM_FN_NAME (rach) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_21.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
{
  DI tmp_tmp1;
tmp_tmp1 = ANDDI (CPU (h_accum), MAKEDI (16777215, 0xffffffff));
if (ANDIFSI (GEDI (tmp_tmp1, MAKEDI (16383, 0x80000000)), LEDI (tmp_tmp1, MAKEDI (8388607, 0xffffffff))))
{
  tmp_tmp1 = MAKEDI (16383, 0x80000000);
} else {
if (ANDIFSI (GEDI (tmp_tmp1, MAKEDI (8388608, 0)), LEDI (tmp_tmp1, MAKEDI (16760832, 0))))
{
  tmp_tmp1 = MAKEDI (16760832, 0);
} else {
  tmp_tmp1 = ANDDI (ADDDI (CPU (h_accum), MAKEDI (0, 1073741824)), MAKEDI (0xffffffff, 0x80000000));
}
}
  tmp_tmp1 = SHLDI (tmp_tmp1, 1);
CPU (h_accum) = SRADI (SHLDI (tmp_tmp1, 7), 7);
  TRACE_RESULT (current_cpu, "h_accum", 'D', SRADI (SHLDI (tmp_tmp1, 7), 7));
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform rte: rte.  */
CIA
SEM_FN_NAME (rte) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_21.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
{
CPU (h_sm) = CPU (h_bsm);
  TRACE_RESULT (current_cpu, "h_sm", 'x', CPU (h_bsm));
CPU (h_ie) = CPU (h_bie);
  TRACE_RESULT (current_cpu, "h_ie", 'x', CPU (h_bie));
CPU (h_cond) = CPU (h_bcond);
  TRACE_RESULT (current_cpu, "h_cond", 'x', CPU (h_bcond));
  new_pc = SEM_BRANCH_VIA_ADDR (sem_arg, CPU (h_bpc));
  TRACE_RESULT (current_cpu, "new_pc", 'x', SEM_NEW_PC_ADDR (new_pc));
  taken_p = 1;
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform seth: seth $dr,$hi16.  */
CIA
SEM_FN_NAME (seth) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_22.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = SHLSI (FLD (f_hi16), 16);
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform sll: sll $dr,$sr.  */
CIA
SEM_FN_NAME (sll) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = SHLSI (* FLD (f_r1), ANDSI (* FLD (f_r2), 31));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform sll3: sll3 $dr,$sr,$simm16.  */
CIA
SEM_FN_NAME (sll3) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_5.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = SHLSI (* FLD (f_r2), ANDSI (FLD (f_simm16), 31));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform slli: slli $dr,$uimm5.  */
CIA
SEM_FN_NAME (slli) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_23.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = SHLSI (* FLD (f_r1), FLD (f_uimm5));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform sra: sra $dr,$sr.  */
CIA
SEM_FN_NAME (sra) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = SRASI (* FLD (f_r1), ANDSI (* FLD (f_r2), 31));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform sra3: sra3 $dr,$sr,$simm16.  */
CIA
SEM_FN_NAME (sra3) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_5.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = SRASI (* FLD (f_r2), ANDSI (FLD (f_simm16), 31));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform srai: srai $dr,$uimm5.  */
CIA
SEM_FN_NAME (srai) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_23.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = SRASI (* FLD (f_r1), FLD (f_uimm5));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform srl: srl $dr,$sr.  */
CIA
SEM_FN_NAME (srl) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = SRLSI (* FLD (f_r1), ANDSI (* FLD (f_r2), 31));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform srl3: srl3 $dr,$sr,$simm16.  */
CIA
SEM_FN_NAME (srl3) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_5.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = SRLSI (* FLD (f_r2), ANDSI (FLD (f_simm16), 31));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform srli: srli $dr,$uimm5.  */
CIA
SEM_FN_NAME (srli) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_23.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = SRLSI (* FLD (f_r1), FLD (f_uimm5));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform st: st $src1,@$src2.  */
CIA
SEM_FN_NAME (st) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
SETMEMSI (current_cpu, * FLD (f_r2), * FLD (f_r1));
  TRACE_RESULT (current_cpu, "memory", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform st-d: st $src1,@($slo16,$src2).  */
CIA
SEM_FN_NAME (st_d) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_24.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
SETMEMSI (current_cpu, ADDSI (* FLD (f_r2), FLD (f_simm16)), * FLD (f_r1));
  TRACE_RESULT (current_cpu, "memory", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform stb: stb $src1,@$src2.  */
CIA
SEM_FN_NAME (stb) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
SETMEMQI (current_cpu, * FLD (f_r2), * FLD (f_r1));
  TRACE_RESULT (current_cpu, "memory", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform stb-d: stb $src1,@($slo16,$src2).  */
CIA
SEM_FN_NAME (stb_d) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_24.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
SETMEMQI (current_cpu, ADDSI (* FLD (f_r2), FLD (f_simm16)), * FLD (f_r1));
  TRACE_RESULT (current_cpu, "memory", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform sth: sth $src1,@$src2.  */
CIA
SEM_FN_NAME (sth) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
SETMEMHI (current_cpu, * FLD (f_r2), * FLD (f_r1));
  TRACE_RESULT (current_cpu, "memory", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform sth-d: sth $src1,@($slo16,$src2).  */
CIA
SEM_FN_NAME (sth_d) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_24.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
SETMEMHI (current_cpu, ADDSI (* FLD (f_r2), FLD (f_simm16)), * FLD (f_r1));
  TRACE_RESULT (current_cpu, "memory", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform st-plus: st $src1,@+$src2.  */
CIA
SEM_FN_NAME (st_plus) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
{
* FLD (f_r2) = ADDSI (* FLD (f_r2), 4);
  TRACE_RESULT (current_cpu, "src2", 'x', * FLD (f_r2));
SETMEMSI (current_cpu, * FLD (f_r2), * FLD (f_r1));
  TRACE_RESULT (current_cpu, "memory", 'x', * FLD (f_r1));
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform st-minus: st $src1,@-$src2.  */
CIA
SEM_FN_NAME (st_minus) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
{
* FLD (f_r2) = SUBSI (* FLD (f_r2), 4);
  TRACE_RESULT (current_cpu, "src2", 'x', * FLD (f_r2));
SETMEMSI (current_cpu, * FLD (f_r2), * FLD (f_r1));
  TRACE_RESULT (current_cpu, "memory", 'x', * FLD (f_r1));
}
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform sub: sub $dr,$sr.  */
CIA
SEM_FN_NAME (sub) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
* FLD (f_r1) = SUBSI (* FLD (f_r1), * FLD (f_r2));
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform subv: subv $dr,$sr.  */
CIA
SEM_FN_NAME (subv) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
do {
  BI temp1;SI temp0;
temp0 = SUBSI (* FLD (f_r1), * FLD (f_r2));
temp1 = SUBOFSI (* FLD (f_r1), * FLD (f_r2), 0);
* FLD (f_r1) = temp0;
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
CPU (h_cond) = temp1;
  TRACE_RESULT (current_cpu, "h_cond", 'x', temp1);
} while (0);
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform subx: subx $dr,$sr.  */
CIA
SEM_FN_NAME (subx) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_0.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
do {
  BI temp1;SI temp0;
temp0 = SUBCSI (* FLD (f_r1), * FLD (f_r2), CPU (h_cond));
temp1 = SUBCFSI (* FLD (f_r1), * FLD (f_r2), CPU (h_cond));
* FLD (f_r1) = temp0;
  TRACE_RESULT (current_cpu, "dr", 'x', * FLD (f_r1));
CPU (h_cond) = temp1;
  TRACE_RESULT (current_cpu, "h_cond", 'x', temp1);
} while (0);
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_mark_set_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform trap: trap $uimm4.  */
CIA
SEM_FN_NAME (trap) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_25.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
  int taken_p = 0;
do_trap (current_cpu, FLD (f_uimm4));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_profile_cti_insn (current_cpu, abuf, taken_p);
    }
#endif
  return new_pc;
#undef FLD
}

/* Perform unlock: unlock $src1,@$src2.  */
CIA
SEM_FN_NAME (unlock) (SIM_CPU *current_cpu, SEM_ARG sem_arg)
{
#define FLD(f) abuf->fields.fmt_10.f
  ARGBUF *abuf = SEM_ARGBUF (sem_arg);
  CIA new_pc = SEM_NEXT_PC (sem_arg);
do_unlock (current_cpu, * FLD (f_r1), * FLD (f_r2));
#if WITH_PROFILE_MODEL_P
  if (PROFILE_MODEL_P (current_cpu))
    {
      model_mark_get_h_gr (current_cpu, abuf);
      model_profile_insn (current_cpu, abuf);
    }
#endif
  return new_pc;
#undef FLD
}

