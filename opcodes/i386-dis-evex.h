static const struct dis386 evex_table[][256] = {
  /* EVEX_0F */
  {
    /* 00 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 08 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 10 */
    { PREFIX_TABLE (PREFIX_VEX_0F10) },
    { PREFIX_TABLE (PREFIX_VEX_0F11) },
    { PREFIX_TABLE (PREFIX_VEX_0F12) },
    { MOD_TABLE (MOD_VEX_0F13) },
    { "vunpcklpX",	{ XM, Vex, EXx }, PREFIX_OPCODE },
    { "vunpckhpX",	{ XM, Vex, EXx }, PREFIX_OPCODE },
    { PREFIX_TABLE (PREFIX_VEX_0F16) },
    { MOD_TABLE (MOD_VEX_0F17) },
    /* 18 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 20 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 28 */
    { "vmovapX",	{ XM, EXx }, PREFIX_OPCODE },
    { "vmovapX",	{ EXxS, XM }, PREFIX_OPCODE },
    { PREFIX_TABLE (PREFIX_VEX_0F2A) },
    { MOD_TABLE (MOD_VEX_0F2B) },
    { PREFIX_TABLE (PREFIX_VEX_0F2C) },
    { PREFIX_TABLE (PREFIX_VEX_0F2D) },
    { PREFIX_TABLE (PREFIX_VEX_0F2E) },
    { PREFIX_TABLE (PREFIX_VEX_0F2F) },
    /* 30 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 38 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 40 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 48 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 50 */
    { Bad_Opcode },
    { PREFIX_TABLE (PREFIX_VEX_0F51) },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vandpX",	{ XM, Vex, EXx }, PREFIX_OPCODE },
    { "vandnpX",	{ XM, Vex, EXx }, PREFIX_OPCODE },
    { "vorpX",	{ XM, Vex, EXx }, PREFIX_OPCODE },
    { "vxorpX",	{ XM, Vex, EXx }, PREFIX_OPCODE },
    /* 58 */
    { PREFIX_TABLE (PREFIX_VEX_0F58) },
    { PREFIX_TABLE (PREFIX_VEX_0F59) },
    { PREFIX_TABLE (PREFIX_VEX_0F5A) },
    { PREFIX_TABLE (PREFIX_EVEX_0F5B) },
    { PREFIX_TABLE (PREFIX_VEX_0F5C) },
    { PREFIX_TABLE (PREFIX_VEX_0F5D) },
    { PREFIX_TABLE (PREFIX_VEX_0F5E) },
    { PREFIX_TABLE (PREFIX_VEX_0F5F) },
    /* 60 */
    { "vpunpcklbw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpunpcklwd",	{ XM, Vex, EXx }, PREFIX_DATA },
    { VEX_W_TABLE (EVEX_W_0F62) },
    { "vpacksswb",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpcmpgtb",	{ MaskG, Vex, EXx }, PREFIX_DATA },
    { "vpcmpgtw",	{ MaskG, Vex, EXx }, PREFIX_DATA },
    { VEX_W_TABLE (EVEX_W_0F66) },
    { "vpackuswb",	{ XM, Vex, EXx }, PREFIX_DATA },
    /* 68 */
    { "vpunpckhbw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpunpckhwd",	{ XM, Vex, EXx }, PREFIX_DATA },
    { VEX_W_TABLE (EVEX_W_0F6A) },
    { VEX_W_TABLE (EVEX_W_0F6B) },
    { VEX_W_TABLE (EVEX_W_0F6C) },
    { VEX_W_TABLE (EVEX_W_0F6D) },
    { VEX_LEN_TABLE (VEX_LEN_0F6E) },
    { PREFIX_TABLE (PREFIX_EVEX_0F6F) },
    /* 70 */
    { PREFIX_TABLE (PREFIX_EVEX_0F70) },
    { REG_TABLE (REG_EVEX_0F71) },
    { REG_TABLE (REG_EVEX_0F72) },
    { REG_TABLE (REG_EVEX_0F73) },
    { "vpcmpeqb",	{ MaskG, Vex, EXx }, PREFIX_DATA },
    { "vpcmpeqw",	{ MaskG, Vex, EXx }, PREFIX_DATA },
    { VEX_W_TABLE (EVEX_W_0F76) },
    { Bad_Opcode },
    /* 78 */
    { PREFIX_TABLE (PREFIX_EVEX_0F78) },
    { PREFIX_TABLE (PREFIX_EVEX_0F79) },
    { PREFIX_TABLE (PREFIX_EVEX_0F7A) },
    { PREFIX_TABLE (PREFIX_EVEX_0F7B) },
    { Bad_Opcode },
    { Bad_Opcode },
    { PREFIX_TABLE (PREFIX_EVEX_0F7E) },
    { PREFIX_TABLE (PREFIX_EVEX_0F7F) },
    /* 80 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 88 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 90 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 98 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* A0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* A8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* B0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* B8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* C0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { PREFIX_TABLE (PREFIX_EVEX_0FC2) },
    { Bad_Opcode },
    { VEX_LEN_TABLE (VEX_LEN_0FC4) },
    { VEX_LEN_TABLE (VEX_LEN_0FC5) },
    { "vshufpX",	{ XM, Vex, EXx, Ib }, PREFIX_OPCODE },
    { Bad_Opcode },
    /* C8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* D0 */
    { Bad_Opcode },
    { "vpsrlw",		{ XM, Vex, EXxmm }, PREFIX_DATA },
    { VEX_W_TABLE (EVEX_W_0FD2) },
    { VEX_W_TABLE (EVEX_W_0FD3) },
    { VEX_W_TABLE (EVEX_W_0FD4) },
    { "vpmullw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { VEX_W_TABLE (EVEX_W_0FD6) },
    { Bad_Opcode },
    /* D8 */
    { "vpsubusb",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpsubusw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpminub",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpand%DQ",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpaddusb",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpaddusw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpmaxub",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpandn%DQ",	{ XM, Vex, EXx }, PREFIX_DATA },
    /* E0 */
    { "vpavgb",		{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpsraw",		{ XM, Vex, EXxmm }, PREFIX_DATA },
    { "vpsra%DQ",	{ XM, Vex, EXxmm }, PREFIX_DATA },
    { "vpavgw",		{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpmulhuw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpmulhw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { PREFIX_TABLE (PREFIX_EVEX_0FE6) },
    { VEX_W_TABLE (EVEX_W_0FE7) },
    /* E8 */
    { "vpsubsb",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpsubsw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpminsw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpor%DQ",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpaddsb",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpaddsw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpmaxsw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpxor%DQ",	{ XM, Vex, EXx }, PREFIX_DATA },
    /* F0 */
    { Bad_Opcode },
    { "vpsllw",		{ XM, Vex, EXxmm }, PREFIX_DATA },
    { VEX_W_TABLE (EVEX_W_0FF2) },
    { VEX_W_TABLE (EVEX_W_0FF3) },
    { VEX_W_TABLE (EVEX_W_0FF4) },
    { "vpmaddwd",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpsadbw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { Bad_Opcode },
    /* F8 */
    { "vpsubb",		{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpsubw",		{ XM, Vex, EXx }, PREFIX_DATA },
    { VEX_W_TABLE (EVEX_W_0FFA) },
    { VEX_W_TABLE (EVEX_W_0FFB) },
    { "vpaddb",		{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpaddw",		{ XM, Vex, EXx }, PREFIX_DATA },
    { VEX_W_TABLE (EVEX_W_0FFE) },
    { Bad_Opcode },
  },
  /* EVEX_0F38 */
  {
    /* 00 */
    { "vpshufb",	{ XM, Vex, EXx }, PREFIX_DATA },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vpmaddubsw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 08 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vpmulhrsw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { VEX_W_TABLE (VEX_W_0F380C) },
    { "vpermilp%XD", { XM, Vex, EXx }, PREFIX_DATA },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 10 */
    { PREFIX_TABLE (PREFIX_EVEX_0F3810) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3811) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3812) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3813) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3814) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3815) },
    { EVEX_LEN_TABLE (EVEX_LEN_0F3816) },
    { Bad_Opcode },
    /* 18 */
    { VEX_W_TABLE (VEX_W_0F3818) },
    { EVEX_LEN_TABLE (EVEX_LEN_0F3819) },
    { MOD_TABLE (MOD_EVEX_0F381A) },
    { MOD_TABLE (MOD_EVEX_0F381B) },
    { "vpabsb",		{ XM, EXx }, PREFIX_DATA },
    { "vpabsw",		{ XM, EXx }, PREFIX_DATA },
    { VEX_W_TABLE (EVEX_W_0F381E) },
    { VEX_W_TABLE (EVEX_W_0F381F) },
    /* 20 */
    { PREFIX_TABLE (PREFIX_EVEX_0F3820) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3821) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3822) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3823) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3824) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3825) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3826) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3827) },
    /* 28 */
    { PREFIX_TABLE (PREFIX_EVEX_0F3828) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3829) },
    { PREFIX_TABLE (PREFIX_EVEX_0F382A) },
    { VEX_W_TABLE (EVEX_W_0F382B) },
    { "vscalefp%XW",	{ XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    { "vscalefs%XW",	{ XMScalar, VexScalar, EXdq, EXxEVexR }, PREFIX_DATA },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 30 */
    { PREFIX_TABLE (PREFIX_EVEX_0F3830) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3831) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3832) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3833) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3834) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3835) },
    { EVEX_LEN_TABLE (EVEX_LEN_0F3836) },
    { VEX_W_TABLE (EVEX_W_0F3837) },
    /* 38 */
    { PREFIX_TABLE (PREFIX_EVEX_0F3838) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3839) },
    { PREFIX_TABLE (PREFIX_EVEX_0F383A) },
    { "vpminu%DQ",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpmaxsb",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpmaxs%DQ",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpmaxuw",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpmaxu%DQ",	{ XM, Vex, EXx }, PREFIX_DATA },
    /* 40 */
    { "vpmull%DQ",	{ XM, Vex, EXx }, PREFIX_DATA },
    { Bad_Opcode },
    { "vgetexpp%XW",	{ XM, EXx, EXxEVexS }, PREFIX_DATA },
    { "vgetexps%XW",	{ XMScalar, VexScalar, EXdq, EXxEVexS }, PREFIX_DATA },
    { "vplzcnt%DQ",	{ XM, EXx }, PREFIX_DATA },
    { "vpsrlv%DQ",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpsrav%DQ",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpsllv%DQ",	{ XM, Vex, EXx }, PREFIX_DATA },
    /* 48 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vrcp14p%XW",	{ XM, EXx }, PREFIX_DATA },
    { "vrcp14s%XW",	{ XMScalar, VexScalar, EXdq }, PREFIX_DATA },
    { "vrsqrt14p%XW",	{ XM, EXx }, 0 },
    { "vrsqrt14s%XW",	{ XMScalar, VexScalar, EXdq }, PREFIX_DATA },
    /* 50 */
    { VEX_W_TABLE (VEX_W_0F3850) },
    { VEX_W_TABLE (VEX_W_0F3851) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3852) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3853) },
    { "vpopcnt%BW",	{ XM, EXx }, PREFIX_DATA },
    { "vpopcnt%DQ",	{ XM, EXx }, PREFIX_DATA },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 58 */
    { VEX_W_TABLE (VEX_W_0F3858) },
    { VEX_W_TABLE (EVEX_W_0F3859) },
    { MOD_TABLE (MOD_EVEX_0F385A) },
    { MOD_TABLE (MOD_EVEX_0F385B) },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 60 */
    { Bad_Opcode },
    { Bad_Opcode },
    { "vpexpand%BW",	{ XM, EXbwUnit }, PREFIX_DATA },
    { "vpcompress%BW",	{ EXbwUnit, XM }, PREFIX_DATA },
    { "vpblendm%DQ",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vblendmp%XW",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpblendm%BW",	{ XM, Vex, EXx }, PREFIX_DATA },
    { Bad_Opcode },
    /* 68 */
    { PREFIX_TABLE (PREFIX_EVEX_0F3868) },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 70 */
    { VEX_W_TABLE (EVEX_W_0F3870) },
    { "vpshldv%DQ",  { XM, Vex, EXx }, PREFIX_DATA },
    { PREFIX_TABLE (PREFIX_EVEX_0F3872) },
    { "vpshrdv%DQ",  { XM, Vex, EXx }, PREFIX_DATA },
    { Bad_Opcode },
    { "vpermi2%BW",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpermi2%DQ",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpermi2p%XW",	{ XM, Vex, EXx }, PREFIX_DATA },
    /* 78 */
    { VEX_W_TABLE (VEX_W_0F3878) },
    { VEX_W_TABLE (VEX_W_0F3879) },
    { VEX_W_TABLE (EVEX_W_0F387A) },
    { VEX_W_TABLE (EVEX_W_0F387B) },
    { MOD_TABLE (MOD_EVEX_0F387C) },
    { "vpermt2%BW",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpermt2%DQ",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpermt2p%XW",	{ XM, Vex, EXx }, PREFIX_DATA },
    /* 80 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { VEX_W_TABLE (EVEX_W_0F3883) },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 88 */
    { "vexpandp%XW",	{ XM, EXEvexXGscat }, PREFIX_DATA },
    { "vpexpand%DQ",	{ XM, EXEvexXGscat }, PREFIX_DATA },
    { "vcompressp%XW",	{ EXEvexXGscat, XM }, PREFIX_DATA },
    { "vpcompress%DQ",	{ EXEvexXGscat, XM }, PREFIX_DATA },
    { Bad_Opcode },
    { "vperm%BW",	{ XM, Vex, EXx }, PREFIX_DATA },
    { Bad_Opcode },
    { "vpshufbitqmb",	{ MaskG, Vex, EXx }, PREFIX_DATA },
    /* 90 */
    { "vpgatherd%DQ",	{ XMGatherD, MVexVSIBDWpX }, PREFIX_DATA },
    { "vpgatherq%DQ",	{ XMGatherQ, MVexVSIBQWpX }, PREFIX_DATA },
    { "vgatherdp%XW",	{ XMGatherD, MVexVSIBDWpX }, PREFIX_DATA },
    { "vgatherqp%XW",	{ XMGatherQ, MVexVSIBQWpX }, PREFIX_DATA },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vfmaddsub132p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    { "vfmsubadd132p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    /* 98 */
    { "vfmadd132p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    { "vfmadd132s%XW", { XMScalar, VexScalar, EXdq, EXxEVexR }, PREFIX_DATA },
    { PREFIX_TABLE (PREFIX_EVEX_0F389A) },
    { PREFIX_TABLE (PREFIX_EVEX_0F389B) },
    { "vfnmadd132p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    { "vfnmadd132s%XW", { XMScalar, VexScalar, EXdq, EXxEVexR }, PREFIX_DATA },
    { "vfnmsub132p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    { "vfnmsub132s%XW", { XMScalar, VexScalar, EXdq, EXxEVexR }, PREFIX_DATA },
    /* A0 */
    { "vpscatterd%DQ",	{ MVexVSIBDWpX, XM }, PREFIX_DATA },
    { "vpscatterq%DQ",	{ MVexVSIBQWpX, XMGatherQ }, PREFIX_DATA },
    { "vscatterdp%XW",	{ MVexVSIBDWpX, XM }, PREFIX_DATA },
    { "vscatterqp%XW",	{ MVexVSIBQWpX, XMGatherQ }, PREFIX_DATA },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vfmaddsub213p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    { "vfmsubadd213p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    /* A8 */
    { "vfmadd213p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    { "vfmadd213s%XW", { XMScalar, VexScalar, EXdq, EXxEVexR }, PREFIX_DATA },
    { PREFIX_TABLE (PREFIX_EVEX_0F38AA) },
    { PREFIX_TABLE (PREFIX_EVEX_0F38AB) },
    { "vfnmadd213p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    { "vfnmadd213s%XW", { XMScalar, VexScalar, EXdq, EXxEVexR }, PREFIX_DATA },
    { "vfnmsub213p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    { "vfnmsub213s%XW", { XMScalar, VexScalar, EXdq, EXxEVexR }, PREFIX_DATA },
    /* B0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vpmadd52luq",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vpmadd52huq",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vfmaddsub231p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    { "vfmsubadd231p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    /* B8 */
    { "vfmadd231p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    { "vfmadd231s%XW", { XMScalar, VexScalar, EXdq, EXxEVexR }, PREFIX_DATA },
    { "vfmsub231p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    { "vfmsub231s%XW", { XMScalar, VexScalar, EXdq, EXxEVexR }, PREFIX_DATA },
    { "vfnmadd231p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    { "vfnmadd231s%XW", { XMScalar, VexScalar, EXdq, EXxEVexR }, PREFIX_DATA },
    { "vfnmsub231p%XW", { XM, Vex, EXx, EXxEVexR }, PREFIX_DATA },
    { "vfnmsub231s%XW", { XMScalar, VexScalar, EXdq, EXxEVexR }, PREFIX_DATA },
    /* C0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vpconflict%DQ",	{ XM, EXx }, PREFIX_DATA },
    { Bad_Opcode },
    { MOD_TABLE (MOD_EVEX_0F38C6) },
    { MOD_TABLE (MOD_EVEX_0F38C7) },
    /* C8 */
    { "vexp2p%XW",	{ XM, EXx, EXxEVexS }, PREFIX_DATA },
    { Bad_Opcode },
    { "vrcp28p%XW",	{ XM, EXx, EXxEVexS }, PREFIX_DATA },
    { "vrcp28s%XW",	{ XMScalar, VexScalar, EXdq, EXxEVexS }, PREFIX_DATA },
    { "vrsqrt28p%XW",	{ XM, EXx, EXxEVexS }, PREFIX_DATA },
    { "vrsqrt28s%XW",	{ XMScalar, VexScalar, EXdq, EXxEVexS }, PREFIX_DATA },
    { Bad_Opcode },
    { VEX_W_TABLE (VEX_W_0F38CF) },
    /* D0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* D8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vaesenc",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vaesenclast",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vaesdec",	{ XM, Vex, EXx }, PREFIX_DATA },
    { "vaesdeclast",	{ XM, Vex, EXx }, PREFIX_DATA },
    /* E0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* E8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* F0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* F8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
  },
  /* EVEX_0F3A */
  {
    /* 00 */
    { EVEX_LEN_TABLE (EVEX_LEN_0F3A00) },
    { EVEX_LEN_TABLE (EVEX_LEN_0F3A01) },
    { Bad_Opcode },
    { "valign%DQ",	{ XM, Vex, EXx, Ib }, PREFIX_DATA },
    { VEX_W_TABLE (VEX_W_0F3A04) },
    { "vpermilp%XD", { XM, EXx, Ib }, PREFIX_DATA },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 08 */
    { PREFIX_TABLE (PREFIX_EVEX_0F3A08) },
    { "vrndscalep%XD", { XM, EXx, EXxEVexS, Ib }, PREFIX_DATA },
    { PREFIX_TABLE (PREFIX_EVEX_0F3A0A) },
    { "vrndscales%XD", { XMScalar, VexScalar, EXq, EXxEVexS, Ib }, PREFIX_DATA },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vpalignr",	{ XM, Vex, EXx, Ib }, PREFIX_DATA },
    /* 10 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { VEX_LEN_TABLE (VEX_LEN_0F3A14) },
    { VEX_LEN_TABLE (VEX_LEN_0F3A15) },
    { VEX_LEN_TABLE (VEX_LEN_0F3A16) },
    { VEX_LEN_TABLE (VEX_LEN_0F3A17) },
    /* 18 */
    { EVEX_LEN_TABLE (EVEX_LEN_0F3A18) },
    { EVEX_LEN_TABLE (EVEX_LEN_0F3A19) },
    { EVEX_LEN_TABLE (EVEX_LEN_0F3A1A) },
    { EVEX_LEN_TABLE (EVEX_LEN_0F3A1B) },
    { Bad_Opcode },
    { VEX_W_TABLE (VEX_W_0F3A1D) },
    { "vpcmpu%DQ",	{ MaskG, Vex, EXx, VPCMP }, PREFIX_DATA },
    { "vpcmp%DQ",	{ MaskG, Vex, EXx, VPCMP }, PREFIX_DATA },
    /* 20 */
    { VEX_LEN_TABLE (VEX_LEN_0F3A20) },
    { VEX_W_TABLE (EVEX_W_0F3A21) },
    { VEX_LEN_TABLE (VEX_LEN_0F3A22) },
    { EVEX_LEN_TABLE (EVEX_LEN_0F3A23) },
    { Bad_Opcode },
    { "vpternlog%DQ",	{ XM, Vex, EXx, Ib }, PREFIX_DATA },
    { PREFIX_TABLE (PREFIX_EVEX_0F3A26) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3A27) },
    /* 28 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 30 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 38 */
    { EVEX_LEN_TABLE (EVEX_LEN_0F3A38) },
    { EVEX_LEN_TABLE (EVEX_LEN_0F3A39) },
    { EVEX_LEN_TABLE (EVEX_LEN_0F3A3A) },
    { EVEX_LEN_TABLE (EVEX_LEN_0F3A3B) },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vpcmpu%BW",	{ MaskG, Vex, EXx, VPCMP }, PREFIX_DATA },
    { "vpcmp%BW",	{ MaskG, Vex, EXx, VPCMP }, PREFIX_DATA },
    /* 40 */
    { Bad_Opcode },
    { Bad_Opcode },
    { VEX_W_TABLE (EVEX_W_0F3A42) },
    { EVEX_LEN_TABLE (EVEX_LEN_0F3A43) },
    { "vpclmulqdq",	{ XM, Vex, EXx, PCLMUL }, PREFIX_DATA },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 48 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 50 */
    { "vrangep%XW",	{ XM, Vex, EXx, EXxEVexS, Ib }, PREFIX_DATA },
    { "vranges%XW",	{ XMScalar, VexScalar, EXdq, EXxEVexS, Ib }, PREFIX_DATA },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vfixupimmp%XW",	{ XM, Vex, EXx, EXxEVexS, Ib }, PREFIX_DATA },
    { "vfixupimms%XW",	{ XMScalar, VexScalar, EXdq, EXxEVexS, Ib }, PREFIX_DATA },
    { PREFIX_TABLE (PREFIX_EVEX_0F3A56) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3A57) },
    /* 58 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 60 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { PREFIX_TABLE (PREFIX_EVEX_0F3A66) },
    { PREFIX_TABLE (PREFIX_EVEX_0F3A67) },
    /* 68 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 70 */
    { VEX_W_TABLE (EVEX_W_0F3A70) },
    { "vpshld%DQ",   { XM, Vex, EXx, Ib }, PREFIX_DATA },
    { VEX_W_TABLE (EVEX_W_0F3A72) },
    { "vpshrd%DQ",   { XM, Vex, EXx, Ib }, PREFIX_DATA },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 78 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 80 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 88 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 90 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 98 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* A0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* A8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* B0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* B8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* C0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { PREFIX_TABLE (PREFIX_EVEX_0F3AC2) },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* C8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { VEX_W_TABLE (VEX_W_0F3ACE) },
    { VEX_W_TABLE (VEX_W_0F3ACF) },
    /* D0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* D8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* E0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* E8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* F0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* F8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
  },
  /* EVEX_MAP5_ */
  {
    /* 00 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 08 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 10 */
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_10) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_11) },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 18 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_1D) },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 20 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 28 */
    { Bad_Opcode },
    { Bad_Opcode },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_2A) },
    { Bad_Opcode },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_2C) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_2D) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_2E) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_2F) },
    /* 30 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 38 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 40 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 48 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 50 */
    { Bad_Opcode },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_51) },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 58 */
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_58) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_59) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_5A) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_5B) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_5C) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_5D) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_5E) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_5F) },
    /* 60 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 68 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vmovw", { XMScalar, Edw }, PREFIX_DATA },
    { Bad_Opcode },
    /* 70 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 78 */
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_78) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_79) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_7A) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_7B) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_7C) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP5_7D) },
    { "vmovw",	  { Edw, XMScalar }, PREFIX_DATA },
    { Bad_Opcode },
    /* 80 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 88 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 90 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 98 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* A0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* A8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* B0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* B8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* C0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* C8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* D0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* D8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* E0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* E8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* F0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* F8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
  },
  /* EVEX_MAP6_ */
  {
    /* 00 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 08 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 10 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { PREFIX_TABLE (PREFIX_EVEX_MAP6_13) },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 18 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 20 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 28 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vscalefp%XH",      { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vscalefs%XH",      { XMScalar, VexScalar, EXw, EXxEVexR }, PREFIX_DATA },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 30 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 38 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 40 */
    { Bad_Opcode },
    { Bad_Opcode },
    { "vgetexpp%XH",      { XM, EXxh, EXxEVexS }, PREFIX_DATA },
    { "vgetexps%XH",      { XMScalar, VexScalar, EXw, EXxEVexS }, PREFIX_DATA },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 48 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vrcpp%XH",	  { XM, EXxh }, PREFIX_DATA },
    { "vrcps%XH",	  { XMScalar, VexScalar, EXw }, PREFIX_DATA },
    { "vrsqrtp%XH",       { XM, EXxh }, PREFIX_DATA },
    { "vrsqrts%XH",       { XMScalar, VexScalar, EXw }, PREFIX_DATA },
    /* 50 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { PREFIX_TABLE (PREFIX_EVEX_MAP6_56) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP6_57) },
    /* 58 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 60 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 68 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 70 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 78 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 80 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 88 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* 90 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vfmaddsub132p%XH",  { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfmsubadd132p%XH",  { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    /* 98 */
    { "vfmadd132p%XH",  { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfmadd132s%XH",  { XMScalar, VexScalar, EXw, EXxEVexR }, PREFIX_DATA },
    { "vfmsub132p%XH",  { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfmsub132s%XH",  { XMScalar, VexScalar, EXw, EXxEVexR }, PREFIX_DATA },
    { "vfnmadd132p%XH", { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfnmadd132s%XH", { XMScalar, VexScalar, EXw, EXxEVexR }, PREFIX_DATA },
    { "vfnmsub132p%XH", { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfnmsub132s%XH", { XMScalar, VexScalar, EXw, EXxEVexR }, PREFIX_DATA },
    /* A0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vfmaddsub213p%XH",  { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfmsubadd213p%XH",  { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    /* A8 */
    { "vfmadd213p%XH",  { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfmadd213s%XH",  { XMScalar, VexScalar, EXw, EXxEVexR }, PREFIX_DATA },
    { "vfmsub213p%XH",  { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfmsub213s%XH",  { XMScalar, VexScalar, EXw, EXxEVexR }, PREFIX_DATA },
    { "vfnmadd213p%XH", { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfnmadd213s%XH", { XMScalar, VexScalar, EXw, EXxEVexR }, PREFIX_DATA },
    { "vfnmsub213p%XH", { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfnmsub213s%XH", { XMScalar, VexScalar, EXw, EXxEVexR }, PREFIX_DATA },
    /* B0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { "vfmaddsub231p%XH",  { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfmsubadd231p%XH",  { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    /* B8 */
    { "vfmadd231p%XH",  { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfmadd231s%XH",  { XMScalar, VexScalar, EXw, EXxEVexR }, PREFIX_DATA },
    { "vfmsub231p%XH",  { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfmsub231s%XH",  { XMScalar, VexScalar, EXw, EXxEVexR }, PREFIX_DATA },
    { "vfnmadd231p%XH", { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfnmadd231s%XH", { XMScalar, VexScalar, EXw, EXxEVexR }, PREFIX_DATA },
    { "vfnmsub231p%XH", { XM, Vex, EXxh, EXxEVexR }, PREFIX_DATA },
    { "vfnmsub231s%XH", { XMScalar, VexScalar, EXw, EXxEVexR }, PREFIX_DATA },
    /* C0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* C8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* D0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { PREFIX_TABLE (PREFIX_EVEX_MAP6_D6) },
    { PREFIX_TABLE (PREFIX_EVEX_MAP6_D7) },
    /* D8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* E0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* E8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* F0 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    /* F8 */
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
    { Bad_Opcode },
  },
};
