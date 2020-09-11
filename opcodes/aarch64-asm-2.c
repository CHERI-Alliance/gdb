/* This file is automatically generated by aarch64-gen.  Do not edit!  */
/* Copyright (C) 2012-2023 Free Software Foundation, Inc.
   Contributed by ARM Ltd.

   This file is part of the GNU opcodes library.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING3. If not,
   see <http://www.gnu.org/licenses/>.  */

#include "sysdep.h"
#include "aarch64-asm.h"


const aarch64_opcode *
aarch64_find_real_opcode (const aarch64_opcode *opcode)
{
  /* Use the index as the key to locate the real opcode.  */
  int key = opcode - aarch64_opcode_table;
  int value;
  switch (key)
    {
    case 3:	/* ngc */
    case 2:	/* sbc */
      value = 2;	/* --> sbc.  */
      break;
    case 5:	/* ngcs */
    case 4:	/* sbcs */
      value = 4;	/* --> sbcs.  */
      break;
    case 8:	/* cmn */
    case 7:	/* adds */
      value = 7;	/* --> adds.  */
      break;
    case 11:	/* cmp */
    case 10:	/* subs */
      value = 10;	/* --> subs.  */
      break;
    case 13:	/* mov */
    case 12:	/* add */
      value = 12;	/* --> add.  */
      break;
    case 15:	/* cmn */
    case 14:	/* adds */
      value = 14;	/* --> adds.  */
      break;
    case 18:	/* cmp */
    case 17:	/* subs */
      value = 17;	/* --> subs.  */
      break;
    case 23:	/* cmn */
    case 22:	/* adds */
      value = 22;	/* --> adds.  */
      break;
    case 25:	/* neg */
    case 24:	/* sub */
      value = 24;	/* --> sub.  */
      break;
    case 27:	/* cmp */
    case 28:	/* negs */
    case 26:	/* subs */
      value = 26;	/* --> subs.  */
      break;
    case 153:	/* mov */
    case 152:	/* umov */
      value = 152;	/* --> umov.  */
      break;
    case 155:	/* mov */
    case 154:	/* ins */
      value = 154;	/* --> ins.  */
      break;
    case 157:	/* mov */
    case 156:	/* ins */
      value = 156;	/* --> ins.  */
      break;
    case 243:	/* mvn */
    case 242:	/* not */
      value = 242;	/* --> not.  */
      break;
    case 318:	/* mov */
    case 317:	/* orr */
      value = 317;	/* --> orr.  */
      break;
    case 389:	/* sxtl */
    case 388:	/* sshll */
      value = 388;	/* --> sshll.  */
      break;
    case 391:	/* sxtl2 */
    case 390:	/* sshll2 */
      value = 390;	/* --> sshll2.  */
      break;
    case 413:	/* uxtl */
    case 412:	/* ushll */
      value = 412;	/* --> ushll.  */
      break;
    case 415:	/* uxtl2 */
    case 414:	/* ushll2 */
      value = 414;	/* --> ushll2.  */
      break;
    case 536:	/* mov */
    case 535:	/* dup */
      value = 535;	/* --> dup.  */
      break;
    case 623:	/* sxtw */
    case 622:	/* sxth */
    case 621:	/* sxtb */
    case 624:	/* asr */
    case 620:	/* sbfx */
    case 619:	/* sbfiz */
    case 618:	/* sbfm */
      value = 618;	/* --> sbfm.  */
      break;
    case 627:	/* bfc */
    case 628:	/* bfxil */
    case 626:	/* bfi */
    case 625:	/* bfm */
      value = 625;	/* --> bfm.  */
      break;
    case 633:	/* uxth */
    case 632:	/* uxtb */
    case 635:	/* lsr */
    case 634:	/* lsl */
    case 631:	/* ubfx */
    case 630:	/* ubfiz */
    case 629:	/* ubfm */
      value = 629;	/* --> ubfm.  */
      break;
    case 665:	/* cset */
    case 664:	/* cinc */
    case 663:	/* csinc */
      value = 663;	/* --> csinc.  */
      break;
    case 668:	/* csetm */
    case 667:	/* cinv */
    case 666:	/* csinv */
      value = 666;	/* --> csinv.  */
      break;
    case 670:	/* cneg */
    case 669:	/* csneg */
      value = 669;	/* --> csneg.  */
      break;
    case 688:	/* rev */
    case 689:	/* rev64 */
      value = 688;	/* --> rev.  */
      break;
    case 714:	/* lsl */
    case 713:	/* lslv */
      value = 713;	/* --> lslv.  */
      break;
    case 716:	/* lsr */
    case 715:	/* lsrv */
      value = 715;	/* --> lsrv.  */
      break;
    case 718:	/* asr */
    case 717:	/* asrv */
      value = 717;	/* --> asrv.  */
      break;
    case 720:	/* ror */
    case 719:	/* rorv */
      value = 719;	/* --> rorv.  */
      break;
    case 723:	/* cmpp */
    case 722:	/* subps */
      value = 722;	/* --> subps.  */
      break;
    case 736:	/* mul */
    case 735:	/* madd */
      value = 735;	/* --> madd.  */
      break;
    case 738:	/* mneg */
    case 737:	/* msub */
      value = 737;	/* --> msub.  */
      break;
    case 740:	/* smull */
    case 739:	/* smaddl */
      value = 739;	/* --> smaddl.  */
      break;
    case 742:	/* smnegl */
    case 741:	/* smsubl */
      value = 741;	/* --> smsubl.  */
      break;
    case 745:	/* umull */
    case 744:	/* umaddl */
      value = 744;	/* --> umaddl.  */
      break;
    case 747:	/* umnegl */
    case 746:	/* umsubl */
      value = 746;	/* --> umsubl.  */
      break;
    case 759:	/* ror */
    case 758:	/* extr */
      value = 758;	/* --> extr.  */
      break;
    case 996:	/* bic */
    case 995:	/* and */
      value = 995;	/* --> and.  */
      break;
    case 998:	/* mov */
    case 997:	/* orr */
      value = 997;	/* --> orr.  */
      break;
    case 1001:	/* tst */
    case 1000:	/* ands */
      value = 1000;	/* --> ands.  */
      break;
    case 1005:	/* mov */
    case 1195:	/* mov */
    case 1006:	/* uxtw */
    case 1004:	/* orr */
      value = 1004;	/* --> orr.  */
      break;
    case 1008:	/* mvn */
    case 1007:	/* orn */
      value = 1007;	/* --> orn.  */
      break;
    case 1012:	/* tst */
    case 1011:	/* ands */
      value = 1011;	/* --> ands.  */
      break;
    case 1138:	/* staddb */
    case 1042:	/* ldaddb */
      value = 1042;	/* --> ldaddb.  */
      break;
    case 1139:	/* staddh */
    case 1043:	/* ldaddh */
      value = 1043;	/* --> ldaddh.  */
      break;
    case 1140:	/* stadd */
    case 1044:	/* ldadd */
      value = 1044;	/* --> ldadd.  */
      break;
    case 1141:	/* staddlb */
    case 1046:	/* ldaddlb */
      value = 1046;	/* --> ldaddlb.  */
      break;
    case 1142:	/* staddlh */
    case 1049:	/* ldaddlh */
      value = 1049;	/* --> ldaddlh.  */
      break;
    case 1143:	/* staddl */
    case 1052:	/* ldaddl */
      value = 1052;	/* --> ldaddl.  */
      break;
    case 1144:	/* stclrb */
    case 1054:	/* ldclrb */
      value = 1054;	/* --> ldclrb.  */
      break;
    case 1145:	/* stclrh */
    case 1055:	/* ldclrh */
      value = 1055;	/* --> ldclrh.  */
      break;
    case 1146:	/* stclr */
    case 1056:	/* ldclr */
      value = 1056;	/* --> ldclr.  */
      break;
    case 1147:	/* stclrlb */
    case 1058:	/* ldclrlb */
      value = 1058;	/* --> ldclrlb.  */
      break;
    case 1148:	/* stclrlh */
    case 1061:	/* ldclrlh */
      value = 1061;	/* --> ldclrlh.  */
      break;
    case 1149:	/* stclrl */
    case 1064:	/* ldclrl */
      value = 1064;	/* --> ldclrl.  */
      break;
    case 1150:	/* steorb */
    case 1066:	/* ldeorb */
      value = 1066;	/* --> ldeorb.  */
      break;
    case 1151:	/* steorh */
    case 1067:	/* ldeorh */
      value = 1067;	/* --> ldeorh.  */
      break;
    case 1152:	/* steor */
    case 1068:	/* ldeor */
      value = 1068;	/* --> ldeor.  */
      break;
    case 1153:	/* steorlb */
    case 1070:	/* ldeorlb */
      value = 1070;	/* --> ldeorlb.  */
      break;
    case 1154:	/* steorlh */
    case 1073:	/* ldeorlh */
      value = 1073;	/* --> ldeorlh.  */
      break;
    case 1155:	/* steorl */
    case 1076:	/* ldeorl */
      value = 1076;	/* --> ldeorl.  */
      break;
    case 1156:	/* stsetb */
    case 1078:	/* ldsetb */
      value = 1078;	/* --> ldsetb.  */
      break;
    case 1157:	/* stseth */
    case 1079:	/* ldseth */
      value = 1079;	/* --> ldseth.  */
      break;
    case 1158:	/* stset */
    case 1080:	/* ldset */
      value = 1080;	/* --> ldset.  */
      break;
    case 1159:	/* stsetlb */
    case 1082:	/* ldsetlb */
      value = 1082;	/* --> ldsetlb.  */
      break;
    case 1160:	/* stsetlh */
    case 1085:	/* ldsetlh */
      value = 1085;	/* --> ldsetlh.  */
      break;
    case 1161:	/* stsetl */
    case 1088:	/* ldsetl */
      value = 1088;	/* --> ldsetl.  */
      break;
    case 1162:	/* stsmaxb */
    case 1090:	/* ldsmaxb */
      value = 1090;	/* --> ldsmaxb.  */
      break;
    case 1163:	/* stsmaxh */
    case 1091:	/* ldsmaxh */
      value = 1091;	/* --> ldsmaxh.  */
      break;
    case 1164:	/* stsmax */
    case 1092:	/* ldsmax */
      value = 1092;	/* --> ldsmax.  */
      break;
    case 1165:	/* stsmaxlb */
    case 1094:	/* ldsmaxlb */
      value = 1094;	/* --> ldsmaxlb.  */
      break;
    case 1166:	/* stsmaxlh */
    case 1097:	/* ldsmaxlh */
      value = 1097;	/* --> ldsmaxlh.  */
      break;
    case 1167:	/* stsmaxl */
    case 1100:	/* ldsmaxl */
      value = 1100;	/* --> ldsmaxl.  */
      break;
    case 1168:	/* stsminb */
    case 1102:	/* ldsminb */
      value = 1102;	/* --> ldsminb.  */
      break;
    case 1169:	/* stsminh */
    case 1103:	/* ldsminh */
      value = 1103;	/* --> ldsminh.  */
      break;
    case 1170:	/* stsmin */
    case 1104:	/* ldsmin */
      value = 1104;	/* --> ldsmin.  */
      break;
    case 1171:	/* stsminlb */
    case 1106:	/* ldsminlb */
      value = 1106;	/* --> ldsminlb.  */
      break;
    case 1172:	/* stsminlh */
    case 1109:	/* ldsminlh */
      value = 1109;	/* --> ldsminlh.  */
      break;
    case 1173:	/* stsminl */
    case 1112:	/* ldsminl */
      value = 1112;	/* --> ldsminl.  */
      break;
    case 1174:	/* stumaxb */
    case 1114:	/* ldumaxb */
      value = 1114;	/* --> ldumaxb.  */
      break;
    case 1175:	/* stumaxh */
    case 1115:	/* ldumaxh */
      value = 1115;	/* --> ldumaxh.  */
      break;
    case 1176:	/* stumax */
    case 1116:	/* ldumax */
      value = 1116;	/* --> ldumax.  */
      break;
    case 1177:	/* stumaxlb */
    case 1118:	/* ldumaxlb */
      value = 1118;	/* --> ldumaxlb.  */
      break;
    case 1178:	/* stumaxlh */
    case 1121:	/* ldumaxlh */
      value = 1121;	/* --> ldumaxlh.  */
      break;
    case 1179:	/* stumaxl */
    case 1124:	/* ldumaxl */
      value = 1124;	/* --> ldumaxl.  */
      break;
    case 1180:	/* stuminb */
    case 1126:	/* lduminb */
      value = 1126;	/* --> lduminb.  */
      break;
    case 1181:	/* stuminh */
    case 1127:	/* lduminh */
      value = 1127;	/* --> lduminh.  */
      break;
    case 1182:	/* stumin */
    case 1128:	/* ldumin */
      value = 1128;	/* --> ldumin.  */
      break;
    case 1183:	/* stuminlb */
    case 1130:	/* lduminlb */
      value = 1130;	/* --> lduminlb.  */
      break;
    case 1184:	/* stuminlh */
    case 1133:	/* lduminlh */
      value = 1133;	/* --> lduminlh.  */
      break;
    case 1185:	/* stuminl */
    case 1136:	/* lduminl */
      value = 1136;	/* --> lduminl.  */
      break;
    case 1187:	/* mov */
    case 1186:	/* movn */
      value = 1186;	/* --> movn.  */
      break;
    case 1189:	/* mov */
    case 1188:	/* movz */
      value = 1188;	/* --> movz.  */
      break;
    case 1194:	/* mov */
    case 1193:	/* cpy */
      value = 1193;	/* --> cpy.  */
      break;
    case 1254:	/* autibsp */
    case 1253:	/* autibz */
    case 1252:	/* autiasp */
    case 1251:	/* autiaz */
    case 1250:	/* pacibsp */
    case 1249:	/* pacibz */
    case 1248:	/* paciasp */
    case 1247:	/* paciaz */
    case 1223:	/* clearbhb */
    case 1222:	/* tsb */
    case 1221:	/* psb */
    case 1220:	/* esb */
    case 1219:	/* autib1716 */
    case 1218:	/* autia1716 */
    case 1217:	/* pacib1716 */
    case 1216:	/* pacia1716 */
    case 1215:	/* xpaclri */
    case 1213:	/* sevl */
    case 1212:	/* sev */
    case 1211:	/* wfi */
    case 1210:	/* wfe */
    case 1209:	/* yield */
    case 1208:	/* bti */
    case 1207:	/* csdb */
    case 1206:	/* nop */
    case 1205:	/* hint */
      value = 1205;	/* --> hint.  */
      break;
    case 1229:	/* pssbb */
    case 1228:	/* ssbb */
    case 1227:	/* dfb */
    case 1225:	/* dsb */
      value = 1225;	/* --> dsb.  */
      break;
    case 1226:	/* dsb */
      value = 1226;	/* --> dsb.  */
      break;
    case 1242:	/* cpp */
    case 1241:	/* dvp */
    case 1240:	/* cfp */
    case 1237:	/* tlbi */
    case 1236:	/* ic */
    case 1235:	/* dc */
    case 1234:	/* at */
    case 1233:	/* sys */
      value = 1233;	/* --> sys.  */
      break;
    case 1238:	/* wfet */
      value = 1238;	/* --> wfet.  */
      break;
    case 1239:	/* wfit */
      value = 1239;	/* --> wfit.  */
      break;
    case 2056:	/* bic */
    case 1303:	/* and */
      value = 1303;	/* --> and.  */
      break;
    case 1286:	/* mov */
    case 1305:	/* and */
      value = 1305;	/* --> and.  */
      break;
    case 1290:	/* movs */
    case 1306:	/* ands */
      value = 1306;	/* --> ands.  */
      break;
    case 2057:	/* cmple */
    case 1341:	/* cmpge */
      value = 1341;	/* --> cmpge.  */
      break;
    case 2060:	/* cmplt */
    case 1344:	/* cmpgt */
      value = 1344;	/* --> cmpgt.  */
      break;
    case 2058:	/* cmplo */
    case 1346:	/* cmphi */
      value = 1346;	/* --> cmphi.  */
      break;
    case 2059:	/* cmpls */
    case 1349:	/* cmphs */
      value = 1349;	/* --> cmphs.  */
      break;
    case 1283:	/* mov */
    case 1371:	/* cpy */
      value = 1371;	/* --> cpy.  */
      break;
    case 1285:	/* mov */
    case 1372:	/* cpy */
      value = 1372;	/* --> cpy.  */
      break;
    case 2067:	/* fmov */
    case 1288:	/* mov */
    case 1373:	/* cpy */
      value = 1373;	/* --> cpy.  */
      break;
    case 1277:	/* mov */
    case 1385:	/* dup */
      value = 1385;	/* --> dup.  */
      break;
    case 1280:	/* mov */
    case 1276:	/* mov */
    case 1386:	/* dup */
      value = 1386;	/* --> dup.  */
      break;
    case 2066:	/* fmov */
    case 1282:	/* mov */
    case 1387:	/* dup */
      value = 1387;	/* --> dup.  */
      break;
    case 1281:	/* mov */
    case 1388:	/* dupm */
      value = 1388;	/* --> dupm.  */
      break;
    case 2061:	/* eon */
    case 1390:	/* eor */
      value = 1390;	/* --> eor.  */
      break;
    case 1291:	/* not */
    case 1392:	/* eor */
      value = 1392;	/* --> eor.  */
      break;
    case 1292:	/* nots */
    case 1393:	/* eors */
      value = 1393;	/* --> eors.  */
      break;
    case 2062:	/* facle */
    case 1398:	/* facge */
      value = 1398;	/* --> facge.  */
      break;
    case 2063:	/* faclt */
    case 1399:	/* facgt */
      value = 1399;	/* --> facgt.  */
      break;
    case 2064:	/* fcmle */
    case 1412:	/* fcmge */
      value = 1412;	/* --> fcmge.  */
      break;
    case 2065:	/* fcmlt */
    case 1414:	/* fcmgt */
      value = 1414;	/* --> fcmgt.  */
      break;
    case 1274:	/* fmov */
    case 1420:	/* fcpy */
      value = 1420;	/* --> fcpy.  */
      break;
    case 1273:	/* fmov */
    case 1443:	/* fdup */
      value = 1443;	/* --> fdup.  */
      break;
    case 1275:	/* mov */
    case 1775:	/* orr */
      value = 1775;	/* --> orr.  */
      break;
    case 2068:	/* orn */
    case 1776:	/* orr */
      value = 1776;	/* --> orr.  */
      break;
    case 1279:	/* mov */
    case 1278:	/* mov */
    case 1778:	/* orr */
      value = 1778;	/* --> orr.  */
      break;
    case 1289:	/* movs */
    case 1779:	/* orrs */
      value = 1779;	/* --> orrs.  */
      break;
    case 1284:	/* mov */
    case 1842:	/* sel */
      value = 1842;	/* --> sel.  */
      break;
    case 1287:	/* mov */
    case 1843:	/* sel */
      value = 1843;	/* --> sel.  */
      break;
    default: return NULL;
    }

  return aarch64_opcode_table + value;
}

bool
aarch64_insert_operand (const aarch64_operand *self,
			   const aarch64_opnd_info *info,
			   aarch64_insn *code, const aarch64_inst *inst,
			   aarch64_operand_error *errors)
{
  /* Use the index as the key.  */
  int key = self - aarch64_operands;
  switch (key)
    {
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 17:
    case 18:
    case 19:
    case 20:
    case 22:
    case 23:
    case 24:
    case 25:
    case 26:
    case 27:
    case 28:
    case 29:
    case 30:
    case 31:
    case 168:
    case 169:
    case 170:
    case 171:
    case 172:
    case 173:
    case 174:
    case 175:
    case 176:
    case 177:
    case 178:
    case 179:
    case 180:
    case 181:
    case 196:
    case 197:
    case 198:
    case 199:
    case 200:
    case 201:
    case 202:
    case 203:
    case 204:
    case 211:
    case 214:
    case 218:
    case 225:
    case 226:
    case 233:
    case 234:
    case 235:
    case 236:
    case 278:
    case 279:
    case 280:
    case 281:
    case 282:
    case 283:
    case 284:
    case 285:
      return aarch64_ins_regno (self, info, code, inst, errors);
    case 15:
      return aarch64_ins_reg_extended (self, info, code, inst, errors);
    case 16:
      return aarch64_ins_reg_shifted (self, info, code, inst, errors);
    case 21:
      return aarch64_ins_ft (self, info, code, inst, errors);
    case 32:
    case 33:
    case 34:
    case 35:
    case 272:
      return aarch64_ins_reglane (self, info, code, inst, errors);
    case 36:
      return aarch64_ins_reglist (self, info, code, inst, errors);
    case 37:
      return aarch64_ins_ldst_reglist (self, info, code, inst, errors);
    case 38:
      return aarch64_ins_ldst_reglist_r (self, info, code, inst, errors);
    case 39:
      return aarch64_ins_ldst_elemlist (self, info, code, inst, errors);
    case 40:
    case 41:
    case 42:
    case 43:
    case 53:
    case 54:
    case 55:
    case 56:
    case 57:
    case 58:
    case 59:
    case 60:
    case 61:
    case 62:
    case 63:
    case 64:
    case 65:
    case 66:
    case 67:
    case 68:
    case 69:
    case 81:
    case 82:
    case 83:
    case 84:
    case 108:
    case 165:
    case 167:
    case 188:
    case 189:
    case 190:
    case 191:
    case 192:
    case 193:
    case 194:
    case 195:
    case 239:
    case 266:
    case 267:
    case 269:
    case 271:
    case 276:
    case 277:
      return aarch64_ins_imm (self, info, code, inst, errors);
    case 44:
    case 45:
      return aarch64_ins_advsimd_imm_shift (self, info, code, inst, errors);
    case 46:
    case 47:
    case 48:
      return aarch64_ins_advsimd_imm_modified (self, info, code, inst, errors);
    case 52:
    case 155:
      return aarch64_ins_fpimm (self, info, code, inst, errors);
    case 70:
    case 163:
      return aarch64_ins_limm (self, info, code, inst, errors);
    case 71:
      return aarch64_ins_aimm (self, info, code, inst, errors);
    case 72:
      return aarch64_ins_imm_half (self, info, code, inst, errors);
    case 73:
      return aarch64_ins_fbits (self, info, code, inst, errors);
    case 75:
    case 76:
    case 160:
      return aarch64_ins_imm_rotate2 (self, info, code, inst, errors);
    case 77:
    case 159:
    case 161:
      return aarch64_ins_imm_rotate1 (self, info, code, inst, errors);
    case 78:
    case 79:
      return aarch64_ins_cond (self, info, code, inst, errors);
    case 85:
    case 94:
      return aarch64_ins_addr_simple (self, info, code, inst, errors);
    case 86:
      return aarch64_ins_addr_regoff (self, info, code, inst, errors);
    case 87:
    case 88:
    case 89:
    case 91:
    case 93:
      return aarch64_ins_addr_simm (self, info, code, inst, errors);
    case 90:
      return aarch64_ins_addr_simm10 (self, info, code, inst, errors);
    case 92:
      return aarch64_ins_addr_uimm12 (self, info, code, inst, errors);
    case 95:
      return aarch64_ins_addr_offset (self, info, code, inst, errors);
    case 96:
      return aarch64_ins_simd_addr_post (self, info, code, inst, errors);
    case 97:
      return aarch64_ins_sysreg (self, info, code, inst, errors);
    case 98:
      return aarch64_ins_pstatefield (self, info, code, inst, errors);
    case 99:
    case 100:
    case 101:
    case 102:
    case 103:
      return aarch64_ins_sysins_op (self, info, code, inst, errors);
    case 104:
    case 106:
      return aarch64_ins_barrier (self, info, code, inst, errors);
    case 105:
      return aarch64_ins_barrier_dsb_nxs (self, info, code, inst, errors);
    case 107:
      return aarch64_ins_prfop (self, info, code, inst, errors);
    case 109:
    case 268:
    case 270:
      return aarch64_ins_none (self, info, code, inst, errors);
    case 110:
      return aarch64_ins_hint (self, info, code, inst, errors);
    case 111:
    case 112:
      return aarch64_ins_sve_addr_ri_s4 (self, info, code, inst, errors);
    case 113:
    case 114:
    case 115:
    case 116:
      return aarch64_ins_sve_addr_ri_s4xvl (self, info, code, inst, errors);
    case 117:
      return aarch64_ins_sve_addr_ri_s6xvl (self, info, code, inst, errors);
    case 118:
      return aarch64_ins_sve_addr_ri_s9xvl (self, info, code, inst, errors);
    case 119:
    case 120:
    case 121:
    case 122:
      return aarch64_ins_sve_addr_ri_u6 (self, info, code, inst, errors);
    case 123:
    case 124:
    case 125:
    case 126:
    case 127:
    case 128:
    case 129:
    case 130:
    case 131:
    case 132:
    case 133:
    case 134:
    case 135:
    case 136:
    case 137:
      return aarch64_ins_sve_addr_rr_lsl (self, info, code, inst, errors);
    case 138:
    case 139:
    case 140:
    case 141:
    case 142:
    case 143:
    case 144:
    case 145:
      return aarch64_ins_sve_addr_rz_xtw (self, info, code, inst, errors);
    case 146:
    case 147:
    case 148:
    case 149:
      return aarch64_ins_sve_addr_zi_u5 (self, info, code, inst, errors);
    case 150:
      return aarch64_ins_sve_addr_zz_lsl (self, info, code, inst, errors);
    case 151:
      return aarch64_ins_sve_addr_zz_sxtw (self, info, code, inst, errors);
    case 152:
      return aarch64_ins_sve_addr_zz_uxtw (self, info, code, inst, errors);
    case 153:
      return aarch64_ins_sve_aimm (self, info, code, inst, errors);
    case 154:
      return aarch64_ins_sve_asimm (self, info, code, inst, errors);
    case 156:
      return aarch64_ins_sve_float_half_one (self, info, code, inst, errors);
    case 157:
      return aarch64_ins_sve_float_half_two (self, info, code, inst, errors);
    case 158:
      return aarch64_ins_sve_float_zero_one (self, info, code, inst, errors);
    case 162:
      return aarch64_ins_inv_limm (self, info, code, inst, errors);
    case 164:
      return aarch64_ins_sve_limm_mov (self, info, code, inst, errors);
    case 166:
      return aarch64_ins_sve_scale (self, info, code, inst, errors);
    case 182:
    case 183:
    case 184:
      return aarch64_ins_sve_shlimm (self, info, code, inst, errors);
    case 185:
    case 186:
    case 187:
    case 252:
      return aarch64_ins_sve_shrimm (self, info, code, inst, errors);
    case 205:
    case 206:
    case 207:
    case 208:
    case 209:
    case 210:
      return aarch64_ins_sve_quad_index (self, info, code, inst, errors);
    case 212:
      return aarch64_ins_sve_index (self, info, code, inst, errors);
    case 213:
    case 215:
    case 232:
      return aarch64_ins_sve_reglist (self, info, code, inst, errors);
    case 216:
    case 217:
    case 219:
    case 220:
    case 221:
    case 222:
    case 231:
      return aarch64_ins_sve_aligned_reglist (self, info, code, inst, errors);
    case 223:
    case 224:
      return aarch64_ins_sve_strided_reglist (self, info, code, inst, errors);
    case 227:
    case 229:
    case 240:
      return aarch64_ins_sme_za_hv_tiles (self, info, code, inst, errors);
    case 228:
    case 230:
      return aarch64_ins_sme_za_hv_tiles_range (self, info, code, inst, errors);
    case 237:
    case 238:
    case 253:
    case 254:
    case 255:
    case 256:
    case 257:
    case 258:
    case 259:
    case 260:
    case 261:
    case 262:
    case 263:
    case 264:
    case 265:
      return aarch64_ins_simple_index (self, info, code, inst, errors);
    case 241:
    case 242:
    case 243:
    case 244:
    case 245:
    case 246:
    case 247:
      return aarch64_ins_sme_za_array (self, info, code, inst, errors);
    case 248:
      return aarch64_ins_sme_addr_ri_u4xvl (self, info, code, inst, errors);
    case 249:
      return aarch64_ins_sme_sm_za (self, info, code, inst, errors);
    case 250:
      return aarch64_ins_sme_pred_reg_with_index (self, info, code, inst, errors);
    case 251:
      return aarch64_ins_plain_shrimm (self, info, code, inst, errors);
    case 273:
    case 274:
    case 275:
      return aarch64_ins_x0_to_x30 (self, info, code, inst, errors);
    default: assert (0); abort ();
    }
}
