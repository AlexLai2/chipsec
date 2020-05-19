#!/usr/bin/python
#
# *********************************************************
#
#                   PRE-RELEASE NOTICE
#
#    This software specifically enables pre-production
#    hardware provided by Intel Corporation.  The terms
#    describing your rights and responsibilities to use
#    such hardware are covered by a separate evaluation
#    agreement.  Of specific note in that agreement is
#    the requirement that you do not release or publish
#    information on the hardware without the specific
#    written authorization of Intel Corporation.
#
#    Intel Corporation requests that you do not release,
#    publish, or distribute this software until you are
#    specifically authorized.  These terms are deleted
#    upon publication of this software.
#
# *********************************************************
#
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2019-2020, Intel Corporation
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com

from chipsec.module_common import BaseModule
from chipsec.module_common import ModuleResult
from chipsec.module_common import MTAG_HWCONFIG
from chipsec.chipset import CHIPSET_CODE_ICL, CHIPSET_CODE_SKL, CHIPSET_CODE_CNL, CHIPSET_CODE_KBL
from chipsec.chipset import CHIPSET_CODE_CML, CHIPSET_CODE_WHL, CHIPSET_CODE_APL, CHIPSET_CODE_GLK
from chipsec.chipset import CHIPSET_CODE_CFL, CHIPSET_CODE_AML
from chipsec.hal.pci import PCI_HDR_VID_OFF, PCI_HDR_DID_OFF, PCI_HDR_RID_OFF

TAGS = [MTAG_HWCONFIG]

MAX_IMR_REG_NUMBER = 11

class igd_mem_map(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.platforms = []
        self.new_platforms = [CHIPSET_CODE_ICL]
        self.core_gen9_platforms = [CHIPSET_CODE_SKL, CHIPSET_CODE_KBL, CHIPSET_CODE_AML, CHIPSET_CODE_CML, CHIPSET_CODE_CFL, CHIPSET_CODE_WHL]
        self.atom_gen9_platforms = [CHIPSET_CODE_GLK]
        self.platforms.extend(self.new_platforms)
        self.platforms.extend(self.core_gen9_platforms)
        self.platforms.extend(self.atom_gen9_platforms)
        self.base_above_imr = None
        self.gms_size = {
            0x00: 0,
            0x01: 32,
            0x02: 64,
            0x03: 96,
            0x04: 128,
            0x05: 160,
            0x06: 192,
            0x07: 224,
            0x08: 256,
            0x09: 288,
            0x0A: 320,
            0x0B: 352,
            0x0C: 384,
            0x0D: 416,
            0x0E: 448,
            0x0F: 480,
            0x10: 512,
            0x20: 1024,
            0x30: 1536,
            0x40: 2048,
            0xF0: 4,
            0xF1: 8,
            0xF2: 12,
            0xF3: 16,
            0xF4: 20,
            0xF5: 24,
            0xF6: 28,
            0xF7: 32,
            0xF8: 36,
            0xF9: 40,
            0xFA: 44,
            0xFB: 48,
            0xFC: 52,
            0xFD: 56,
            0xFE: 60
            }
        self.ggms_size = {
            0x00: 0,
            0x01: 2,
            0x02: 4,
            0x03: 8
        }
        self.pavpc_size = {
            0x00: 1,
            0x01: 2,
            0x02: 4,
            0x03: 8
        }

    def _get_bdsm(self):
        bdsm_size = None
        bdsm_base = self.cs.read_register_field('PCI0.0.0_BDSM', 'BDSM', True)
        gms = self.cs.read_register_field('PCI0.0.0_GGC', 'GMS')
        try:
            bdsm_size = self.gms_size[gms] << 20
        except:
            self.logger.log_bad("Invalid GMS Value: 0x{:02X}".format(gms))
        return (bdsm_base, bdsm_size)

    def _get_bgsm(self):
        bgsm_size = None
        bgsm_base = self.cs.read_register_field('PCI0.0.0_BGSM', 'BGSM', True)
        ggms = self.cs.read_register_field('PCI0.0.0_GGC', 'GGMS')
        try:
            bgsm_size = self.ggms_size[ggms] << 20
        except:
            self.logger.log_bad("Invalid GGMS Value: 0x{:02X}".format(ggms))
        return (bgsm_base, bgsm_size)

    def _get_tolud(self):
        return self.cs.read_register_field('PCI0.0.0_TOLUD', 'TOLUD', True)

    def _get_imr_info(self):
        imr_base = None
        imr_top = None
        imr_size = None
        for reg_num in range(MAX_IMR_REG_NUMBER):
            reg_name = "IMR_MASK_{}".format(reg_num)
            if not self.cs.is_register_defined(reg_name):
                continue
            mch_reg_val = self.cs.read_register(reg_name)
            if self.cs.get_register_field(reg_name, mch_reg_val, "EN") == 1:
                # NOTE: Range base and mask do not have bits 10:0 stored so they need to be shifted
                range_mask = self.cs.get_register_field(reg_name, mch_reg_val, "MASK", True)
                range_size = self._find_size_from_mask(range_mask) << 10
                range_base = self.cs.read_register_field("IMR_BASE_{}".format(reg_num), "BASE", True) << 10
                range_top = range_base + range_size
                if self.logger.VERBOSE: self.logger.log_information("IMR {}: 0x{:08X} - 0x{:08X}".format(reg_num, range_base, range_top))
                if imr_base is None or range_base < imr_base:
                    imr_base = range_base
                if imr_top is None or range_top > imr_top:
                    imr_top = range_top
        if self.logger.VERBOSE: self.logger.log("[*]")
        if imr_base is not None and imr_top is not None and imr_top > imr_base:
            imr_size = imr_top - imr_base
        return (imr_base, imr_size)

    def _get_tseg(self):
        (tseg_base, _, tseg_size) = self.cs.cpu.get_TSEG()
        return (tseg_base, tseg_size)

    def _check_overlap(self, base_1, size_1, base_2, size_2):
        overlap = False
        top_1 = base_1 + size_1
        top_2 = base_2 + size_2

        if base_1 == base_2:
            overlap = True
        elif top_1 == top_2:
            overlap = True
        elif base_1 > base_2 and base_1 < top_2:
            overlap = True
        elif top_1 > base_2 and top_1 < top_2:
            overlap = True
        elif base_2 > base_1 and base_2 < top_1:
            overlap = True
        elif top_2 > base_1 and top_2 < top_1:
            overlap = True

        return overlap

    def _buffer_1_in_2(self, base_1, size_1, base_2, size_2):
        top_1 = base_1 + size_1
        top_2 = base_2 + size_2

        if base_1 >= base_2 and top_1 <= top_2:
            return True
        return False

    def _find_size_from_mask(self, mask_val):
        bit_num = 63
        while bit_num >= 0:
            if (mask_val & (1 << bit_num)) != 0:
                return ((~mask_val) & ((1 << (bit_num + 1)) - 1)) + 1
            bit_num -= 1
        return 0

    def is_supported(self):
        if self.cs.get_chipset_code() in self.platforms:
            if self.cs.is_device_enabled('IGD'):
                return True
            else:
                self.logger.log('[*] IGD is disabled')
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_igfx_layout(self):
        self.logger.log("[*] ========================================================================")
        self.logger.log("[*] Checking for memory overlaps")
        self.logger.log("[*]")
        # =======================================================
        # MDRB_CTXBASE and RC6CTXBASE
        # - Must not overlap with each other
        # - Must be in the BDSM region
        #   - BDSM size defined in GGC
        # - PAVP/WOPCM should be near the top of BDSM
        # - MDRB_CTXBASE => 64B based on BAR granularity
        # - RC6CTXBASE => 4KB based on BAR granularity
        # =======================================================
        res = ModuleResult.PASSED

        # Get PAVPC information
        reg_val = self.cs.read_register('PCI0.0.0_PAVPC')
        pavpc_base = self.cs.get_register_field('PCI0.0.0_PAVPC', reg_val, 'PCMBASE', True)
        pavpc_size = self.pavpc_size[self.cs.get_register_field('PCI0.0.0_PAVPC', reg_val, 'WOPCM')] << 20
        pavpc_enable = self.cs.get_register_field('PCI0.0.0_PAVPC', reg_val, 'PCME')
        pavpc_lock = self.cs.get_register_field('PCI0.0.0_PAVPC', reg_val, 'PAVPLCK')
        if pavpc_lock == 1:
            self.logger.log_good("PAVPC settings locked")
        else:
            self.logger.log_bad("PAVPC settings not locked")
            res = ModuleResult.FAILED
        if pavpc_enable == 0:
            self.logger.log_bad("PAVPC disabled")
            return ModuleResult.FAILED

        # Get MDRB_CTX and RC6CTX base addresses
        rc6_ctx_base = None
        rc6_ctx_size = None
        mdrb_ctx_base = None
        mdrb_ctx_size = None
        if self.cs.is_register_defined('IGD_RC6CTXBASE') and self.cs.is_register_defined('IGD_MDRB_CTXBASE'):
            rc6_ctx_base = self.cs.read_register_field('IGD_RC6CTXBASE', 'BASE', True)
            mdrb_ctx_base = self.cs.read_register_field('IGD_MDRB_CTXBASE', 'BASE', True)
            ctx_lock = self.cs.read_register_field('IGD_RC6CTXBASE', 'LOCK')
            ctx_enable = self.cs.read_register_field('IGD_MDRB_CTXBASE', 'ENABLE')
            if ctx_lock == 1:
                self.logger.log_good("RC6_CTX and MDRB_CTX registers locked")
            else:
                self.logger.log_bad("RC6_CTX and MDRB_CTX registers not locked")
                res = ModuleResult.FAILED
            if ctx_enable == 0:
                self.logger.log_bad("RC6_CTX and MDRB_CTX disabled")
                return ModuleResult.FAILED

            # Values of these registers are hardware dependent
            # RC6 size is 32k for ICL+
            # RC6 size is 24k for Gen9 small core
            # MDRB size is 4k for Gen9 small core and ICL+
            if self.cs.get_chipset_code() in self.atom_gen9_platforms:
                rc6_ctx_size = 0x6000
            else:
                rc6_ctx_size = 0x8000
            mdrb_ctx_size = 0x1000

        # Get BDSM base and size
        (bdsm_base, bdsm_size) = self._get_bdsm()
        if bdsm_size is None:
            self.logger.log_bad("Unable to determine BDSM size")
            return ModuleResult.FAILED

        # Display region data
        self.logger.log("[*]")
        self.logger.log("[*] TOLUD:      0x{:08X}".format(self._get_tolud()))
        self.logger.log("[*] BDSM:       0x{:08X} - 0x{:08X}".format(bdsm_base, bdsm_base + bdsm_size))
        self.logger.log("[*] PAVPC:      0x{:08X} - 0x{:08X}".format(pavpc_base, pavpc_base + pavpc_size))
        if mdrb_ctx_base is not None:
            self.logger.log("[*]   MDRB_CTX: 0x{:08X} - 0x{:08X}".format(mdrb_ctx_base, mdrb_ctx_base + mdrb_ctx_size))
        if rc6_ctx_base is not None:
            self.logger.log("[*]   RC6_CTX:  0x{:08X} - 0x{:08X}".format(rc6_ctx_base, rc6_ctx_base + rc6_ctx_size))
        self.logger.log("[*]")

        # Check that PAVPC region is subregion of BDSM
        # Must check that PAVP is mapped to very top of DSM (PAVP top == DSM top)
        if pavpc_base + pavpc_size != bdsm_base + bdsm_size:
            self.logger.log_bad("PAVPC region not mapped to top of BDSM")
            res = ModuleResult.FAILED
        else:
            self.logger.log_good("PAVPC region mapped to top of BDSM")
        if pavpc_base < bdsm_base or pavpc_base + pavpc_size > bdsm_base + bdsm_size:
            self.logger.log_bad("PAVPC region is outsize BDSM")
            res = ModuleResult.FAILED
        else:
            self.logger.log_good("PAVPC region is inside BDSM")

        if rc6_ctx_base is not None and mdrb_ctx_base is not None:
            # Verify that MDRB and RC6 don't overlap
            if self._check_overlap(rc6_ctx_base, rc6_ctx_size, mdrb_ctx_base, mdrb_ctx_size):
                self.logger.log_bad("RC6_CTX and MDRB_CTX overlap found")
                res = ModuleResult.FAILED
            else:
                self.logger.log_good("No RC6_CTX and MDRB_CTX overlap found")

            # Verify that MDRB and RC6 are in PAVP
            if pavpc_base + pavpc_size - mdrb_ctx_size == mdrb_ctx_base and pavpc_base + pavpc_size - mdrb_ctx_size - rc6_ctx_size == rc6_ctx_base:
                self.logger.log_good("MDRB_CTX and RC6_CTX contiguous in PAVP region")
            else:
                self.logger.log_bad("MDRB_CTX and RC6_CTX are not contiguous in PAVP region")
                res = ModuleResult.FAILED
            if self._buffer_1_in_2(rc6_ctx_base, rc6_ctx_size, pavpc_base, pavpc_size):
                self.logger.log_good("RC6_CTX in PAVPC Range")
            else:
                self.logger.log_bad("RC6_CTX not in PAVPC Range")
                res = ModuleResult.FAILED
            if self._buffer_1_in_2(mdrb_ctx_base, mdrb_ctx_size, pavpc_base, pavpc_size):
                self.logger.log_good("MDRB_CTX in PAVPC Range")
            else:
                self.logger.log_bad("MDRB_CTX not in PAVPC Range")
                res = ModuleResult.FAILED

        self.logger.log("[*]")
        return res

    def check_memory_layout(self):
        self.logger.log("[*] ========================================================================")
        self.logger.log("[*] Checking memory map")
        self.logger.log("[*]")

        res = ModuleResult.PASSED
        range_list = []

        # Read IMR range information
        (imr_base, imr_size) = self._get_imr_info()
        if imr_base is not None:
            range_list.append((imr_base, imr_size, 'IMR'))

        # Get PRMR information if enabled
        prmr_base = None
        mch_reg_val = self.cs.read_register("PRMRR_PHYBASE")
        prmrr_configured = False
        if self.cs.register_has_field("PRMRR_PHYBASE", "PRMRR_CONFIGURED"):
            if self.cs.get_register_field("PRMRR_PHYBASE", mch_reg_val, "PRMRR_CONFIGURED") == 1:
                prmrr_configured = True
        else:
            prmrr_configured = True
        if prmrr_configured and self.cs.read_register_field("PRMRR_MASK", "PRMRR_VLD") == 1:
            prmr_base = self.cs.get_register_field("PRMRR_PHYBASE", mch_reg_val, "PRMRR_base_address_fields", True)
            prmr_mask = self.cs.read_register_field("PRMRR_MASK", "PRMRR_mask_bits", True)
            prmr_size = self._find_size_from_mask(prmr_mask)
            range_list.append((prmr_base, prmr_size, 'PRMRR'))
            if self.base_above_imr is None:
                self.base_above_imr = prmr_base

        # Get DPR information
        dpr_base = None
        mch_reg_val = self.cs.read_register("PCI0.0.0_DPR")
        if self.cs.get_register_field("PCI0.0.0_DPR", mch_reg_val, "EPM") == 1:
            dpr_size = self.cs.get_register_field("PCI0.0.0_DPR", mch_reg_val, "DPRSIZE") << 20
            dpr_base = self.cs.get_register_field("PCI0.0.0_DPR", mch_reg_val, "TOPOFDPR", True) - dpr_size
            range_list.append((dpr_base, dpr_size, 'DPR'))
            if self.base_above_imr is None:
                self.base_above_imr = dpr_base

        # Should not assume we have TSEG
        (tseg_base, tseg_size) = self._get_tseg()
        range_list.append((tseg_base, tseg_size, 'TSEG'))
        if self.base_above_imr is None:
            self.base_above_imr = tseg_base

        # Get BDSM and BGSM ranges
        (bgsm_base, bgsm_size) = self._get_bgsm()
        if bgsm_size is not None:
            range_list.append((bgsm_base, bgsm_size, 'BGSM'))
        (bdsm_base, bdsm_size) = self._get_bdsm()
        if bdsm_size is not None:
            range_list.append((bdsm_base, bdsm_size, 'BDSM'))

        # Get the TOLUD address
        tolud = self._get_tolud()
        if tolud is not None:
            range_list.append((tolud, 0, 'TOULD'))

        # Display ranges for manual verification
        self.logger.log("[*] Memory Range Values")
        self.logger.log("[*]   TOLUD: 0x{:08X}".format(tolud))
        if bdsm_size is not None:
            self.logger.log("[*]   BDSM:  0x{:08X} - 0x{:08X}".format(bdsm_base, bdsm_base + bdsm_size))
        if bgsm_size is not None:
            self.logger.log("[*]   BGSM:  0x{:08X} - 0x{:08X}".format(bgsm_base, bgsm_base + bgsm_size))
        if tseg_base is not None:
            self.logger.log("[*]   TSEG:  0x{:08X} - 0x{:08X}".format(tseg_base, tseg_base + tseg_size))
        if dpr_base is not None:
            self.logger.log("[*]   DPR:   0x{:08X} - 0x{:08X}".format(dpr_base, dpr_base + dpr_size))
        if prmr_base is not None:
            self.logger.log("[*]   PRMR:  0x{:08X} - 0x{:08X}".format(prmr_base, prmr_base + prmr_size))
        if imr_base is not None:
            self.logger.log("[*]   IMR:   0x{:08X} - 0x{:08X}".format(imr_base, imr_base + imr_size))
        self.logger.log("[*]")

        # Verify that each region is contiguous
        prev_top = None
        for item in range_list:
            if prev_top is None:
                prev_top = item[0] + item[1]
                continue
            if item[0] < prev_top:
                self.logger.log('{} overlaps previous range'.format(item[2]))
                res = ModuleResult.FAILED
            prev_top = item[0] + item[1]
        if bgsm_base + bgsm_size != bdsm_base:
            self.logger.log_bad("BGSM incorrectly configured")
            res = ModuleResult.FAILED

        # Display results for contiguous ranges
        if res == ModuleResult.PASSED:
            self.logger.log_good("Memory range layout check passed")
        else:
            self.logger.log_bad("Memory range layout check failed")

        self.logger.log("[*]")
        return res

    def check_exclusion(self):
        self.logger.log("[*] ========================================================================")
        self.logger.log("[*] Checking IA / GT exclusion ranges")
        self.logger.log("[*]")

        res = ModuleResult.PASSED

        # Get all IMRs
        (imr_base, imr_size) = self._get_imr_info()

        # Should not assume we have TSEG
        (tseg_base, tseg_size) = self._get_tseg()

        # Get IA and GT Exclude ranges
        ia_ex_base = self.cs.read_register_field("IMR_IA_EX_BASE", "BASE", True)
        ia_ex_size = self.cs.read_register_field("IMR_IA_EX_LIMIT", "LIMIT", True) - ia_ex_base
        gt_ex_base = self.cs.read_register_field("IMR_GT_EX_BASE", "BASE", True)
        gt_ex_size = self.cs.read_register_field("IMR_GT_EX_LIMIT", "LIMIT", True) - gt_ex_base

        if tseg_base is not None:
            self.logger.log("[*]   TSEG:  0x{:08X} - 0x{:08X}".format(tseg_base, tseg_base + tseg_size))
        if imr_base is not None:
            self.logger.log("[*]   IMR:   0x{:08X} - 0x{:08X}".format(imr_base, imr_base + imr_size))
        if ia_ex_base is not None:
            self.logger.log("[*]   IA EX: 0x{:08X} - 0x{:08X}".format(ia_ex_base, ia_ex_base + ia_ex_size))
        if gt_ex_base is not None:
            self.logger.log("[*]   GT EX: 0x{:08X} - 0x{:08X}".format(gt_ex_base, gt_ex_base + gt_ex_size))

        # Check that this matches the GT Exclusion range
        if imr_base != ia_ex_base or imr_size > (ia_ex_base + ia_ex_size):
            self.logger.log_bad("IA Exclude range does not cover IMRs")
            res = ModuleResult.FAILED
        if self.base_above_imr is not None:
            if self.base_above_imr < ia_ex_base + ia_ex_size:
                self.logger.log_bad("IA Exclude range overlaps next memory region")
                res = ModuleResult.FAILED
        else:
            self.logger.log_bad("Unable to determine next range above IMR for IA Exclude range check")
            res = ModuleResult.FAILED
        if imr_base < gt_ex_base or (tseg_base + tseg_size) > (gt_ex_base + gt_ex_size):
            self.logger.log_bad("GT Exclude range does not cover IMR base to top of TSEG")
            res = ModuleResult.FAILED

        # Display IA/GT Exclude range check
        if res == ModuleResult.PASSED:
            self.logger.log_good("IA and GT Exclude ranges configured as expected")
        else:
            self.logger.log_bad("IA and GT Exclude ranges not configured as expected")

        self.logger.log("[*]")
        return res

    def run(self, module_argv):
        self.logger.start_test("IGD Memory Map")
        self.logger.log("[*]")

        # Display graphics information
        bus, dev, func = self.cs.get_device_BDF('IGD')
        vid = self.cs.pci.read_word(bus, dev, func, PCI_HDR_VID_OFF)
        did = self.cs.pci.read_word(bus, dev, func, PCI_HDR_DID_OFF)
        rid = self.cs.pci.read_byte(bus, dev, func, PCI_HDR_RID_OFF)
        self.logger.log('[*] IGD:')
        self.logger.log('[*]   VID: {:04X}'.format(vid))
        self.logger.log('[*]   DID: {:04X}'.format(did))
        self.logger.log('[*]   RID: {:02X}'.format(rid))
        self.logger.log('[*]')

        res_list = []
        res_list.append(self.check_memory_layout())
        res_list.append(self.check_igfx_layout())
        if self.cs.get_chipset_code() in self.new_platforms:
            res_list.append(self.check_exclusion())

        self.logger.log("[*] ========================================================================")
        if res_list.count(ModuleResult.PASSED) == len(res_list):
            self.logger.log_passed_check("All IGD Memory Map tests passed")
            self.res = ModuleResult.PASSED
        elif res_list.count(ModuleResult.FAILED) > 0:
            self.logger.log_failed_check("One or more IGD Memory Map tests failed")
            self.res = ModuleResult.FAILED
        elif res_list.count(ModuleResult.WARNING) > 0:
            self.logger.log_warn_check("One or more IGD Memory Map tests generated a warning")
            self.res = ModuleResult.WARNING
        else:
            self.logger.log_error_check("IGD Memory Map generated an unexpected result")
            self.res = ModuleResult.ERROR

        return self.res
