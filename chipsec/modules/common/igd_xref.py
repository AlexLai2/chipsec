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
from chipsec.chipset import CHIPSET_CODE_ICL
from chipsec.hal.pci import PCI_HDR_VID_OFF, PCI_HDR_DID_OFF, PCI_HDR_RID_OFF

TAGS = [MTAG_HWCONFIG]

class reg_data_item(object):
    def __init__(self, reg_name, igd_reg, mch_reg, fields=[], enables=[], locks=[], enable_pol=1):
        self.reg_name = reg_name
        self.igd_reg = igd_reg
        self.mch_reg = mch_reg
        self.fields = fields
        self.enables = enables
        self.enable_pol = enable_pol
        self.locks = locks

class igd_xref(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.platforms = [CHIPSET_CODE_ICL]
        self.reg_xref_data = [
            reg_data_item('TOUUD', 'IGD_TOUUD', 'PCI0.0.0_TOUUD', ['TOUUD'], [], ['LOCK']),
            reg_data_item('TOLUD', 'IGD_TOLUD', 'PCI0.0.0_TOLUD', ['TOLUD']),
            reg_data_item('BDSM', 'IGD_BDSM', 'PCI0.0.0_BDSM', ['BDSM'], [], ['LOCK']),
            reg_data_item('BGSM', 'IGD_BGSM', 'PCI0.0.0_BGSM', ['BGSM'], [], ['LOCK']),
            reg_data_item('PAVPC', 'IGD_PAVPC', 'PCI0.0.0_PAVPC', ['PCMBASE'], ['PCME'], ['PAVPLCK']),
            reg_data_item('TSEGMB', 'IGD_TSEGMB', 'PCI0.0.0_TSEGMB', ['TSEGMB']),
            reg_data_item('GGC', 'IGD_GGC', 'PCI0.0.0_GGC', ['GMS', 'GGMS'], [], ['GGCLOCK']),
            reg_data_item('PRMRR_BASE', 'IGD_MEMRR_BASE', 'PRMRR_PHYBASE', ['PRMRR_base_address_fields'], ['PRMRR_CONFIGURED']),
            reg_data_item('PRMRR_MASK', 'IGD_MEMRR_MASK', 'PRMRR_MASK', ['PRMRR_mask_bits'], ['PRMRR_VLD'], ['PRMRR_LOCK'])
        ]
        self.pmr_xref_data = [
            reg_data_item('PLMBASE', 'IGD_MPLMBASE', 'VTBAR_PLMBASE', ['PLMB']),
            reg_data_item('PLMLIMIT', 'IGD_MPLMLIMIT', 'VTBAR_PLMLIMIT', ['PLML']),
            reg_data_item('PHMBASE', 'IGD_MPHMBASE', 'VTBAR_PHMBASE', ['PHMB']),
            reg_data_item('PHMLIMIT', 'IGD_MPHMLIMIT', 'VTBAR_PHMLIMIT', ['PHML'])
        ]

    def is_supported(self):
        if self.cs.get_chipset_code() in self.platforms:
            if self.cs.is_device_enabled('IGD'):
                return True
            else:
                self.logger.log('[*] IGD is disabled')
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_sai_lock(self):
        self.logger.log("[*] ========================================================================")
        self.logger.log("[*] Checking to see if SAI is being used and locked")
        if self.cs.is_register_defined('MSR_BIOS_DONE') and self.cs.register_has_field('MSR_BIOS_DONE', 'IA_UNTRUSTED'):
            if self.cs.read_register_field('MSR_BIOS_DONE', 'IA_UNTRUSTED') == 1:
                self.logger.log_good("SAI locks enabled")
                self.logger.log("[*]")
                return ModuleResult.PASSED
        self.logger.log_bad("SAI locks disabled")
        self.logger.log("[*]")
        return ModuleResult.FAILED

    def reg_xref(self):
        self.logger.log("[*] ========================================================================")
        self.logger.log("[*] Checking region mapping is consistent between devices")
        res = ModuleResult.PASSED

        # Run generic tests
        for item in self.reg_xref_data:
            reg_res = self._check_register(item)
            if res == ModuleResult.PASSED and (reg_res == ModuleResult.WARNING or reg_res == ModuleResult.FAILED):
                res = reg_res
            elif res == ModuleResult.WARNING and reg_res == ModuleResult.FAILED:
                res = reg_res

        # Handle registers that need special processing (DPR)
        dpr_enabled = True
        self.logger.log("[*] Processing: DPR")
        mch_dpr_reg = self.cs.read_register("PCI0.0.0_DPR")
        if self.cs.get_register_field("PCI0.0.0_DPR", mch_dpr_reg, "EPM") == 1:
            self.logger.log("[*]   DPR Enabled")
        else:
            dpr_enabled = False
            self.logger.log("[*]   DPR Disabled")
        if dpr_enabled:
            field = "BDPR"
            dpr_top = self.cs.get_register_field("PCI0.0.0_DPR", mch_dpr_reg, "TOPOFDPR", True)
            dpr_size = self.cs.get_register_field("PCI0.0.0_DPR", mch_dpr_reg, "DPRSIZE")
            mch_dpr_base = dpr_top - (dpr_size << 20)
            igd_dpr_base = self.cs.read_register_field("IGD_DPR", field, True)
            self.logger.log("[*]   [{}] MCH/MSR Field: 0x{:08X} / IGD Field: 0x{:08X}".format(field, mch_dpr_base, igd_dpr_base))
            if igd_dpr_base == mch_dpr_base:
                self.logger.log_good("  + {} Passed Verification".format(field))
            else:
                self.logger.log_bad("  - {} Failed Verification".format(field))
                res = ModuleResult.FAILED
        self.logger.log("[*]")

        # Handle PHMR and PLMR so see if they are enabled first
        pmr_enabled = True
        self.logger.log("[*] Processing: PMEN")
        igd_reg_val = self.cs.read_register("IGD_MPMEN")
        mch_reg_val = self.cs.read_register("VTBAR_PMEN")
        self.logger.log("[*]   MCH/MSR: 0x{:08X} / IGD: 0x{:08X}".format(mch_reg_val, igd_reg_val))
        igd_data = self.cs.get_register_field("IGD_MPMEN", igd_reg_val, "EPM")
        mch_data = self.cs.get_register_field("VTBAR_PMEN", mch_reg_val, "EPM")
        if mch_data == 0:
            pmr_enabled = False
            self.logger.log("[*]   PHMR/PLMR Disabled")
        else:
            self.logger.log("[*]   PHMR/PLMR Enabled")
        if mch_data != igd_data:
            self.logger.log_warning("Enable bits do not match: MCH/MSR 0x{:02X} != IGD 0x{:02X}".format(mch_data, igd_data))
            if res != ModuleResult.FAILED:
                res = ModuleResult.WARNING
        self.logger.log("[*]")
        if pmr_enabled:
            # Now check each memory range (L/H) since the feature is enabled
            for item in self.pmr_xref_data:
                reg_res = self._check_register(item)
                if res == ModuleResult.PASSED and (reg_res == ModuleResult.WARNING or reg_res == ModuleResult.FAILED):
                    res = reg_res
                elif res == ModuleResult.WARNING and reg_res == ModuleResult.FAILED:
                    res = reg_res

        return res

    def _check_register(self, item):
        res = ModuleResult.PASSED

        # Read the register so we have the bits we need
        self.logger.log("[*] Processing: {}".format(item.reg_name))
        igd_reg_val = self.cs.read_register(item.igd_reg)
        mch_reg_val = self.cs.read_register(item.mch_reg)
        self.logger.log("[*]   MCH/MSR: 0x{:08X} / IGD: 0x{:08X}".format(mch_reg_val, igd_reg_val))

        # Check if the feature is enabled in the MCH
        # - If not enabled in the MCH skip testing the feature fields
        # - Always need to check lock registers
        # - Only check enable registers if they also exist in the IGD region
        reg_enabled = True
        for field in item.enables:
            if self.cs.register_has_field(item.igd_reg, field):
                igd_data = self.cs.get_register_field(item.igd_reg, igd_reg_val, field)
            else:
                igd_data = None
            mch_data = self.cs.get_register_field(item.mch_reg, mch_reg_val, field)
            if mch_data == item.enable_pol:
                self.logger.log("[*]   {} Enabled".format(item.reg_name))
            else:
                self.logger.log("[*]   {} Disabled".format(item.reg_name))
                reg_enabled = False
            if (igd_data is not None) and (mch_data != igd_data):
                self.logger.log_warning("Enable bits do not match: MCH/MSR 0x{:02X} != IGD 0x{:02X}".format(mch_data, igd_data))
                if res != ModuleResult.FAILED:
                    res = ModuleResult.WARNING

        # Check specific fields match between regions
        if reg_enabled:
            for field in item.fields:
                igd_data = self.cs.get_register_field(item.igd_reg, igd_reg_val, field, True)
                mch_data = self.cs.get_register_field(item.mch_reg, mch_reg_val, field, True)
                self.logger.log("[*]   [{}] MCH/MSR Field: 0x{:08X} / IGD Field: 0x{:08X}".format(field, mch_data, igd_data))
                if igd_data == mch_data:
                    self.logger.log_good("  + {} Passed Verification".format(field))
                else:
                    self.logger.log_bad("  - {} Failed Verification".format(field))
                    res = ModuleResult.FAILED

        # Verify that the register is locked.  Only some registers have lock bits.
        for field in item.locks:
            igd_data = self.cs.get_register_field(item.igd_reg, igd_reg_val, field)
            mch_data = self.cs.get_register_field(item.mch_reg, mch_reg_val, field)
            if igd_data == 0:
                self.logger.log_bad("  Register Not Locked")
                res = ModuleResult.FAILED
            else:
                self.logger.log_good("  Register Locked")

        # Add a break between register test blocks
        self.logger.log("[*]")

        return res

    def run(self, module_argv):
        self.logger.start_test("IGD XRef")
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
        res_list.append(self.check_sai_lock())
        res_list.append(self.reg_xref())

        self.logger.log("[*] ========================================================================")
        if res_list.count(ModuleResult.PASSED) == len(res_list):
            self.logger.log_passed_check("All IGD XREF tests passed")
            self.res = ModuleResult.PASSED
        elif res_list.count(ModuleResult.FAILED) > 0:
            self.logger.log_failed_check("One or more IGD XREF tests failed")
            self.res = ModuleResult.FAILED
        elif res_list.count(ModuleResult.WARNING) > 0:
            self.logger.log_warn_check("One or more IGD XREF tests generated a warning")
            self.res = ModuleResult.WARNING
        else:
            self.logger.log_error_check("IGD XREF generated an unexpected result")
            self.res = ModuleResult.ERROR

        return self.res
