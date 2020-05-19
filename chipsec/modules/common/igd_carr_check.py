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

import time

from chipsec.module_common import BaseModule
from chipsec.module_common import ModuleResult
from chipsec.module_common import MTAG_HWCONFIG
from chipsec.chipset import CHIPSET_CODE_CFL, CHIPSET_CODE_CML, CHIPSET_CODE_WHL
from chipsec.chipset import CHIPSET_CODE_ICL
from chipsec.hal.pci import PCI_HDR_VID_OFF, PCI_HDR_DID_OFF, PCI_HDR_RID_OFF

TAGS = [MTAG_HWCONFIG]

MAX_RETRY_COUNT = 200

class reg_check_item(object):
    def __init__(self, reg_name, expected_value):
        self.reg_name = reg_name
        self.expected_value = expected_value

class igd_carr_check(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)

        # WHL, CML, CFL
        self.gen9_platforms = [CHIPSET_CODE_CFL, CHIPSET_CODE_WHL, CHIPSET_CODE_CML]
        self.gen9_carr_vals = [
            reg_check_item("IGD_CARR_BASE_0", 0x80040003),
            reg_check_item("IGD_CARR_LIMIT_0", 0x800507FC),
            reg_check_item("IGD_CARR_BASE_1", 0x800508D3),
            reg_check_item("IGD_CARR_LIMIT_1", 0x800BFFFC),
            reg_check_item("IGD_CARR_BASE_2", 0x80114001),
            reg_check_item("IGD_CARR_LIMIT_2", 0x80117FFC),
            reg_check_item("IGD_CARR_BASE_3", 0x80138001),
            reg_check_item("IGD_CARR_LIMIT_3", 0x80147FFC),
            reg_check_item("IGD_CARR_BASE_4", 0x80000000),
            reg_check_item("IGD_CARR_LIMIT_4", 0x80000000),
            reg_check_item("IGD_CARR_BASE_5", 0x80000000),
            reg_check_item("IGD_CARR_LIMIT_5", 0x80000000),
            reg_check_item("IGD_CARR_BASE_6", 0x80000000),
            reg_check_item("IGD_CARR_LIMIT_6", 0x80000000),
            reg_check_item("IGD_CARR_BASE_7", 0x80000000),
            reg_check_item("IGD_CARR_LIMIT_7", 0x80000000),
        ]

        # ICLLP U/Y, LKF, EHL/JSL
        self.gen11_platforms = [CHIPSET_CODE_ICL]
        self.gen11_carr_vals = [
            reg_check_item("IGD_CARR_BASE_0", 0x80040003),
            reg_check_item("IGD_CARR_LIMIT_0", 0x800507FC),
            reg_check_item("IGD_CARR_BASE_1", 0x800508D3),
            reg_check_item("IGD_CARR_LIMIT_1", 0x800BFFFC),
            reg_check_item("IGD_CARR_BASE_2", 0x80138001),
            reg_check_item("IGD_CARR_LIMIT_2", 0x8014FFFC),
            reg_check_item("IGD_CARR_BASE_3", 0x80190003),
            reg_check_item("IGD_CARR_LIMIT_3", 0x80197FFC),
            reg_check_item("IGD_CARR_BASE_4", 0x80000000),
            reg_check_item("IGD_CARR_LIMIT_4", 0x80000000),
            reg_check_item("IGD_CARR_BASE_5", 0x80000000),
            reg_check_item("IGD_CARR_LIMIT_5", 0x80000000),
            reg_check_item("IGD_CARR_BASE_6", 0x80000000),
            reg_check_item("IGD_CARR_LIMIT_6", 0x80000000),
            reg_check_item("IGD_CARR_BASE_7", 0x80000000),
            reg_check_item("IGD_CARR_LIMIT_7", 0x80000000),
        ]

        # RKL, TGL
        self.gen12_platforms = []
        self.gen12_carr_vals = [
            reg_check_item("IGD_CARR_BASE_0", 0x80040003),
            reg_check_item("IGD_CARR_LIMIT_0", 0x800507FC),
            reg_check_item("IGD_CARR_BASE_1", 0x800508D3),
            reg_check_item("IGD_CARR_LIMIT_1", 0x800BFFFC),
            reg_check_item("IGD_CARR_BASE_2", 0x80138001),
            reg_check_item("IGD_CARR_LIMIT_2", 0x8015FFFC),
            reg_check_item("IGD_CARR_BASE_3", 0x80190003),
            reg_check_item("IGD_CARR_LIMIT_3", 0x80197FFC),
            reg_check_item("IGD_CARR_BASE_4", 0x80000000),
            reg_check_item("IGD_CARR_LIMIT_4", 0x80000000),
            reg_check_item("IGD_CARR_BASE_5", 0x80000000),
            reg_check_item("IGD_CARR_LIMIT_5", 0x80000000),
            reg_check_item("IGD_CARR_BASE_6", 0x80000000),
            reg_check_item("IGD_CARR_LIMIT_6", 0x80000000),
            reg_check_item("IGD_CARR_BASE_7", 0x80000000),
            reg_check_item("IGD_CARR_LIMIT_7", 0x80000000),
        ]

        self.platforms = self.gen9_platforms
        self.platforms.extend(self.gen11_platforms)
        self.platforms.extend(self.gen12_platforms)

    def is_supported(self):
        if self.cs.get_chipset_code() in self.platforms:
            if self.cs.is_device_enabled('IGD'):
                return True
            else:
                self.logger.log('[*] IGD is disabled')
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_carr_vals(self):
        regs_not_programmed = False
        regs_not_implemented = False
        res = ModuleResult.PASSED
        if  self.cs.get_chipset_code() in self.gen12_platforms:
            reg_list = self.gen12_carr_vals
        elif self.cs.get_chipset_code() in self.gen11_platforms:
            reg_list = self.gen11_carr_vals
        elif self.cs.get_chipset_code() in self.gen9_platforms:
            reg_list = self.gen9_carr_vals
        else:
            self.logger.log_warning("CARR check not supported on this platform.")
            return ModuleResult.WARNING

        self.logger.log("[*]                        Actual   |  Expected")
        for item in reg_list:
            igd_reg_val = self.cs.read_register(item.reg_name)
            if igd_reg_val == item.expected_value:
                self.logger.log_good("  {:17}: 0x{:08X} == 0x{:08X}".format(item.reg_name, igd_reg_val, item.expected_value))
            elif igd_reg_val == 0:
                self.cs.write_register_field(item.reg_name, 'LOCK', 1)
                if self.cs.read_register_field(item.reg_name, 'LOCK') == 0:
                    regs_not_implemented = True
                    self.logger.log_good("  {:17}: 0x{:08X} == 0x{:08X}".format(item.reg_name, igd_reg_val, item.expected_value))
                else:
                    self.logger.log_bad("  {:17}: 0x{:08X} != 0x{:08X}".format(item.reg_name, igd_reg_val, item.expected_value))
                    res = ModuleResult.FAILED
            else:
                self.logger.log_bad("  {:17}: 0x{:08X} != 0x{:08X}".format(item.reg_name, igd_reg_val, item.expected_value))
                res = ModuleResult.FAILED
        if regs_not_implemented and not (res == ModuleResult.FAILED):
            self.logger.log('[*]')
            self.logger.log("CARR registers not implemented/supported on this platform")
        self.logger.log('[*]')
        return res

    def _get_wake_state(self):
        if self.cs.is_register_defined('GTSP1') and self.cs.register_has_field('GTSP1', 'WAKE_REQUEST'):
            return self.cs.read_register_field('GTSP1', 'WAKE_REQUEST')
        return None

    def _set_gt_wake(self, wake=False, sleep=0x8000):
        if self.cs.is_register_defined('GT_FORCE_WAKE') and self.cs.register_has_field('GT_FORCE_WAKE', 'WAKE_REQUEST') and \
           self.cs.is_register_defined('GTSP1') and self.cs.register_has_field('GTSP1', 'WAKE_REQUEST'):
            state = self._get_wake_state()
            self.logger.log('[*] GT Force Wake')
            self.logger.log('[*]   Force Wake initial state: 0x{:08X}'.format(state))
            reg_mask = 0x8000
            while reg_mask:
                if wake:
                    while reg_mask & state != 0:
                        reg_mask = reg_mask >> 1
                else:
                    reg_mask = sleep
                reg_val = self.cs.set_register_field('GT_FORCE_WAKE', 0, 'WAKE_MASK', reg_mask)
                if not wake:
                    reg_mask = 0
                reg_val = self.cs.set_register_field('GT_FORCE_WAKE', reg_val, 'WAKE_REQUEST', reg_mask)
                self.cs.write_register('GT_FORCE_WAKE', reg_val)
                for i in range(MAX_RETRY_COUNT):
                    if self._get_wake_state() & reg_mask == reg_mask:
                        self.logger.log('[*]   Force Wake new state: 0x{:08X}'.format(self.cs.read_register_field('GTSP1', 'WAKE_REQUEST')))
                        self.logger.log('[*]   GT Force Wake complete')
                        self.logger.log('[*]')
                        return reg_mask
                    time.sleep(.01)
            self.logger.log_warning('GT Force Wake failed')
        else:
            self.logger.log_warning("Missing register definitions to enable Force Wake support.")
        self.logger.log('[*]')
        return None

    def run(self, module_argv):
        self.logger.start_test('CARR Register Check')
        self.logger.log('[*]')

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

        mask = self._set_gt_wake(True)
        if mask:
            self.res = self.check_carr_vals()
            self._set_gt_wake(False, mask)
        else:
            self.res = ModuleResult.WARNING

        if self.res == ModuleResult.PASSED:
            self.logger.log_passed_check("CARR values match expected values")
        elif self.res == ModuleResult.FAILED:
            self.logger.log_failed_check("CARR values do not match expected values")
        elif self.res == ModuleResult.WARNING:
            self.logger.log_warn_check("Unable to run module")
        else:
            self.logger.log_error_check("Unexpected test result returned")

        return self.res
