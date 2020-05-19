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
from chipsec.chipset import CHIPSET_CODE_SKL, CHIPSET_CODE_KBL, CHIPSET_CODE_CFL, CHIPSET_CODE_CML
from chipsec.chipset import CHIPSET_CODE_WHL, CHIPSET_CODE_APL, CHIPSET_CODE_GLK, CHIPSET_CODE_AML
from chipsec.hal.pci import PCI_HDR_VID_OFF, PCI_HDR_DID_OFF, PCI_HDR_RID_OFF

TAGS = [MTAG_HWCONFIG]

class igd_config0(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.supported = [
            CHIPSET_CODE_SKL,
            CHIPSET_CODE_KBL,
            CHIPSET_CODE_AML,
            CHIPSET_CODE_CFL,
            CHIPSET_CODE_CML,
            CHIPSET_CODE_WHL,
            CHIPSET_CODE_APL,
            CHIPSET_CODE_GLK
            ]
        self.expected_val = 0x07

    def is_supported(self):
        if self.cs.get_chipset_code() in self.supported:
            if self.cs.is_device_enabled('IGD'):
                return True
            else:
                self.logger.log('[*] IGD is disabled')
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_config0(self):
        res = ModuleResult.PASSED
        reg_val = self.cs.read_register('IGD_CONFIG_0')
        self.cs.print_register('IGD_CONFIG_0', reg_val)
        icb_val = self.cs.get_register_field('IGD_CONFIG_0', reg_val, 'ICB')
        if icb_val == self.expected_val:
            self.logger.log_good('Config0 programmed with expected value')
        elif icb_val != 0:
            self.logger.log_warning('Config0 programmed but value does not match expected value 0x{:02X}'.format(self.expected_val))
            res = ModuleResult.WARNING
        else:
            self.logger.log_bad('Config0 does not seem to be programmed')
            res = ModuleResult.FAILED
        if self.cs.get_register_field('IGD_CONFIG_0', reg_val, 'LOCK') == 1:
            self.logger.log_good('Config0 locked')
        else:
            self.logger.log_bad('Config0 not locked')
            res = ModuleResult.FAILED
        return res

    def run(self, module_argv):
        self.logger.start_test('IGD Config0 Check')
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

        self.res = self.check_config0()
        if self.res == ModuleResult.PASSED:
            self.logger.log_passed_check('Expected value in Config0 detected.')
        elif self.res == ModuleResult.WARNING:
            self.logger.log_warn_check('Unexpected value in Config0 detected')
        elif self.res == ModuleResult.FAILED:
            self.logger.log_failed_check('Required bits not programmed in Config0')
        return self.res
