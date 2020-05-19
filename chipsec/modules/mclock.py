#!/usr/bin/env python
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
#Copyright (c) 2010-2020, Intel Corporation
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
#
#
# Authors:
#  Yuriy Bulygin
#


"""
Check Memory Controller Configuration
"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_HWCONFIG
from chipsec.chipset import CHIPSET_FAMILY_CORE

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'mclock'

TAGS = [MTAG_HWCONFIG]


MCHBAR_MCLOCK_OFFSET = 0x50FC

class mclock(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        self.res = ModuleResult.NOTAPPLICABLE
        if self.cs.is_register_defined('MSR_BIOS_DONE') and self.cs.register_has_field('MSR_BIOS_DONE', 'IA_UNTRUSTED'):
            self.logger.log('[*] Not Applicable: Use the IA_UNTRUSTED test module.')
            return False
        elif self.cs.is_atom():
            self.res = ModuleResult.NOTAPPLICABLE
            return False
        elif self.cs.is_core():
            return True
        return False

    def check_mclock(self):
        self.logger.start_test( "Memory Controller Lock" )

        mchbar_addr = self.cs.read_register("PCI0.0.0_MCHBAR") #mmio.get_MCHBAR_base_address()
        self.logger.log("[*] MC_LOCK address: 0x{:08X}".format(mchbar_addr + MCHBAR_MCLOCK_OFFSET))
        mclock = self.cs.mmio.read_MMIO_reg_dword(mchbar_addr, MCHBAR_MCLOCK_OFFSET) & 0xFF
        self.logger.log( "[*] MC_LOCK register = 0x{:02X}".format(mclock) )

        res = ModuleResult.PASSED
        if ( 0x87 == (mclock & 0x87) ):
            self.logger.log_passed_check( "Memory controller configuration is locked\n" )
        else:
            self.logger.log_failed_check( "Memory controller configuration is NOT locked\n" )
            res = ModuleResult.FAILED

        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self,  module_argv ):
        self.res = self.check_mclock()
        return self.res
