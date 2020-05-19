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
# Authors:
#  Yuriy Bulygin
#

"""
Check BIOS Guard related configuration
"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'biosguard'

TAGS = [MTAG_BIOS]


class biosguard(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)


    def is_supported(self):
        # MS HyperV workaround. HyperV reports SMRR support but throws and exception on access to SMRR msrs.
        # Not a problem for chipsec driver but crashes RwDrv.'
        from chipsec.hal.cpu import VMM_HYPER_V
        if self.cs.cpu.check_vmm() == VMM_HYPER_V:
            self.logger.log("Not supported under Hyper-V")
            self.res = ModuleResult.NOTAPPLICABLE
            return False
        if self.cs.read_register_field('MSR_PLATFORM_INFO', 'BIOSGuard') == 1 and self.cs.is_register_defined('PLAT_FRMW_PROT_CTRL_MSR'):
            return True
        else:
            self.res = ModuleResult.NOTAPPLICABLE
            return False

    ## check_BIOS_Guard_config
    # Checks that BIOS Guard protection is enabled and locked
    def check_BIOS_Guard_config( self ):
        self.logger.log( "[*] Checking if CPU BIOS Guard is enabled and locked in PLAT_FRMW_PROT_CTRL MSR.." )

        pfpc_msr_reg = self.cs.read_register( 'PLAT_FRMW_PROT_CTRL_MSR' )
        self.cs.print_register( 'PLAT_FRMW_PROT_CTRL_MSR', pfpc_msr_reg )
        biosguard_lock = self.cs.get_register_field( 'PLAT_FRMW_PROT_CTRL_MSR', pfpc_msr_reg, 'Lock' )
        biosguard_en   = self.cs.get_register_field( 'PLAT_FRMW_PROT_CTRL_MSR', pfpc_msr_reg, 'Enable' )

        if 1 == biosguard_en:
            self.logger.log_good( "CPU BIOS Guard is used. BIOS Update is protected by the CPU\n" )
            if 1 == biosguard_lock:
                res = ModuleResult.PASSED
                self.logger.log_passed_check( "CPU BIOS Guard configuration is locked" )
            else:
                res = ModuleResult.FAILED
                self.logger.log_failed_check( "CPU BIOS Guard configuration is not locked" )
        else:
            self.logger.log('')
            if 1 == biosguard_lock:
                res = ModuleResult.WARNING
                self.logger.log_warn_check( "CPU BIOS Guard is not used. BIOS Update is done via legacy update mechanisms" )
            else:
                res = ModuleResult.FAILED
                self.logger.log_failed_check( "BIOS Guard configuration is not locked" )
        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.logger.start_test( "Intel BIOS Guard Configuration" )

        self.res = self.check_BIOS_Guard_config()
        return self.res
