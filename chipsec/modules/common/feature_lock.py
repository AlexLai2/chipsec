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
# Aaron Frinzell
# Brent Holtsclaw
#

from chipsec.module_common import BaseModule, ModuleResult
from chipsec.chipset import CHIPSET_CODE_BDX, CHIPSET_CODE_HSX, CHIPSET_CODE_KNL, CHIPSET_CODE_AVN, CHIPSET_CODE_JVL

SUPPORTED_CS = [CHIPSET_CODE_BDX, CHIPSET_CODE_HSX, CHIPSET_CODE_KNL, CHIPSET_CODE_AVN, CHIPSET_CODE_JVL]

class feature_lock(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        if self.cs.get_chipset_code() in SUPPORTED_CS:
            return True
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_FEATURE_LOCK(self):
        xeon_ok = ok = True
        self.logger.log('')
        self.logger.log( "[*] checking Personality Lock Key Control Register Capability Lock.." )
        if self.cs.is_register_defined('PLKCTL_Fn0'):
            plkctl = { 'PLKCTL_Fn0': self.cs.read_register( 'PLKCTL_Fn0' ), 'PLKCTL_Fn1': self.cs.read_register( 'PLKCTL_Fn1' ), 'PLKCTL_Fn2': self.cs.read_register( 'PLKCTL_Fn2' ), 'PLKCTL_Fn3': self.cs.read_register( 'PLKCTL_Fn3' ) }
        elif self.cs.is_register_defined( 'PLKCTL_Fn3' ):
            plkctl = { 'PLKCTL_Fn3': self.cs.read_register( 'PLKCTL_Fn3' ), 'PLKCTL_Fn4': self.cs.read_register( 'PLKCTL_Fn4' ), 'PLKCTL_Fn5': self.cs.read_register( 'PLKCTL_Fn5' ) }
        elif self.cs.get_chipset_code() == CHIPSET_CODE_AVN:
            plkctl = {'PLKCTL_RTF': self.cs.read_register('PLKCTL_RTF'), 'PLKCTL_D1': self.cs.read_register( 'PLKCTL_D1'),'PLKCTL_D2': self.cs.read_register( 'PLKCTL_D2'), 'PLKCTL_D3': self.cs.read_register( 'PLKCTL_D3'), 'PLKCTL_D4': self.cs.read_register( 'PLKCTL_D4') }
        else:
            plkctl = { 'PLKCTL': self.cs.read_register( 'PLKCTL' ) }
        for reg in list(plkctl.keys()):
            plkctl_reg = self.cs.read_register( reg )
            self.logger.log( '[*]   {:<20s}  : 0x{:04X}'.format(reg,plkctl_reg) )
            plkctl_cl  = self.cs.get_register_field( reg, plkctl_reg, 'CL' )
            self.logger.log( '[*]     CL               : {:d}'.format(plkctl_cl) )
            if (1 != plkctl_cl): ok = False
        if ok: self.logger.log_good( "Capability Lock set" )
        else:  self.logger.log_bad( "Capability Lock is not set" )

        self.logger.log('')
        self.logger.log( "[*] checking C-State Configuration Register configuration.." )
        cst_config = self.cs.read_register( 'MSR_PKG_CST_CONFIG_CONTROL' )
        self.logger.log( "[*]   MSR_PKG_CST_CONFIG_CONTROL : 0x{:016X}".format(cst_config) )
        cst_config_lck = self.cs.get_register_field( 'MSR_PKG_CST_CONFIG_CONTROL', cst_config, 'LOCK' )
        self.logger.log( "[*]     Lock                     : {:d}".format(cst_config_lck) )
        ok = (1 == cst_config_lck)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_good( "C-State Configuration Control Register is locked" )
        else:  self.logger.log_bad( "C-State Configuration Control Register is not locked" ) #Warning

        if xeon_ok == True:
            self.logger.log_passed_check("Feature locks are set correctly")
            return ModuleResult.PASSED
        else:
            self.logger.log_failed_check("Feature locks are not set correctly")
            return ModuleResult.FAILED

    def run(self,module_argv):
        self.logger.start_test("[*] checking if Registers are set correctly..")
        self.res = self.check_FEATURE_LOCK()
        return self.res
