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
Checks if Power Management Controller (PMC) in PCH is configured securely

 SKL PSCS Reference: table 7-8 test #4
 BDW PSCS Reference: table 3-10 test #4
 HSW PSCS Reference: 2.2.9 test #4
"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_HWCONFIG

#from chipsec.hal.mmio import *

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'pmc'

TAGS = [MTAG_HWCONFIG]


class pmc(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        if self.cs.is_register_defined("PM_CFG") and self.cs.register_has_field('PM_CFG','BIT27'):
            return True
        else:
            self.res = ModuleResult.NOTAPPLICABLE
            return False

    def check_pm_cfg( self ):
        self.logger.start_test( "Power Management Controller (PMC) Config" )

        pm_cfg = self.cs.read_register( 'PM_CFG' )
        val = self.cs.get_register_field("PM_CFG", pm_cfg, "BIT27")
        if self.logger.VERBOSE: self.cs.print_register( 'PM_CFG', pm_cfg )

        if val == 1:
            res = ModuleResult.PASSED
            self.logger.log_passed_check( "All required bits are set in PM_CFG" )
        else:
            res = ModuleResult.FAILED
            self.logger.log_failed_check( "Production systems should disable PMC debug mode by setting bit 27 in PM_CFG" )

        return res


    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.res = self.check_pm_cfg()
        return self.res
