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
Checks for SPI Controller Vendor Components Locks
"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS
TAGS = [MTAG_BIOS]

class spi_vcl(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        if not self.cs.is_register_defined( 'LVSCC' ):
            self.logger.log( "Couldn't find definition of required registers (LVSCC)" )
            return ModuleResult.NOTAPPLICABLE
        return True

    def check_vendor_component_lock(self):
        self.logger.start_test( "SPI Vendor Component Lock" )

        lvscc_reg = self.cs.read_register( 'LVSCC' )
        self.cs.print_register( 'LVSCC', lvscc_reg )
        vcl = self.cs.get_register_field( 'LVSCC', lvscc_reg, 'VCL')

        if 1 == vcl:
            self.logger.log_passed_check( "Vendor Specific Component Capabilities is locked" )
            res = ModuleResult.PASSED
        else:
            self.logger.log_failed_check( "Vendor Specific Component Capabilities can be modified" )
            res = ModuleResult.FAILED
        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.res = self.check_vendor_component_lock()
        return self.res
