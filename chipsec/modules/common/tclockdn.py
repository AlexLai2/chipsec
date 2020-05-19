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

class tclockdn(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        if self.cs.is_register_defined('TCLOCKDN'):
            return True
        else:
            self.res = ModuleResult.NOTAPPLICABLE
            return False

    def check_TCLOCKDN(self):
        tclockdn = self.cs.read_register( 'TCLOCKDN' )
        self.logger.log( "[*]   TCLOCKDN           : 0x{:08X}".format(tclockdn) )
        TC_LockDown    = self.cs.get_register_field( 'TCLOCKDN', tclockdn, 'TC_LockDown' )
        self.logger.log( "[*]     TC_LockDown      : {:d}".format(TC_LockDown) )
        if TC_LockDown == 1:
            self.logger.log_passed_check( "Virtual Resource control registers [V0CTL, V1CTL] are locked" )
            return ModuleResult.PASSED
        else:
            self.logger.log_failed_check( "Virtual Resource control registers [V0CTL, V1CTL] are not locked" )
            return ModuleResult.FAILED

    def run(self,module_argv):
        self.logger.start_test("[*] checking TC Lock-Down is set (TCLOCKDN)..")
        self.res = self.check_TCLOCKDN()
        return self.res
