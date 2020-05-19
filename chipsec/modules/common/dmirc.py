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

class dmirc(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        if self.cs.is_register_defined('DMIRCBAR'):
            return True
        else:
            self.res = ModuleResult.NOTAPPLICABLE
            return False

    def check_DMIRC(self):
        dmircbar = self.cs.read_register( 'DMIRCBAR' )
        self.logger.log( "[*]   DMIRCBAR           : 0x{:08X}".format(dmircbar) )
        dmircbar_en = self.cs.get_register_field( 'DMIRCBAR', dmircbar, 'dmircbaren' )
        self.logger.log( "[*]     dmircbaren       : {:d}".format(dmircbar_en) )
        ok = (0 == dmircbar_en)
        if ok:
            self.logger.log_passed_check( "DMIRCBAR is disabled" )
            return ModuleResult.PASSED
        else:
            self.logger.log_failed_check( "DMIRCBAR is not disabled" )
            return ModuleResult.FAILED

    def run(self,module_argv):
        self.logger.start_test("[*] checking DMI Root Complex BAR settings..")
        self.res = self.check_DMIRC()
        return self.res
