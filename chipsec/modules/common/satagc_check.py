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
#Copyright (c) 2020, Intel Corporation
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
from chipsec.module_common import BaseModule, ModuleResult

class satagc_check(BaseModule):
    def __init__(self):
        super(satagc_check,self).__init__()

    def is_supported(self):
        if self.cs.is_register_defined('SATAGC') and self.cs.register_has_field("SATAGC","REGLOCK"):
            return True
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_satagc_lock(self):
        res = ModuleResult.PASSED
        SATAGC = self.cs.read_register('SATAGC')
        SATAGC_REGLOCK = self.cs.get_register_field('SATAGC',SATAGC,'REGLOCK')
        if SATAGC_REGLOCK == 1:
            self.logger.log_passed("SATAGC_REGLOCK is set!")
        else:
            res = ModuleResult.FAILED
            self.logger.log_failed("SATAGC_REGLOCK is not set!")
        return res

    def run(self, module_argv):
        self.logger.start_test('Checking that SATAGC_RELGOCK is set')
        self.res = self.check_satagc_lock()
        return self.res
