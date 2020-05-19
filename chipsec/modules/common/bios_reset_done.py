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

class bios_reset_done(BaseModule):
    def __init__(self):
        super(bios_reset_done,self).__init__()

    def is_supported(self):
        if self.cs.is_register_defined('BIOS_RESET_CPL') and self.cs.register_has_field('BIOS_RESET_CPL','BIOS_RESET_DONE'):
            return True
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_bios_reset_done(self):
        res = ModuleResult.PASSED
        BIOS_RESET_CPL = self.cs.get_register('BIOS_RESET_CPL')
        BIOS_RESET_DONE = self.cs.get_register_field('BIOS_RESET_CPL',BIOS_RESET_CPL,'BIOS_RESET_DONE')
        if BIOS_RESET_DONE == 1:
            self.logger.log_passed("BIOS_RESET_DONE is set!")
        else:
            res = ModuleResult.FAILED
            self.logger.log_failed("BIOS_RESET_DONE is not set!")
        return res

    def run(self, module_argv):
        self.logger.start_test('Checking that bios_reset_done bit is set')
        self.res = self.check_bios_reset_done()
        return self.res
