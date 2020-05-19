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

class bmbound_check(BaseModule):
    def __init__(self):
        super(bmbound_check,self).__init__()

    def is_supported(self):
        if self.cs.is_register_defined('RTF_BMBOUND') and self.cs.is_register_defined('RTF_BMBOUNDHI'):
            return True
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_bmbound_locks(self):
        res = ModuleResult.PASSED
        BMBOUND = self.cs.read_register('RTF_BMBOUND')
        BMBOUND_LOCK = self.cs.get_register_field('RTF_BMBOUND',BMBOUND,'LOCK')
        if BMBOUND_LOCK == 1:
            self.logger.log_good("RTF_BMBOUND lock is set!")
        else:
            res = ModuleResult.FAILED
            self.logger.log_bad("RTF_BMBOUND lock is not set!")
        BMBOUNDHI = self.cs.read_register('RTF_BMBOUNDHI')
        BMBOUNDHI_LOCK = self.cs.get_register_field('RTF_BMBOUNDHI',BMBOUNDHI,'LOCK')
        if BMBOUNDHI_LOCK == 1:
            self.logger.log_good("RTF_BMBOUNDHI lock is set!")
        else:
            res = ModuleResult.FAILED
            self.logger.log_bad("RTF_BMBOUNDHI lock is not set!")
        return res

    def run(self, module_argv):
        self.logger.start_test('Checking that RTF_BMBOUND{HI} locks are set')
        self.res = self.check_bmbound_locks()
        return self.res
