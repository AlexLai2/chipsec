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

class cf9_lock(BaseModule):
    def __init__(self):
        super(cf9_lock,self).__init__()

    def is_supported(self):
        if self.cs.is_register_defined('ETR3') and self.cs.register_has_field('ETR3','CF9LOCK'):
            return True
        return False

    def check_cf9_lock(self):
        res = ModuleResult.PASSED
        ETR3 = self.cs.read_register('ETR3')
        self.cs.print_register('ETR3', ETR3)
        if self.cs.get_register_field('ETR3', ETR3, 'CF9LOCK') == 0:
            res = ModuleResult.FAILED
            self.logger.log_failed('CF9 Lockdown bit not set.')
        else:
            self.logger.log_good('CF9 LOckdown bit is set.')
        return res

    def run(self, module_argv):
        self.logger.start_test('Checking that CF9LOCK bit is set')
        self.res = self.check_cf9_lock()
        return self.res
