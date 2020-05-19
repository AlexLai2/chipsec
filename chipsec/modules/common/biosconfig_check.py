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

class biosconfig_check(BaseModule):
    def __init__(self):
        super(biosconfig_check,self).__init__()

    def is_supported(self):
        if self.cs.is_register_defined('BIOS_CONFIG') and self.cs.register_has_field("BIOS_CONFIG","LOCK"):
            return True
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_mailbox_lock(self):
        res = ModuleResult.PASSED
        BIOS_CONFIG = self.cs.read_register('BIOS_CONFIG')
        MAILBOX_LOCK = self.cs.get_register_field('BIOS_CONFIG',BIOS_CONFIG,'LOCK')
        if MAILBOX_LOCK == 1:
            self.logger.log_passed("Mailbox is locked!")
        else:
            res = ModuleResult.FAILED
            self.logger.log_failed("Mailbox is not locked!")
        return res

    def run(self, module_argv):
        self.logger.start_test('Checking that BIOS_CONFIG mailbox is locked')
        self.res = self.check_mailbox_lock()
        return self.res
