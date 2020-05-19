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
#Copyright (c) 2019-2020, Intel Corporation
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

class bios_wpd(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        return self.cs.is_control_defined('BiosWriteEnable')

    def run(self, module_argv):
        self.logger.start_test('BIOS Write Enable Check')
        self.res = ModuleResult.PASSED
        wpd = self.cs.get_control('BiosWriteEnable')
        self.logger.log('[*] BIOS Write Enable (WPD) State: 0x{:02X}'.format(wpd))
        if wpd != 0:
            self.res = ModuleResult.FAILED
            self.logger.log_failed('BIOS Write Enable (WPD) already set.')
            return self.res
        self.logger.log('[*] Setting BIOS Write Enable (WPD)')
        self.cs.set_control('BiosWriteEnable', 1)
        wpd = self.cs.get_control('BiosWriteEnable')
        self.logger.log('[*] BIOS Write Enable (WPD) State: 0x{:02X}'.format(wpd))
        if wpd != 0:
            self.res = ModuleResult.FAILED
            self.logger.log_failed('BIOS Write Enable (WPD) not reset by SMI handler.')
        else:
            self.logger.log_passed('BIOS Write Enable (WPD) reset by SMI handler.')
        return self.res
