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

from chipsec.module_common import ModuleResult, BaseModule
from chipsec.chipset import CHIPSET_CODE_JKT, CHIPSET_CODE_IVT, CHIPSET_CODE_HSX, CHIPSET_CODE_BDX


class spd_config(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.res = ModuleResult.NOTAPPLICABLE
        self.cid = None
        self.servers_ddr3 = [CHIPSET_CODE_JKT, CHIPSET_CODE_IVT, CHIPSET_CODE_HSX, CHIPSET_CODE_BDX]
        self.servers_ddr4 = [CHIPSET_CODE_HSX, CHIPSET_CODE_BDX]

    def is_supported(self):
        if self.cs.is_register_defined('SMB_CMD_CFG_0') or self.cs.is_register_defined('SMBCNTL_0_19') or self.cs.is_register_defined('SMBCNTL_0'):
            if self.cs.is_server():  # Client will be tested in a different module
                self.cid = self.cs.get_chipset_code()
                if (self.cid in self.servers_ddr3):
                    return True
        else:
            self.res = ModuleResult.NOTAPPLICABLE
            return False

    def check_SPDCONFIG(self):
        res = ModuleResult.PASSED
        if self.cs.is_register_defined('SMB_CMD_CFG_0'):
            regs = ['SMB_CMD_CFG_0', 'SMB_CMD_CFG_1', 'SMB_CMD_CFG_2']
        elif self.cs.is_register_defined('SMBCNTL_0_19'):
            regs = ['SMBCNTL_0_19', 'SMBCNTL_0_22', 'SMBCNTL_1_19', 'SMBCNTL_1_22']
        elif self.cs.is_register_defined('SMBCNTL_0'):
            regs = ['SMBCNTL_0', 'SMBCNTL_1']
        else:
            return ModuleResult.NOTAPPLICABLE

        for reg in regs:
            cntl = self.cs.read_register(reg)
            self.logger.log( '[*] {}    : 0x{:08X}'.format(reg,cntl) )
            if self.cs.is_device_enabled( '_' + reg ):
                smb_dis_wrt = self.cs.get_register_field( reg , cntl, 'smb_dis_wrt' )
                self.logger.log( '[*]   smb_dis_wrt    : {:d}'.format(smb_dis_wrt) )
                if smb_dis_wrt:
                    self.logger.log_good( 'SMBCNTL_0 SMBUS write disabled' )
                elif self.cid in self.servers_ddr4:
                    self.logger.log_warn_check("This platform can support both DDR3 and DDR4 DIMMs" )
                    self.logger.log_warn_check("If DDR3 DIMMs installed, this is a FAILURE.  Otherwise, NOT_APPLICABLE.")
                    res = ModuleResult.WARNING
                else:
                    self.logger.log_bad( 'SMBCNTL_0 SMBUS write not disabled' )
                    res = ModuleResult.FAILED
            else:
                self.logger.log_not_applicable_check( 'Device may be disabled. Bypassing check.' )
                res = ModuleResult.NOTAPPLICABLE
        return res

    def run(self,module_argv):
        self.logger.start_test('[*] Checking SPD Configuration...')

        self.res = self.check_SPDCONFIG()
        return self.res
