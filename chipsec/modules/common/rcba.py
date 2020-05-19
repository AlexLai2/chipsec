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
from chipsec.hal import mmio

RCBA_LIMIT = 0x4000
_64k_ALIGNED = 0xFFFF

class rcba(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.mmio = mmio.MMIO(self.cs)

    def is_supported(self):
        if self.cs.is_register_defined('RCBA') and self.cs.is_register_defined('GENPROTRANGE0_BASE'):
            return True
        else:
            self.res = ModuleResult.NOTAPPLICABLE
            return False

    def check_RCBA(self):
        self.logger.log("[*] checking if GENPROTRANGE_BASE/LIMIT pair overlaps with RCBA..")
        res = ModuleResult.FAILED
        (rcba, rcba_size) = self.mmio.get_MMIO_BAR_base_address( 'RCBA' )
        rcba_limit  = rcba + RCBA_LIMIT - 1
        for i in range(3):
            genprot_base       = self.cs.read_register( 'GENPROTRANGE'+ str(i)+ '_BASE' )
            genprot_base_addr  = self.cs.get_register_field( 'GENPROTRANGE'+ str(i)+ '_BASE', genprot_base, 'base_address', True )
            genprot_limit      = self.cs.read_register( 'GENPROTRANGE'+ str(i) + '_LIMIT' )
            genprot_limit_addr = self.cs.get_register_field( 'GENPROTRANGE0_LIMIT', genprot_limit, 'limit_address', True ) + _64k_ALIGNED
            if (genprot_base_addr <= rcba) and (genprot_limit_addr >= rcba_limit):
                res = ModuleResult.PASSED
            self.logger.log( "[*]   GENPROTRANGE{:d} [BASE-LIMIT] : 0x{:016X}-0x{:016X}".format(i,genprot_base_addr, genprot_limit_addr) )
        self.logger.log( "[*]   RCBA                       : 0x{:016X}-0x{:016X}".format(rcba, rcba_limit) )
        if res == ModuleResult.PASSED:
            self.logger.log_good( "A GENPROTRANGE_BASE/LIMIT does contain RCBA" )
        elif res == ModuleResult.FAILED:
            self.logger.log_bad( "A GENPROTRANGE_BASE/LIMIT does not completely contain RCBA" )

        if self.cs.is_register_defined('ULKMC') and (self.cs.register_has_field('ULKMC', 'RCBALK')):
            self.logger.log( "[*] checking RCBA is locked.." )
            ulkmc          = self.cs.read_register( 'ULKMC' )
            self.logger.log( "[*]   ULKMC              : 0x{:08X}".format(ulkmc) )
            rcbalk         = self.cs.get_register_field( 'ULKMC', ulkmc, 'RCBALK' )
            self.logger.log( "[*]     RCBALK           : {:d}".format(rcbalk) )
            ok = (1 == rcbalk)
            if ok:
                self.logger.log_good( "RCBA is locked" )
            else:
                self.logger.log_bad( "RCBA is not locked" )
                res = ModuleResult.FAILED

        return res


    def run(self,module_argv):
        self.logger.start_test("[*] checking if RCBA is locked and protected..")
        self.res = self.check_RCBA()
        if self.res == ModuleResult.PASSED:
            self.logger.log_passed_check("RCBA is locked and protected")
        else:
            self.logger.log_failed_check("RCBA is not locked and protected")
        return self.res
