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

from chipsec.module_common import ModuleResult, BaseModule, MTAG_SMM, MTAG_HWCONFIG
from chipsec.chipset import CHIPSET_CODE_BDX, CHIPSET_CODE_HSX, CHIPSET_CODE_KNL, CHIPSET_CODE_SKX, CHIPSET_CODE_JVL

_MODULE_NAME = 'miscctrlsts0'


TAGS = [MTAG_SMM, MTAG_HWCONFIG]

SUPPORTED_CS = [CHIPSET_CODE_BDX,
                CHIPSET_CODE_HSX,
                CHIPSET_CODE_KNL,
                CHIPSET_CODE_SKX,
                CHIPSET_CODE_JVL]

BUSES = [0]
DEVICES = [0, 1, 2, 3, 4, 5, 6, 7]
FUNCTIONS = [0, 1, 2, 3]

class miscctrlsts0(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.defined_devices = []
        self.enabled_devices = []
        self.res = ModuleResult.PASSED


    def is_supported(self):
        if self.cs.get_chipset_code() in SUPPORTED_CS:
            return True
        else:
            self.res = ModuleResult.NOTAPPLICABLE
            return False

    def scan_miscctrlsts_registers(self):
        for b in BUSES:
            for d in DEVICES:
                for f in FUNCTIONS:
                    name = "MISCCTRLSTS0_{:d}.{:d}.{:d}".format(b, d, f)
                    if self.cs.is_register_defined(name):
                        self.defined_devices.append(name)
                        if self.logger.VERBOSE:
                            self.logger.log("Found {:s}".format(name))

        for d in self.defined_devices:
            name = "_{:s}".format(d)
            if self.cs.is_device_enabled(name):
                self.enabled_devices.append(d)
                if self.logger.VERBOSE:
                    self.logger.log("{:s} is enabled".format(name))

    def check_miscctrlsts(self):
        res = ModuleResult.PASSED

        self.logger.log( '' )

        for d in self.enabled_devices:
            reg_value = self.cs.read_register(d)
            bdf = d.split('_').pop()
            self.logger.log( '[*] MISCCTRLSTS0 [{:s}]           : 0x{:08X}'.format(bdf, reg_value) )
            inbound = self.cs.get_register_field( d, reg_value, 'inbound_configuration_enable' )
            self.logger.log( '[*]   inbound_configuration_enable : {:d}'.format(inbound) )
            if inbound == 1:
                res = ModuleResult.FAILED
        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.logger.start_test("[*] Verifying MISCCTRLSTS_0.inbound_configuration_enable bit is not set on every PCI port..")
        self.scan_miscctrlsts_registers()
        self.res = self.check_miscctrlsts()
        if self.res == ModuleResult.PASSED:
            self.logger.log_passed_check( "Inbound Configuration Requests are disabled on all PCI ports." )
        elif self.res == ModuleResult.FAILED:
            self.logger.log_failed_check( "Inbound Configuration Requests are not disabled on all PCI ports." )
        return self.res
