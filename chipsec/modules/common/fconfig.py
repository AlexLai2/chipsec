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

""" SMM Tests
Reference: Platform Secure Configuration Spec

"""

from chipsec.module_common import *
import chipsec.chipset
import chipsec.logger
from chipsec.hal.mmio import *


TAGS = [MTAG_HWCONFIG]

AES_NI = 0x2000000

class fconfig(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.res = ModuleResult.PASSED

    def is_supported(self):
        return True

    def check_featureconfig(self):
        self.logger.start_test( 'FEATURE_CONFIG Lock' )
        self.logger.log( '[*] Verifying FEATURE_CONFIG register is locked..' )
        feat_conf = self.cs.read_register( 'FEATURE_CONFIG' )
        self.cs.print_register( 'FEATURE_CONFIG', feat_conf)
        ok = self.cs.get_control( 'FeatureConfigLock')
        if ok: self.logger.log_passed_check( 'FEATURE_CONFIG.Lock is set' )
        else: self.logger.log_failed_check( 'FEATURE_CONFIG.Lock is not set' )

        if (self.cs.helper.os_system != 'uefi'):
            (r_eax, r_ebx, r_ecx, r_edx) = self.cs.cpu.cpuid( 0x01, 0x00 )
        else:
            self.logger.log('')
            self.logger.log_important( 'Assuming AES_NI available...' )
            r_ecx = AES_NI
        if (r_ecx & AES_NI != 0):
            self.logger.log('')
            if self.logger.VERBOSE: self.logger.log( 'Processor was manufactured with AES-NI enabled.' )
            return ok
        else:
            self.logger.log('')
            if self.logger.VERBOSE: self.logger.log_skipped_check( 'Processor was not manufactured with AES-NI enabled.  Ignoring FEATURE_CONFIG check.' )
            return True

    def run(self, module_argv):
        return self.check_featureconfig()