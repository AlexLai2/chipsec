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
# Authors:
#  HC Wang
#


"""
Checks if CPU support speculation control feature.

"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_HWCONFIG

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'spec_ctrl'

TAGS = [MTAG_HWCONFIG]

CPUID_PROCESSOR_INFO_EAX = 0x01

CPUID_EXTENDED_FEATURES_EAX = 0x07
CPUID_EXTENDED_FEATURES_ECX = 0x00
SPECULATION_CONTROL_PRESENCE_BIT = 0x04000000

class spec_ctrl(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        return True

    def check_spec_ctrl_support( self ):
        self.logger.start_test( "Speculation Control Check" )

        # get the processor info
        eax = CPUID_PROCESSOR_INFO_EAX

        (_eax,_ebx,_ecx,_edx) = self.cs.cpu.cpuid( eax, 0 )

        self.logger.log( "[CHIPSEC] CPU Info: 0x{:08X}".format(_eax) )

        # get uCode patch info
        ucode_revision = self.cs.read_register_field( 'IA32_BIOS_SIGN_ID', 'Microcode', False )

        self.logger.log( "[CHIPSEC] uCode Revision: 0x{:08X}".format(ucode_revision) )

        #check speculation control feature presence 
        eax = CPUID_EXTENDED_FEATURES_EAX
        ecx = CPUID_EXTENDED_FEATURES_ECX

        self.logger.log( "[CHIPSEC] CPUID < EAX: 0x{:08X}".format(eax))
        self.logger.log( "[CHIPSEC]         ECX: 0x{:08X}".format(ecx))

        (_eax,_ebx,_ecx,_edx) = self.cs.cpu.cpuid( eax, ecx )

        self.logger.log( "[CHIPSEC] CPUID > EAX: 0x{:08X}".format(_eax) )
        self.logger.log( "[CHIPSEC]         EBX: 0x{:08X}".format(_ebx) )
        self.logger.log( "[CHIPSEC]         ECX: 0x{:08X}".format(_ecx) )
        self.logger.log( "[CHIPSEC]         EDX: 0x{:08X}".format(_edx) )

        if (_edx & SPECULATION_CONTROL_PRESENCE_BIT):
            res = ModuleResult.PASSED
            self.logger.log_passed_check( "The CPU supports speculation control feature." )
        else:
            res = ModuleResult.FAILED
            self.logger.log_failed_check( "The CPU doesn't support speculation control feature, please update uCode!!!" )

        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.res = self.check_spec_ctrl_support()
        return self.res
