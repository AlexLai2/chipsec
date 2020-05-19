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



"""
In EDK II  source code, some infrastructure exists for the Memory Overwrite Request (MOR) capability, which allows an OS to request that memory be cleared upon reboot
(see the TCG Platform Reset Attack Mitigation Specification Version 1.00, Revision .92 or later).

On some platforms, the signal to clear memory is not honored.
This could be because the platform-specific code to do the clear is not implemented or because the firmware fails to invoke this code correctly.
If the MOR signal is not honored, Cold Boot attacks may be able to more easily reveal encryption keys or other secrets from OS runtime.

http://www.trustedcomputinggroup.org/resources/pc_client_work_group_platform_reset_attack_mitigation_specification_version_10

https://msdn.microsoft.com/en-us/library/windows/hardware/mt270973(v=vs.85).aspx

.. note:: Before running this test, it will be necessary to disable memory scrambler in BIOS. On CRB, this can be done from the Setup menus. Failure to do this may cause a false negative (PASS when actual result is FAIL).

"""

import os
import time
import struct

from chipsec.module_common import BaseModule, ModuleResult
from chipsec.hal.uefi      import UEFI
from chipsec.module_common import cs_input

_MODULE_NAME = 'morclear'

MORC_NAME = "MemoryOverwriteRequestControl"
MORC_GUID = "e20939be-32d4-41be-a150-897f85d49829"

class morclear( BaseModule ):
    def __init__(self):
        BaseModule.__init__(self)
        self._uefi = UEFI(self.cs)

    def is_supported(self):
        supported = self.cs.helper.is_efi()
        if not supported:
            self.logger.log_skipped_check("MOR Clear should only be run from the UEFI Shell.")
            self.res = ModuleResult.SKIPPED
        return supported

    def set_morclear( self ):
        sentinel = 0xc0ffee00
        size     = 0x1000
        count    = 8
        self.logger.set_always_flush( True )

        if os.path.isfile( 'morClearReset.bin' ) == False:
            fileBuf = struct.pack( '3I', sentinel, size, count )
            self.logger.log( 'Writing 1 to MemoryOverwriteRequestControl' )
            mcr = struct.pack( 'B', 1 )
            f = open( 'setBitZero.bin', 'w' )
            f.write( mcr )
            f.close( )
            self._uefi.set_EFI_variable_from_file( MORC_NAME, MORC_GUID, 'setBitZero.bin' )
            for i in range( 0, count ):
                ( va, tempAddress ) = self.cs.mem.alloc_physical_mem( size, 0xFFFFFFFF )
                self.logger.log( '\tWriting sentinel value: {:X}, to address: {:X}'.format( sentinel, tempAddress ) )
                self.cs.mem.write_physical_mem_dword( tempAddress, sentinel )
                fileBuf += struct.pack( 'Q', tempAddress )
                val = self.cs.mem.read_physical_mem_dword( tempAddress )
                self.logger.log( 'Confirming write {:X}: {:X}'.format( tempAddress, val ) )
            # saving sentinel, size, count and addresses to file
            f = open( 'morClearReset.bin', 'w' )
            f.write( fileBuf )
            f.flush( )
            f.close( )
            time.sleep( 10 )
            self.logger.log( 'Rebooting the platform, please run this test again once the OS has loaded' )
            input = cs_input( "Type 'yes' to reboot > " )
            if input == 'yes':
                self.cs.io.write_port_byte( 0x0CF9, 0x06 )
        else:
            passed = True
            self.logger.log( 'Returning from a reboot, loading used data' )
            f = open( 'morClearReset.bin', 'r' )
            fileValues = f.read()
            f.close( )
            ( sentinel, size, count ) = struct.unpack( '3I', fileValues[:12] )
            self.logger.log( 'Looking for sentinel value {:X} in memory...'.format( sentinel ) )
            addresses = struct.unpack('Q'*count, fileValues[12:])
            for i in range( 0, count ):
                tempAddress = addresses[i]
                val = self.cs.mem.read_physical_mem_dword( tempAddress )
                self.logger.log( 'Reading address {:X}: {:X}'.format( tempAddress, val ) )
                if val == sentinel:
                    passed = False
            os.remove( 'morClearReset.bin' )
            os.remove( 'setBitZero.bin' )
            if passed:
                self.logger.log_passed_check( 'PASSED: No sentinel values were detected. Memory appears to have been cleared after reboot' )
                return ModuleResult.PASSED
            else:
                self.logger.log_failed_check( 'FAILED: Sentinel value does not appear to be cleared from memory after reboot' )
                return ModuleResult.FAILED



    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.res = self.set_morclear()
        return self.res
