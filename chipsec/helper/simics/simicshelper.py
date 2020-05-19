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
#Copyright (c) 2018-2020, Intel Corporation
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
Intel In-Target Probe (ITPII) / DFx Abstraction Layer (DAL) helper for SIMICS
"""

__version__ = '1.0'

import struct
import sys

from chipsec.logger import logger
import itpii
import ipccli
from ctypes import *
from chipsec.helper.oshelper import Helper


class SimicsHelperError (RuntimeError):
    pass


class SimicsHelper(Helper):
    ### Make thread to use selectable?
    def __init__(self):
        super(SimicsHelper, self).__init__()
        self.base = itpii.baseaccess()
        if logger().VERBOSE:
            logger().log( '[helper] Simics Helper' )
        if not len(self.base.threads):
            logger().log( '[helper] No threads detected!  Simics Helper will fail to load!' )
        elif self.base.threads[self.find_thread()].cv.isrunning:
            self.base.halt()
        self.os_system  = '(Via Simics ITP DAL)'
        self.os_release = '(N/A)'
        self.os_version = self.dal_version()
        self.os_machine = self.target_machine()

    def __del__(self):
        if not len(self.base.threads):
            logger().log( '[helper] No threads detected!' )
        elif not self.base.threads[self.find_thread()].cv.isrunning:
            logger().log( '[helper] Threads are halted' )
        else:
            logger().log( '[helper] Threads are running' )


###############################################################################################
# Driver/service management functions
###############################################################################################

    def create( self, start_driver ):
        if logger().VERBOSE:
            logger().log( '[helper] Simics Helper created' )
        return True

    def start( self, start_driver, driver_exhists=False ):
        self.driver_loaded = True
        if self.base.threads[self.find_thread()].cv.isrunning:
            self.base.halt()
        if logger().VERBOSE:
            logger().log( '[helper] Simics Helper started/loaded' )
        return not self.base.threads[self.find_thread()].cv.isrunning

    def stop( self, start_driver ):
        self.base.go()
        if logger().VERBOSE:
            logger().log( '[helper] Simics Helper stopped/unloaded' )
        return self.base.threads[self.find_thread()].cv.isrunning

    def delete( self, start_driver ):
        if logger().VERBOSE:
            logger().log( '[helper] Simics Helper deleted' )
        return True


###############################################################################################
# Functions to get information about the remote target
###############################################################################################

    def target_machine( self ):
        return self.base.devicelist[0].devicetype + '-' + self.base.devicelist[0].stepping

    def dal_version( self ):
        return self.base.cv.version

    # return first enabled thread
    def find_thread( self ):
        for en_thread in range(len(self.base.threads)):
            if self.base.threads[en_thread].isenabled:
                return en_thread
        logger().log( '[WARNING] No enabled threads found.' )
        return 0

###############################################################################################
# Actual API functions to access HW resources
###############################################################################################

    #
    # PCIe configuration access
    #

    def pci_addr( self, bus, device, function, offset ):
        if (bus >= 256) or (device >= 32) or (function >= 8) or (offset >= 256):
            logger().log( '[WARNING] PCI access out of range. Use mmio functions to access PCIEXBAR.' )
        config_addr = self.base.threads[self.find_thread()].dport(0xCF8)
        config_addr &= 0x7f000003 # Zero out non-reserved bits
        config_addr |= 0x80000000 # Set the Config enable bit
        config_addr |= (bus & 0xFF) << 16 # Set the bus number
        config_addr |= (device & 0x1F) << 11 # Set the device number
        config_addr |= (function & 0x07) << 8 # Set the function number
        config_addr |= (offset & 0xFF) << 0 # Set the offset
        return config_addr

    ### TODO: use port/wport/dport for byte/word/dword access respectively
    ### WA: add byte/word/dword access respectively
    ### Limitation: If the address is not alignment, the return value would be truncated.
    def read_pci_reg( self, bus, device, function, address, size ):
        value = 0xFFFFFFFF
        ie_thread = self.find_thread()
        self.base.threads[ie_thread].dport(0xCF8, self.pci_addr(bus, device, function, address))
        value = (self.base.threads[ie_thread].dport(0xCFC) >> ((address % 4) * 8))
        if 1 == size:
            value &= 0xFF
        elif 2 == size:
            value &= 0xFFFF
        return int(value)

    def write_pci_reg( self, bus, device, function, address, dword_value, size ):
        old_value = 0xFFFFFFFF
        ie_thread = self.find_thread()
        self.base.threads[ie_thread].dport(0xCF8, self.pci_addr(bus, device, function, address))
        old_value = self.base.threads[ie_thread].dport(0xCFC)
        self.base.threads[ie_thread].dport(0xCFC, dword_value)
        return old_value

    #
    # Physical memory access
    #

    def read_physical_mem( self, phys_address, length, bytewise=False ):
        # read memory in largest chunks possible unless bytewise is set
        if bytewise :
            width = 1
        else :
            # do we need to handle systems that don't support quad-word memory accesses?
            width = 8
        out_buf = (c_char * length)()
        ptr = 0
        format = {1: 'B', 2: 'H', 4: 'L', 8:'Q'}
        while width >= 1 :
            while (length - ptr) >= width :
                v = self.base.threads[self.find_thread()].mem(str(ipccli.address.ItpAddress(phys_address + ptr)), width)
                struct.pack_into(format[width], out_buf, ptr, long(v))
                ptr += width
            width = width / 2
        return ''.join(out_buf)

    def write_physical_mem( self, phys_address, length, buf, bytewise=False ):
        # write memory in largest chunks possible unless bytewise is set
        if bytewise :
            width = 1
        else :
            # do we need to handle systems that don't support quad-word memory accesses?
            width = 8
        ptr = 0
        format = {1: 'B', 2: 'H', 4: 'L', 8:'Q'}
        while width >= 1 :
            while (length - ptr) >= width :
                v = struct.unpack_from(format[width], buf, ptr)
                self.base.threads[self.find_thread()].mem(str(ipccli.address.ItpAddress(phys_address + ptr)), width, v[0])
                self.base.threads[self.find_thread()].mem(phys_address + ptr, width, v[0])
                ptr += width
            width = width / 2
        return

    def read_phys_mem( self, phys_address_hi, phys_address_lo, length ) :
        return self.read_physical_mem((phys_address_hi << 32) | phys_address_lo, length)

    def write_phys_mem( self, phys_address_hi, phys_address_lo, length, buf ) :
        self.write_physical_mem((phys_address_hi << 32) | phys_address_lo, length, buf)
        return

    def alloc_phys_mem( self, length, max_pa ):
        logger().error( '[helper] API alloc_phys_mem() is not supported' )
        return None

    #
    # CPU I/O port access
    #

    def read_io_port( self, io_port, size ):
        if size == 1 :
            val = self.base.threads[self.find_thread()].port(io_port)
        elif size == 2 :
            val = self.base.threads[self.find_thread()].wport(io_port)
        elif size == 4 :
            val = self.base.threads[self.find_thread()].dport(io_port)
        else :
            raise SimicsHelperError(size, 'is not a valid IO port size.')
        return int(val)

    def write_io_port( self, io_port, value, size ):
        if size == 1 :
            self.base.threads[self.find_thread()].port(io_port, value)
        elif size == 2 :
            self.base.threads[self.find_thread()].wport(io_port, value)
        elif size == 4 :
            self.base.threads[self.find_thread()].dport(io_port, value)
        else :
            raise SimicsHelperError(size, 'is not a valid IO port size.')
        return

    #
    # CPU related API
    #

    def read_msr( self, thread, msr_addr ):
        if not self.base.threads[thread].isenabled:
            en_thread = self.find_thread()
            logger().log( '[WARNING] Selected thread [{:d}] was disabled, using [{:d}].'.format(thread, en_thread) )
            thread = en_thread
        val = self.base.threads[thread].msr( msr_addr )
        edx = ( long(val) >> 32 )
        eax = long(val) & 0xffffffff
        return ( eax, edx )

    def write_msr( self, thread, msr_addr, eax, edx ):
        if not self.base.threads[thread].isenabled:
            en_thread = self.find_thread()
            logger().log( '[WARNING] Selected thread [{:d}] was disabled, using [{:d}].'.format(thread, en_thread) )
            thread = en_thread
        val = ( edx << 32 ) | eax
        self.base.threads[thread].msr( msr_addr, val )
        return True

    def read_cr(self, cpu_thread_id, cr_number):
        if not self.base.threads[cpu_thread_id].isenabled:
            en_thread = self.find_thread()
            logger().log( '[WARNING] Selected thread [{:d}] was disabled, using [{:d}].'.format(cpu_thread_id, en_thread) )
            cpu_thread_id = en_thread
        if cr_number == 0:
            val = self.base.threads[cpu_thread_id].state.regs.cr0.value
        elif cr_number == 2:
            val = self.base.threads[cpu_thread_id].state.regs.cr2.value
        elif cr_number == 3:
            val = self.base.threads[cpu_thread_id].state.regs.cr3.value
        elif cr_number == 4:
            val = self.base.threads[cpu_thread_id].state.regs.cr4.value
        elif cr_number == 8:
            val = self.base.threads[cpu_thread_id].state.regs.cr8.value
        else:
            logger().log( '[ERROR] Selected CR{:d} is not supported.'.format(cr_number) )
            val = 0
        return val

    def write_cr(self, cpu_thread_id, cr_number, value):
        if not self.base.threads[cpu_thread_id].isenabled:
            en_thread = self.find_thread()
            logger().log( '[WARNING] Selected thread [{:d}] was disabled, using [{:d}].'.format(cpu_thread_id, en_thread) )
            cpu_thread_id = en_thread
        if cr_number == 0:
            self.base.threads[cpu_thread_id].state.regs.cr0 = value
        elif cr_number == 2:
            self.base.threads[cpu_thread_id].state.regs.cr2 = value
        elif cr_number == 3:
            self.base.threads[cpu_thread_id].state.regs.cr3 = value
        elif cr_number == 4:
            self.base.threads[cpu_thread_id].state.regs.cr4 = value
        elif cr_number == 8:
            self.base.threads[cpu_thread_id].state.regs.cr8 = value
        else:
            logger().log( '[ERROR] Selected CR{:d} is not supported.'.format(cr_number) )
            return False
        return True

    def load_ucode_update( self, core_id, ucode_update_buf ):
        logger().error( '[helper] API load_ucode_update() is not supported yet' )
        return False

    def get_threads_count( self ):
        no_threads = len(self.base.threads)
        if logger().VERBOSE:
            logger().log( '[helper] Threads discovered : 0x{:X} ({:d})'.format(no_threads, no_threads) )
        return no_threads

    def cpuid(self, eax, ecx):
        ie_thread = self.find_thread()
        reax = int(self.base.threads[ie_thread].cpuid_eax(eax,ecx))
        rebx = int(self.base.threads[ie_thread].cpuid_ebx(eax,ecx))
        recx = int(self.base.threads[ie_thread].cpuid_ecx(eax,ecx))
        redx = int(self.base.threads[ie_thread].cpuid_edx(eax,ecx))
        return (reax, rebx, recx, redx)

    def get_descriptor_table( self, cpu_thread_id, desc_table_code ):
        logger().error( '[helper] API get_descriptor_table() is not supported yet' )
        return None

    #
    # EFI Variable API
    #

    # @TODO: Simics helper doesn't support EFI runtime API yet
    def EFI_supported(self):
        return False

    # Placeholders for EFI Variable API

    def delete_EFI_variable(self, name, guid):
        logger().error( '[helper] API delete_EFI_variable() is not supported yet' )
        return None
    def native_delete_EFI_variable(self, name, guid):
        logger().error( '[helper] API native_delete_EFI_variable() is not supported yet' )
        return None

    def list_EFI_variables(self):
        logger().error( '[helper] API list_EFI_variables() is not supported yet' )
        return None
    def native_list_EFI_variables(self):
        logger().error( '[helper] API native_list_EFI_variables() is not supported yet' )
        return None

    def get_EFI_variable(self, name, guid, attrs=None):
        logger().error( '[helper] API get_EFI_variable() is not supported yet' )
        return None
    def native_get_EFI_variable(self, name, guid, attrs=None):
        logger().error( '[helper] API native_get_EFI_variable() is not supported yet' )
        return None

    def set_EFI_variable(self, name, guid, data, datasize, attrs=None):
        logger().error( '[helper] API set_EFI_variable() is not supported yet' )
        return None
    def native_set_EFI_variable(self, name, guid, data, datasize, attrs=None):
        logger().error( '[helper] API native_set_EFI_variable() is not supported yet' )
        return None

    #
    # Memory-mapped I/O (MMIO) access
    #

    def map_io_space(self, physical_address, length, cache_type):
        return physical_address

    def read_mmio_reg(self, phys_address, size):
        out_buf = self.read_physical_mem( phys_address, size )
        if size == 8:
            value = struct.unpack( '=Q', out_buf[:size] )[0]
        elif size == 4:
            value = struct.unpack( '=I', out_buf[:size] )[0]
        elif size == 2:
            value = struct.unpack( '=H', out_buf[:size] )[0]
        elif size == 1:
            value = struct.unpack( '=B', out_buf[:size] )[0]
        else: value = 0
        return value

    def write_mmio_reg(self, phys_address, size, value):
        if size == 8:
            buf = struct.pack( '=Q', value )
        elif size == 4:
            buf = struct.pack( '=I', value&0xFFFFFFFF )
        elif size == 2:
            buf = struct.pack( '=H', value&0xFFFF )
        elif size == 1:
            buf = struct.pack( '=B', value&0xFF )
        else: buf = 0
        self.write_physical_mem( phys_address, size, buf )

    #
    # Interrupts
    #
    def send_sw_smi( self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi ):
        logger().error( '[helper] API send_sw_smi() is not supported' )
        return None

    def set_affinity( self, value ):
        logger().error( '[helper] API set_affinity() is not supported' )
        return 0

    def get_affinity( self ):
        logger().error( '[helper] API get_affinity() is not supported' )
        return 0

    #
    # ACPI tables access
    #
    def get_ACPI_SDT( self ):
        logger().error( '[helper] API get_ACPI_SDT() is not supported' )
        return None, None

    def native_get_ACPI_table( self, table_name ):
        logger().error( '[helper] API native_get_ACPI_table() is not supported' )
        return None

    def get_ACPI_table( self ):
        logger().error( '[helper] API get_ACPI_table() is not supported' )
        return None

    #
    # IOSF Message Bus access
    #
    def msgbus_send_read_message( self, mcr, mcrx ):
        logger().error( '[helper] API msgbus_send_read_message() is not supported' )
        return None

    def msgbus_send_write_message( self, mcr, mcrx, mdr ):
        logger().error( '[helper] API msgbus_send_write_message() is not supported' )
        return None

    def msgbus_send_message( self, mcr, mcrx, mdr=None ):
        logger().error( '[helper] API msgbus_send_message() is not supported' )
        return None

    #
    # File system
    #
    def get_tool_info( self, tool_type ):
        logger().error( '[helper] API get_tool_info() is not supported' )
        return None,None

def get_helper():
    return SimicsHelper()

if __name__ == '__main__':
    try:
        logger().log( 'Not doing anything...' )

    except SimicsHelperError as msg:
        logger().log(msg)
