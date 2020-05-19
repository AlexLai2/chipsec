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
#  Yuriy Bulygin
#


import os
import time

from  chipsec.file import read_file, write_file
from chipsec.command import BaseCommand

from chipsec.hal.spi import FLASH_DESCRIPTOR, BIOS, ME
from chipsec.hal.spi_descriptor import get_spi_flash_descriptor, get_spi_regions, parse_spi_flash_descriptor
from chipsec.hal.spi_me import parse_me_region_from_file
from chipsec.hal.spi_uefi import decode_uefi_region
from chipsec.hal.uefi import UEFI
from chipsec.hal.uefi_platform import fw_types


# ###################################################################
#
# Complete decode of SPI flash memory image including ME region
#
# ###################################################################

class FullDecodeCommand(BaseCommand):
    """
    >>> chipsec_util decodefull <rom> [fw_type]\n

    For a list of fw types run:

    >>> chipsec_util decodefull types

    Examples:

    >>> chipsec_util decodefull spi.bin vss
    """
    def requires_driver(self):
        return False

    def run(self):

        if self.argv[2] == '--help':
            print (FullDecodeCommand.__doc__)
            return

        _uefi = UEFI( self.cs )
        if self.argv[2] == "types":
            print ("\n<fw_type> should be in [ {} ]\n".format( " | ".join( [str(t) for t in fw_types] ) ))
            return

        rom_file = self.argv[2]

        fwtype = ''
        if 4 == len(self.argv):
            fwtype = self.argv[3]

        self.logger.log( "[CHIPSEC] Decoding SPI ROM image from a file '{}'".format(rom_file) )
        t = time.time()

        f = read_file( rom_file )
        (fd_off, fd) = get_spi_flash_descriptor( f )
        if (-1 == fd_off) or (fd is None):
            self.logger.error( "Could not find SPI Flash descriptor in the binary '{}'".format(rom_file) )
            return False

        self.logger.log( "[CHIPSEC] Found SPI Flash descriptor at offset 0x{:x} in the binary '{}'".format(fd_off, rom_file) )
        rom = f[fd_off:]

        # Decoding SPI Flash Regions
        # flregs[r] = (r,SPI_REGION_NAMES[r],flreg,base,limit,notused)
        flregs = get_spi_regions( fd )
        if flregs is None:
            self.logger.error( "SPI Flash descriptor region is not valid" )
            return False

        _orig_logname = self.logger.LOG_FILE_NAME

        pth = os.path.join( self.cs.helper.getcwd(), rom_file + ".dir" )
        if not os.path.exists( pth ):
            os.makedirs( pth )

        for r in flregs:
            idx     = r[0]
            name    = r[1]
            base    = r[3]
            limit   = r[4]
            notused = r[5]
            if not notused:
                region_data = rom[base:limit+1]
                fname = os.path.join( pth, '{:d}_{:04X}-{:04X}_{}.bin'.format(idx, base, limit, name) )
                write_file( fname, region_data )
                if FLASH_DESCRIPTOR == idx:
                    # Decoding Flash Descriptor
                    self.logger.set_log_file( os.path.join( pth, fname + '.log' ) )
                    parse_spi_flash_descriptor( self.cs, region_data )
                elif ME == idx:
                    # Decoding ME Region
                    self.logger.set_log_file( os.path.join( pth, fname + '.log' ) )
                    parse_me_region_from_file( fname )
                elif BIOS == idx:
                    # Decoding EFI Firmware Volumes
                    self.logger.set_log_file( os.path.join( pth, fname + '.log' ) )
                    decode_uefi_region(_uefi, pth, fname, fwtype)

        self.logger.set_log_file( _orig_logname )
        self.logger.log( "[CHIPSEC] (decode) time elapsed {:.3f}".format(time.time()-t) )


commands = { 'decodefull': FullDecodeCommand }
