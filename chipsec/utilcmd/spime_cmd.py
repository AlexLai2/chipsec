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


import time

from chipsec.command import BaseCommand

from chipsec.hal.spi_me import parse_me_region_from_file

class MECommand(BaseCommand):
    """
    >>> chipsec_util me [rom]

    Examples:

    >>> chipsec_util me spi.bin
    """
    def requires_driver(self):
        return False

    def run(self):
        if self.argv[2] == '--help':
            print (MECommand.__doc__)
            return

        rom_file = self.argv[2]
        self.logger.log( "[CHIPSEC] Parsing SPI ME Region from file '{}'\n".format(rom_file) )

        t = time.time()
        parse_me_region_from_file( rom_file )
        self.logger.log( "\n[CHIPSEC] (me) time elapsed {:.3f}".format(time.time()-t) )


commands = { 'me': MECommand }
