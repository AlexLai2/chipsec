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

from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS
TAGS = [MTAG_BIOS]

class smi_gpio(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.res = ModuleResult.NOTAPPLICABLE

    def is_supported(self):
        return self.cs.is_control_defined('GPIOSMIEnable')

    def check_smi_gpio(self):
        self.logger.start_test( 'GPIO SMI Config Lock' )

        self.logger.log('')
        self.logger.log( '[*] Check SMI GPIO setting...' )
        smi_en     = self.cs.read_register( 'SMI_EN' )
        self.logger.log( '[*]   SMI_EN               : 0x{:08X}'.format(smi_en) )
        smi_en_gpio  = self.cs.get_register_field( 'SMI_EN', smi_en, 'GPIO_UNLOCK_SMI_EN' )
        self.logger.log( '[*]     GPIO_UNLOCK_SMI_EN : {:d}'.format(smi_en_gpio) )
        if (0 != smi_en_gpio):
            self.logger.log_passed_check( 'SMI Config of GPIOs are locked down' )
            return ModuleResult.PASSED
        else:
            self.logger.log_warn_check( 'SMI Config of GPIOs are not locked down' )
            if self.cs.is_server():
                return ModuleResult.WARNING
            else:
                return ModuleResult.INFORMATION

    def run( self, module_argv ):
        self.res = self.check_smi_gpio()
        return self.res
