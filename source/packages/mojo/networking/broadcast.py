"""
.. module:: broadcast
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Module that contains broadcast helper functions.

.. moduleauthor:: Myron Walker <myron.walker@gmail.com>
"""

__author__ = "Myron Walker"
__copyright__ = "Copyright 2023, Myron W Walker"
__credits__ = []
__version__ = "1.0.0"
__maintainer__ = "Myron Walker"
__email__ = "myron.walker@gmail.com"
__status__ = "Development" # Prototype, Development or Production
__license__ = "MIT"

def broadcast_wake_on_lan_magic_message(brodcast_addr: str, mac_addr: str):
    '[FF FF FF FF FF FF] + [mac] * 16   ( len 102 bytes )'
    return