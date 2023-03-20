"""
.. module:: exceptions
    :platform: Darwin, Linux, Unix, Windows
    :synopsis: Contains exceptions that can be raised for exceptional network and protocol
               conditions.

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

class ProtocolError(RuntimeError):
    """
        This error is raised when a communications protocol encounters an error.
    """
