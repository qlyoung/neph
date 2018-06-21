# BGP fuzzing stuff.
# -----------------------------------
# Copyright (c) 2018, Quentin Young.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import pprint


class FuzzerMixin(object):
    """
    Mixin inteded to extend Protocol subclasses.

    Adds functionality for fuzzing. Assumes the same attributes present in the
    Protocol class.
    """

    # List of packet types + fields we want to fuzz
    fuzzlist = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def fuzzables(self):
        names = []
        pp = pprint.PrettyPrinter(indent=4)
        for cls in self.packets:
            names += [cls.__name__ + "." + field.name for field in cls.fields_desc]
        pp.pprint(names)

    def fuzz(self, fields):
        fuzzlist += fields
