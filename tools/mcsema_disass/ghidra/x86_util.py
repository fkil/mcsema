# Copyright (c) 2020 Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import collections

from __main__ import currentProgram

def has_delayed_slot(inst):
  return False

def fixup_function_return_address(inst, next_ea):
  return next_ea

if currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0).getSize() == 64:
  def return_values():
    return {
      "register": "RAX",
      "type": "L"
    }

  def return_address():
    return {
      "memory": {
        "register": "RSP",
        "offset": 0
      },
      "type": "L"
    }

  def return_stack_pointer():
    return {
      "register": "RSP",
      "offset": 8,
      "type": "L"
    }

elif currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0).getSize() == 32:
  def return_values():
    return {
      "register": "EAX",
      "type": "I"
    }

  def return_address():
    return {
      "memory": {
        "register": "ESP",
        "offset": 0
      },
      "type": "I"
    }

  def return_stack_pointer():
    return {
      "register": "ESP",
      "offset": 4,
      "type": "I"
    }

def recover_value_spec(V, spec):
  """Recovers the default value specification."""
  V.type = spec["type"]

  if "name" in spec and len(spec["name"]):
    V.name = spec["name"]

  if "register" in spec:
    V.register = spec["register"]
  elif "memory" in spec:
    mem_spec = spec["memory"]
    V.memory.register = mem_spec["register"]
    if mem_spec["offset"]:
      V.memory.offset = mem_spec["offset"]

def recover_function_spec_from_arch(E):
  """ recover the basic information about the function spec"""
  D = E.decl
  if E.argument_count >= 8:
    D.is_noreturn = E.no_return
    D.is_variadic = (E.argument_count >= 8)
    D.calling_convention = 0
    if D.is_noreturn == False:
      V = D.return_values.add()
      recover_value_spec(V, return_values())
    recover_value_spec(D.return_address, return_address())
    recover_value_spec(D.return_stack_pointer, return_stack_pointer())
