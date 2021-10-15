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
import itertools
import struct
import inspect
import sys

import ghidra.app.util.bin.format.elf.ElfHeader as ElfHeader
import ghidra.app.util.bin.MemoryByteProvider as MemoryByteProvider
import ghidra.program.model.mem.MemoryBlock as MemoryBlock
import ghidra.program.model.mem.MemoryBlockType as MemoryBlockType
import generic.continues.RethrowContinuesFactory as RethrowContinuesFactory
import ghidra.program.model.symbol.SymbolType as SymbolType 


import ghidra.program.model.symbol.RefType as RefType 
import ghidra.program.model.symbol.FlowType as FlowType 
import ghidra.app.util.bin.format.elf.ElfSymbol as ElfSymbol 





import ghidra.program.model.address.Address as Address
import ghidra.program.model.mem.MemoryAccessException as MemoryAccessException
import ghidra.program.database.map.AddressMap as AddressMap

from __main__ import currentProgram, getGlobalFunctions

FUNC_LSDA_ENTRIES = collections.defaultdict()

IS_ARM = False

IS_SPARC = False

# True if this is a Windows PE file.
IS_PE = False


if IS_ARM:
  from arm_util import *
elif IS_SPARC:
  from sparc_util import *
else:
  from x86_util import *

BADADDR = AddressMap.INVALID_ADDRESS_KEY

# True if we are running on an ELF file.
IS_ELF = 'ELF' in currentProgram.getExecutableFormat()
_ELF_HEADER = None

# Set of symbols to TLS
TLS_SYMS = set()

_DEBUG_FILE = None
_DEBUG_PREFIX = ""
def INIT_DEBUG_FILE(file):
  global _DEBUG_FILE
  _DEBUG_FILE = file

def DEBUG_PUSH():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX += "  "

def DEBUG_POP():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX = _DEBUG_PREFIX[:-2]

def DEBUG(s):
  global _DEBUG_FILE
  if _DEBUG_FILE:
    _DEBUG_FILE.write("{}{}\n".format(_DEBUG_PREFIX, str(s)))

def wrap_address(ea):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(ea)

def wrapJavaIterator(it):
    while it.hasNext():
        yield it.next()

def initTlsSyms(elfHeader):
    global TLS_SYMS
    for symTab in elfHeader.getSymbolTables():
        for elfSymbol in symTab.getSymbols():
            if elfSymbol.isTLS():
                TLS_SYMS.add(elfSymbol.getNameAsString())

def getElfHeader():
    global _ELF_HEADER
    assert IS_ELF
    if _ELF_HEADER:
        return _ELF_HEADER
    memory = currentProgram.getMemory()
    provider = MemoryByteProvider(memory, currentProgram.getMinAddress())
    header = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, provider)
    initTlsSyms(header)
    _ELF_HEADER = header
    return header


def getFunctionByName(name):
    for symb in currentProgram.getSymbolTable().getSymbols(name):
        if symb.getSymbolType() == SymbolType.FUNCTION:
            return currentProgram.getFunctionManager().getFunctionAt(symb.getAddress())
    return None

def getReferencesTo(addr):
    return currentProgram.getReferenceManager().getReferencesTo(addr)

def getReferencesFrom(addr):
    return currentProgram.getReferenceManager().getReferencesFrom(addr)

def isReferencedByData(addr):
    for ref in getReferencesTo(addr):
        rt = ref.getReferenceType()

        dataRefTypes = [ FlowType.COMPUTED_JUMP, RefType.DATA ]
        if rt in dataRefTypes:
            return True
    return False


def usesJumpTable(inst):
    symbName = getSymbolName(inst.getAddress())
    if symbName and symbName.startswith("switch"):
        return True
    return False

def getSymbolAt(ea):
    symbols = list(currentProgram.getSymbolTable().getSymbols(ea))
    if not symbols:
        return None
    return symbols[0]

def getSymbolByName(name):
    symbols = list(currentProgram.getSymbolTable().getSymbols(name))
    if not symbols:
        return None
    return symbols[0]

def getSymbolsInAddressSet(addressSet, types):
    its = []
    for typ in types:
        its.append(currentProgram.getSymbolTable().getSymbols(addressSet, typ, False))
    return itertools.chain(*its)


# Tries to get the name of a symbol.
def getSymbolName(from_ea, ea=None, allow_dummy=False):
    if ea is None:
        ea = from_ea

    symbols = list(currentProgram.getSymbolTable().getSymbols(ea))
    if not symbols:
        return None

    return symbols[0].getName()

def getSegments():
    return currentProgram.getMemory().getBlocks()


def getSegmentAt(ea):
    seg = currentProgram.getMemory().getBlock(ea)
    if seg.getStart() != ea:
        return None
    return seg

def getSegmentContaining(ea):
    return currentProgram.getMemory().getBlock(ea)

def getSegmentByNames(names):
    """ Return the segment that has one of the given names """
    for seg in getSegments():
        if seg.getName() in names:
            return seg
    return None
    


def get_address_size_in_bits():
    """Returns the available address size."""
    if getElfHeader().is64Bit():
        return 64
    else:
        return 32

def get_address_size_in_bytes():
    return get_address_size_in_bits() // 8

### Memory reading
def read_bytes_slowly(start, end):
    mem = currentProgram.getMemory()
    bytestr = bytearray()
    addressSet = currentProgram.getAddressFactory().getAddressSet(start, end)
    for addr in addressSet.getAddresses(True): 
        try:
            bt = mem.getByte(addr)
            if bt < 0:
                bt += 256
            bytestr.append(bt)
        except MemoryAccessException:
            bytestr.append(0)
        
    return bytes(bytestr)

def read_byte(ea):
    byte = read_bytes_slowly(ea, ea + 1)
    byte = ord(byte) 
    return byte

IS_BIG_ENDIAN = False

_UNPACK_FORMAT_WORD = IS_BIG_ENDIAN and ">H" or "<H"
_UNPACK_FORMAT_DWORD = IS_BIG_ENDIAN and ">L" or "<L"
_UNPACK_FORMAT_QWORD = IS_BIG_ENDIAN and ">Q" or "<Q"

def read_word(ea):
    bytestr = read_bytes_slowly(ea, ea + 2)
    word = struct.unpack(_UNPACK_FORMAT_WORD, bytestr)[0]
    return word

def read_dword(ea):
    bytestr = read_bytes_slowly(ea, ea + 4)
    dword = struct.unpack(_UNPACK_FORMAT_DWORD, bytestr)[0]
    return dword

def read_qword(ea):
    bytestr = read_bytes_slowly(ea, ea + 8)
    qword = struct.unpack(_UNPACK_FORMAT_QWORD, bytestr)[0]
    return qword

def read_leb128(ea, signed):
    """ Read LEB128 encoded data
    """
    mem = currentProgram.getMemory()
    bytestr = bytearray()
    val = 0
    shift = 0
    while True:
        try:
            byte = t = mem.getByte(i)
            val |= (byte & 0x7F) << shift
            shift += 7
            ea += 1
            if (byte & 0x80) == 0:
                break

            if shift > 64:
                DEBUG("Bad leb128 encoding at {0:x}".format(ea - shift/7))
                return BADADDR
        except MemoryAccessException:
            return BADADDR

    if signed and (byte & 0x40):
        val -= (1<<shift)
    return val, ea

def read_uleb128(ea):
    return read_leb128(ea, False)

def read_sleb128(ea):
    return read_leb128(ea, True)


def read_string(ea):
    mem = currentProgram.getMemory()
    bytestr = bytearray()
    while True:
        try:
            bt = mem.getByte(i)
            if bt == 0:
                break
            bytestr.append(bt)
        except MemoryAccessException:
            break
        
    return bytes(bytestr).decode('utf-8')


def read_pointer(ea):
    if getElfHeader().is64Bit():
        return read_qword(ea)
    else:
        return read_dword(ea)

def is_invalid_ea(ea):
    """Returns `True` if `ea` is not valid, i.e. it doesn't point into any
    valid segment."""
    if (BADADDR == ea):
        return True

    #if not IS_SPARC:
    seg = getSegmentAt(ea)
    return seg is not None

def segment_contains_external_function_pointers(seg):
    """Returns `True` if a segment contains pointers to external functions."""
    return seg.getName().lower() in (".idata", ".plt.got")


def is_segment_external(seg):
    """Returns `True` if the segment is the special EXTERNAL or other informational segments."""
    return seg.getName() == "EXTERNAL" or not seg.isLoaded()

def is_tls_segment(seg):
    return seg.getName() in (".tbss", ".tdata", ".tls")

# Returns `True` if `ea` looks like a thread-local thing.
def is_tls(ea):
    if is_invalid_ea(ea):
        return False

    if is_tls_segment(getSegmentContaining(ea)):
        return True

    # Check if ELF header defines it as TLS symbol
    if IS_ELF:
        symb = getSymbolAt(ea)
        if symb and symb.getName() in TLS_SYMS:
            return True

    return False

def is_constructor_segment(seg):
    """Returns `True` if the segment containing `ea` belongs to global constructor section"""
    return seg.getName().lower() in [".init_array", ".ctor"]

def is_destructor_segment(seg):
    """Returns `True` if the segment containing `ea` belongs to global destructor section"""
    return seg.getName() in [".fini_array", ".dtor"]

def get_destructor_segment():
    """Returns the start address of the global destructor section"""
    return getSegmentByNames([".fini_array", ".dtor"])

def is_runtime_external_data_reference(ea):
    """This can happen in ELF binaries, where you'll have somehting like
    `stdout@@GLIBC_2.2.5` in the `.bss` section, where at runtime the
    linker will fill in the slot with a pointer to the real `stdout`.

    Ghidra discovers this type of reference, and will add an external
    reference to the address, therefore, we check for the existence of it"""
    for ref in getReferencesTo(ea):
        if ref.isExternalReference():
            return True
    return False

def is_referenced(ea):
    """Returns `True` if the data at `ea` is referenced by something else."""
    return currentProgram.getReferenceManager().hasReferencesTo(ea)

def getDataAt(ea):
    return currentProgram.getListing().getDataAt(ea)

def getDataContaining(ea):
    return currentProgram.getListing().getDataContaining(ea)

def getRealExternalNameOfReloc(reloc):
    symb = getSymbolAt(reloc.getAddress())

    symb_name = symb.getName()

    if symb_name.startswith("PTR_"):
        symb_name = symb_name[4:]
        symb_name = symb_name[:symb_name.rfind('_')]

    return symb_name

# sign extension to the given bits
def sign_extend(x, b):
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m
