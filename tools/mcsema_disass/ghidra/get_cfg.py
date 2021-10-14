#!/usr/bin/env python

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

#import idautils
#import idaapi
#import ida_funcs
#import idc
import sys
import os
sys.path.insert(0,os.path.dirname(__file__))

import argparse
import struct
import traceback
import collections
import itertools
import pprint


# Bring in utility libraries.
from util import *
import util
from table import *
from flow import *
from refs import *
from segment import *
from exception import *


import ghidra.program.model.symbol.SymbolType as SymbolType 
import ghidra.program.model.block.BasicBlockModel as BasicBlockModel


# Bring in Anvill
try:
    import anvill
except:
    import anvill_compat as anvill

ANVILL_PROGRAM = None


tools_disass_ghidra_dir = os.path.dirname(__file__)
tools_disass_dir = os.path.dirname(tools_disass_ghidra_dir)

# Note: The bootstrap file will copy CFG_pb2.py into this dir!!
import CFG_pb2

RECOVERED_EAS = set()

RECOVER_EHTABLE = False

#PERSONALITY_FUNCTIONS = [
#        "__gxx_personality_v0",
#        "__gnat_personality_v0"
#        ]

# Map of external functions names to a tuple containing information like the
# number of arguments and calling convention of the function.
EMAP = {}

# Map of external variable names to their sizes, in bytes.
EMAP_DATA = {}

# Map of the functions which are forced to be extern and does not require to
# be recovered.
FORCED_EXTERNAL_EMAP = {}

# Set of "weak" symbols. In ELF binaries,
# a weak symbol is kind of an optional linking thing. For example, the 
# `__gmon_start__` function is referenced as a weak symbol. This function is
# used for gcov-based profiling. If gcov is available, then this symbol will
# be resolved to a real function, but if not, it will be NULL and programs
# will detect it as such. An example use of a weak symbol in C would be:
#
#     extern void __gmon_start__(void) __attribute__((weak));
#     ...
#     if (__gmon_start__) {
#       __gmon_start__();
#     }
WEAK_SYMS = set()


# `True` if we are getting the CFG of a position independent executable. This
# affects heuristics like trying to turn immediate operands in instructions
# into references into the data.
PIE_MODE = False

# Name of the operating system that runs the program being lifted. E.g. if
# we're lifting an ELF then this will typically be `linux`.
OS_NAME = ""

# Set of substrings that can be found inside of symbol names that are usually
# signs that the symbol is external. For example, `stderr@@GLIBC_2.2.5` is
# really the external `stderr`, so we want to be able to chop out the `@@...`
# part to resolve the "true" name. There are a lot of `@@` variants in PE files,
# e.g. `@@QEAU_..`, `@@AEAV..`, though these are likely for name mangling.
EXTERNAL_NAMES = ("@@GLIBC_", "@@GLIBCXX_", "@@CXXABI_", "@@GCC_")


# Returns `True` if this is an ELF binary (as opposed to an ELF object file).
def is_linked_ELF_program():
    return IS_ELF and getElfHeader().isExecutable()

# Used to track thunks that are actually implemented. For example, in a static
# binary, you might have a bunch of calls to `strcpy` in the `.plt` section
# that go through the `.plt.got` to call the implementation of `strcpy` compiled
# into the binary.
INTERNALLY_DEFINED_EXTERNALS = {}    # Name external to EA of internal.
INTERNAL_THUNK_EAS = {}    # EA of thunk to EA of implementation.

def parse_os_defs_file(df):
    """Parse the file containing external function and variable
    specifications."""
    global OS_NAME, EMAP, EMAP_DATA
    global _FIXED_EXTERNAL_NAMES, INTERNALLY_DEFINED_EXTERNALS
    
    is_linux = OS_NAME == "linux"
    for l in df.readlines():
        #skip comments / empty lines
        l = l.strip()
        if not l or l[0] == "#":
            continue

        if l.startswith('DATA:'):
            # process as data
            (marker, symname, dsize) = l.split()
            if 'PTR' in dsize:
                dsize = get_address_size_in_bytes()

            EMAP_DATA[symname] = int(dsize)

        else:
            fname = args = conv = ret = sign = None
            line_args = l.split()

            if len(line_args) == 4:
                (fname, args, conv, ret) = line_args
            elif len(line_args) == 5:
                (fname, args, conv, ret, sign) = line_args

            if conv == "C":
                realconv = CFG_pb2.ExternalFunction.CallerCleanup
            elif conv == "E":
                realconv = CFG_pb2.ExternalFunction.CalleeCleanup
            elif conv == "F":
                realconv = CFG_pb2.ExternalFunction.FastCall
            else:
                DEBUG("ERROR: Unknown calling convention: {}".format(l))
                continue

            if ret not in "YN":
                DEBUG("ERROR: Unknown return type {} in {}".format(ret, l))
                continue

            func = getFunctionByName(fname)

            EMAP[fname] = (int(args), realconv, ret, sign)
            if ret == 'Y':
                noreturn_external_function(fname, int(args), realconv, ret, sign)

    df.close()

def parse_fextern_defs_file(df):
    """Parse the file containing forced external function which
    does not need to be recovered.
    """
    global FORCED_EXTERNAL_EMAP

    for l in df.readlines():
        #skip comments / empty lines
        l = l.strip()
        if not l or l[0] == "#":
            continue

        fname = args = conv = ret = None
        line_args = l.split()

        if len(line_args) == 4:
            (fname, args, conv, ret) = line_args

        if conv == "C":
            realconv = CFG_pb2.ExternalFunction.CallerCleanup
        elif conv == "E":
            realconv = CFG_pb2.ExternalFunction.CalleeCleanup
        elif conv == "F":
            realconv = CFG_pb2.ExternalFunction.FastCall
        else:
            DEBUG("ERROR: Unknown calling convention for forced extern : {}".format(l))
            continue

        if ret not in "YN":
            DEBUG("ERROR: Unknown return type {} in {}".format(ret, l))
            continue


        FORCED_EXTERNAL_EMAP[fname] = (int(args), realconv, ret, None)

    df.close()

def get_function_name(ea):
    """Return name of a function, as IDA sees it. This includes allowing
    dummy names, e.g. `sub_abc123`."""
    return getSymbolName(ea, ea, allow_dummy=True)

_ELF_THUNKS = {}
_NOT_ELF_THUNKS = set()
_INVALID_THUNK = (False, BADADDR, "")
_INVALID_THUNK_ADDR = (False, BADADDR)

# NOTE(pag): `is_ELF_thunk_by_structure` is arch-specific.

def is_thunk_by_flags(ea):
    """Try to identify a thunk based off of the IDA flags. This isn't actually
    specific to ELFs.

    IDA seems to have a kind of thunk-propagation. So if one thunk calls
    another thunk, then the former thing is treated as a thunk. The former
    thing will not actually follow the 'structured' form matched above, so
    we'll try to recursively match to the 'final' referenced thunk."""
    global _INVALID_THUNK_ADDR

    if not is_thunk(ea):
        return _INVALID_THUNK_ADDR
    
    ea_name = get_function_name(ea)
    inst, _ = decode_instruction(ea)
    if not inst:
        DEBUG("WARNING: {} at {:x} is a thunk with no code??".format(ea_name, ea))
        return _INVALID_THUNK_ADDR

    # Recursively find thunk-to-thunks.
    if is_direct_jump(inst) or is_direct_function_call(inst):
        targ_ea = get_direct_branch_target(inst)
        targ_is_thunk = is_thunk(targ_ea)
        if targ_is_thunk:
            targ_thunk_name = getSymbolName(ea, targ_ea)
            DEBUG("Found thunk-to-thunk {:x} -> {:x}: {} to {}".format(
                    ea, targ_ea, ea_name, targ_thunk_name))
            return True, targ_ea
        
        DEBUG("ERROR? targ_ea={:x} is not thunk".format(targ_ea))

    if not is_external_reference(ea):
        return _INVALID_THUNK_ADDR

    return True, targ_ea


_REFERENCE_OPERAND_TYPE = {
    Reference.IMMEDIATE: CFG_pb2.CodeReference.ImmediateOperand,
    Reference.DISPLACEMENT: CFG_pb2.CodeReference.MemoryDisplacementOperand,
    Reference.MEMORY: CFG_pb2.CodeReference.MemoryOperand,
    Reference.CODE: CFG_pb2.CodeReference.ControlFlowOperand,
}

def reference_operand_type(ref):
    global _REFERENCE_OPERAND_TYPE
    if ref.getReferenceType().isFlow():
        return CFG_pb2.CodeReference.ControlFlowOperand
    if ref.isMemoryReference():
        if ref.isOffsetReference():
            return CFG_pb2.CodeReference.MemoryDisplacementOperand
        else:
            return CFG_pb2.CodeReference.MemoryOperand
    return CFG_pb2.CodeReference.ImmediateOperand

_OPERAND_NAME = {
    CFG_pb2.CodeReference.ImmediateOperand: "imm",
    CFG_pb2.CodeReference.MemoryDisplacementOperand: "disp",
    CFG_pb2.CodeReference.MemoryOperand: "mem",
    CFG_pb2.CodeReference.ControlFlowOperand: "flow",
}

def format_instruction_reference(ref):
    """Returns a string representation of a cross reference contained
    in an instruction."""
    mask_begin = ""
    mask_end = ""
    if ref.mask:
        mask_begin = "("
        mask_end = " & {:x})".format(ref.mask)

    return "({} {}{:x}{})".format(
            _OPERAND_NAME[ref.operand_type],
            mask_begin,
            ref.ea,
            mask_end)

def recover_instruction_references(I, inst):
    """Add the memory/code reference information from this instruction
    into the CFG format. The LLVM side of things needs to be able to
    match instruction operands to references to internal/external
    code/data.

    The `get_instruction_references` gives us an accurate picture of the
    references as they are, but in practice we want a higher-level perspective
    that resolves things like thunks to their true external representations.

    Note: References are a kind of gotcha that need special explaining. We kind
    of 'devirtualize' references. An example of this is:
        
        extern:00000000002010A8                 extrn stderr@@GLIBC_2_2_5

        extern:00000000002010D8 ; struct _IO_FILE *stderr
        extern:00000000002010D8                 extrn stderr
                            |                     ; DATA XREF: .got:stderr_ptr
                            `-------------------------------.
                                                            |                         
            .got:0000000000200FF0 stderr_ptr        dq offset stderr
                                    |             ; DATA XREF: main+12
                                    `-------------------------------.
                                                                    | 
         .text:0000000000000932                 mov     rax, cs:stderr_ptr
         .text:0000000000000939                 mov     rdi, [rax]        ; stream
                                    ...
         .text:0000000000000949                 call    _fprintf
    
    So above we see that the `mov` instruction is dereferencing `stderr_ptr`,
    and from there it's getting the address of `stderr`. Then it dereferences
    that, which is the value of `stderr, getting us the address of the `FILE *`.
    That is passed at the first argument to `fprintf`.

    Now, what we see in the `mcseam-disass` log is a bit different.

            Variable at 200ff0 is the external stderr
            Variable at 2010a8 is the external stderr
            Variable at 2010d8 is the external stderr
                            ...
            I: 932 (data mem external 200ff0 stderr)

    So even though the `mov` instruction uses `stderr_ptr` and an extra level
    of indirection, we devirtualize that to `stderr`. But, how could this work?
    It seems like it's removing a layer of indirection. The answer is on the
    LLVM side of things.

    On the LLVM side, `stderr` is a global variable:

            @stderr = external global %struct._IO_FILE*, align 8

    And the corresponding call is:

        %4 = load %struct._IO_FILE*, %struct._IO_FILE** @stderr, align 8
        %5 = call i32 (...) @fprintf(%struct._IO_FILE* %4, i8* ...)

    So now we see that by declaring the global variable `stderr` on the LLVM
    side, we regain this extra level of indirection because all global variables
    are really pointers to their type (i.e. `%struct._IO_FILE**`), thus we
    preserve the intent of the original assembly.
    """
    DEBUG_PUSH()

    debug_info = ["I: {:x}".format(inst.getAddress().getOffset())]
    for ref in getReferencesFrom(inst.getAddress()):
        if ref.isStackReference():
            continue

        ref_ea = ref.getToAddress().getOffset()

        if ref.getReferenceType().isJump() or ref.getReferenceType().isCall():
            targetFun = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress())
            if targetFun and targetFun.isThunk():
                thunkedFun = targetFun.getThunkedFunction(False)
                ref_ea = thunkedFun.getEntryPoint().getOffset()

        R = I.xrefs.add()
        R.ea = ref_ea
        #if ref.mask:
        #    R.mask = ref.mask
        #if ref.imm_val:
        #    R.ea = ref.imm_val

        R.operand_type = reference_operand_type(ref)
        
        debug_info.append(format_instruction_reference(R))

    DEBUG_POP()
    DEBUG(" ".join(debug_info))

def recover_instruction_offset_table(I, table):
    """Recovers an offset table as a kind of reference."""
    DEBUG("Offset-based jump table")
    R = I.xrefs.add()
    R.ea = 0 # TODO: What does this value mean
    R.operand_type = CFG_pb2.CodeReference.OffsetTable


def recover_instruction(M, F, B, inst):
    """Recover an instruction, adding it to its parent block in the CFG."""
    global _REG_SETS

    inst_bytes = inst.getBytes()

    I = B.instructions.add()
    I.ea = inst.getAddress().getOffset() # May not be `inst.ea` because of prefix coalescing.

    recover_instruction_references(I, inst)

    # TODO: Check in what way necessary and implement for Ghidra
    #regs_saved = recover_preserved_regs(M, F, inst, xrefs, _REG_SETS)

    DEBUG_PUSH()
    if usesJumpTable(inst):
        recover_instruction_offset_table(I, inst)

    #if regs_saved and len(regs_saved):
    #    DEBUG("Added save record: {}".format(regs_saved))

    DEBUG_POP()

    return I

def recover_basic_block(M, F, bb):
    """Add in a basic block to a specific function in the CFG."""

    insts = list(currentProgram.getListing().getInstructions(bb, True))
    block_ea = bb.getFirstStartAddress().getOffset()

    DEBUG("BB: {:x} in func {:x} with {} insts".format(
            block_ea, F.ea, len(insts)))
    
    B = F.blocks.add()
    B.ea = block_ea

    DEBUG_PUSH()


    B.is_referenced_by_data = isReferencedByData(bb.getFirstStartAddress())

    I = None
    for inst in insts:
        I = recover_instruction(M, F, B, inst)
        # Get the landing pad associated with the instructions;
        # 0 if no landing pad associated
        if RECOVER_EHTABLE is True and I:
            I.lp_ea = get_exception_landingpad(F, inst.getAddress().getOffset())

    DEBUG_PUSH()

    successor_eas = list(map(lambda x: x.getDestinationAddress().getOffset(), wrapJavaIterator(bb.getDestinations(monitor))))
    if len(successor_eas) > 0:
        B.successor_eas.extend(successor_eas)
        DEBUG("Successors: {}".format(", ".join("{0:x}".format(i) for i in successor_eas)))
    else:
        DEBUG("No successors")

    DEBUG_POP()
    DEBUG_POP()

def analyze_jump_table_targets(inst, new_eas, new_func_eas):
    """Function recovery is an iterative process. Sometimes we'll find things
    in the entries of the jump table that we need to go mark as code to be
    added into the CFG."""
    table = get_jump_table(inst, PIE_MODE)
    if not table:
        return

    for entry_addr, entry_target in table.entries.items():
        new_eas.add(entry_target)
        if is_start_of_function(entry_target):
            DEBUG("    Jump table {:x} entry at {:x} references function at {:x}".format(
                    table.table_ea, entry_addr, entry_target))
            new_func_eas.append(entry_target)
        else:
            DEBUG("    Jump table {:x} entry at {:x} references block at {:x}".format(
                    table.table_ea, entry_addr, entry_target))

def recover_value_spec(V, spec):
    """Recovers an Anvill value specification into the CFG proto format."""
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

def recover_function_spec(F, spec):
    """Recovers most of an Anvill function specification into the CFG proto format."""
    D = F.decl

    if "is_noreturn" in spec:
        D.is_noreturn = spec["is_noreturn"]
    else:
        D.is_noreturn = False
    
    if "is_variadic" in spec:
        D.is_variadic = spec["is_variadic"]
    else:
        D.is_variadic = False

    if "parameters" in spec:
        for param in spec["parameters"]:
            P = D.parameters.add()
            recover_value_spec(P, param)

    if "return_values" in spec:
        for ret_val in spec["return_values"]:
            V = D.return_values.add()
            recover_value_spec(V, ret_val)

    if "calling_convention" in spec:
        D.calling_convention = spec["calling_convention"]
    else:
        D.calling_convention = 0

    recover_value_spec(D.return_address, spec["return_address"])
    recover_value_spec(D.return_stack_pointer, spec["return_stack_pointer"])

def try_get_anvill_func(func_ea, is_thunk, thunk_target_ea):
    """Try to get the Anvill Function object for the function associated with
    `func_ea`, and if it's a thunk, then `thunk_target_ea`."""
    
    if is_thunk:
        try:
            if ANVILL_PROGRAM.add_function_declaration(thunk_target_ea):
                return ANVILL_PROGRAM.get_function(thunk_target_ea)
        except Exception as e:
            pass

    try:
        if ANVILL_PROGRAM.add_function_declaration(func_ea):
            return ANVILL_PROGRAM.get_function(func_ea)
    except:
        pass
    
    return None

_RECOVERED_FUNCS = set()

def recover_function(M, func, new_funcs, exports, prev_F, processed_blocks):
    """Decode a function and store it, all of its basic blocks, and all of
    their instructions into the CFG file."""
    global _RECOVERED_FUNCS
    global ANVILL_PROGRAM
    if func in _RECOVERED_FUNCS:
        return prev_F

    _RECOVERED_FUNCS.add(func)


    assert not func.isThunk() and not func.isExternal()

    func_ea = func.getEntryPoint().getOffset()
    name = func.getName()
    F = M.funcs.add()
    F.ea = func_ea
    F.is_entrypoint = (func in exports)

    if not name:
        DEBUG("Recovering {:x}".format(func_ea))
    else:
        F.name = name.format('utf-8')
        DEBUG("Recovering {} at {:x}".format(F.name, func_ea))

        # Try to get the Anvill representation of this function.
        anvill_func = try_get_anvill_func(func_ea, False, None)
        if anvill_func:
            recover_function_spec(F, anvill_func.proto())

    DEBUG_PUSH()

    # Update the protobuf with the recovered eh_frame entries
    if RECOVER_EHTABLE is True:
        recover_exception_entries(F, func_ea)
    
    
    blockModel = BasicBlockModel(currentProgram)
    
    blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor)

    while blocks.hasNext():
        bb = blocks.next()
        recover_basic_block(M, F, bb)

    DEBUG_POP()
    return F

def get_functions():
    """Get every function"""
    func_eas = []
    for seg in getSegments():
        address_set = currentProgram.getAddressFactory().getAddressSet(seg.getStart(), seg.getEnd())
        for func in currentProgram.getFunctionManager().getFunctions(address_set, True):
            ep = func.getEntryPoint()
            if ep:
                func_eas.append(func)
    return func_eas

def recover_region_variables(M, S, seg_ea, seg_end_ea, exported_vars):
    """Look for named locations pointing into the data of this segment, and
    add them to the protobuf."""

    seg = getSegmentContaining(seg_ea)
    is_code_seg = seg.isExecute()

    addressSet = currentProgram.getAddressFactory().getAddressSet(seg_ea, seg_end_ea)
    symbolTypes = [SymbolType.GLOBAL, SymbolType.GLOBAL_VAR, SymbolType.LABEL]

    assert not is_segment_external(seg)

    for symb in getSymbolsInAddressSet(addressSet, symbolTypes):
        ea = symb.getAddress()
        name = symb.getName()
        # Check if it is code
        if is_code_seg and currentProgram.getListing().getInstructionAt(ea):
            continue

        # Only add named internal variables if they are referenced or exported. 
        if is_referenced(ea) or symb in exported_vars:
            DEBUG("Variable {} at {:x}".format(name, ea.getOffset()))
            V = S.vars.add()
            V.ea = ea.getOffset()
            V.name = name.format('utf-8')


def recover_region_cross_references(M, S, seg_ea, seg_end_ea):
    """Goes through the segment and identifies fixups that need to be
    handled by the LLVM side of things."""
    global PIE_MODE

    max_xref_width = get_address_size_in_bytes()
    min_xref_width = PIE_MODE and max_xref_width or 4

    seg = getSegmentContaining(seg_ea)
    is_code_seg = seg.isExecute()
    seg_name = seg.getName()
    has_func_pointers = segment_contains_external_function_pointers(seg)

    addressSet = currentProgram.getAddressFactory().getAddressSet(seg_ea, seg_end_ea)
    for refAddr in wrapJavaIterator(currentProgram.getReferenceManager().getReferenceSourceIterator(addressSet, True)):
        if is_runtime_external_data_reference(refAddr):
            continue

        # Check if it is code
        if is_code_seg and currentProgram.getListing().getInstructionAt(refAddr):
            continue

        for ref in currentProgram.getReferenceManager().getReferencesFrom(refAddr):
            target_ea = ref.getToAddress()

            xref_width = max_xref_width

            X = S.xrefs.add()
            X.ea = refAddr.getOffset()
            X.width = xref_width
            X.target_ea = target_ea.getOffset()
            target_name = getSymbolName(target_ea)

            # A cross-reference to some TLS data. Because each thread has its own
            # instance of the data, this reference ends up actually being an offset
            # from a thread base pointer. In x86, this tends to be the base of one of
            # the segment registers, e.g. `fs` or `gs`. On the McSema side, we fill in
            # this xref lazily by computing the offset.
            if is_tls(target_ea):
                X.target_fixup_kind = CFG_pb2.DataReference.OffsetFromThreadBase
                DEBUG("{}-byte TLS offset at {:x} to {:x} ({})".format(
                        X.width, X.ea, target_ea.getOffset(), target_name))

            # A cross-reference to a 'single' thing, where the fixup that we create
            # will be an absolute address to the targeted variable/function.
            else:
                X.target_fixup_kind = CFG_pb2.DataReference.Absolute
                DEBUG("{}-byte reference at {:x} to {:x} ({})".format(
                        X.width, X.ea, target_ea.getOffset(), target_name))



def recover_region(M, region_name, region_ea, region_end_ea, exported_vars):
    """Recover the data and cross-references from a segment. The data of a
    segment is stored verbatim within the protobuf, and accompanied by a
    series of variable and cross-reference entries."""

    seg = getSegmentContaining(region_ea)
    seg_name = seg.getName()

    DEBUG("Recovering region {} [{:x}, {:x}) in segment {}".format(
            region_name, region_ea.getOffset(), region_end_ea.getOffset(), seg_name))

    S = M.segments.add()
    S.ea = region_ea.getOffset()
    S.data = read_bytes_slowly(region_ea, region_end_ea)
    S.read_only = (seg.getPermissions() & MemoryBlock.WRITE) == 0
    S.is_external = is_segment_external(seg)
    S.is_thread_local = is_tls_segment(seg)
    S.name = seg_name.format('utf-8')
    symb = getSymbolAt(region_ea)
    S.is_exported = bool(symb) and symb in exported_vars

    if region_name != seg_name:
        S.variable_name = region_name.format('utf-8')

    DEBUG_PUSH()
    recover_region_cross_references(M, S, region_ea, region_end_ea)
    recover_region_variables(M, S, region_ea, region_end_ea, exported_vars)
    DEBUG_POP()

def recover_regions(M, exported_vars, global_vars=[]):
    """Recover all non-external segments into the CFG module. This will also
    recover global variables, specified in terms of a list of
    `(name, begin_ea, end_ea)` tuples, as their own segments."""

    seg_names = {}

    # Collect the segment bounds to lift.
    seg_parts = collections.defaultdict(set)
    for seg in getSegments():
        seg_ea = seg.getStart()
        seg_name = seg.getName()
        seg_names[seg_ea] = seg_name

        if (not is_segment_external(seg) or \
                segment_contains_external_function_pointers(seg)) and \
                not (is_constructor_segment(seg) or is_destructor_segment(seg)):
            seg_parts[seg_ea].add(seg_ea)
            seg_parts[seg_ea].add(seg_ea.add(seg.getSize()))

        # Fix for an important feature - static storage allocation of the objects in C++, where
        # the constructor gets invoked before the main and it typically calls the 'init/__libc_csu_init' function.
        #
        # The function iterate over the array conatined in .init_array initializing the global constructor/destructor
        # function pointers using the symbol `off_201D70` and `off_201D80` as the array bounds as shown below. These
        # symbols falls in section `.init_array` and `.fini_array` correspondingly.
        #
        # .init_array:0000000000201D70 ; ELF Initialization Function Table
        # .init_array:0000000000201D70 ; ===========================================================================
        # .init_array:0000000000201D70 ; Segment type: Pure data
        # .init_array:0000000000201D70 _init_array         segment para public 'DATA' use64
        # .init_array:0000000000201D70                                 assume cs:_init_array
        # .init_array:0000000000201D70                                 ;org 201D70h
        # .init_array:0000000000201D70 off_201D70            dq offset sub_C40
        # .init_array:0000000000201D70
        # .init_array:0000000000201D78                                 dq offset sub_10E5
        # .init_array:0000000000201D78 _init_array         ends
        #
        # .fini_array:0000000000201D80 ; ELF Termination Function Table
        # .fini_array:0000000000201D80 ; ===========================================================================
        # .fini_array:0000000000201D80 ; Segment type: Pure data
        # .fini_array:0000000000201D80 _fini_array         segment para public 'DATA' use64
        # .fini_array:0000000000201D80                                 assume cs:_fini_array
        # .fini_array:0000000000201D80                                 ;org 201D80h
        # .fini_array:0000000000201D80 off_201D80            dq offset sub_C00
        # .fini_array:0000000000201D80 _fini_array         ends
        #
        # .text:0000000000001160 ; void init(void)
        # .text:0000000000001160                                 push        r15
        # .text:0000000000001162                                 mov         r15d, edi
        # .text:0000000000001165                                 push        r14
        # .text:0000000000001167                                 mov         r14, rsi
        # .text:000000000000116A                                 push        r13
        # .text:000000000000116C                                 mov         r13, rdx
        # .text:000000000000116F                                 push        r12
        # .text:0000000000001171                                 lea         r12, off_201D70
        # .text:0000000000001178                                 push        rbp
        # .text:0000000000001179                                 lea         rbp, off_201D80
        # .text:0000000000001180                                 push        rbx
        # .text:0000000000001181                                 sub         rbp, r12
        # .text:0000000000001184                                 xor         ebx, ebx
        # .text:0000000000001186                                 sar         rbp, 3
        # .text:000000000000118A                                 sub         rsp, 8
        # .text:000000000000118E                                 call        _init_proc
        # ...
        # Extracting these sections as different LLVM GlobalVariable will not guarantee the adjacency placement in
        # recompiled binary. Hence it should be lifted as one LLVM GlobalVariable if they are adjacent.

        if is_constructor_segment(seg):
            seg_parts[seg_ea].add(seg_ea)
            end_ea = seg_ea.add(seg.getSize())
            nextSeg = getSegmentAt(end_ea)
            if nextSeg and is_destructor_segment(nextSeg):
                seg_parts[seg_ea].add(end_ea.add(nextSeg.getSize()))
                DEBUG("WARNING: Global constructor and destructor sections are adjacent!")
            else:
                seg_parts[seg_ea].add(end_ea)
                fini_seg = get_destructor_segment()
                if fini_seg:
                    fini_ea = fini_seg.getStart()
                    seg_parts[fini_ea].add(fini_ea)
                    seg_parts[fini_ea].add(fini_ea.add(fini_seg.getSize()))

    # Treat analysis-identified global variables as segment begin/end points.
    for var_name, begin_ea, end_ea in global_vars:
        if is_invalid_ea(begin_ea) or is_invalid_ea(end_ea):
            DEBUG("ERROR: Variable {} at [{:x}, {:x}) is not valid.".format(
                    var_name, begin_ea.getOffset(), end_ea.getOffset()))
            continue

        if is_segment_external(begin_ea):
            DEBUG("ERROR: Variable {} at [{:x}, {:x}) is in an external segment.".format(
                    var_name, begin_ea.getOffset(), end_ea.getOffset()))
            continue

        seg = getSegmentContaining(begin_ea)
        seg_ea = seg.getStart()
        seg_name = seg.getName()

        DEBUG("Splitting segment {} from {:x} to {:x} for global variable {}".format(
                seg_name, begin_ea.getOffset(), end_ea.getOffset(), var_name))

        seg_parts[seg_ea].add(begin_ea)
        seg_names[begin_ea] = var_name

        if end_ea <= seg_ea.add(seg.getSize()):
            seg_parts[seg_ea].add(end_ea)

    # Treat exported variables as segment begin/end points.
    for var in exported_vars:
        var_ea = var.getAddress()
        var_name = var.getName()
        seg = getSegmentContaining(var_ea)
        if not seg:
            DEBUG("WARNING: Segment not found for variable {} at: {:x}, ignoring variable".format(var_name, var_ea.getOffset()))
            continue
        seg_ea = seg.getStart()
        seg_name = seg.getName()
        seg_parts[seg_ea].add(var_ea)
        seg_names[var_ea] = var_name
        DEBUG("Splitting segment {} at {:x} for exported variable {}".format(
                seg_name, var_ea.getOffset(), var_name))

    for seg_ea, eas in seg_parts.items():
        parts = list(sorted(list(eas)))
        seg_name = getSegmentContaining(seg_ea).getName()
        for begin_ea, end_ea in zip(parts[:-1], parts[1:]):
            region_name = seg_name
            if begin_ea in seg_names and \
                not is_runtime_external_data_reference(begin_ea):
                region_name = seg_names[begin_ea]

            recover_region(M, region_name, begin_ea, end_ea, exported_vars)

def recover_external_function(M, reloc):
    """Recover the named external functions (e.g. `printf`) that are referenced
    within this binary."""

    name = getRealExternalNameOfReloc(reloc)

    ea = reloc.getAddress().getOffset()
    if not name:
        DEBUG("ERROR: Relocation without name: {}, {:x}".format(name, ea))
    anvill_func = try_get_anvill_func(ea, False, ea)

    DEBUG("Recovering extern function {} at {:x}".format(name, ea))
    args, conv, ret, sign = EMAP[name]
    E = M.external_funcs.add()
    E.name = name.format('utf-8')
    E.ea = ea
    E.argument_count = args
    E.cc = conv
    E.is_weak = name in WEAK_SYMS
    E.no_return = ret == 'Y'

    # TODO(pag): This should probably reflect whether or not the function
    #                        actually returns something, rather than simply does not
    #                        return (e.g. `abort`).
    E.has_return = ret == 'N'

    if anvill_func:
        recover_function_spec(E, anvill_func.proto())
    else:
        recover_function_spec_from_arch(E)

def recover_external_variable(M, reloc):
    """Reover the named external variables (e.g. `stdout`) that are referenced
    within this binary."""
    global WEAK_SYMS

    name = getRealExternalNameOfReloc(reloc)
    ea = reloc.getAddress()

    EV = M.external_vars.add()
    EV.ea = ea.getOffset()
    EV.name = name.format('utf-8')
    EV.is_weak = (name in WEAK_SYMS)
    EV.is_thread_local = is_tls(ea)
    if name in EMAP_DATA:
        EV.size = EMAP_DATA[name]
    else:
        EV.size = getDataAt(ea).getLength()

    if EV.is_thread_local:
        DEBUG("Recovering extern TLS variable {} at {:x} [size: {}]".format(name, ea.getOffset(), EV.size))
    else:
        DEBUG("Recovering extern variable {} at {:x} [size: {}]".format(name, ea.getOffset(), EV.size))

def recover_external_symbols(M):
    if IS_ELF:
        identify_weak_symbols()
    for reloc in currentProgram.getRelocationTable().getRelocations():
        symb = getSymbolAt(reloc.getAddress())
        if symb.getSymbolType() == SymbolType.FUNCTION:
            recover_external_function(M, reloc)
        else:
            recover_external_variable(M, reloc)


def identify_weak_symbols():
    """
    Identify weak symbols by looking through the ELF-SymbolTable and check for the SymbolType denoted there
    """
    for symTab in getElfHeader().getSymbolTables():
        for elfSymbol in symTab.getSymbols():
            if elfSymbol.isWeak():
                WEAK_SYMS.add(elfSymbol.getNameAsString())

def get_program_exports(func_eas):
    """ Get all program exports 
        Type: Set(Symbol)
    """
    DEBUG("Looking for exports")
    DEBUG_PUSH()

    exclude = set(["_start", "__libc_csu_fini", "__libc_csu_init", 
                                 "__data_start", "__dso_handle", "_IO_stdin_used",
                                 "_dl_relocate_static_pie", "__DTOR_END__", "__ashlsi3",
                                 "__ashldi3", "__ashlti3", "__ashrsi3", "__ashrdi3", "__ashrti3",
                                 "__divsi3", "__divdi3", "__divti3", "__lshrsi3", "__lshrdi3",
                                 "__lshrti3", "__modsi3", "__moddi3", "__modti3", "__mulsi3",
                                 "__muldi3", "__multi3", "__negdi2", "__negti2", "__udivsi3",
                                 "__udivdi3", "__udivti3", "__udivmoddi4", "__udivmodti4",
                                 "__umodsi3", "__umoddi3", "__umodti3", "__cmpdi2", "__cmpti2",
                                 "__ucmpdi2", "__ucmpti2", "__absvsi2", "__absvdi2", "__addvsi3",
                                 "__addvdi3", "__mulvsi3", "__mulvdi3", "__negvsi2", "__negvdi2",
                                 "__subvsi3", "__subvdi3", "__clzsi2", "__clzdi2", "__clzti2",
                                 "__ctzsi2", "__ctzdi2", "__ctzti2", "__ffsdi2", "__ffsti2",
                                 "__paritysi2", "__paritydi2", "__parityti2", "__popcountsi2",
                                 "__popcountdi2", "__popcountti2", "__bswapsi2", "__bswapdi2"])

    exported_funcs = set()
    exported_vars = set()

    for symb in currentProgram.getSymbolTable().getAllSymbols(True):
        if symb.getName() in exclude:
            continue
        # Check if exported
        if symb.isExternalEntryPoint():
            # Check if function
            if symb.getSymbolType() == SymbolType.FUNCTION:
                exported_funcs.add(symb)
            else:
                exported_vars.add(symb)
            


    DEBUG_POP()
    return exported_funcs, exported_vars

def find_main_in_ELF_file():
    """Tries to automatically find the `main` function if we haven't found it
    yet. """
    # TODO
    return BADADDR


def recover_module(entrypoint, gvar_infile = None):
    global EMAP

    M = CFG_pb2.Module()
    M.name = currentProgram.getExecutablePath()
    DEBUG("Recovering module {}".format(M.name))
    
    entry_ea = -1
    if args.entrypoint:
        entry_ea = getFunctionByName(args.entrypoint)
        # If the entrypoint is `main`, then we'll try to find `main` via another
        # means.
        if is_invalid_ea(entry_ea):
            if "main" == args.entrypoint and IS_ELF:
                entry_ea = find_main_in_ELF_file()

        ### TODO
        ###if not is_invalid_ea(entry_ea):
        ###    DEBUG("Found {} at {:x}".format(args.entrypoint, entry_ea))
        ###    if not is_start_of_function(entry_ea):
        ###        try_mark_as_function(entry_ea)

    if RECOVER_EHTABLE:
        recover_exception_table()

    process_segments(PIE_MODE)

    funcs = get_functions()

    recovered_fns = 0
    
    exported_funcs, exported_vars = get_program_exports(funcs)

    prev_F = None
    processed_blocks = set()


    # Process and recover functions. 
    while len(funcs):
        func = funcs.pop()
        if func in RECOVERED_EAS or func.isExternal() or func.isThunk():
            continue

        RECOVERED_EAS.add(func)

        prev_F = recover_function(M, func, funcs, exported_funcs, prev_F, processed_blocks)
        recovered_fns += 1

    # TODO: SPARC
    #recover_deferred_preserved_regs(M)

    if recovered_fns == 0:
        DEBUG("COULD NOT RECOVER ANY FUNCTIONS")
        return

    global_vars = []    # TODO(akshay): Pass in relevant info.
    
    DEBUG("Global Variable {}".format(gvar_infile))
    if gvar_infile is not None:
        GM = CFG_pb2.Module()
        GM.ParseFromString(gvar_infile.read())
        count = 0
        for gvar in GM.global_vars:
            global_vars.append([gvar.name, wrap_address(gvar.ea), wrap_address(gvar.ea + gvar.size)])
            
    recover_regions(M, exported_vars, global_vars)
    recover_external_symbols(M)

    DEBUG("Recovered {0} functions.".format(recovered_fns))
    return M

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument(
            "--log_file",
            type=argparse.FileType('w'),
            default=sys.stderr,
            help="Log to a specific file. Default is stderr.")

    parser.add_argument(
            '--arch',
            help='Name of the architecture. Valid names are x86, amd64.',
            required=True)

    parser.add_argument(
            '--os',
            help='Name of the operating system. Valid names are linux, windows.',
            required=True)

    parser.add_argument(
            "--output",
            type=argparse.FileType('wb'),
            default=None,
            help="The output control flow graph recovered from this file",
            required=True)

    parser.add_argument(
            "--std-defs",
            action='append',
            type=str,
            default=[],
            help="std_defs file: definitions and calling conventions of imported functions and data")
    
    parser.add_argument(
            "--syms",
            type=argparse.FileType('r'),
            default=None,
            help="File containing <name> <address> pairs of symbols to pre-define.")

    parser.add_argument(
            "--pie-mode",
            action="store_true",
            default=False,
            help="Assume all immediate values are constants (useful for ELFs built with -fPIE")

    parser.add_argument(
            '--entrypoint',
            help="The entrypoint where disassembly should begin",
            required=False)
    
    parser.add_argument(
            '--recover-global-vars',
            type=argparse.FileType('r'),
            default=None,
            help="File containing the global variables to be lifted")

    parser.add_argument(
            '--recover-exception',
            action="store_true",
            default=False,
            help="Flag to enable the exception handler recovery")

    parser.add_argument(
            '--forced-extern-defs',
            help='List of functions which are forced to be extern and dont need to be recovered',
            default=None,
            required=False)

    parser.add_argument(
            "--rebase",
            help="Amount by which to rebase a binary",
            default=0,
            type=int,
            required=False)

    args = getScriptArgs()[0].strip().split(' ')
    args = parser.parse_args(args)

    if args.log_file != os.devnull:
        INIT_DEBUG_FILE(args.log_file)
        DEBUG("Debugging is enabled.")

    addr_size = {"x86": 32, "amd64": 64, "aarch64": 64, "sparc32": 32,    "sparc64": 64}.get(args.arch, 0)
    if addr_size != get_address_size_in_bits():
        DEBUG("Arch {} address size does not match IDA's available bitness {}! Did you mean to use idal64?".format(
                args.arch, get_address_size_in_bits()))
        sys.exit(1)

    if args.pie_mode:
        DEBUG("Using PIE mode.")
        PIE_MODE = True
        
    if args.recover_exception:
        RECOVER_EHTABLE = True

    EMAP = {}
    EMAP_DATA = {}

    # Try to find the defs file or this OS
    OS_NAME = args.os
    os_defs_file = os.path.join(tools_disass_dir, "defs", "{}.txt".format(args.os))
    if os.path.isfile(os_defs_file):
        args.std_defs.insert(0, os_defs_file)

    # Load in all defs files, include custom ones.
    for defsfile in args.std_defs:
        with open(defsfile, "r") as df:
            DEBUG("Loading Standard Definitions file: {0}".format(defsfile))
            parse_os_defs_file(df)


    ## Shift the program image in memory.
    #if args.rebase:
    #    rebase_flags = idc.MSF_FIXONCE
    #    if idc.MOVE_SEGM_OK != idc.rebase_program(args.rebase, rebase_flags):
    #        DEBUG("ERROR: Failed to rebase program with delta {:08x}".format(args.rebase))

    #    idaapi.auto_wait()

    ANVILL_PROGRAM = anvill.get_program()

    DEBUG("Starting analysis")
    try:
        # TODO: Add prescript
        # Pre-define a bunch of symbol names and their addresses. Useful when reading
        # a core dump.
        #if args.syms:
        #    for line in args.syms:
        #        name, ea_str = line.strip().split(" ")
        #        ea = int(ea_str, base=16)
        #        if not is_internal_code(ea):
        #            try_mark_as_code(ea)
        #        if is_code(ea):
        #            try_mark_as_function(ea)
        #            set_symbol_name(ea, name)
        
        M = recover_module(args.entrypoint, args.recover_global_vars)

        DEBUG("Saving to: {0}".format(args.output.name))
        args.output.write(M.SerializeToString())
        args.output.close()

    except:
        DEBUG(traceback.format_exc())
    
    DEBUG("Done analysis!")
    sys.exit(0)
