"""
This script identifies and decrypts obfuscated strings in garble obfuscated binaries by:

1. Finding runtime functions (newobject, makeslice, growslice)
2. Identifying decryption functions (inlined and normal functions)
3. Emulating the string decryption code using unicorn to get decrypted strings
4. Adding decrypted strings as comments in IDA

Errors can be ignored as most of them are false positives.
Decrypted string comment in the decompilation can get orphaned sometimes.

TODO:
- Patch in the decrypted string
"""

import time
import idautils
import idc
import idaapi
import ida_segment
import ida_funcs
import ida_name
import ida_bytes
import ida_kernwin
import ida_ua
from unicorn import *
from unicorn.x86_const import *

start_time = time.time()

if idc.get_inf_attr(idc.INF_PROCNAME) != "metapc":
    raise Exception("only x86 is supported!")

ARCH = 64 if (idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT) else 32
MODE = UC_MODE_64 if ARCH == 64 else UC_MODE_32
mu = Uc(UC_ARCH_X86, MODE)


def get_xrefs(ea):
    return [x.frm for x in idautils.XrefsTo(ea)]


# From: https://gist.github.com/herrcore/c63f305c5b08df8fc8b6526d4f838a3a
def set_hexrays_comment(address, text):
    """Set comment in decompiled code."""
    cfunc = idaapi.decompile(address)
    if cfunc is not None:
        tl = idaapi.treeloc_t()
        tl.ea = address
        tl.itp = idaapi.ITP_SEMI
        cfunc.set_user_cmt(tl, text)
        cfunc.save_user_cmts()


def set_comment(address, text, decomp=False):
    """Set comment in assembly or decompiled code."""
    if decomp is True:
        # Set in decompiled data
        set_hexrays_comment(address, text)
    else:
        # Set in disassembly
        idc.set_cmt(address, text, 0)


# runtime function signatures
SIGS = [
        (b"\x4C\x89\xC7\x49\xC1\xE0\x03\x49\x81\xF8\xF8\x7F\x00\x00", "runtime.growslice", True),
        (b"\x89\xC6\xC1\xE0\x02\x3D\xF8\x7F\x00\x00", "runtime.growslice", False),
        (b"\x48\x8B\x10\x48\x89\xC6\x48\x89\xD0\x48\x89\xC7\x48\xF7\xE1", "runtime.makeslice", True),
        (b"\x8B\x4C\x24\x14\x8B\x01\x8B\x54\x24\x1C\x89\xC3\xF7\xE2", "runtime.makeslice", False),
        (b"\x55\x48\x89\xE5\x48\x83\xEC\x18\x48\x8B\x10\x48\x89\xC3\xB9\x01\x00\x00\x00\x48\x89\xD0", "runtime.newobject", True),
        (b"\x83\xEC\x10\x8B\x44\x24\x14\x8B\x08\x89\x0C\x24\x89\x44\x24\x04\xC6\x44\x24\x08\x01", "runtime.newobject", False),
]

def name_runtime_funcs():
    """Scan the binary for runtime function patterns and name them."""
    lo, hi = idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea()
    for sig, name, is_64 in SIGS:
        if (ARCH == 64) != is_64:
            continue
        if idc.get_name_ea_simple(name) != idc.BADADDR:
            continue
        hits = []
        ea = ida_bytes.find_bytes(sig, lo)
        while ea != idc.BADADDR and ea < hi:
            f = ida_funcs.get_func(ea)
            if f:
                hits.append((f.start_ea, len(get_xrefs(f.start_ea))))
            ea = ida_bytes.find_bytes(sig, ea + 1)
        if hits:
            best = max(hits, key=lambda x: x[1])[0]
            ida_name.set_name(best, name, ida_name.SN_FORCE)


# name runtime functions if not already named
if any(idc.get_name_ea_simple(n) == idc.BADADDR for n in ("runtime.newobject", "runtime.makeslice", "runtime.growslice")):
    name_runtime_funcs()

# store runtime addresses
r_newobject = idc.get_name_ea_simple("runtime.newobject")
r_makeslice = idc.get_name_ea_simple("runtime.makeslice")
r_growslice = idc.get_name_ea_simple("runtime.growslice")

# duff-copy signatures
D32 = b"\x8B\x0E\x83\xC6\x04"
D64 = b"\x0f\x10\x06\x48\x83\xc6\x10"

# map entire image once
tcnt = idaapi.get_segm_qty()
st = idaapi.getnseg(0).start_ea
en = idaapi.getnseg(tcnt - 1).end_ea
sz = ((en - st) + 0xFFF) & ~0xFFF
mu.mem_map(st, sz)
mu.mem_write(st, idc.get_bytes(st, en - st))

# zero .noptrbss if present
bss = ida_segment.get_segm_by_name(".noptrbss")  # only present on 64 bit elfs
if bss:
    mu.mem_write(bss.start_ea, b"\x00" * (bss.end_ea - bss.start_ea))


text_start = ida_segment.get_segm_by_name(".text").start_ea
text_end = ida_segment.get_segm_by_name(".text").end_ea


mnem_map = {}
op1_type = {}
op2_type = {}
op1_val = {}
op2_val = {}
next_inst = {}
insn = ida_ua.insn_t()
decode_insn = ida_ua.decode_insn
MEM_TYPES = {ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near}

insn = ida_ua.insn_t()
ea = text_start
while ea < text_end:
    if not decode_insn(insn, ea):
        break
    op1, op2 = insn.ops[0], insn.ops[1]
    t1, t2 = op1.type, op2.type
    mnem_map[ea] = insn.get_canon_mnem()

    op1_type[ea], op2_type[ea] = t1, t2

    op1_val[ea] = op1.addr if t1 in MEM_TYPES else (op1.value if t1 == ida_ua.o_imm else None)
    op2_val[ea] = op2.addr if t2 in MEM_TYPES else (op2.value if t2 == ida_ua.o_imm else None)
    next_inst[ea] = insn.size + ea
    ea = insn.size + ea
next_inst[ea] = idc.BADADDR

stack_addr, stack_size = 0x20000, 0x5000
heap_addr, heap_size = 0x30000, 0x7000
temp_addr, temp_size = 0x40000, 0x2000
null_addr, null_size = 0x10000, 0x1000

for addr, size in ((stack_addr, stack_size), (heap_addr, heap_size), (temp_addr, temp_size), (null_addr, null_size)):
    mu.mem_map(addr, size)

# global state variables
top_chunk_addr = heap_addr
junk_byte_remove_call_hit = False
decrypted_string = b""
decryption_func_addr = None
junk_byte_remove_indirect_call = None
runtime_new_object_hits = 0
mapped = []  # tracks auto-mapped pages


regs_32 = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EDI, UC_X86_REG_ESI]
regs_64 = [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R15]
regs = regs_32 if ARCH == 32 else regs_64


def reset_state():
    """clear regs, regions and some other stuff."""
    global top_chunk_addr, junk_byte_remove_call_hit, decrypted_string, decryption_func_addr, mapped, runtime_new_object_hits, junk_byte_remove_indirect_call

    if ARCH == 64:
        mu.reg_write(UC_X86_REG_RSP, stack_addr + (stack_size // 2))
        mu.reg_write(UC_X86_REG_RBP, stack_addr + (stack_size // 2))
    else:
        mu.reg_write(UC_X86_REG_ESP, stack_addr + (stack_size // 2))
        mu.reg_write(UC_X86_REG_EBP, stack_addr + (stack_size // 2))
    
    for reg in regs:
        mu.reg_write(reg, temp_addr + 0x500)
    
    # unmap pages
    for p in mapped:
        mu.mem_unmap(p, 0x1000)
    mapped.clear()
    
    # zero regions
    mu.mem_write(heap_addr, b"\x00" * heap_size)
    mu.mem_write(stack_addr, b"\x00" * stack_size)
    mu.mem_write(temp_addr, b"\x00" * temp_size)
    
    # reset state
    top_chunk_addr = heap_addr
    junk_byte_remove_call_hit = False
    decrypted_string = b""
    decryption_func_addr = None
    junk_byte_remove_indirect_call = None
    runtime_new_object_hits = 0


def map_unmapped_mem(uc, access, address, size, value, user_data):
    """map unmapped memory on demand."""
    global mapped
    uc.mem_map(address & ~(0x1000 - 1), 0x1000)
    mapped.append(address & ~(0x1000 - 1))
    return True


def code_hook(uc, address, size, user_data):

    global top_chunk_addr, junk_byte_remove_call_hit, decrypted_string, runtime_new_object_hits
    mnem = mnem_map[address]

    if mnem == "cmp":
        if "cmp     rsp, [r14+10h]" in idc.generate_disasm_line(address, 0):
            uc.reg_write(UC_X86_REG_RIP, address + size)
            rflags = uc.reg_read(UC_X86_REG_RFLAGS)
            rflags &= ~(1 << 0)  # Clear ZF and CF
            rflags &= ~(1 << 6)
            uc.reg_write(UC_X86_REG_RFLAGS, rflags)

        elif op1_type[address] == idc.o_mem and op2_type[address] == idc.o_imm and op2_val[address] == 0x0:
            rflags = uc.reg_read(UC_X86_REG_RFLAGS)
            rflags |= (1 << 6)  # Set zf
            uc.reg_write(UC_X86_REG_RFLAGS, rflags)
            uc.reg_write(UC_X86_REG_RIP, address + size)

    # To deal with this code in the seed decryption function (only on 32 bit pe files)
    # mov       ecx, dword_78B758
    # test      ecx, ecx
    # jnz       panic
    if ARCH == 32 and runtime_new_object_hits == 4 and mnem == "test" and op2_type[address] == idc.o_reg:  # Called 4 times in the seed decryption func before the above code ^
        # Skip inst and set zf
        eflags = uc.reg_read(UC_X86_REG_EFLAGS)
        eflags |= (1 << 6)
        uc.reg_write(UC_X86_REG_EFLAGS, eflags)
        uc.reg_write(UC_X86_REG_EIP, address + size)
        return
    
    if junk_byte_remove_call_hit:
        # Fetch the actual string without the prepended, and appended junk bytes.
        if mnem.startswith("j"):
            if mnem == "jbe" or mnem == "jb":
                uc.reg_write(UC_X86_REG_RIP if ARCH == 64 else UC_X86_REG_EIP, address + size)
            else:
                raise Exception(f"unexpected jump instruction {mnem} at {hex(address)}")
        elif mnem == "call":
            if ARCH == 64:
                # rbx holds the string address (without the prepended bytes)
                # rcx holds the actual string size
                addr = uc.reg_read(UC_X86_REG_RBX)
                size = uc.reg_read(UC_X86_REG_RCX)
                decrypted_string = uc.mem_read(addr, size)
            elif ARCH == 32:
                # esp+0x4 holds the string address (without the prepended bytes)
                # esp+0x8 holds the actual string size
                esp = uc.reg_read(UC_X86_REG_ESP)
                addr = uc.mem_read(esp + 0x4, 4)
                size = uc.mem_read(esp + 0x8, 4)
                addr = int.from_bytes(addr, byteorder='little')
                size = int.from_bytes(size, byteorder='little')
                decrypted_string = uc.mem_read(addr, size)  
            uc.emu_stop()
            return
        elif mnem == "mov" and ARCH == 32:
            line = idc.generate_disasm_line(address, 0)
            if "mov     ecx, large gs:0" in line or "fs:[ecx]" in line:
                # Ignore this, and manually move some address to ecx that can later be dereferenced
                uc.reg_write(UC_X86_REG_EIP, address + size)
                uc.reg_write(UC_X86_REG_ECX, null_addr + 0x100)  # So [ecx-4] works

    elif address == r_newobject or (address == r_makeslice and ARCH == 64):
        sp = uc.reg_read(UC_X86_REG_RSP) if ARCH == 64 else uc.reg_read(UC_X86_REG_ESP)
        if address == r_newobject:
            addr = uc.reg_read(UC_X86_REG_RAX) if ARCH == 64 else uc.reg_read(UC_X86_REG_EAX)
            size = uc.mem_read(addr, 8) if ARCH == 64 else uc.mem_read(addr, 4)
            size = int.from_bytes(size, byteorder='little')
            runtime_new_object_hits += 1
        else:
            size = uc.reg_read(UC_X86_REG_RCX)
        if ARCH == 64:
            uc.reg_write(UC_X86_REG_RAX, top_chunk_addr)
        else:
            uc.mem_write(sp + 0x8, top_chunk_addr.to_bytes(4, byteorder='little'))
        # Minimum chunk size is a bit large, so the seed decryption funcs runtime.newobject calls work
        if size < 0x100:
            size = 0x100
        top_chunk_addr = top_chunk_addr + size
        ret_addr = uc.mem_read(sp, 8) if ARCH == 64 else uc.mem_read(sp, 4)
        ret_addr = int.from_bytes(ret_addr, byteorder='little')
        sp += 8 if ARCH == 64 else 4
        uc.reg_write(UC_X86_REG_RSP if ARCH == 64 else UC_X86_REG_ESP, sp)
        uc.reg_write(UC_X86_REG_RIP if ARCH == 64 else UC_X86_REG_EIP, ret_addr)
        
    elif (address == r_makeslice and ARCH == 32):
        esp = uc.reg_read(UC_X86_REG_ESP)
        size = uc.mem_read(esp + 0x8, 4)
        ptr_addr = esp + 0xC
        # Allocate memory
        size = int.from_bytes(size, byteorder='little')
        uc.mem_write(ptr_addr, top_chunk_addr.to_bytes(4, byteorder='little'))
        top_chunk_addr = heap_addr + size
        ret_addr = uc.mem_read(esp, 4)
        ret_addr = int.from_bytes(ret_addr, byteorder='little')
        esp += 4
        uc.reg_write(UC_X86_REG_ESP, esp)
        uc.reg_write(UC_X86_REG_EIP, ret_addr)

    # The capacity is set to 0x5000 to deal with super large strings
    elif address == r_growslice and ARCH == 64:
        # runtime.growslice, return values:
        #
        #    newPtr = pointer to the new backing store
        #    newLen = same value as the argument
        #    newCap = capacity of the new backing store
        # rax = pointer, rbx = size(rbx), rcx = capacity (0x5000, something super big, so there is no need to grow the slice again)
        uc.reg_write(UC_X86_REG_RAX, top_chunk_addr)
        top_chunk_addr = top_chunk_addr + 0x5000
        uc.reg_write(UC_X86_REG_RCX, 0x5000)  # New capacity
        sp = uc.reg_read(UC_X86_REG_RSP)
        ret_addr = uc.mem_read(sp, 8)
        ret_addr = int.from_bytes(ret_addr, byteorder='little')
        sp += 8
        uc.reg_write(UC_X86_REG_RSP, sp)
        uc.reg_write(UC_X86_REG_RIP, ret_addr)    
    elif address == r_growslice and ARCH == 32:
        sp = uc.reg_read(UC_X86_REG_ESP)
        size = int.from_bytes(uc.mem_read(sp + 0x8, 4), byteorder='little')
        mu.mem_write(sp + 0x20, 0x5000.to_bytes(4, byteorder='little'))  # Capacity
        mu.mem_write(sp + 0x1C, size.to_bytes(4, byteorder='little'))  # Size
        mu.mem_write(sp + 0x18, top_chunk_addr.to_bytes(4, byteorder='little'))  # Pointer
        top_chunk_addr = top_chunk_addr + 0x5000
        ret_addr = uc.mem_read(sp, 4)
        ret_addr = int.from_bytes(ret_addr, byteorder='little')
        sp += 4
        uc.reg_write(UC_X86_REG_ESP, sp)
        uc.reg_write(UC_X86_REG_EIP, ret_addr)

    elif "call" == mnem_map[address]:
        if op1_type[address] == idc.o_reg:
            if junk_byte_remove_indirect_call is not None: 
                if address == junk_byte_remove_indirect_call:
                    junk_byte_remove_call_hit = True  # Seed transformation func's junk bytes remove call was hit
                return  
            else:
                junk_byte_remove_call_hit = True
        
    if "call" == mnem_map[address] and op1_type[address] == idc.o_near:
        if decryption_func_addr is not None:
            if op1_val[address] == decryption_func_addr:
                return
        if op1_val[address] != r_newobject and op1_val[address] != r_makeslice and op1_val[address] != r_growslice:
            call_target = op1_val[address]
            if ARCH == 32:
                if idc.get_bytes(call_target, len(D32)) != D32:    # Helps with killing false positives during emulation
                    uc.emu_stop()
                    raise Exception(f"unexpected call target {hex(call_target)} at {hex(address)}") 
            else:
                if idc.get_bytes(call_target, len(D64)) != D64:
                    uc.emu_stop()
                    raise Exception(f"unexpected call target {hex(call_target)} at {hex(address)}")


mu.hook_add(UC_HOOK_CODE, code_hook)       
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, map_unmapped_mem)
mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, map_unmapped_mem)

# pattern checks for finding decryption functions
_checks_32 = [
    lambda x: mnem_map.get(x, '') == 'mov' and op1_type[x] == idc.o_reg and op2_type[x] in (idc.o_displ, idc.o_mem, idc.o_phrase),
    lambda x: mnem_map.get(x, '') == 'mov' and op1_type[x] == idc.o_reg and op2_type[x] in (idc.o_displ, idc.o_mem, idc.o_phrase),
    lambda x: mnem_map.get(x, '') == 'mov' and op1_type[x] in (idc.o_displ, idc.o_mem, idc.o_phrase) and op2_type[x] == idc.o_reg,
    lambda x: mnem_map.get(x, '') == 'mov' and op1_type[x] in (idc.o_displ, idc.o_mem, idc.o_phrase) and op2_type[x] == idc.o_reg,
    lambda x: mnem_map.get(x, '').lower() in ('add', 'sub') and idc.print_operand(x, 0).lower() == 'esp' and op2_type[x] == idc.o_imm,
    lambda x: mnem_map.get(x, '').lower() in ('retn', 'ret')
]
_checks_64 = [
    lambda x: mnem_map.get(x, '').lower() in ('add', 'sub') and idc.print_operand(x, 0) == 'rsp' and op2_type[x] == idc.o_imm,
    lambda x: mnem_map.get(x, '') == 'pop' and idc.print_operand(x, 0) == 'rbp',
    lambda x: mnem_map.get(x, '').lower() in ('retn', 'ret')
]


def get_start_addr(addr, duff_copy_check=True):
    """find the start address of a code block."""
    ea = idc.prev_head(addr)
    D = D32 if ARCH == 32 else D64

    while True:
        mnem = mnem_map.get(ea, "")
        if "j" in mnem or mnem == "retn":
            break

        if mnem == "call":
            if duff_copy_check:
                target = op1_val.get(ea)
                if target is not None and idc.get_bytes(target, len(D)) == D:
                    ea = idc.prev_head(ea)
                    continue
                else:
                    break
            else:
                break

        ea = idc.prev_head(ea)

    return next_inst[ea]


def find_decryption_funcs():
    """find decryption functions using the pattern of the indirect junk bytes removal call."""
    call_addrs, addrs = [], []
    seg = ida_segment.get_segm_by_name('.text')
    if not seg:
        raise Exception('no .text segment found')

    ea, end_ea = seg.start_ea, seg.end_ea
    while ea < end_ea and ea != idc.BADADDR:

        while ea < end_ea and mnem_map.get(ea, '').lower() == 'nop':
            ea = next_inst[ea]
        if ea >= end_ea:
            break

        if mnem_map.get(ea, '') == 'call' and op1_type[ea] == idc.o_reg:
            call_addr = ea
            ptr = next_inst[ea]

            while ptr < end_ea and mnem_map.get(ptr, '').lower() == 'nop':
                ptr = next_inst[ptr]

            checks = _checks_32 if ARCH == 32 else _checks_64

            is_match = True
            for check in checks:
                if ptr >= end_ea or not check(ptr):
                    is_match = False
                    break
                ptr = next_inst[ptr]
                # skip any interspersed nops
                while ptr < end_ea and mnem_map.get(ptr, '').lower() == 'nop':
                    ptr = next_inst[ptr]

            if is_match:
                func = ida_funcs.get_func(ea)
                if func:
                    xrefs = get_xrefs(func.start_ea)
                    if 0 < len(xrefs) <= 3:
                        for xref in xrefs:
                            if mnem_map.get(xref, '').lower() == 'call':
                                call_addrs.append([call_addr, get_start_addr(xref, duff_copy_check=False)])
                                addrs.append(func.start_ea)

        ea = next_inst[ea]

    return call_addrs, addrs


def find_seed_transformation_funcs():
    """find seed transformation functions (used to differentiate between non inlined and inlined ones)."""
    ea, call_count, first_hit = text_start, 0, 0
    hits, first_addrs = [], []

    while ea < text_end and ea != idc.BADADDR:
        mnem = mnem_map.get(ea, '')
        if mnem == 'call' and op1_val[ea] == r_newobject:
            if call_count == 0:
                first_hit = ea
            call_count += 1
        elif mnem == 'call' or mnem == 'retn' or mnem.startswith('j'):
            call_count, first_hit = 0, 0
        if call_count == 4:
            hits.append(next_inst[ea])
            first_addrs.append(idc.prev_head(first_hit))
            call_count, first_hit = 0, 0
        ea = next_inst[ea]
    
    candidates = []
    for i, hit in enumerate(hits):
        ea, indirect_count, call_count = hit, 0, 0
        last_indirect = 0
        while ea < text_end and ea != idc.BADADDR:
            mnem = mnem_map.get(ea, '')
            if mnem == 'call':
                if op1_type[ea] == idc.o_reg:
                    last_indirect = ea
                    indirect_count += 1
                else:
                    call_count += 1
            elif mnem == 'retn' or (indirect_count >= 2 and mnem.startswith('j')):
                break
            if call_count == 2:
                break
            ea = next_inst[ea]
        if last_indirect:
            candidates.append([first_addrs[i], last_indirect])
    return candidates


def is_valid_runtime_make_slice_ref(addr):
    """check if a runtime.makeslice reference is used for string decryption"""
    ea = next_inst.get(addr, idc.BADADDR)
    mnem = mnem_map.get(ea)

    while ea != idc.BADADDR:
        if mnem == "retn":
            break
        elif mnem == "call" and op1_type.get(ea) != ida_ua.o_reg:
            break
        elif mnem == "call" and op1_type.get(ea) == ida_ua.o_reg:
            return True
        elif mnem == "jmp":
            ea = op1_val.get(ea)
            mnem = mnem_map.get(ea)
            while mnem not in ("cmp", "test"):
                if mnem == "call" or mnem.startswith("j") or "retn" in mnem:
                    return False
                ea = next_inst.get(ea, idc.BADADDR)
                mnem = mnem_map.get(ea)
            cond = next_inst.get(ea, idc.BADADDR)
            if not mnem_map.get(cond, "").startswith("j"):
                break
            ea = op1_val.get(cond)
            mnem = mnem_map.get(ea)
            while ea != idc.BADADDR and not (mnem.startswith("j") or mnem == "retn"):
                if mnem == "call":
                    return op1_type.get(ea) == ida_ua.o_reg
                ea = next_inst.get(ea, idc.BADADDR)
                mnem = mnem_map.get(ea)
            break
        elif mnem.startswith("j") and mnem != "jnb":
            break

        ea = next_inst.get(ea, idc.BADADDR)
        mnem = mnem_map.get(ea)

    return False


def emulate(start, end):

    global mu
    try:
        mu.emu_start(start, end, timeout=2000000)
    except UcError as uc_err:
        return f"unicorn error: {uc_err} | {mu.reg_read(UC_X86_REG_RIP if ARCH == 64 else UC_X86_REG_EIP):x}"
    except Exception as e:
        return e
    return None


pdata_start = None
pdata_end = None
if ida_segment.get_segm_by_name(".pdata"):
    pdata_start = ida_segment.get_segm_by_name(".pdata").start_ea
    pdata_end = ida_segment.get_segm_by_name(".pdata").end_ea

# find all types of decryption candidates
decryption_func_calls, decryption_funcs = find_decryption_funcs()

seed_transformation_funcs = find_seed_transformation_funcs()
seed_transformation_candidates = [
    candidate for candidate in seed_transformation_funcs
    if not ida_funcs.get_func(candidate[1]) or 
    (ida_funcs.get_func(candidate[1]) and ida_funcs.get_func(candidate[1]).start_ea not in decryption_funcs)
]

runtime_new_object_dec_candidates = []
r_newobject_xrefs = get_xrefs(r_newobject)
for xref in r_newobject_xrefs:
    if pdata_start is not None and pdata_end is not None:
        if pdata_start <= xref < pdata_end:
            continue
    if ARCH == 64:
        cur_ptr = xref
        next_ea = next_inst[cur_ptr]
        if mnem_map[next_ea] == "mov" and op2_type[next_ea] == idc.o_imm and op1_type[next_ea] == idc.o_reg:
            runtime_new_object_dec_candidates.append([xref, get_start_addr(xref)])
    else:
        cur_ptr = xref
        next_ea = next_inst[next_inst[cur_ptr]]
        mnem = mnem_map[next_ea]
        prev_ea = idc.prev_head(idc.prev_head(cur_ptr))
        
        
        if mnem_map[next_ea] == "mov" and (op2_type[next_ea] == idc.o_imm or op2_type[next_ea] == idc.o_reg) and op1_type[next_ea] in (idc.o_displ, idc.o_mem, idc.o_phrase):
            if op1_type[prev_ea] == idc.o_reg and op2_type[prev_ea] == idc.o_mem and mnem_map[idc.prev_head(xref)] == "mov" and op2_type[idc.prev_head(xref)] == idc.o_reg:
                if "byte ptr" in idc.generate_disasm_line(prev_ea, 0):
                    continue
                runtime_new_object_dec_candidates.append([xref, get_start_addr(xref)])

# remove the addresses that are in the decryption funcs (we'll decrypt those separately) 
runtime_new_object_dec_candidates = [
    candidate for candidate in runtime_new_object_dec_candidates
    if not ida_funcs.get_func(candidate[0]) or 
    (ida_funcs.get_func(candidate[0]) and ida_funcs.get_func(candidate[0]).start_ea not in decryption_funcs)
]

r_makeslice_xrefs = get_xrefs(r_makeslice)
runtime_make_slice_dec_candidates = []

for xref in r_makeslice_xrefs:
    if pdata_start is not None and pdata_end is not None:
        if pdata_start <= xref < pdata_end:
            continue
    if is_valid_runtime_make_slice_ref(xref):
        runtime_make_slice_dec_candidates.append([xref, get_start_addr(xref)])

# remove the addresses that are in the decryption funcs
runtime_make_slice_dec_candidates = [
    candidate for candidate in runtime_make_slice_dec_candidates
    if not ida_funcs.get_func(candidate[1]) or 
    (ida_funcs.get_func(candidate[1]) and ida_funcs.get_func(candidate[1]).start_ea not in decryption_funcs)
]

end_time = time.time()
execution_time = end_time - start_time
print(f"execution time to find decryption candidates : {execution_time:.4f} seconds")
print(f"Found : {len(runtime_new_object_dec_candidates)} runtime.newobject candidates")
print(f"Found : {len(runtime_make_slice_dec_candidates)} runtime.makeslice candidates")
print(f"Found : {len(seed_transformation_candidates)} inlined seed transformation candidates")
print(f"Found : {len(decryption_funcs)} decryption functions")

print("Starting emulation...")
decrypted_strings = []

# process seed transformation candidates
for candidate in seed_transformation_candidates:
    reset_state()
    start = get_start_addr(candidate[0])
    junk_byte_remove_indirect_call = candidate[1]
    res = emulate(start, 0xFFFFFFFF)
    if res is not None:
        print(f"Error: {hex(start)} : {res}")
        continue
    else:
        try:
            decrypted_string = decrypted_string.decode()
        except Exception as e:
            print(f"Error: {hex(candidate[0])}: {e} (decoding string)")
            continue
        decrypted_strings.append([candidate[0], decrypted_string])

# process runtime.newobject candidates        
for candidate in runtime_new_object_dec_candidates:
    reset_state()    
    start = candidate[1]
    res = emulate(start, 0xFFFFFFFF)
    if res is not None:
        print(f"Error: {hex(candidate[0])} : {res}")
        continue
    else:
        try:
            decrypted_string = decrypted_string.decode()
        except Exception as e:
            print(f"Error: {hex(candidate[0])}: {e} (decoding string)")
            continue
        decrypted_strings.append([candidate[0], decrypted_string])

# process runtime.makeslice candidates
for candidate in runtime_make_slice_dec_candidates:
    reset_state()    
    start = candidate[1]
    end = 0xFFFFFFFF
    res = emulate(start, end)
    if res is not None:
        print(f"Error: {hex(candidate[0])} : {res}")
        continue
    else:
        try:
            decrypted_string = decrypted_string.decode()
        except Exception as e:
            print(f"Error: {hex(candidate[0])}: {e} (decoding string)")
            continue
        decrypted_strings.append([candidate[0], decrypted_string])

# process decryption function calls
for i, candidate in enumerate(decryption_func_calls):
    reset_state()    
    start = candidate[1]
    decryption_func_addr = decryption_funcs[i]
    junk_byte_remove_indirect_call = candidate[0]
    end = 0xFFFFFFFF
    res = emulate(start, end)
    if res is not None:
        print(f"Error: {hex(start)} : {res}")
        continue
    else:
        try:
            decrypted_string = decrypted_string.decode()
        except Exception as e:
            print(f"Error: {hex(start)}: {e} (decoding string)")
            continue
        decrypted_strings.append([start, decrypted_string])

print(f"Found {hex(len(decrypted_strings))} strings")

decrypted_strings.sort(key=lambda x: x[0])

# add comments to disassembly
for addr, string in decrypted_strings:
    set_comment(addr, string)




class DecryptedStringsChooser(ida_kernwin.Choose):
    """chooser widget for displaying decrypted strings."""
    
    def __init__(self, items):
        self.items = items
        ida_kernwin.Choose.__init__(
            self,
            "Decrypted Strings",
            [["Address", ida_kernwin.Choose.CHCOL_HEX], ["String", ida_kernwin.Choose.CHCOL_PLAIN]],
            flags=ida_kernwin.Choose.CH_MULTI
        )
        self.icon = 0

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        addr, string = self.items[n]
        return [f"{addr:08X}", string]

    def OnSelectLine(self, n):
        for i in n:
            addr, _ = self.items[i]
            ida_kernwin.jumpto(addr)


chooser = DecryptedStringsChooser(decrypted_strings)
chooser.Show()

result = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Would you like to add the strings as comments to the decompiled code as well?")
if result == ida_kernwin.ASKBTN_YES:
    for addr, string in decrypted_strings:
        set_comment(addr, string, decomp=True)

