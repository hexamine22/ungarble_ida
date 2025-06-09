import idautils
import idc
from unicorn import *
from unicorn.x86_const import *
import idaapi
import ida_segment
import ida_funcs
import ida_name
import ida_bytes
import ida_kernwin

"""
Errors can be ignored as most of them are false positives.
decrypted string comment in the decompilation can get orphaned sometimes.

TODO : 
Optimize the code (performance is pretty bad rn), but it works
Patch in the decrypted string. 
Add more comments, and refactor the ugly code
"""

arch = None
if idc.get_inf_attr(idc.INF_PROCNAME) == "metapc":
    if idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT:
        arch = 64
    else:
        arch = 32
else:
    raise Exception("failed to determine architecture, only x86 is supported!")
if arch == 64:
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
else:
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

def get_xref_list(address):
    xref_list = []
    xrefs = idautils.XrefsTo(address)
    for addr in xrefs:
        xref_list.append(addr.frm)
    return xref_list

#from : https://gist.github.com/herrcore/c63f305c5b08df8fc8b6526d4f838a3a
def set_hexrays_comment(address, text):
    '''
    set comment in decompiled code
    '''
    cfunc = idaapi.decompile(address)
    if cfunc != None:
        tl = idaapi.treeloc_t()
        tl.ea = address
        tl.itp = idaapi.ITP_SEMI
        cfunc.set_user_cmt(tl, text)
        cfunc.save_user_cmts() 


def set_comment(address, text):
    ## Set in dissassembly
    idc.set_cmt(address, text,0)
    ## Set in decompiled data
    set_hexrays_comment(address, text)


def find_and_name_runtime_funcs():
    signatures = [
        # 64-bit growslice
        (b"\x4C\x89\xC7\x49\xC1\xE0\x03\x49\x81\xF8\xF8\x7F\x00\x00", "runtime.growslice", True),
        # 32-bit growslice
        (b"\x89\xC6\xC1\xE0\x02\x3D\xF8\x7F\x00\x00",                     "runtime.growslice", False),

        # 64-bit makeslice
        (b"\x48\x8B\x10\x48\x89\xC6\x48\x89\xD0\x48\x89\xC7\x48\xF7\xE1", "runtime.makeslice", True),
        # 32-bit makeslice
        (b"\x8B\x4C\x24\x14\x8B\x01\x8B\x54\x24\x1C\x89\xC3\xF7\xE2",     "runtime.makeslice", False),

        # 64-bit newobject
        (b"\x55\x48\x89\xE5\x48\x83\xEC\x18\x48\x8B\x10"
         b"\x48\x89\xC3\xB9\x01\x00\x00\x00\x48\x89\xD0",                 "runtime.newobject", True),
        # 32-bit newobject
        (b"\x83\xEC\x10\x8B\x44\x24\x14\x8B\x08\x89\x0C\x24"
         b"\x89\x44\x24\x04\xC6\x44\x24\x08\x01",                         "runtime.newobject", False),
    ]

    min_ea = idaapi.inf_get_min_ea()
    max_ea = idaapi.inf_get_max_ea()

    for sig_bytes, name, sig_is64 in signatures:
        if (arch == 64) != sig_is64:
            continue

        # already named? skip
        if idc.get_name_ea_simple(name) != idc.BADADDR:
            continue

        candidates = []
        ea = ida_bytes.find_bytes(sig_bytes, min_ea)
        while ea != idc.BADADDR and ea < max_ea:
            f = ida_funcs.get_func(ea)
            if f:
                fea = f.start_ea
                candidates.append((fea, len(get_xref_list(fea))))
            ea = ida_bytes.find_bytes(sig_bytes, ea + 1)

        if candidates:
            #pick the function with the most xrefs
            best_ea = max(candidates, key=lambda x: x[1])[0]
            ida_name.set_name(best_ea, name, ida_name.SN_FORCE)

if any(idc.get_name_ea_simple(n) == idc.BADADDR
       for n in ("runtime.newobject", "runtime.makeslice", "runtime.growslice")):
    find_and_name_runtime_funcs()

runtimenewobject = idc.get_name_ea_simple("runtime.newobject")
runtimemakeslice = idc.get_name_ea_simple("runtime.makeslice")
runtimegrowslice = idc.get_name_ea_simple("runtime.growslice")


runtimeDuffCopySig = b"\x8B\x0E\x83\xC6\x04"
runtimeDuffCopySig64 = b"\x0f\x10\x06\x48\x83\xc6\x10"

runtimenewobjectXrefs = get_xref_list(runtimenewobject)

noOfSegs = idaapi.get_segm_qty()
start = idaapi.getnseg(0).start_ea
end = idaapi.getnseg(noOfSegs - 1).end_ea
allignedSize = ((end - start) + 0xFFF) & ~0xFFF
data = idc.get_bytes(start, end - start)
mu.mem_map(start, allignedSize)
mu.mem_write(start, data)

noptrbss_seg = ida_segment.get_segm_by_name(".noptrbss") #only present on 64 bit elfs
if noptrbss_seg:
    noptrbss_start = noptrbss_seg.start_ea
    noptrbss_end = noptrbss_seg.end_ea
    mu.mem_write(noptrbss_start, b"\x00" * (noptrbss_end - noptrbss_start))

stackaddr = 0x20000
stack_size = 0x5000
tempMemAddr = 0x10000
tempMemSize = 0x2000
heapAddr = 0x30000
heapSize = 0x7000
topChunkAddr = heapAddr
junkByteRemoveCallHit = False
decryptedString = b""
decryptionFuncAddr = None
junkByteRemoveIndirectCall = None
runtimeNewObjectHits = 0

mu.mem_map(tempMemAddr, tempMemSize)
mu.mem_map(heapAddr, heapSize)
arch32Regs = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EDI, UC_X86_REG_ESI]
arch64Regs = [UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R15]
mu.mem_map(stackaddr, stack_size)

mappedMem = []
def resetState():
    global topChunkAddr
    global junkByteRemoveCallHit
    global decryptedString
    global decryptionFuncAddr
    global mappedMem
    global runtimeNewObjectHits
    global junkByteRemoveIndirectCall

    
    #To prevent exceptions when a random reg is dereferenced (MapUnmappedMem handles this so I should probably remove this now)
    if arch == 64:
        for reg in arch64Regs:
            mu.reg_write(reg, tempMemAddr)
    else:
        for reg in arch32Regs:
            mu.reg_write(reg, tempMemAddr)

    if arch == 64:
        mu.reg_write(UC_X86_REG_RSP, stackaddr + (stack_size // 2))
        mu.reg_write(UC_X86_REG_RBP, stackaddr + (stack_size // 2))
        mu.reg_write(UC_X86_REG_R14, stackaddr + (stack_size // 2))
    else:
        mu.reg_write(UC_X86_REG_ESP, stackaddr + (stack_size // 2))
        mu.reg_write(UC_X86_REG_EBP, stackaddr + (stack_size // 2))
    for addr in mappedMem:
        mu.mem_unmap(addr, 0x1000)
    mu.mem_write(tempMemAddr, b"\x00" * tempMemSize)
    mu.mem_write(heapAddr, b"\x00" * heapSize)
    mu.mem_write(stackaddr, b"\x00" * stack_size)
    mappedMem = []
    topChunkAddr = heapAddr
    junkByteRemoveCallHit = False
    decryptedString = b""
    decryptionFuncAddr = None
    junkByteRemoveIndirectCall = None
    runtimeNewObjectHits = 0

def MapUnmappedMem(uc, access, address, size, value, user_data):
    global mappedMem
    uc.mem_map(address & ~(0x1000 - 1),0x1000)
    mappedMem.append(address & ~(0x1000 - 1))
    return True

def codehook(uc, address, size, user_data):
    global topChunkAddr
    global junkByteRemoveCallHit
    global decryptedString
    global runtimeNewObjectHits
    if "cmp     rsp, [r14+10h]" in idc.generate_disasm_line(address, 0):
        uc.reg_write(UC_X86_REG_RIP, address + size)
        rflags = uc.reg_read(UC_X86_REG_RFLAGS)
        rflags &= ~(1 << 0)
        rflags &= ~(1 << 6)
        uc.reg_write(UC_X86_REG_RFLAGS, rflags)

    if idc.print_insn_mnem(address) == "cmp":
        if idc.get_operand_type(address,0) == idc.o_mem and idc.get_operand_type(address,1) == idc.o_imm and idc.get_operand_value(address, 1) == 0x0:
            rflags = uc.reg_read(UC_X86_REG_RFLAGS)
            # set zf
            rflags |= (1 << 6)
            uc.reg_write(UC_X86_REG_RFLAGS, rflags)
            uc.reg_write(UC_X86_REG_RIP, address + size)

    """ To deal with this code in the seed decryption function (only on 32 bit pe files)
    mov     ecx, dword_78B758
    test    ecx, ecx
    jnz     panic
    """

    if arch == 32 and runtimeNewObjectHits == 4 and idc.print_insn_mnem(address) == "test" and idc.get_operand_type(address,1) == idc.o_reg: #called 4 times in the seed decryption func before the above code ^
        #skip inst and set zf
        eflags = uc.reg_read(UC_X86_REG_EFLAGS)
        eflags |= (1 << 6)
        uc.reg_write(UC_X86_REG_EFLAGS, eflags)
        uc.reg_write(UC_X86_REG_EIP, address + size)
        return
    if junkByteRemoveCallHit:
        #fetch the actual string without the prepended, and appended junk bytes.
        mnem = idc.print_insn_mnem(address)
        if mnem.startswith("j"):
            if mnem == "jbe" or mnem == "jb":
                uc.reg_write(UC_X86_REG_RIP if arch == 64 else UC_X86_REG_EIP, address + size)
            else:
                raise Exception(f"unexpected jump instruction {mnem} at {hex(address)}")
        elif mnem == "call":
            if arch == 64:
                #rbx holds the string address (without the prepended bytes)
                #rcx holds the actual string size
                addr = uc.reg_read(UC_X86_REG_RBX)
                size = uc.reg_read(UC_X86_REG_RCX)
                decryptedString = uc.mem_read(addr, size)
            elif arch == 32:
                #esp+0x4 holds the string address (without the prepended bytes)
                #esp+0x8 holds the actual string size
                esp = uc.reg_read(UC_X86_REG_ESP)
                addr = uc.mem_read(esp + 0x4, 4)
                size = uc.mem_read(esp + 0x8, 4)
                addr = int.from_bytes(addr, byteorder='little')
                size = int.from_bytes(size, byteorder='little')
                decryptedString = uc.mem_read(addr, size)  
            uc.emu_stop()
            return
        elif mnem == "mov" and arch == 32:
            line = idc.generate_disasm_line(address, 0)
            if "mov     ecx, large gs:0" in line or "fs:[ecx]" in line:
                #ignore this, and manually move some address to ecx that can later be dereferenced
                uc.reg_write(UC_X86_REG_EIP, address + size)
                uc.reg_write(UC_X86_REG_ECX, tempMemAddr+0x100) # so [ecx-4] works
    elif address == runtimenewobject or (address == runtimemakeslice and arch == 64):
        sp = uc.reg_read(UC_X86_REG_RSP) if arch == 64 else uc.reg_read(UC_X86_REG_ESP)
        if address == runtimenewobject:
            addr = uc.reg_read(UC_X86_REG_RAX) if arch == 64 else uc.reg_read(UC_X86_REG_EAX)
            size = uc.mem_read(addr, 8) if arch == 64 else uc.mem_read(addr, 4)
            size = int.from_bytes(size, byteorder='little')
            runtimeNewObjectHits += 1
        else:
            size = uc.reg_read(UC_X86_REG_RCX)
        if arch == 64:
            uc.reg_write(UC_X86_REG_RAX, topChunkAddr)
        else:
            uc.mem_write(sp + 0x8, topChunkAddr.to_bytes(4, byteorder='little'))
        #minimum chunk size is a bit large, so the seed decryption funcs runtime.newobject calls work
        if size < 0x100:
            size = 0x100
        topChunkAddr = topChunkAddr + size
        retAddr = uc.mem_read(sp, 8) if arch == 64 else uc.mem_read(sp, 4)
        retAddr = int.from_bytes(retAddr, byteorder='little')
        sp += 8 if arch == 64 else 4
        uc.reg_write(UC_X86_REG_RSP if arch == 64 else UC_X86_REG_ESP, sp)
        uc.reg_write(UC_X86_REG_RIP if arch == 64 else UC_X86_REG_EIP, retAddr)
        
    elif (address == runtimemakeslice and arch == 32):
        esp = uc.reg_read(UC_X86_REG_ESP)
        size = uc.mem_read(esp + 0x8, 4)
        ptrAddr = esp + 0xC
        #allocate memory
        size = int.from_bytes(size, byteorder='little')
        uc.mem_write(ptrAddr, topChunkAddr.to_bytes(4, byteorder='little'))
        topChunkAddr = heapAddr + size
        retAddr = uc.mem_read(esp, 4)
        retAddr = int.from_bytes(retAddr, byteorder='little')
        esp += 4
        uc.reg_write(UC_X86_REG_ESP, esp)
        uc.reg_write(UC_X86_REG_EIP, retAddr)

    #The capacity is set to 0x5000 to deal with super large strings
    elif address == runtimegrowslice and arch == 64:
        """
        // runtime.growslice, return values:
        //
        //	newPtr = pointer to the new backing store
        //	newLen = same value as the argument
        //	newCap = capacity of the new backing store
        """
        #rax = pointer, rbx = size(rbx), rcx = capacity (0x5000, something super big, so there is no need to grow the slice again)
        uc.reg_write(UC_X86_REG_RAX, topChunkAddr)
        topChunkAddr = topChunkAddr + 0x5000
        uc.reg_write(UC_X86_REG_RCX, 0x5000) #new capacity
        sp = uc.reg_read(UC_X86_REG_RSP)
        retAddr = uc.mem_read(sp, 8)
        retAddr = int.from_bytes(retAddr, byteorder='little')
        sp += 8
        uc.reg_write(UC_X86_REG_RSP, sp)
        uc.reg_write(UC_X86_REG_RIP, retAddr)   
    elif address == runtimegrowslice and arch == 32:
        sp = uc.reg_read(UC_X86_REG_ESP)
        size = int.from_bytes(uc.mem_read(sp+0x8, 4),byteorder='little')
        mu.mem_write(sp + 0x20, 0x5000.to_bytes(4, byteorder='little')) #capacity
        mu.mem_write(sp + 0x1C, size.to_bytes(4, byteorder='little')) #size
        mu.mem_write(sp + 0x18, topChunkAddr.to_bytes(4, byteorder='little')) #pointer
        topChunkAddr = topChunkAddr + 0x5000
        retAddr = uc.mem_read(sp, 4)
        retAddr = int.from_bytes(retAddr, byteorder='little')
        sp += 4
        uc.reg_write(UC_X86_REG_ESP, sp)
        uc.reg_write(UC_X86_REG_EIP, retAddr)

    elif "call" == idc.print_insn_mnem(address):
        if idc.get_operand_type(address, 0) == idc.o_reg:
            if junkByteRemoveIndirectCall is not None: 
                if address == junkByteRemoveIndirectCall:
                    junkByteRemoveCallHit = True #seed transformation func's junk bytes remove call was hit
                return  
            else:
                junkByteRemoveCallHit = True
    
    if "call" == idc.print_insn_mnem(address) and idc.get_operand_type(address, 0) == idc.o_near:
        if decryptionFuncAddr is not None:
            if idc.get_operand_value(address, 0) == decryptionFuncAddr:
                return
        if idc.get_operand_value(address, 0) != runtimenewobject and idc.get_operand_value(address, 0) != runtimemakeslice and idc.get_operand_value(address, 0) != runtimegrowslice:
            callTarget = idc.get_operand_value(address, 0)
            if arch == 32:
                if idc.get_bytes(callTarget, len(runtimeDuffCopySig)) != runtimeDuffCopySig:    #helps with killing false positives during emulation
                    uc.emu_stop()
                    raise Exception(f"unexpected call target {hex(callTarget)} at {hex(address)}") 
            else:
                if idc.get_bytes(callTarget, len(runtimeDuffCopySig64)) != runtimeDuffCopySig64:
                    uc.emu_stop()
                    raise Exception(f"unexpected call target {hex(callTarget)} at {hex(address)}")
                
            
mu.hook_add(UC_HOOK_CODE, codehook)      
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, MapUnmappedMem)
mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, MapUnmappedMem)

"""
Pattern to find
call    eax
mov     eax, [esp+2Ch+var_20]
mov     ecx, [esp+2Ch+var_1C]
mov     [esp+2Ch+arg_14], eax
mov     [esp+2Ch+arg_18], ecx
add/sub     esp, 2Ch
retn
"""
def findDecryptionFuncs32Bit():
    callAddrs = []
    addrs = []
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        raise Exception("no .text segment found")
    start_ea = seg.start_ea
    end_ea   = seg.end_ea
    ea = start_ea

    while ea < end_ea:
        # skip nops
        while ea < end_ea and idc.print_insn_mnem(ea) == "nop":
            ea = idc.next_head(ea)
        if ea >= end_ea:
            break

        # call reg
        if (idc.print_insn_mnem(ea) == "call" and
            idc.get_operand_type(ea, 0) == idc.o_reg):
            callAddr = ea

            # mov reg, [mem]
            ea1 = idc.next_head(ea)
            while ea1 < end_ea and idc.print_insn_mnem(ea1) == "nop":
                ea1 = idc.next_head(ea1)
            if (ea1 < end_ea and
                idc.print_insn_mnem(ea1) == "mov" and
                idc.get_operand_type(ea1, 0) == idc.o_reg and
                idc.get_operand_type(ea1, 1) in (idc.o_displ, idc.o_mem, idc.o_phrase)):

                # mov reg, [mem]
                ea2 = idc.next_head(ea1)
                while ea2 < end_ea and idc.print_insn_mnem(ea2) == "nop":
                    ea2 = idc.next_head(ea2)
                if (ea2 < end_ea and
                    idc.print_insn_mnem(ea2) == "mov" and
                    idc.get_operand_type(ea2, 0) == idc.o_reg and
                    idc.get_operand_type(ea2, 1) in (idc.o_displ, idc.o_mem, idc.o_phrase)):

                    # mov [mem], reg
                    ea3 = idc.next_head(ea2)
                    while ea3 < end_ea and idc.print_insn_mnem(ea3) == "nop":
                        ea3 = idc.next_head(ea3)
                    if (ea3 < end_ea and
                        idc.print_insn_mnem(ea3) == "mov" and
                        idc.get_operand_type(ea3, 0) in (idc.o_displ, idc.o_mem, idc.o_phrase) and
                        idc.get_operand_type(ea3, 1) == idc.o_reg):

                        # mov [mem], reg
                        ea4 = idc.next_head(ea3)
                        while ea4 < end_ea and idc.print_insn_mnem(ea4) == "nop":
                            ea4 = idc.next_head(ea4)
                        if (ea4 < end_ea and
                            idc.print_insn_mnem(ea4) == "mov" and
                            idc.get_operand_type(ea4, 0) in (idc.o_displ, idc.o_mem, idc.o_phrase) and
                            idc.get_operand_type(ea4, 1) == idc.o_reg):

                            # add/sub esp, imm
                            ea5 = idc.next_head(ea4)
                            while ea5 < end_ea and idc.print_insn_mnem(ea5) == "nop":
                                ea5 = idc.next_head(ea5)
                            if (ea5 < end_ea and
                                idc.print_operand(ea5, 0).lower() == "esp" and
                                idc.get_operand_type(ea5, 1) == idc.o_imm and
                                idc.print_insn_mnem(ea5).lower() in ("add", "sub")):

                                # retn
                                ea6 = idc.next_head(ea5)
                                while ea6 < end_ea and idc.print_insn_mnem(ea6) == "nop":
                                    ea6 = idc.next_head(ea6)
                                if (ea6 < end_ea and
                                    idc.print_insn_mnem(ea6).lower() in ("retn", "ret")):
                                    func = ida_funcs.get_func(ea)
                                    if func:
                                        xrefs = get_xref_list(func.start_ea)
                                        if 0 < len(xrefs) <= 3:
                                            for xref in xrefs:
                                                if idc.print_insn_mnem(xref).lower() == "call":
                                                    callAddrs.append([callAddr, getStartAddr(xref, duffcopyCheck=False)])
                                                    addrs.append(func.start_ea)
                                                    break
        ea = idc.next_head(ea)

    return callAddrs, addrs

"""
Pattern to find
call    r8
add/sub     rsp, 38h
pop     rbp
retn
"""
def findDecryptionFuncs64Bit():
    callAddrs = []
    addrs = []
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        raise Exception("no .text segment found")
    start_ea = seg.start_ea
    end_ea   = seg.end_ea
    ea = start_ea
    while ea < end_ea:
        while ea < end_ea and idc.print_insn_mnem(ea) == "nop":
            ea = idc.next_head(ea)
        if ea >= end_ea:
            break
        #call reg
        if idc.print_insn_mnem(ea) == "call":
            callAddr = ea
            if idc.get_operand_type(ea, 0) == idc.o_reg:
                ea1 = idc.next_head(ea)
                while ea1 < end_ea and idc.print_insn_mnem(ea1) == "nop":
                    ea1 = idc.next_head(ea1)
                #add rsp, imm or sub rsp, 0xFFFFFFFFFFFF....
                if idc.print_insn_mnem(ea1) == "add" or idc.print_insn_mnem(ea1) == "sub":
                    if idc.print_operand(ea1, 0) == "rsp" and idc.get_operand_type(ea1, 1) == idc.o_imm:
                        ea2 = idc.next_head(ea1)
                        while ea2 < end_ea and idc.print_insn_mnem(ea2) == "nop":
                            ea2 = idc.next_head(ea2)
                        #pop rbp
                        if idc.print_insn_mnem(ea2) == "pop" and idc.print_operand(ea2, 0) == "rbp":
                            ea3 = idc.next_head(ea2)
                            while ea3 < end_ea and idc.print_insn_mnem(ea3) == "nop":
                                ea3 = idc.next_head(ea3)
                            #ret
                            if idc.print_insn_mnem(ea3) == "retn":
                                func = ida_funcs.get_func(ea)
                                #if the function is not identified by ida, it's very likely a false positive, so we can ignore it
                                if func:
                                    xrefs = get_xref_list(func.start_ea)
                                    #1. jmp func, call func, reference in .pdata (only on windows)
                                    if len(xrefs) <= 3 and len(xrefs) != 0:
                                        #find the call xref (not the jmp xref)
                                        for xref in xrefs:
                                            if idc.print_insn_mnem(xref) == "call":
                                                addrs.append(func.start_ea)
                                                callAddrs.append([callAddr,getStartAddr(xref, duffcopyCheck=False)])
        ea = idc.next_head(ea)
    return callAddrs, addrs

#used to differentiate between non inlined seed transformation functions and inlined ones (it's very rare for this to be inlined though)
def find_seed_transformation_funcs():
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        raise Exception("no .text segment found")
    start_ea = seg.start_ea
    end_ea   = seg.end_ea
    ea = start_ea
    callCount = 0
    hits = []
    seedTransformationCandidates = []
    firstAddrs = []
    firstHit = 0
    while ea < end_ea and ea != idc.BADADDR:
        mnem = idc.print_insn_mnem(ea)
        if mnem == "call" and idc.get_operand_value(ea,0) == runtimenewobject:
            if callCount == 0:
                firstHit = ea
            
            callCount += 1
        elif mnem == "call" or mnem == "retn" or mnem.startswith("j"):
            callCount = 0
            firstHit = 0
        if callCount == 4:
            hits.append(idc.next_head(ea))
            firstAddrs.append(idc.prev_head(firstHit))
            callCount = 0
            firstHit = 0
        ea = idc.next_head(ea)
    #find the final call reg inst
    for i, hit in enumerate(hits):
        ea = hit
        callCount = 0
        indirectCallCount = 0
        lastIndirectCall = 0
        while ea < end_ea and ea != idc.BADADDR:
            mnem = idc.print_insn_mnem(ea)
            if mnem == "call" and idc.get_operand_type(ea,0) == idc.o_reg:
                lastIndirectCall = ea
                indirectCallCount += 1
            elif mnem == "call":
                callCount += 1
            elif mnem == "retn":
                break
            elif indirectCallCount >= 2 and mnem.startswith("j"):
                break
            if callCount == 2:
                break
            ea = idc.next_head(ea)
        if lastIndirectCall != 0:
            seedTransformationCandidates.append([firstAddrs[i],lastIndirectCall])
    return seedTransformationCandidates

def getStartAddr(addr,duffcopyCheck=True):
    start_addr = idc.prev_head(addr)
    mnem = idc.print_insn_mnem(start_addr)
    while "j" not in mnem and mnem != "retn":
        if arch == 32 and mnem == "call":
            #check if the call is runtime.duffcopy which can be ignored
            callTarget = idc.get_operand_value(start_addr, 0)
            if duffcopyCheck == True and idc.get_bytes(callTarget, len(runtimeDuffCopySig)) == runtimeDuffCopySig:
                start_addr = idc.prev_head(start_addr)
                mnem = idc.print_insn_mnem(start_addr)
                continue
            else:
                break
        if arch == 64 and mnem == "call":
            #check if the call is runtime.duffcopy which can be ignored
            callTarget = idc.get_operand_value(start_addr, 0)
            if duffcopyCheck == True and idc.get_bytes(callTarget, len(runtimeDuffCopySig64)) == runtimeDuffCopySig64:
                start_addr = idc.prev_head(start_addr)
                mnem = idc.print_insn_mnem(start_addr)
                continue
            else:
                break
        start_addr = idc.prev_head(start_addr)
        mnem = idc.print_insn_mnem(start_addr)
    return idc.next_head(start_addr)

def isValidRuntimeMakeSliceRef(addr):
    #perform a lookup for the call reg instruction
    ea = idc.next_head(addr)
    mnem = idc.print_insn_mnem(ea)
    while ea != idc.BADADDR:
        if mnem == "retn":
            break
        elif mnem == "call" and idc.get_operand_type(ea, 0) != idc.o_reg:
            break
        elif mnem == "call" and idc.get_operand_type(ea, 0) == idc.o_reg:
            return True
        elif mnem == "jmp":
            jmpTarget = idc.get_operand_value(ea, 0)
            ea = jmpTarget
            mnem = idc.print_insn_mnem(ea)
            while mnem != "cmp" and mnem != "test":
                if mnem == "call" or mnem.startswith("j") or "retn" in mnem:
                    return False
                ea = idc.next_head(ea)
                mnem = idc.print_insn_mnem(ea)

            if idc.print_insn_mnem(ea) != "cmp" and idc.print_insn_mnem(ea) != "test":
                break
            condJump = idc.next_head(ea)
            if "j" not in idc.print_insn_mnem(condJump):
                break
            condJumpTarget = idc.get_operand_value(condJump, 0)
            #look for a call reg inst here
            ea = condJumpTarget
            mnem = idc.print_insn_mnem(ea)
            while mnem != "retn" and "j" not in mnem:
                if mnem == "call":
                    if idc.get_operand_type(ea, 0) == idc.o_reg:
                        return True
                    else:
                        return False
                ea = idc.next_head(ea)
                mnem = idc.print_insn_mnem(ea)
            break
        elif "j" in mnem and mnem != "jnb":
            break 
        ea = idc.next_head(ea)
        mnem = idc.print_insn_mnem(ea)
    return False


def emulate(start,end):
    global mu
    try:
        mu.emu_start(start, end,timeout=2000000)
    except UcError as uc_err:
        return f"unicorn error: {uc_err} | {mu.reg_read(UC_X86_REG_RIP if arch == 64 else UC_X86_REG_EIP):x}"
    except Exception as e:
        return e
    return None

pdata_start = None
pdata_end = None
if ida_segment.get_segm_by_name(".pdata"):
    pdata_start = ida_segment.get_segm_by_name(".pdata").start_ea
    pdata_end = ida_segment.get_segm_by_name(".pdata").end_ea

if arch == 64:
    decryptionFuncCalls, decryptionFuncs  = findDecryptionFuncs64Bit()
else:
    decryptionFuncCalls, decryptionFuncs = findDecryptionFuncs32Bit()

seedTransformationFuncs = find_seed_transformation_funcs()
seedTransformationCandidates = [
    candidate for candidate in seedTransformationFuncs
    if not ida_funcs.get_func(candidate[1]) or 
    (ida_funcs.get_func(candidate[1]) and ida_funcs.get_func(candidate[1]).start_ea not in decryptionFuncs)
]

runtimeNewObjectDecCandidates = []
for xref in runtimenewobjectXrefs:
    if pdata_start is not None and pdata_end is not None:
        if pdata_start <= xref < pdata_end:
            continue
    if arch == 64:
        cur_ptr = xref
        next = idc.next_head(cur_ptr)
        #check for a mov reg, imm instruction
        if idc.print_insn_mnem(next) == "mov" and idc.get_operand_type(next, 1) == idc.o_imm and idc.get_operand_type(next, 0) == idc.o_reg:
            runtimeNewObjectDecCandidates.append([xref,getStartAddr(xref)])
    else:
        cur_ptr = xref
        next = idc.next_head(idc.next_head(cur_ptr))
        mnem = idc.print_insn_mnem(next)
        prev = idc.prev_head(idc.prev_head(cur_ptr))
        if idc.print_insn_mnem(next) == "mov" and (idc.get_operand_type(next, 1) == idc.o_imm or idc.get_operand_type(next, 1) == idc.o_reg) and idc.get_operand_type(next, 0) in (idc.o_displ, idc.o_mem, idc.o_phrase):
            if idc.get_operand_type(prev,0) == idc.o_reg and idc.get_operand_type(prev,1) == idc.o_mem and idc.print_insn_mnem(idc.prev_head(xref)) == "mov" and idc.get_operand_type(idc.prev_head(xref), 1) == idc.o_reg:
                if "byte ptr" in idc.generate_disasm_line(prev, 0):
                    continue
                runtimeNewObjectDecCandidates.append([xref,getStartAddr(xref)])

#remove the addresses that are in the decryption funcs (we'll decrypt those separately) 

runtimeNewObjectDecCandidates = [
    candidate for candidate in runtimeNewObjectDecCandidates
    if not ida_funcs.get_func(candidate[0]) or 
    (ida_funcs.get_func(candidate[0]) and ida_funcs.get_func(candidate[0]).start_ea not in decryptionFuncs)
]

runtimemakesliceXrefs = get_xref_list(runtimemakeslice)

runtimeMakeSliceDecCandidates = []

for xref in runtimemakesliceXrefs:
    if pdata_start is not None and pdata_end is not None:
        if pdata_start <= xref < pdata_end:
            continue
    if isValidRuntimeMakeSliceRef(xref):
        runtimeMakeSliceDecCandidates.append([xref,getStartAddr(xref)])

#remove the addresses that are in the decryption funcs
runtimeMakeSliceDecCandidates = [
    candidate for candidate in runtimeMakeSliceDecCandidates
    if not ida_funcs.get_func(candidate[1]) or 
    (ida_funcs.get_func(candidate[1]) and ida_funcs.get_func(candidate[1]).start_ea not in decryptionFuncs)
]

print(f"Found : {len(runtimeNewObjectDecCandidates)} runtime.newobject candidates")
print(f"Found : {len(runtimeMakeSliceDecCandidates)} runtime.makeslice candidates")
print(f"Found : {len(seedTransformationCandidates)} inlined seed transformation candidates")
print(f"Found : {len(decryptionFuncs)} decryption functions")

print("Starting emulation...")
decryptedStrings = []

for candidate in seedTransformationCandidates:
    resetState()
    start = getStartAddr(candidate[0])
    junkByteRemoveIndirectCall = candidate[1]
    res = emulate(start, 0xFFFFFFFF)
    if res != None:
        print(f"Error: {hex(candidate[0])} : {res}")
        continue
    else:
        try:
            decryptedString = decryptedString.decode()
        except Exception as e:
            print(f"Error: {hex(candidate[0])}: {e} (decoding string)")
            continue
        decryptedStrings.append([candidate[0], decryptedString])

for candidate in runtimeNewObjectDecCandidates:
    resetState()    
    start = candidate[1]
    res = emulate(start, 0xFFFFFFFF)
    if res != None:
        print(f"Error: {hex(candidate[0])} : {res}")
        continue
    else:
        try:
            decryptedString = decryptedString.decode()
        except Exception as e:
            print(f"Error: {hex(candidate[0])}: {e} (decoding string)")
            continue
        decryptedStrings.append([candidate[0], decryptedString])

for candidate in runtimeMakeSliceDecCandidates:
    resetState()    
    start = candidate[1]
    end = 0xFFFFFFFF
    res = emulate(start, end)
    if res != None:
        print(f"Error: {hex(candidate[0])} : {res}")
        continue
    else:
        try:
            decryptedString = decryptedString.decode()
        except Exception as e:
            print(f"Error: {hex(candidate[0])}: {e} (decoding string)")
            continue
        decryptedStrings.append([candidate[0], decryptedString])

for i, candidate in enumerate(decryptionFuncCalls):
    resetState()    
    start = candidate[1]
    decryptionFuncAddr = decryptionFuncs[i]
    junkByteRemoveIndirectCall = candidate[0]
    end = 0xFFFFFFFF
    res = emulate(start, end)
    if res != None:
        print(f"Error: {hex(start)} : {res}")
        continue
    else:
        try:
            decryptedString = decryptedString.decode()
        except Exception as e:
            print(f"Error: {hex(start)}: {e} (decoding string)")
            continue
        decryptedStrings.append([start, decryptedString])

print(f"Found {hex(len(decryptedStrings))} strings")

decryptedStrings.sort(key=lambda x: x[0])
for addr, string in decryptedStrings:
    print(f"{hex(addr)}: {string}")
    set_comment(addr,string)
print("Comments set in IDA!")

class DecryptedStringsChooser(ida_kernwin.Choose):
    def __init__(self, items):
        self.items = items
        ida_kernwin.Choose.__init__(
            self,
            "Decrypted Strings",
            [ ["Address", ida_kernwin.Choose.CHCOL_HEX], ["String", ida_kernwin.Choose.CHCOL_PLAIN] ],
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

chooser = DecryptedStringsChooser(decryptedStrings)
chooser.Show()

