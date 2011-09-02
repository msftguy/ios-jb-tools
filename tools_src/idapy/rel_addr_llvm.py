import idaapi
import idautils

import time
import struct

# Fixes IDA's bug that it doesn't understand
#   MOV.W Rn, imm16
#   MOVT.W Rn, imm16
#   ADD Rn, PC
# as a data ref and doesn't generate xrefs for that
# relevant for iOS 5.0 Beta 3 CommCenterClassic binary and idk what else..
#
# Pretty slow - mostly because of DecodeInstruction() calls, but prints don't help either..
# Takes about a minute to grok CommCenterClassic on a Core 2 Duo
#
# idaapi.add_dref() sometimes silently fails - just rerun the script to get more xrefs ;)

refs = []

def add_refs():
    global refs
    
    for (ea, target_addr, target_name) in refs:
        if target_name and len(target_name) != 0:
            idaapi.set_cmt(ea, "%s - 0x%X" % (target_name, ea + 4), False)
        else:
            idaapi.set_cmt(ea, "0x%X - 0x%X" % (target_addr, ea + 4), False)
        idaapi.add_dref(ea, target_addr, dr_O)


def main():
    
    # wait till autoanalysis is done
    idaapi.autoWait()
    
    ea = 0
    numInst = 0
    numAddRegPc = 0
    numFixed = 0
    t0 = time.clock()
    # last MOV/MOVT inst targeting the register, key=register number
    movVal = dict()
    movtVal = dict()
    global refs
    
    cnt = 0
    while True:
        cnt += 1
        ea = NextHead(ea)
        if cnt & 0xfff == 0:
            print "[progress] ea: %x" % ea
        if ea == BADADDR:
            break
        if not idaapi.isCode(idaapi.getFlags(ea)):
            continue
        numInst += 1
        # slow, is there any way to avoid it?..
        i = DecodeInstruction(ea)
        if not i:
            continue
        mnem = i.get_canon_mnem()

        if i[0].type != 1: # only interested in register target operands
            continue
        target_reg = i[0].phrase
        if mnem == 'ADD':
            if i[1].type == 1 and i[1].phrase == 15:
                numAddRegPc += 1

                (val, mov_ea) = movVal.get(target_reg, (0, 0))
                (val_t, movt_ea) = movtVal.get(target_reg, (0, 0))
                if not mov_ea:
                    # No preceding MOV, bailing..
                    continue
                numFixed += 1

                target_addr = 0xffffFFFF & (ea + 4 + val + 0x10000 * val_t)
                # could be THUMB proc..
                if target_addr & 1 and idaapi.isCode(idaapi.getFlags(target_addr - 1)):
                    target_name = idaapi.get_name(target_addr - 1, target_addr - 1)                    
                else:
                    target_name = idaapi.get_name(target_addr,target_addr)
                refs.append((ea, target_addr, target_name))

        if i[1].type == 5:
            if mnem == 'MOV':
                movVal[target_reg] = (i[1].value, ea)
                movtVal[target_reg] = (0, 0) # since movw clears top bits anyway
            elif mnem == 'MOVT':
                movtVal[target_reg] = (i[1].value, ea)
        else:
            movVal[target_reg] = (0, 0)
            movtVal[target_reg] = (0, 0)
    print "%u instructions scanned in %f seconds" % (numInst, time.clock() - t0)

    add_refs()

    if numAddRegPc == 0:
        successRate = 100
    else:
        successRate = numFixed * 100.0 / numAddRegPc
    print "%u 'ADD Reg, PC' found, %u fixed: %u%%"  % (numAddRegPc, numFixed, successRate)

    print "run 'add_refs()' again a couple of times to mitigate IDA's bugs"

if __name__ == "__main__":
    main()
