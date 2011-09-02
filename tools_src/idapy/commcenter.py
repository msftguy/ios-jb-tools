import os
import sys
import idc
import idaapi
import idautils
import rel_addr_llvm

thumbRegId = idaapi.str2reg('T')

def isThumb(ea):
    global thumbRegId
    return idaapi.getSR(ea, thumbRegId) != 0

def process_func_for_string(str, f):
    loc = idaapi.find_binary(0, idc.BADADDR, "\"%s" % str, 16, 0)
    if loc == idc.BADADDR:
        print "String '%s' not found" % str
        return False
    xrEa = 0
    for xr in idautils.XrefsTo(loc):
        xrEa = xr.frm
        break
    if xrEa == 0:
        print "No xrefs to string '%s'" % str
        return False
    
    fn = idaapi.get_func(xrEa)

    if not fn:
        print "No function at xref to string '%s' (at %x)" % (str, xrEa)
        return False

    fnEa = fn.startEA

    if isThumb(fnEa):
        fnEa += 1

    if f:
        f.write("\t// %s\n" % str)
        f.write("\t{0x%x, 0x%x, 0x%x},\n" % (loc, xrEa, fnEa))

    print "// %s" % str
    print "{0x%x, 0x%x, 0x%x}," % (loc, xrEa, fnEa)
    
    return True

def main():
    f = None
    if len(idc.ARGV) > 1:
        out_name = idc.ARGV[1]
        print "Writing to %s" % out_name 
        f = open(out_name, "w+")
    
    rel_addr_llvm.ensure_all()
    
    strings = ["+xsimstate=1", "Sending internal notification %s", "activation ticket accepted... drive thru"]
    if f:
        f.write("#pragma once\n")
        f.write("REF_ENTRY ref_table[] = {\n")
        f.write("// TODO: version\n")
        f.write("// generated automatically with commcenter.py, IDA and IdaPython\n")
        
    print "// TODO: version"
    print "// generated automatically with commcenter.py, IDA and IdaPython"

    for s in strings:
        if not process_func_for_string(s, f):
            if f:
                f.close()
                os.unlink(f.name)
            raise Exception("Failed for string %s", s)

    if f:
        f.write("};\n")        
        f.close()
        idc.Exit(0)

    print

if __name__ == '__main__':
    main()