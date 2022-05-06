
import argparse
import json
import re
import sys

crash_registers = {}
crash_registers_list = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
    "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
    "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "fp",
    "lr", "sp", "pc", "cpsr", "esr", "far"]

crash_backtrace_lr = []
crash_backtrace_fp = []
KernelCache_slide = None
KernelCache_base = None
Kernel_slide = None
Kernel_text_base = None
Kernel_text_exec_slide = None
Kernel_text_exec_base = None

def reformat_panic(panic_str):
    panic_str = panic_str.replace("\\n", "\n")
    panic_str = panic_str.replace("\\t", "\t")
    panic_str = panic_str.replace("\\/", "/")
    return panic_str

def get_panicString(panic_str):
    panoot = None
    jsondictbases = panic_str.split("\n{")
    for i in range(1, len(jsondictbases)):
        jsondictbases[i] = "\n{" + jsondictbases[i]
    for i in jsondictbases:
        jsontmp = json.loads(i)
        try:
            panoot = jsontmp["panicString"]
            break
        except:
            panoot = None
    return panoot

def leading_key(keystr, strnet):
    intret = None
    if keystr in strnet:
        print(strnet)
        indfind = strnet.find(keystr) + len(keystr)
        reststring = strnet[indfind:]
        intret = ""
        for i in reststring:
            if i.isalnum():
                intret += i
            else:
                break
        intret = int(intret, 0x10)
    return intret        

# for example
# x0:  0xfffffe14cce3c138 x1:  0xfffffe001d194251  x2:  0x0000000000000004  x3:  0xfffffe14cce3c138
# x4:  0x0000000000000000 x5:  0xfffffe24cbd08b20  x6:  0x0000000000000000  x7:  0x0000000000000000
# x8:  0x000000000000001c x9:  0xfffffe001d1a4000  x10: 0x0000000000006210  x11: 0xb20dfe608a343cc0
# x12: 0x0000000000000000 x13: 0xfffffe24cbd090b0  x14: 0xfffffe3000108000  x15: 0x0000000000000000
# x16: 0x00000200272d3220 x17: 0xfffffe001d1b4180  x18: 0x0000000000000000  x19: 0xfffffe24ce5703b8
# x20: 0xfffffe6015dc9300 x21: 0xfffffe1ffeb3435c  x22: 0x0000000000000000  x23: 0xfffffe24cc8e5800
# x24: 0xfffffe608a343cc0 x25: 0x3a967e001e10a860  x26: 0xfffffe1ffeb34300  x27: 0xfffffe608a343c18
# x28: 0xfffffe6015dc9300 fp:  0xfffffe608a343a60  lr:  0x24b47e001d1b11e0  sp:  0xfffffe608a343a60
# pc:  0xfffffe001db04ab4 cpsr: 0x20401208         esr: 0x9600004f          far: 0xfffffe14cce3c138
def getregline(regline_ind, regline):
    global crash_registers
    for i in range(0, 4):
        curreg = crash_registers_list[regline_ind * 4 + i]
        regvalue = leading_key("{}: ".format(curreg), regline)
        crash_registers[curreg] = regvalue

# for example
# lr: 0xfffffe001db5d53c  fp: 0xfffffe608a342e40
# lr: 0xfffffe001db5d204  fp: 0xfffffe608a342eb0
# lr: 0xfffffe001dca1570  fp: 0xfffffe608a342ed0
def getstackline(stack_line):
    global crash_backtrace_lr
    global crash_backtrace_fp

    lrtmp = leading_key("lr: ", stack_line)
    crash_backtrace_lr.append(lrtmp)
    fptmp = leading_key("fp: ", stack_line)
    crash_backtrace_fp.append(fptmp)

def getcrashstats(panicstr):
    global KernelCache_slide
    global KernelCache_base
    global Kernel_slide
    global Kernel_text_base
    global Kernel_text_exec_slide
    global Kernel_text_exec_base

    ps_lineend = panicstr.split("\n")
    stackparsing = False
    global_finding = False
    for i in range(0, len(ps_lineend)):
        curline = ps_lineend[i]
        curline = re.sub(' +', ' ', curline)
        curline = curline.replace("\t", "")

        if len(curline) > 1:
            if curline[0] == " ":
                curline = curline[1:]
        
        if i > 0 and i < 10:
            getregline(i - 1, curline)

        if "Panicked thread: " in curline:
            if curline[0:len("Panicked thread: ")] == "Panicked thread: ":
                stackparsing = True
                continue
        if stackparsing == True:
            if curline[0:len("lr: ")] == "lr: ":
                getstackline(curline)
                continue
            else:
                stackparsing = False
# FOR EXAMPLE
# KernelCache slide: 0x0000000016278000
# KernelCache base:  0xfffffe001d27c000
# Kernel slide:      0x0000000016a18000
# Kernel text base:  0xfffffe001da1c000
# Kernel text exec slide: 0x0000000016b00000
# Kernel text exec base:  0xfffffe001db04000
        tmpval = leading_key("KernelCache slide: ", curline)
        if tmpval != None:
            global_finding = True
            KernelCache_slide = tmpval
            continue
        if global_finding == True:
            tmpval = leading_key("KernelCache base: ", curline)
            if tmpval != None:
                KernelCache_base = tmpval
                continue
            tmpval = leading_key("Kernel slide: ", curline)
            if tmpval != None:
                Kernel_slide = tmpval
                continue
            tmpval = leading_key("Kernel text base: ", curline)
            if tmpval != None:
                Kernel_text_base = tmpval
                continue
            tmpval = leading_key("Kernel text exec slide: ", curline)
            if tmpval != None:
                Kernel_text_exec_slide = tmpval
                continue
            tmpval = leading_key("Kernel text exec base: ", curline)
            if tmpval != None:
                Kernel_text_exec_base = tmpval
                global_finding = False
                continue

def binja_xnu_panic():
    parser = argparse.ArgumentParser(description='Process xnu panic log.')
    parser.add_argument('panic',
                        help='panic log to analyze')
    parser.add_argument('-o', '--output', required=False, action='store_true',
                        help='optional output the translated log')
    args = parser.parse_args()
    
    f = open(args.panic, "r")
    g = f.read()
    f.close()

    panicString = get_panicString(g)
    if panicString == None:
        return False
    
    panicString = reformat_panic(panicString)
    getcrashstats(panicString)


def main():
    binja_xnu_panic()

def wmain(sysargv_line):
    sys.argv = []
    sys.argv.append("binja_xnu_panic.py")
    for i in sysargv_line.split(" "):
        sys.argv.append(i)
    binja_xnu_panic()

# if __name__ == "__main__":
#     main()
