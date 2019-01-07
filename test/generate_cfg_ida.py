import idaapi
import idautils
import idc
import json

idc.Wait()
def analysis():
    all_funcs = idautils.Functions()
    overall_addr = dict()

    for f in all_funcs:
        f = idaapi.FlowChart(idaapi.get_func(f),flags=idaapi.FC_PREDS)
        for block in f:
            if block.startEA > idc.PrevHead(block.endEA):
                continue
            key = ''
            # overall_addr.append(hex(block.startEA))
            key += hex(block.startEA)

            key += ','
            key += hex(idc.PrevHead(block.endEA))
            sus_addr = list()
            successor = block.succs()
            for addr in successor:
                sus_addr.append(hex(addr.startEA))

            overall_addr[key] = sus_addr

    filename = idc.GetInputFile() + "_cfg"
    with open(filename, 'w') as f:
        json.dump(overall_addr, f)

def main():
    analysis()
    print "Finished!"
if __name__ == "__main__":
    main()

    idc.Exit(0)
