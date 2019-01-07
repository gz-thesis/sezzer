import angr
import argparse
import json

def get_cfg(bin_path):
    b = angr.Project(bin_path, load_options={'auto_load_libs': False})
    cfg = b.analyses.CFGAccurate(enable_symbolic_back_traversal=True, keep_state=True)
    # cfg = b.analyses.CFGFast()

    return cfg

def generate_dict(cfg):
    nodes = cfg.graph.nodes()
    res = dict()
    for node in nodes:
        if node.size != None:
            start = node.addr
            end = start + node.size
        else:
            start = node.addr
            end = start
        key = "0x%x,0x%x" % (start, end)
        if key not in res:
            res[key] = set()

        successors = node.successors
        for successor in successors:
            if successor.size is not None:
                end = successor.addr + successor.size
            else:
                end = successor.addr
            res[key].add("0x%x,0x%x" % (successor.addr, end))
    for key, val in res.iteritems():
        res[key] = list(val)

    return res

def dump_to_file(filename, content):
    with open(filename, 'w+') as f:
        json.dump(content, f)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('--binary',
                        action='store',
                        nargs='*',
                        default=[])

    argument = vars(parser.parse_args())

    target_list = argument['binary']

    for target in target_list:
        filename = '%s_cfg_angr.json' % target[target.rfind('/')+1:]
        cfg = get_cfg(target)
        content = generate_dict(cfg)
        dump_to_file(filename, content)

        print ("Complete generating CFG for %s" % target)
