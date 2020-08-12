

def Tree(nodelist):
    tree = []
    nodes = {}
    infor = "infor"
    children = 'children'

    for child, parent in nodelist:
        pguid = child['_source']['process']['entity_id']
        parent_pguid = parent['_source']['process']['entity_id']
        if not pguid in nodes:
            node = {infor:child}
            nodes[pguid] = node
        else:
            node = nodes[pguid]
        

        if not pguid in nodes:
            node = {infor:child}
            nodes[pguid] = node
        else:
            node = nodes[pguid]

        if not parent_pguid in nodes:
            pa = { infor : parent }
            nodes[parent_pguid] = pa
        else:
            pa = nodes[parent_pguid]
        
        if not children in pa:
            pa[children] = []
        pa[children].append(node)
    
    return nodes

