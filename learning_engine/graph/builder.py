def build(items):
    # minimal graph: nodes = items, edges by shared class
    nodes = [{"id": i, "label": x} for i, x in enumerate(items)]
    return {"nodes": nodes, "edges": []}
