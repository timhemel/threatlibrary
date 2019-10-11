
import sys

from read_tl import MarkdownDocumentReader, Threatlibrary, extract_links_from_list
from graphviz import Digraph

render_node_attrs = {
        'threat': { 'shape': 'Mrecord',
            'style': 'filled',
            'color': '#7f0808',
            'fillcolor': '#f3a1a1',
            'linecolor': 'red'
        },
        'mitigation': { 'shape': 'record',
            'style': 'filled',
            'color': '#087f20',
            'fillcolor': '#81c68f',
            'linecolor': 'green'
        }
}

def render_node(g, title, node_operator, node_attrs):
    if node_operator == 'and':
        label = "{ <f> %s | <and> &}" % title
    else:
        label = "<f> %s" % title
    g.node(title, label=label, _attributes=node_attrs)

def render_edge(g, source, destination):
    print(source,destination)
    g.edge(source, destination)

def render_obj(g, tl_obj):
    attrs = render_node_attrs.get(tl_obj.get_node_type())
    operator = tl_obj.get_node_operator()
    render_node(g, tl_obj.get_name(), operator, attrs)

    if operator == 'or':
        for v in tl_obj.get_variants():
            render_edge(g, tl_obj.get_name(), v)
    elif operator == 'and':
        for v in tl_obj.get_steps():
            render_edge(g, tl_obj.get_name(), v)

    for v in tl_obj.get_mitigations():
        print('x',v)
        render_edge(g, tl_obj.get_name(), v)

    for v in tl_obj.get_threatened_mitigations():
        print('y',v)
        render_edge(g, v, tl_obj.get_name())

def main():
    doc_reader = MarkdownDocumentReader()
    doc_reader.from_file(sys.stdin)
    library = Threatlibrary()
    library.from_markdown_document_reader(doc_reader)
    # library = tl_reader.get_document_name()
    g = Digraph('G', engine='dot')
    for tl_obj in library.get_tl_objects():
        print(tl_obj)
        render_obj(g, tl_obj)
    g.view()

if __name__=="__main__":
    main()


