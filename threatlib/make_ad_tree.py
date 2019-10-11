
import sys

from read_tl import ThreatlibraryReader, extract_links_from_list
from graphviz import Digraph

def render_or_node(g, title, content):
    g.node(title)

def render_threat(g, title, content):
    print('threat', title)
    variants = content.get('Variants')
    if variants is not None:
        render_or_node(g, title, content)
        for v in extract_links_from_list(variants):
            g.edge(title, v)
    pass

def render_mitigation(g, title, content):
    print('mitigation', title)

def main():
    tl_reader = ThreatlibraryReader()
    tl_reader.from_file(sys.stdin)
    library = tl_reader.get_threatlibrary_name()
    g = Digraph('G', engine='dot')
    for title, content in tl_reader.get_sections():
        # is this an attack or a defense?
        if content.get('Threat') is not None:
            render_threat(g, title, content)
            # threat
        else:
            # mitigation
            render_mitigation(g, title, content)
    g.view()

if __name__=="__main__":
    main()


