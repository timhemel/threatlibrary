# read a threat library

import sys, re

def match_section(l):
    m = re.match(r'^# (.*)$', l)
    if m:
        return m.group(1)
    return None

def match_paragraph(l):
    m = re.match(r'^## (.*)$', l)
    if m:
        return m.group(1)
    return None

def match_item_level_1(l):
    m = re.match(r'^\* .*\[(.*?)\].*$', l)
    if m:
        return m.group(1)
    return None


def extract_links_from_list(s):
    for l in s.splitlines():
        x = match_item_level_1(l)
        if x is not None:
            yield x

class TlObject:

    def __init__(self, name, sections):
        self.name = name
        self.determine_node_operator(sections)

    def get_name(self):
        return self.name

    def determine_node_operator(self, sections):
        self.variants = list(extract_links_from_list(
            sections.get('Variants', '')))
        self.steps = list(extract_links_from_list(sections.get('Steps', '')))
        if self.variants != [] and self.steps != []:
            raise Exception('Threat cannot have Variants and Steps simultaneously')
        if self.variants != []:
            self.node_operator = 'or'
        elif self.steps != []:
            self.node_operator = 'and'
        else:
            self.node_operator = 'leaf'

    def get_node_operator(self):
        return self.node_operator

    def get_node_type(self):
        return self.node_type

    def get_variants(self):
        return self.variants

    def get_steps(self):
        return self.steps

    def get_mitigations(self):
        return []

    def get_threatened_mitigations(self):
        return []
 
class TlThreat(TlObject):
    node_type = 'threat'

    def __init__(self, name, sections):
        super().__init__(name, sections)
        self.mitigations = list(extract_links_from_list(
            sections.get('Suggested Mitigation','')))
        self.threatened_mitigations = list(extract_links_from_list(
            sections.get('Threatens','')))

    def get_mitigations(self):
        return self.mitigations

    def get_threatened_mitigations(self):
        return self.threatened_mitigations

class TlMitigation(TlObject):
    node_type = 'mitigation'

class Threatlibrary:

    def __init__(self):
        self.tl_objects = []

    def from_markdown_document_reader(self, doc_reader):
        self.name = doc_reader.get_document_name()
        for title, content in doc_reader.get_sections():
            self.add_tl_object(title, content)

    def add_tl_object(self, title, content):
        print(title, content)
        if content.get('Threat') is not None:
            tl_obj = TlThreat(title, content)
        else:
            tl_obj = TlMitigation(title, content)
        self.tl_objects.append(tl_obj)

    def get_tl_objects(self):
        return self.tl_objects

class MarkdownDocumentReader:
    def __init__(self):
        self.current_section = ('_', {})
        self.sections = [self.current_section]
        self.current_paragraph = '_'

    def from_file(self, f):
        for l in f:
            self.read_line(l)

    def new_section(self, title):
        self.current_section = (title, {})
        self.sections.append(self.current_section)
        self.current_paragraph = '_'

    def new_paragraph(self, title):
        self.current_paragraph = title

    def add_text_to_paragraph(self, line):
        self.current_section[1].setdefault(self.current_paragraph,'')
        self.current_section[1][self.current_paragraph] += line

    def read_line(self, line):
        m = match_section(line)
        if m is not None:
            self.new_section(m)
            return
        m = match_paragraph(line)
        if m is not None:
            self.new_paragraph(m)
            return
        # just text, add it to right paragraph
        self.add_text_to_paragraph(line)

    def get_document_name(self):
        return self.sections[1][1].get('Name').strip()

    def get_sections(self):
        return self.sections[2:]

def main():
    tl_reader = MarkdownDocumentReader()
    tl_reader.from_file(sys.stdin)
    print(tl_reader.get_document_name())
    for s in tl_reader.get_sections():
        print(s)
    # print(tl_reader.sections)

if __name__=="__main__":
    main()

