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

class ThreatlibraryReader:
    pass

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

