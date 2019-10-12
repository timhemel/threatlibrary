
from MarkdownDocumentReader import MarkdownDocumentReader, extract_links_from_list

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


