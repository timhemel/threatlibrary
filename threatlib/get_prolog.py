
import sys

from read_tl import MarkdownDocumentReader

def main():
    tl_reader = MarkdownDocumentReader()
    tl_reader.from_file(sys.stdin)
    library = tl_reader.get_document_name()
    for title, content in tl_reader.get_sections():
        prolog = content.get('Prolog', '').strip()
        if prolog:
            print("%% %s-%s" % (library, title.strip()))
            prolog = prolog.replace('```','').replace(
                '%LIB%', "'%s'" % library).replace(
                '%SEC%', "'%s'" % title.strip())
            print(prolog)

if __name__=="__main__":
    main()

