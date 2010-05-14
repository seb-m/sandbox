#!/usr/bin/env python
#
# 12/18/2009 - seb@dbzteam.org
#
# Use Pygments (http://pygments.org/) to highlight files managed with git
# and web interfaced with cgit (http://hjemli.net/git/cgit/).
#
# Install:
#
# 1- Install python-pygments and python-chardet
# 2- Copy this script to /usr/local/bin/pygmentize_cgit.py (with exec rights)
# 3- Copy 'pygments.css' and 'head' into /var/www/<git_dir>/
# 4- Add these statements under 'global settings' section of cgit
#    configuration file /etc/cgitrc:
#      # Include the content of this file verbatim in HEAD
#      head-include=/var/www/<git_dir>/head
#      # Source code highlighting
#      source-filter=/usr/local/bin/pygmentize_cgit.py
# 5- Edit pygmentize_cgit.py and modify the variable CSS_FILE with
#    '/var/www/<git_dir>/pygments.css'
#
import sys
import chardet
import pygments
import pygments.lexers
import pygments.formatters

# CSS FILE's location
CSS_FILE = '/var/www/git/pygments.css'

def pygmentize(fn, in_stream=None, out_stream=None, debug=False):
    # If not provided in_stream will be read from stdin and out_stream
    # will be written to stdout.
    if in_stream is None:
        in_stream = sys.stdin
    if out_stream is None:
        out_stream = sys.stdout

    # Use pygments to highlight in_stream.
    highlight = True

    lexer = None
    try:
        lexer = pygments.lexers.get_lexer_for_filename(fn, encoding='chardet')
    except pygments.util.ClassNotFound:
        lexer = pygments.lexers.TextLexer()

    formatter = None
    try:
        formatter = pygments.formatters.get_formatter_by_name('html',
                                                              cssfile=CSS_FILE,
                                                              noclobber_cssfile=True,
                                                              style='default')
    except pygments.util.ClassNotFound:
        highlight = False

    # Read input stream.
    in_data = in_stream.read()
    # Detect input charset.
    encoding = chardet.detect(in_data)

    if debug:
        # print detected encoding
        k = file('/tmp/encoding', 'w')
        try:
            k.write(str(encoding) + '\n')
        finally:
            k.close()

    if (highlight and ('encoding' in encoding) and
        (encoding['encoding'] in ('utf-8', 'ascii'))):
        # Sadly we only pygment iff we are sure that the underlying encoding
        # won't be a problem i.e. currently only utf8 and ascii.
        ret = pygments.highlight(in_data, lexer, formatter, outfile=out_stream)
    else:
        # If sth went wrong or the file extension is no recognized or in doubt
        # copy in_stream to out_stream without any modifications.
        out_stream.write(in_data)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(1)
    pygmentize(sys.argv[1], debug=False)
