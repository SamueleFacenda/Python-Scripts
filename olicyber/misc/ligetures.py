import xml.dom.minidom
import sys

data = "".join(sys.stdin)

dom = xml.dom.minidom.parseString(data)
ligature_sets = dom.getElementsByTagName('LigatureSet')

prev = "s1337"

map_chars = {
    "underscore": "_",
    "three": "3",
    "braceleft": "{",
    "braceright": "}",
    "four": "4",
    "zero":"0",
    "one":"1",
    "seven":"7",
    "exclam":"!"
}

def get_previous(glyph):
    for ligature_set in ligature_sets:
        ligature = ligature_set.getElementsByTagName('Ligature')[0]
        start_letter = ligature_set.getAttribute('glyph')
        components = ligature.getAttribute("components")
        gl = ligature.getAttribute("glyph")
        if gl == glyph:
            return (start_letter, components)
    return (None, "f")
            
flag = []       

def map_val(st):
    chars = st.split(",")
    return ''.join([map_chars[c] if c in map_chars else c for c in chars])
 
while prev:
    prev, letter = get_previous(prev)
    flag = [letter] + flag
    print(''.join([map_val(x) for x in flag]))
