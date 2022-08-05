import sys
if sys.version_info[0] == 2:
    from HTMLParser import HTMLParser
else:
    from html.parser import HTMLParser

# extract values from attrList of attributes whose name is contained in attrNames
def add_attrs(attrNames, attrList):
    return [a[1] for a in filter(lambda attr: attr[0] in attrNames, attrList)]

def has_attr(attrs, attr):
    return attr in map(lambda kv: kv[0], attrs)

def attr_val_is(attrs, attr, val):
    try:
        return filter(lambda kv: kv[0] == attr, attrs)[0][1] == val
    except:
        return False

class WASEHTMLParser(HTMLParser, object):
    def reset(self):
        self.doctype = set()
        self.base = set()
        self.stylesheets = set()
        self.frames = set()
        self.scripts = set()
        self.links = set()
        self.images = set()
        self.audio = set()
        self.video = set()
        self.objects = set()
        self.formactions = set()
        super(WASEHTMLParser, self).reset()

    def handle_decl(self, decl):
        self.doctype.add(decl)

    def handle_starttag(self, tag, attrs):
        if tag == "iframe":
            self.frames.update(add_attrs(["src"], attrs))
        elif tag == "base":
            self.base.update(add_attrs(["href"], attrs))
        elif tag == "link" and attr_val_is(attrs, "rel", "stylesheet"):
            self.stylesheets.update(add_attrs(["href"], attrs))
        elif tag == "script":
            self.scripts.update(add_attrs(["src"], attrs))
        elif tag == "a" or tag == "area":
            self.links.update(add_attrs(["href"], attrs))
        elif tag == "img" or tag == "input":
            self.images.update(add_attrs(["src"], attrs))
        elif tag == "svg" or tag == "image":
            self.images.update(add_attrs(["href", "xlink:href"], attrs))
        elif tag == "audio":
            self.audio.update(add_attrs(["src"], attrs))
        elif tag == "video":
            self.video.update(add_attrs(["src"], attrs))
        elif tag == "object":
            self.objects.update(add_attrs(["data"], attrs))
        elif tag == "embed":
            self.objects.update(add_attrs(["src"], attrs))
        elif tag == "applet":
            self.objects.update(add_attrs(["code"], attrs))
        elif tag == "form":
            self.formactions.update(add_attrs(["action"], attrs))
        elif tag == "input" or tag == "button":
            self.formactions.update(add_attrs(["formaction"], attrs))
        else:
            return

    def close(self):
        self.extrefs = set()
        self.extrefs.update(
                self.stylesheets,
                self.frames,
                self.scripts,
                self.links,
                self.images,
                self.audio,
                self.video,
                self.objects,
                self.formactions
                )
        return super(WASEHTMLParser, self).close()
