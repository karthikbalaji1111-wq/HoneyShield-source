"""Decoy Word documents that report being opened.

The document carries one linked (not embedded) picture: a 1x1 transparent image whose source is
the decoy's pixel URL. Word fetches linked pictures to display them, so opening the file requests
that URL and the hit is recorded like any pixel hit. Nothing in the file runs code: no macros, no
fields that need updating, no external templates.

What it does not catch: viewers that never fetch remote images (Word's Protected View for files
from the internet until editing is enabled, previewers that render text only, opening on a machine
with no route to the ingest host). docs/document-decoys.md lists them.

Built with the standard library only, byte-for-byte reproducible for the same input.
"""
from __future__ import annotations

import io
import zipfile
from datetime import datetime, timezone
from xml.sax.saxutils import escape

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_REL_IMAGE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image"
_ZIP_TIME = (2024, 1, 1, 0, 0, 0)

_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

_ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"""

_APP = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
<Application>Microsoft Office Word</Application><DocSecurity>0</DocSecurity><AppVersion>16.0000</AppVersion>
</Properties>"""

# A 1x1 inline picture (9525 EMU = 1 px) whose blip is linked, not embedded: r:link, not r:embed.
_PICTURE = (
    '<w:p><w:r><w:drawing>'
    '<wp:inline distT="0" distB="0" distL="0" distR="0" '
    'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">'
    '<wp:extent cx="9525" cy="9525"/><wp:docPr id="1" name="Picture 1"/>'
    '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
    '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
    '<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
    '<pic:nvPicPr><pic:cNvPr id="0" name="image1.gif"/><pic:cNvPicPr/></pic:nvPicPr>'
    '<pic:blipFill><a:blip r:link="rIdImg1"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
    '<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="9525" cy="9525"/></a:xfrm>'
    '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
    '</pic:pic></a:graphicData></a:graphic></wp:inline>'
    '</w:drawing></w:r></w:p>'
)


def _paragraph(text: str, bold: bool = False, size: int | None = None) -> str:
    props = ""
    if bold or size:
        props = "<w:rPr>" + ("<w:b/>" if bold else "") + (f'<w:sz w:val="{size}"/>' if size else "") + "</w:rPr>"
    return f'<w:p><w:r>{props}<w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>'


def _document(title: str, paragraphs: list[str]) -> str:
    body = _paragraph(title, bold=True, size=32) + "".join(_paragraph(p) for p in paragraphs) + _PICTURE
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<w:document xmlns:w="{_W}" xmlns:r="{_R}"><w:body>{body}'
            '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
            '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" '
            'w:footer="708" w:gutter="0"/></w:sectPr></w:body></w:document>')


def _document_rels(image_url: str) -> str:
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'<Relationship Id="rIdImg1" Type="{_REL_IMAGE}" Target="{escape(image_url, {'"': "&quot;"})}" TargetMode="External"/>'
            '</Relationships>')


def _core(title: str, author: str, created: datetime) -> str:
    when = created.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<dc:title>{escape(title)}</dc:title><dc:creator>{escape(author)}</dc:creator>'
            f'<cp:lastModifiedBy>{escape(author)}</cp:lastModifiedBy>'
            f'<dcterms:created xsi:type="dcterms:W3CDTF">{when}</dcterms:created>'
            f'<dcterms:modified xsi:type="dcterms:W3CDTF">{when}</dcterms:modified>'
            '</cp:coreProperties>')


def build_docx(*, title: str, paragraphs: list[str], image_url: str, author: str, created: datetime) -> bytes:
    """A Word document that requests ``image_url`` when it is opened and displayed."""
    if not image_url.startswith(("https://", "http://")):
        raise ValueError("image_url must be an absolute http(s) URL")
    parts = [
        ("[Content_Types].xml", _CONTENT_TYPES),
        ("_rels/.rels", _ROOT_RELS),
        ("docProps/core.xml", _core(title, author, created)),
        ("docProps/app.xml", _APP),
        ("word/document.xml", _document(title, paragraphs)),
        ("word/_rels/document.xml.rels", _document_rels(image_url)),
    ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in parts:
            info = zipfile.ZipInfo(name, date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, text.encode("utf-8"))
    return buf.getvalue()
