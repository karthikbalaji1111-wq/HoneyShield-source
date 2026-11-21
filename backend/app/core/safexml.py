"""XML parsing for responses from S3-compatible servers, hardened with defusedxml.

The responses come from a configured endpoint, not from attackers, but a compromised or hostile
endpoint must not be able to use entity expansion ("billion laughs") or external entities. DTDs
are refused outright; every refusal surfaces as ``ParseError`` like a malformed document does.
"""
from __future__ import annotations

from xml.etree.ElementTree import Element

from defusedxml import ElementTree as _ET
from defusedxml.common import DefusedXmlException

ParseError = _ET.ParseError


def fromstring(data: bytes | str) -> Element:
    try:
        return _ET.fromstring(data, forbid_dtd=True)
    except DefusedXmlException as exc:
        raise ParseError(f"refused XML: {exc}") from None
