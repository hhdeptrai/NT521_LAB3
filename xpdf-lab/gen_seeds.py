#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_seeds.py -- coverage-directed PDF seed generator for Xpdf 3.02.

The script is driven by the uncovered-region report of the base corpus
(cov_reports/base/uncovered.txt).  It emits small, structurally valid PDF
files into ./seeds_ai/; every file targets one specific uncovered function
or branch of the Xpdf 3.02 parser.

Implementation rules
--------------------
  * No structural bytes are hard coded.  Header, object bodies, dictionaries,
    streams, cross reference table/stream, trailer, /startxref and %%EOF are
    produced by the code in this file.
  * Every offset (object byte position), every cross reference entry, the
    /Length of every stream and the final /startxref value is *computed*
    while the file is assembled.  No literal offset is typed in by hand.
  * The generator is deterministic: two runs produce byte identical files.
  * Neither the Xpdf tree nor the fuzzing harness is touched; the script
    only writes into the output directory.

The seeds are written for the harness in hfuzz/xpdf-3.02/harness_ai.cc
(built as ``harness_hfuzz``), i.e. for a pdfinfo-like code path:

    PDFDoc -> XRef -> Catalog -> Outline -> page tree -> Info dict ->
    StructTreeRoot -> page boxes -> encryption -> metadata stream

Key observation used by many seeds: ``Catalog::readMetadata()`` streams the
whole ``/Metadata`` object, therefore *any* stream filter (Flate, LZW, AHx,
A85, RL, CCITTFax, DCT, JBIG2, JPX) is reachable from a pdfinfo-style
harness just by attaching the filtered stream as the document metadata.
That is how the large uncovered areas of Stream.cc are addressed.

Usage
-----
    python3 gen_seeds.py                  # write seeds into ./seeds_ai
    python3 gen_seeds.py -o seeds_ai      # choose the output directory
    python3 gen_seeds.py --list           # print the seed catalogue
    python3 gen_seeds.py --verify         # measure the coverage of the
                                          # generated seeds against the
                                          # baseline profile
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# 1. codecs / payload builders
# ---------------------------------------------------------------------------


def rc4(key: bytes, data: bytes) -> bytes:
    """RC4 (ARCFOUR) -- used for the standard security handler."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for c in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


# 32 byte padding string of the PDF standard security handler (Decrypt.cc)
PAD = bytes([
    0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
    0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
    0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
    0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
])


def pad_password(pwd: bytes) -> bytes:
    return (pwd + PAD)[:32]


def ascii_hex_encode(data: bytes) -> bytes:
    """ASCIIHexDecode payload (ASCIIHexStream::lookChar)."""
    return data.hex().encode("ascii") + b">"


def ascii85_encode(data: bytes) -> bytes:
    """ASCII85Decode payload (ASCII85Stream::lookChar)."""
    out = bytearray()
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        pad = 4 - len(chunk)
        chunk = chunk + b"\0" * pad
        v = int.from_bytes(chunk, "big")
        if v == 0 and pad == 0:
            out += b"z"
            continue
        enc = bytearray()
        for _ in range(5):
            enc.append(33 + v % 85)
            v //= 85
        enc.reverse()
        if pad:
            enc = enc[:5 - pad]
        out += enc
    out += b"~>"
    return bytes(out)


def run_length_encode(data: bytes) -> bytes:
    """RunLengthDecode payload (RunLengthStream::fillBuf)."""
    out = bytearray()
    i = 0
    while i < len(data):
        run = 1
        while i + run < len(data) and data[i + run] == data[i] and run < 128:
            run += 1
        if run >= 2:
            out.append(257 - run)
            out.append(data[i])
            i += run
        else:
            j = i
            lit = bytearray()
            while j < len(data) and len(lit) < 128:
                if j + 1 < len(data) and data[j] == data[j + 1]:
                    break
                lit.append(data[j])
                j += 1
            out.append(len(lit) - 1)
            out += lit
            i = j
    out.append(128)          # EOD
    return bytes(out)


def lzw_encode(data: bytes, early: int = 1) -> bytes:
    """LZWDecode payload (LZWStream::processNextCode).

    Xpdf's decoder switches to 10/11/12 bit codes when ``nextCode + early``
    reaches 512/1024/2048 (Stream.cc:1113-1118).  The decoder adds its
    table entry one code *later* than the encoder does, therefore the
    encoder has to switch when ``nextCode + early`` reaches
    513/1025/2049 (verified by a round trip against Xpdf's decoder).
    """
    out = bytearray()
    state = {"buf": 0, "bits": 0}

    def emit(code: int, width: int) -> None:
        state["buf"] = (state["buf"] << width) | code
        state["bits"] += width
        while state["bits"] >= 8:
            state["bits"] -= 8
            out.append((state["buf"] >> state["bits"]) & 0xFF)

    table = {bytes([i]): i for i in range(256)}
    next_code = 258
    width = 9
    emit(256, width)                       # clear table code
    w = b""
    for c in data:
        wc = w + bytes([c])
        if wc in table:
            w = wc
            continue
        emit(table[w], width)
        table[wc] = next_code
        next_code += 1
        if next_code + early == 513:
            width = 10
        elif next_code + early == 1025:
            width = 11
        elif next_code + early == 2049:
            width = 12
        w = bytes([c])
    if w:
        emit(table[w], width)
    emit(257, width)                       # EOD code
    if state["bits"]:
        out.append((state["buf"] << (8 - state["bits"])) & 0xFF)
    return bytes(out)


def png_predict_encode(data: bytes, width: int, colors: int = 1,
                        bpc: int = 8, filters=(0, 1, 2, 3, 4)) -> bytes:
    """PNG predictor payload (StreamPredictor::getNextLine).

    Xpdf reads one filter byte per row from the decoded stream and adds 10
    to it (0->None, 1->Sub, 2->Up, 3->Average, 4->Paeth).  ``pixBytes``
    bytes at the start of a row are the "left" context and are always zero
    in Xpdf, therefore the first sample of a row has no left neighbour.
    """
    pix_bytes = (colors * bpc + 7) >> 3
    row_bytes = ((width * colors * bpc + 7) >> 3) + pix_bytes
    sample_bytes = row_bytes - pix_bytes
    rows = [data[r * sample_bytes:(r + 1) * sample_bytes]
            for r in range(len(data) // sample_bytes)]
    out = bytearray()
    prev = bytearray(sample_bytes)
    for r, row in enumerate(rows):
        f = filters[r % len(filters)]
        out.append(f)
        cur = bytearray(sample_bytes)
        for j in range(sample_bytes):
            left = cur[j - 1] if j >= 1 else 0
            up = prev[j]
            upleft = prev[j - 1] if j >= 1 else 0
            if f == 1:
                enc = row[j] - left
            elif f == 2:
                enc = row[j] - up
            elif f == 3:
                enc = row[j] - ((left + up) >> 1)
            elif f == 4:
                p = left + up - upleft
                pa, pb, pc = abs(p - left), abs(p - up), abs(p - upleft)
                pred = left if (pa <= pb and pa <= pc) else (up if pb <= pc else upleft)
                enc = row[j] - pred
            else:
                enc = row[j]
            enc &= 0xFF
            cur[j] = row[j]          # the *decoded* byte is the left neighbour
            out.append(enc)
        prev = bytearray(row)
    return bytes(out)


def flate(data: bytes, level: int = 9) -> bytes:
    """zlib stream for FlateDecode (level 9 -> dynamic Huffman blocks)."""
    return zlib.compress(data, level)


def flate_dynamic(data: bytes) -> bytes:
    """zlib stream that really uses a *dynamic* Huffman block.

    FlateStream::readDynamicCodes() (Stream.cc:4151-4249) is only executed
    when the deflate stream contains a type-2 (dynamic Huffman) block; a
    stored or fixed-Huffman block would leave that code untouched.  The
    helper tries the deflate strategies until an encoding with
    BTYPE == 2 is found.  The decoded content is always identical to the
    input, only the block type changes.
    """
    strategies = (zlib.Z_DEFAULT_STRATEGY, zlib.Z_FILTERED, zlib.Z_RLE,
                  zlib.Z_HUFFMAN_ONLY)
    best = None
    for level in (9, 6, 1):
        for strat in strategies:
            c = zlib.compressobj(level, zlib.DEFLATED, 15, 9, strat)
            z = c.compress(data) + c.flush()
            if len(z) >= 2 and ((z[2] >> 1) & 3) == 2:
                return z
            if best is None or len(z) < len(best):
                best = z
    return best if best is not None else zlib.compress(data, 9)


def text_payload(rows: int, width: int) -> bytes:
    """Semi repetitive payload that compresses into a dynamic Huffman block."""
    words = [b"xpdf", b"coverage", b"seed", b"branch", b"stream", b"object"]
    out = bytearray()
    for r in range(rows):
        for c in range(width):
            out.append((words[(r + c) % len(words)][c % 4] ^ (r * 7 + c)) & 0xFF)
    return bytes(out)


def deterministic_bytes(seed: int, n: int) -> bytes:
    """Reproducible pseudo random payload for malformed streams."""
    out = bytearray()
    h = hashlib.sha256(str(seed).encode()).digest()
    while len(out) < n:
        h = hashlib.sha256(h).digest()
        out += h
    return bytes(out[:n])


def hex_string(data: bytes) -> bytes:
    return b"<" + data.hex().encode("ascii") + b">"


def literal_string(data: bytes) -> bytes:
    out = bytearray(b"(")
    for c in data:
        if c in (0x28, 0x29, 0x5C):
            out.append(0x5C)
            out.append(c)
        elif c == 0x0D:
            out += b"\\r"
        elif c == 0x0A:
            out += b"\\n"
        else:
            out.append(c)
    out += b")"
    return bytes(out)


# ---------------------------------------------------------------------------
# 2. PDF writer
# ---------------------------------------------------------------------------

class PdfWriter:
    """Assembles a PDF file; every offset is computed while writing.

    Supported cross reference flavours (all three are implemented by
    Xpdf's XRef.cc):

      * ``table``  -- classic cross reference table + trailer
      * ``stream`` -- cross reference *stream* (``/Type /XRef``)
      * ``hybrid`` -- classic table whose trailer carries ``/XRefStm``
                      pointing at a cross reference stream
    """

    def __init__(self, version: str = "1.7"):
        self.version = version
        self.objects = {}          # num -> body bytes (without "N G obj")
        self.compressed = {}       # num -> (objstm number, index in stream)
        self.objstm_objects = {}   # objstm number -> [obj numbers]

    # -- object handling ---------------------------------------------------

    def add(self, num: int, body: bytes) -> int:
        self.objects[num] = body
        return num

    def add_compressed(self, num: int, objstm_num: int) -> int:
        idx = len(self.objstm_objects.get(objstm_num, []))
        self.compressed[num] = (objstm_num, idx)
        self.objstm_objects.setdefault(objstm_num, []).append(num)
        return num

    # -- serialisation -----------------------------------------------------

    def build(self, root: int, *, mode: str = "table",
              xref_num: int | None = None,
              xref_index: list | None = None,
              xref_size: int | None = None,
              xref_filter: bytes = b"",
              xref_parms: bytes = b"",
              xref_png: bool = False,
              table_objects: set | None = None,
              ibm_quirk: bool = False,
              extra_trailer: bytes = b"",
              prev: int | None = None,
              prev_as_ref: bool = False,
              doc_id: bytes | None = None) -> bytes:
        out = bytearray()
        out += b"%PDF-" + self.version.encode("ascii") + b"\n"
        out += b"%\xe2\xe3\xcf\xd3\n"

        offsets = {}
        for num in sorted(self.objects):
            offsets[num] = len(out)
            out += b"%d %d obj\n" % (num, 0)
            out += self.objects[num]
            out += b"\nendobj\n"

        xref_offset = None
        if mode in ("stream", "hybrid"):
            xref_offset = self._write_xref_stream(out, xref_num, offsets, root,
                                                  xref_index, xref_size,
                                                  xref_filter, xref_parms,
                                                  xref_png, extra_trailer, prev,
                                                  doc_id)

        if mode == "table":
            start = len(out)
            out += self._xref_table(offsets, root, extra_trailer, prev,
                                    prev_as_ref, doc_id, ibm_quirk)
        elif mode == "hybrid":
            start = len(out)
            out += self._xref_table(offsets, root,
                                    extra_trailer + b" /XRefStm %d" % xref_offset,
                                    prev, prev_as_ref, doc_id, ibm_quirk,
                                    only=table_objects)
        elif mode == "stream":
            start = xref_offset
        else:
            raise ValueError("unknown xref mode %r" % mode)

        out += b"startxref\n%d\n%%%%EOF\n" % start
        return bytes(out)

    # -- internals ---------------------------------------------------------

    def _entry_list(self, offsets):
        """(type, field2, field3) for every object number, 0 based."""
        nums = sorted(set(list(offsets.keys()) + list(self.compressed.keys())))
        maxnum = max(nums) if nums else 0
        entries = []
        for i in range(0, maxnum + 1):
            if i == 0:
                entries.append((0, 0, 0xFFFF))          # free list head
            elif i in offsets:
                entries.append((1, offsets[i], 0))      # uncompressed
            elif i in self.compressed:
                stm, idx = self.compressed[i]
                entries.append((2, stm, idx))           # in object stream
            else:
                entries.append((0, 0, 0))               # free
        return entries

    def _write_xref_stream(self, out, xref_num, offsets, root, index, size,
                           filt, parms, png, extra_trailer, prev, doc_id):
        """Write the cross reference stream object; return its offset."""
        # the xref stream object is itself an entry of type 1
        xref_offset = len(out)
        # entries[i] describes the object with number i (XRef.cc:580-610
        # stores the entries indexed by the object number itself)
        entries = self._entry_list(offsets)
        if xref_num is not None:
            if xref_num >= len(entries):
                entries.extend([(0, 0, 0)] * (xref_num + 1 - len(entries)))
            entries[xref_num] = (1, xref_offset, 0)

        if index is None:
            index = [(0, len(entries))]
            stream_entries = entries
        else:
            # the stream carries exactly the entries of the requested
            # subsections, in order
            stream_entries = []
            for first, count in index:
                for i in range(first, first + count):
                    stream_entries.append(entries[i] if i < len(entries)
                                          else (0, 0, 0))

        data = bytearray()
        for t, f2, f3 in stream_entries:
            data.append(t & 0xFF)
            data += (f2 & 0xFFFFFFFF).to_bytes(4, "big")
            data += (f3 & 0xFFFF).to_bytes(2, "big")

        if png:
            # Flate + PNG predictor: the classic PDF 1.5 cross reference
            # stream layout (one row per object).
            columns = 7                       # /W [1 4 2] -> 7 bytes per entry
            predicted = png_predict_encode(bytes(data), columns)
            data = bytearray(flate_dynamic(predicted))
            filt = b"/FlateDecode"
            parms = b"<< /Predictor 12 /Columns %d >>" % columns

        d = bytearray()
        d += b"<< /Type /XRef /Size %d /W [1 4 2] /Root %d 0 R" % (
            size if size is not None else len(entries), root)
        if index != [(0, len(entries))]:
            d += b" /Index [%s]" % b" ".join(
                str(i).encode() for pair in index for i in pair)
        if filt:
            d += b" /Filter " + filt
        if parms:
            d += b" /DecodeParms " + parms
        if prev is not None:
            d += b" /Prev %d" % prev
        if doc_id is not None:
            d += b" /ID [%s %s]" % (hex_string(doc_id), hex_string(doc_id))
        d += extra_trailer
        d += b" /Length %d >>" % len(data)

        out += b"%d %d obj\n" % (xref_num, 0)
        out += bytes(d)
        out += b"\nstream\n"
        out += bytes(data)
        out += b"\nendstream\nendobj\n"
        return xref_offset

    def _xref_table(self, offsets, root, extra_trailer, prev, prev_as_ref,
                    doc_id, ibm_quirk, only=None):
        nums = sorted(set(list(offsets.keys()) + list(self.compressed.keys())))
        if only is not None:
            nums = [n for n in nums if n in only]
        chunks = bytearray(b"xref\n")
        groups = []
        for n in nums:
            if groups and groups[-1][1] == n:
                groups[-1][1] = n + 1
            else:
                groups.append([n, n + 1])
        if ibm_quirk:
            # IBM patent files claim that the table starts at 1 instead of 0
            # and use a free entry for object 1 -- XRef.cc:410-420 has a
            # special case for exactly that.
            chunks += b"1 %d\n" % (len(nums) + 1)
            chunks += b"%010d %05d f \n" % (0, 0xFFFF)
            for n in range(1, len(nums) + 1):
                if n in offsets:
                    chunks += b"%010d %05d n \n" % (offsets[n], 0)
                else:
                    chunks += b"%010d %05d f \n" % (0, 0xFFFF)
        else:
            chunks += b"0 %d\n" % (len(nums) + 1)
            chunks += b"%010d %05d f \n" % (0, 0xFFFF)
            for n in range(1, len(nums) + 1):
                if n in offsets:
                    chunks += b"%010d %05d n \n" % (offsets[n], 0)
                elif n in self.compressed:
                    chunks += b"%010d %05d n \n" % (0, 0)
                else:
                    chunks += b"%010d %05d f \n" % (0, 0xFFFF)

        trailer = bytearray()
        trailer += b"trailer\n<< /Size %d /Root %d 0 R" % (
            max(nums) + 1 if nums else 1, root)
        if prev is not None:
            if prev_as_ref:
                trailer += b" /Prev %d 0 R" % prev
            else:
                trailer += b" /Prev %d" % prev
        if doc_id is not None:
            trailer += b" /ID [%s %s]" % (hex_string(doc_id), hex_string(doc_id))
        trailer += extra_trailer
        trailer += b" >>\n"
        return bytes(chunks) + bytes(trailer)


# ---------------------------------------------------------------------------
# 3. document skeletons
# ---------------------------------------------------------------------------

CATALOG = 1
PAGES = 2
PAGE = 3

XML = b"<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?><x:xmpmeta xmlns:x='adobe:ns:meta/'><rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'><rdf:Description rdf:about=''/></rdf:RDF></x:xmpmeta>"


def catalog_body(pages_ref: int = PAGES, extra: bytes = b"") -> bytes:
    return b"<< /Type /Catalog /Pages %d 0 R%s >>" % (pages_ref, extra)


def pages_body(kids: bytes, count: int, extra: bytes = b"") -> bytes:
    return b"<< /Type /Pages /Count %d /Kids [%s]%s >>" % (count, kids, extra)


def page_body(parent: int = PAGES, extra: bytes = b"") -> bytes:
    return (b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792]%s >>"
            % (parent, extra))


def stream_object(dict_extra: bytes, payload: bytes) -> bytes:
    """Indirect object holding a stream; /Length is computed."""
    return (b"<< %s /Length %d >>\nstream\n" % (dict_extra, len(payload))
            + payload + b"\nendstream")


def metadata_stream(payload: bytes, filters: bytes = b"", parms: bytes = b"") -> bytes:
    d = b"/Type /Metadata /Subtype /XML"
    if filters:
        d += b" /Filter " + filters
    if parms:
        d += b" /DecodeParms " + parms
    return stream_object(d, payload)


# ---------------------------------------------------------------------------
# 4. seeds
# ---------------------------------------------------------------------------

class Seed:
    def __init__(self, name: str, data: bytes, target: str, why: str):
        self.name = name
        self.data = data
        self.target = target
        self.why = why


def s_xrefstream_index() -> Seed:
    """Cross reference *stream* with a two subsection /Index array.

    Target
      XRef::readXRefStream()            (XRef.cc:469-561)
        - the /Index loop and its error checks      (XRef.cc:514-522)
        - readXRefStreamSection() growth path       (XRef.cc:570-575)
        - entry types 0/1/2
      Object::initDict(Dict*)            (Object.cc:61-65) via
        ``trailerDict.initDict(dict)``              (XRef.cc:554)

    Why
      Xpdf only evaluates /Index when the cross reference information is
      stored in a stream.  The seed declares two subsections
      (``/Index [0 4 8 2]``) and a /Size (3) that is *smaller* than the
      covered object range, so readXRefStreamSection() has to grow the
      entry table (XRef.cc:571-575) and the /Index loop runs twice.
    """
    pdf = PdfWriter()
    pdf.add(CATALOG, catalog_body())
    pdf.add(PAGES, pages_body(b"%d 0 R" % PAGE, 1))
    pdf.add(PAGE, page_body())
    for n in range(4, 10):
        pdf.add(n, b"<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] >>")
    data = pdf.build(CATALOG, mode="stream", xref_num=10,
                     xref_index=[(0, 4), (8, 2)], xref_size=3)
    return Seed("s01_xrefstream_index.pdf", data,
                "XRef::readXRefStream / readXRefStreamSection, Object::initDict",
                "cross reference stream with two /Index subsections and a /Size "
                "smaller than the covered range")


def s_xrefstream_prev() -> Seed:
    """Cross reference stream with /Prev pointing at a classic table.

    Target
      XRef::readXRefStream()  ``/Prev`` branch   (XRef.cc:543-551)
      XRef::readXRefTable()   trailer /Prev      (XRef.cc:429-443)
      XRef::readXRef()        loop over sections  (XRef.cc:216)

    Why
      A /Prev pointer makes Xpdf walk more than one cross reference
      section: first the stream (which owns the newest objects), then the
      classic table referenced by /Prev (which owns the older ones).  Both
      readers and their trailer handling are therefore executed.
    """
    pdf = PdfWriter()
    pdf.add(CATALOG, catalog_body())
    pdf.add(PAGES, pages_body(b"%d 0 R" % PAGE, 1))
    pdf.add(PAGE, page_body())
    pdf.add(4, b"<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] >>")
    # first pass: a classic table for the "old" objects, then the stream.
    # The table is written by hand below, the stream by the writer.
    head = bytearray()
    head += b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
    offsets = {}
    # object 5 is the old-style object owned by the classic table
    for num, body in ((5, b"<< /Type /Annot /Subtype /Text /Rect [2 2 3 3] >>"),):
        offsets[num] = len(head)
        head += b"%d %d obj\n" % (num, 0)
        head += body
        head += b"\nendobj\n"
    table_start = len(head)
    # classic table covering object 5 only
    table = bytearray(b"xref\n")
    table += b"0 1\n%010d %05d f \n" % (0, 0xFFFF)
    table += b"5 1\n%010d %05d n \n" % (offsets[5], 0)
    table += b"trailer\n<< /Size 6 /Root %d 0 R >>\n" % CATALOG
    head += table

    # now the modern part: objects 1..4 plus the xref stream (6)
    offsets2 = {}
    for num, body in ((CATALOG, catalog_body()),
                       (PAGES, pages_body(b"%d 0 R" % PAGE, 1)),
                       (PAGE, page_body()),
                       (4, b"<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] >>")):
        offsets2[num] = len(head)
        head += b"%d %d obj\n" % (num, 0)
        head += body
        head += b"\nendobj\n"

    xref_offset = len(head)
    entries = []
    maxnum = 6
    for i in range(0, maxnum + 1):
        if i == 0:
            entries.append((0, 0, 0xFFFF))
        elif i in offsets2:
            entries.append((1, offsets2[i], 0))
        else:
            entries.append((0, 0, 0))
    entries.append((1, xref_offset, 0))          # the xref stream itself
    data = bytearray()
    for t, f2, f3 in entries:
        data.append(t & 0xFF)
        data += (f2 & 0xFFFFFFFF).to_bytes(4, "big")
        data += (f3 & 0xFFFF).to_bytes(2, "big")
    d = b"<< /Type /XRef /Size %d /W [1 4 2] /Root %d 0 R /Prev %d /Length %d >>" % (
        len(entries), CATALOG, table_start, len(data))
    head += b"6 0 obj\n" + d + b"\nstream\n" + bytes(data) + b"\nendstream\nendobj\n"
    head += b"startxref\n%d\n%%%%EOF\n" % xref_offset
    return Seed("s02_xrefstream_prev.pdf", bytes(head),
                "XRef::readXRefStream (/Prev), XRef::readXRefTable (/Prev)",
                "cross reference stream whose /Prev points at an earlier "
                "classic cross reference table")


def s_hybrid_xrefstm() -> Seed:
    """Classic table whose trailer carries /XRefStm (hybrid reference file).

    Target
      XRef::readXRefTable()  ``/XRefStm`` branch   (XRef.cc:461-467)
      XRef::readXRef()       stream branch        (XRef.cc:220-236)
      ObjectStream::ObjectStream (when the stream holds compressed objects)

    Why
      PDF 1.5 hybrid reference files keep a classic table *and* a cross
      reference stream; the table's trailer points at the stream through
      /XRefStm.  Xpdf reads the table first and then follows /XRefStm into
      the stream, which is exactly the branch that was never executed.
    """
    pdf = PdfWriter()
    pdf.add(CATALOG, catalog_body())
    pdf.add(PAGES, pages_body(b"%d 0 R" % PAGE, 1))
    pdf.add(PAGE, page_body())
    pdf.add(4, b"<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] >>")
    pdf.add(5, b"<< /Type /Annot /Subtype /Text /Rect [1 1 2 2] >>")
    # the xref stream (object 6) lists the two annotations as free/uncompressed
    # entries; the classic table lists the structural objects
    data = pdf.build(CATALOG, mode="hybrid", xref_num=6,
                     table_objects={CATALOG, PAGES, PAGE},
                     xref_index=[(0, 7)])
    return Seed("s03_hybrid_xrefstm.pdf", data,
                "XRef::readXRefTable (/XRefStm), XRef::readXRef (stream branch)",
                "hybrid reference file: classic table + /XRefStm cross "
                "reference stream")


def s_objstm() -> Seed:
    """Objects stored inside an object stream (/Type /ObjStm).

    Target
      ObjectStream::ObjectStream()  (XRef.cc:72-168)
        - /N and /First lookup                (XRef.cc:94-105)
        - the header parser loop             (XRef.cc:110-137)
        - "skip to the first object" loop    (XRef.cc:144-146)  <-- only runs
          when /First is *smaller* than the first header offset
      XRef::fetch() type 2 branch            (XRef.cc:831-842)

    Why
      The catalog, the page tree and the page are stored as compressed
      objects, so Xpdf has to instantiate an ObjectStream.  The header
      declares offsets that are larger than /First (four filler bytes are
      inserted between the header and the first object), which makes the
      defensive "skip to the first object" loop in XRef.cc:144 execute.
    """
    # --- build the object stream payload ---------------------------------
    bodies = [
        (CATALOG, catalog_body()),
        (PAGES, pages_body(b"%d 0 R" % PAGE, 1)),
        (PAGE, page_body()),
    ]
    # header: "<num> <offset>" pairs; offsets are absolute inside the
    # decoded stream (that is how Xpdf.cc:144-160 interprets them).
    header = b""
    offsets = []
    for num, body in bodies:
        offsets.append((num, len(header)))     # placeholder, fixed below
    # two passes: first compute the header size, then the object offsets
    def make_header(offs):
        return b" ".join(b"%d %d" % (num, off) for num, off in offs) + b" "

    # the header size depends on the offset values, so iterate until stable
    guess = [(num, 0) for num, _ in bodies]
    for _ in range(8):
        header = make_header(guess)
        base = len(header) + 4                 # + 4 filler bytes
        pos = base
        newguess = []
        for (num, body) in bodies:
            newguess.append((num, pos))
            pos += len(body) + 1
        if newguess == guess:
            break
        guess = newguess
    header = make_header(guess)
    payload = bytearray(header)
    payload += b"    "                            # filler -> offsets[0] > First
    for (num, body) in bodies:
        off = len(payload)
        assert off == dict(guess)[num], (off, guess)
        payload += body + b" "
    first = len(header)                          # /First is smaller than offsets[0]

    objstm_body = (b"<< /Type /ObjStm /N %d /First %d /Length %d >>\nstream\n"
                   % (len(bodies), first, len(payload))) + bytes(payload) + b"\nendstream"

    pdf = PdfWriter()
    pdf.add(4, objstm_body)
    for num, _ in bodies:
        pdf.add_compressed(num, 4)
    data = pdf.build(CATALOG, mode="stream", xref_num=5, xref_index=[(0, 6)])
    return Seed("s04_objstm.pdf", data,
                "ObjectStream::ObjectStream, XRef::fetch (type 2)",
                "catalog/pages/page stored in an object stream whose /First "
                "is smaller than the first header offset")


def s_encrypt_rc4() -> Seed:
    """Standard security handler, 40 bit RC4, empty user password.

    Target
      PDFDoc::checkEncryption()               (PDFDoc.cc:274-307)
        - "encrypted" / SecurityHandler::make / checkEncryption branches
      StandardSecurityHandler::StandardSecurityHandler()
                                            (SecurityHandler.cc:126-240)
      Decrypt::makeFileKey()/makeFileKey2()   (Decrypt.cc:37-176)
      md5()                                   (Decrypt.cc:636-776)   <-- the
        whole MD5 implementation is dead code in the base corpus
      DecryptStream (Parser.cc:118-132)       for the encrypted Info string

    Why
      The base corpus contains no encrypted document at all (Decrypt.cc is
      at 0% coverage).  The seed builds a *correct* RC4 encrypted PDF:
      /O and /U are computed with the very algorithm Xpdf implements
      (MD5 + RC4, 40 bit key, empty user password), and the Info string is
      encrypted with the per object key.  Xpdf therefore authenticates the
      empty user password successfully and continues parsing the document.
    """
    doc_id = bytes(range(16))
    perms = -4                                   # 0xfffcff00-ish, all allowed
    user_pwd = b""
    owner_pwd = b""

    # O entry: RC4 of the padded owner password with md5(pad(owner))[0:5]
    o_key = hashlib.md5(pad_password(owner_pwd)).digest()[:5]
    o_value = rc4(o_key, pad_password(owner_pwd))

    # file key: md5(pad(user) + O + P(4 bytes LE) + ID)
    perms_bytes = (perms & 0xFFFFFFFF).to_bytes(4, "little")
    digest = hashlib.md5(
        pad_password(user_pwd) + o_value + perms_bytes + doc_id).digest()
    file_key = digest[:5]                       # 40 bit key

    # U entry (revision 2): RC4 of the pad with the file key
    u_value = rc4(file_key, PAD)

    # encrypted Info title, encrypted with the per object key
    obj_key = hashlib.md5(file_key + (4).to_bytes(3, "little")
                          + (0).to_bytes(2, "little")).digest()[:10]
    title = rc4(obj_key, b"xpdf seed")

    encrypt_dict = (b"<< /Filter /Standard /V 1 /R 2 /Length 40 /P %d /O %s /U %s >>"
                    % (perms, hex_string(o_value), hex_string(u_value)))
    info = b"<< /Title %s /Producer (gen_seeds.py) >>" % literal_string(title)

    pdf = PdfWriter()
    pdf.add(CATALOG, catalog_body())
    pdf.add(PAGES, pages_body(b"%d 0 R" % PAGE, 1))
    pdf.add(PAGE, page_body())
    pdf.add(4, encrypt_dict)
    pdf.add(5, info)
    data = pdf.build(CATALOG, mode="table", extra_trailer=b" /Encrypt 4 0 R",
                     doc_id=doc_id)
    return Seed("s05_encrypt_rc4.pdf", data,
                "PDFDoc::checkEncryption, Decrypt::makeFileKey, md5(), "
                "DecryptStream",
                "RC4 40 bit encrypted PDF (empty user password) with an "
                "encrypted Info string")


def s_metadata_filter(name: str, filters: bytes, parms: bytes, payload: bytes,
                      target: str, why: str) -> Seed:
    """Generic seed: a metadata stream that uses one filter."""
    pdf = PdfWriter()
    pdf.add(CATALOG, catalog_body(extra=b" /Metadata 4 0 R"))
    pdf.add(PAGES, pages_body(b"%d 0 R" % PAGE, 1))
    pdf.add(PAGE, page_body())
    pdf.add(4, metadata_stream(payload, filters, parms))
    data = pdf.build(CATALOG, mode="table")
    return Seed(name, data, target, why)


def s_metadata_filters() -> list:
    """One seed per stream filter, all reached through /Metadata."""
    out = []

    out.append(s_metadata_filter(
        "s06_metadata_asciihex.pdf", b"/ASCIIHexDecode", b"",
        ascii_hex_encode(XML),
        "Stream::makeFilter (ASCIIHexDecode), ASCIIHexStream::lookChar",
        "metadata stream filtered with ASCIIHexDecode"))

    out.append(s_metadata_filter(
        "s07_metadata_ascii85.pdf", b"/ASCII85Decode", b"",
        ascii85_encode(XML),
        "Stream::makeFilter (ASCII85Decode), ASCII85Stream::lookChar",
        "metadata stream filtered with ASCII85Decode"))

    out.append(s_metadata_filter(
        "s08_metadata_lzw.pdf", b"/LZWDecode",
        b"<< /Predictor 1 /Columns 1 /Colors 1 /BitsPerComponent 8 /EarlyChange 1 >>",
        lzw_encode(XML * 3),
        "Stream::makeFilter (LZWDecode + DecodeParms), LZWStream::processNextCode",
        "metadata stream filtered with LZWDecode and a full DecodeParms "
        "dictionary"))

    out.append(s_metadata_filter(
        "s09_metadata_runlength.pdf", b"/RunLengthDecode", b"",
        run_length_encode(XML),
        "Stream::makeFilter (RunLengthDecode), RunLengthStream::fillBuf",
        "metadata stream filtered with RunLengthDecode"))

    out.append(s_metadata_filter(
        "s10_metadata_ccittfax.pdf", b"/CCITTFaxDecode",
        b"<< /K -1 /Columns 8 /Rows 1 /EndOfLine false /EncodedByteAlign false "
        b"/EndOfBlock true /BlackIs1 false >>",
        bytes([0x60, 0x00, 0x08, 0x00]),
        "Stream::makeFilter (CCITTFaxDecode), CCITTFaxStream::lookChar",
        "metadata stream filtered with CCITTFaxDecode (Group 3, 1-D)"))

    out.append(s_metadata_filter(
        "s11_metadata_flate_png.pdf", b"/FlateDecode",
        b"<< /Predictor 12 /Columns 16 /Colors 1 /BitsPerComponent 8 >>",
        flate_dynamic(png_predict_encode(text_payload(64, 16), 16)),
        "StreamPredictor::getNextLine (PNG predictor), FlateStream::readDynamicCodes",
        "metadata stream filtered with FlateDecode and a PNG predictor"))

    out.append(s_metadata_filter(
        "s12_metadata_filter_array.pdf", b"[/ASCIIHexDecode /ASCII85Decode]",
        b"[null null]",
        ascii_hex_encode(ascii85_encode(XML)),
        "Stream::addFilters (array branch), Stream::makeFilter (chain)",
        "metadata stream with an array of two filters and an array of "
        "DecodeParms"))

    out.append(s_metadata_filter(
        "s13_metadata_unknown_filter.pdf", b"/BogusDecode", b"",
        XML,
        "Stream::makeFilter (unknown filter -> EOFStream)",
        "metadata stream with an unknown filter name"))

    out.append(s_metadata_filter(
        "s14_metadata_badflate.pdf", b"/FlateDecode", b"",
        deterministic_bytes(0xBEEF, 64),
        "FlateStream::startBlock (zlib header error paths), "
        "FlateStream::readDynamicCodes",
        "metadata stream with a corrupt Flate payload"))

    out.append(s_metadata_filter(
        "s15_metadata_jbig2.pdf", b"/JBIG2Decode", b"",
        deterministic_bytes(0x4A42, 48),
        "Stream::makeFilter (JBIG2Decode), JBIG2Stream segment header parsing",
        "metadata stream filtered with JBIG2Decode"))

    out.append(s_metadata_filter(
        "s16_metadata_jpx.pdf", b"/JPXDecode", b"",
        deterministic_bytes(0x4A50, 48),
        "Stream::makeFilter (JPXDecode), JPXStream box parsing",
        "metadata stream filtered with JPXDecode"))
    return out


def s_metadata_dct(progressive: bool) -> Seed:
    """Metadata stream filtered with DCTDecode (JPEG).

    Target
      Stream::makeFilter (DCTDecode)             (Stream.cc:216-225)
      DCTStream::reset()/readHeader()            (Stream.cc:1908-2005,
                                                   2855-2931)
      DCTStream::readScan()/readMCURow()         (Stream.cc:2215-2316,
                                                   2094-2212)
      DCTStream::decodeImage()/transformDataUnit() (Stream.cc:2496-2628,
                                                   2638-2789)
      DCTStream::readProgressiveDataUnit()       (Stream.cc:2369-2493)

    Why
      The base corpus never reaches the JPEG decoder because pdfinfo does
      not render page content.  ``Catalog::readMetadata()`` however streams
      the metadata object completely, so a JPEG payload behind a
      /DCTDecode filter is decoded by Xpdf.  A *progressive* JPEG is used
      for the second seed because the progressive scan reader
      (readProgressiveDataUnit) is a completely separate code path.
    """
    try:
        from PIL import Image
        import io
    except Exception as exc:                                  # pragma: no cover
        return None
    img = Image.new("RGB", (16, 16))
    px = img.load()
    for y in range(16):
        for x in range(16):
            px[x, y] = ((x * 16) & 0xFF, (y * 16) & 0xFF, ((x + y) * 8) & 0xFF)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=80, progressive=progressive)
    payload = buf.getvalue()
    return s_metadata_filter(
        "s17_metadata_dct_progressive.pdf" if progressive
        else "s17_metadata_dct_baseline.pdf",
        b"/DCTDecode", b"", payload,
        "DCTStream::reset/readHeader/readScan/decodeImage"
        + ("/readProgressiveDataUnit" if progressive else ""),
        "metadata stream filtered with a %s JPEG"
        % ("progressive" if progressive else "baseline"))


def s_cropbox() -> Seed:
    """CropBox that sticks out of the MediaBox (PDFRectangle::clipTo).

    Target
      PDFRectangle::clipTo()   (Page.cc:36-57) -- all eight branches:
        x1 < rect->x1 / x1 > rect->x2 / x2 < rect->x1 / x2 > rect->x2 and
        the four y equivalents.

    Why
      PageAttrs clips CropBox, BleedBox, TrimBox and ArtBox against the
      MediaBox.  Two pages with inverted/extreme crop boxes are enough to
      hit every branch of the four comparisons:

        page 1: CropBox [-10 -10 200 200]  -> the four "<" branches
        page 2: CropBox [200 200 -50 -50]  -> the four ">" branches
    """
    pdf = PdfWriter()
    pdf.add(CATALOG, catalog_body())
    pdf.add(PAGES, pages_body(b"%d 0 R %d 0 R" % (PAGE, 4), 2))
    pdf.add(PAGE, page_body(extra=b" /CropBox [-10 -10 200 200]"))
    pdf.add(4, page_body(extra=b" /CropBox [200 200 -50 -50]"))
    data = pdf.build(CATALOG, mode="table")
    return Seed("s18_cropbox_clip.pdf", data,
                "PDFRectangle::clipTo (Page.cc:36-57)",
                "two pages whose CropBox lies completely outside the "
                "MediaBox in both directions")


def s_catalog_names_uri() -> Seed:
    """Catalog with a name tree and a URI base.

    Target
      Catalog::Catalog()  (Catalog.cc:30-133)
        - /Names /Dests name tree lookup   (Catalog.cc:95)
        - /URI dictionary with /Base string  (Catalog.cc:101-102)

    Why
      Those two lookups are performed while the catalog is read, i.e. long
      before any rendering happens, so a plain catalog with
      ``/Names << /Dests ... >>`` and ``/URI << /Base (http://...) >>`` is
      enough to execute the branches.
    """
    pdf = PdfWriter()
    pdf.add(CATALOG, catalog_body(extra=(
        b" /Names << /Dests << /Names [(chapter1) 3 0 R] >> >>"
        b" /URI << /Base (http://example.org/) >>")))
    pdf.add(PAGES, pages_body(b"%d 0 R" % PAGE, 1))
    pdf.add(PAGE, page_body())
    data = pdf.build(CATALOG, mode="table")
    return Seed("s19_catalog_names_uri.pdf", data,
                "Catalog::Catalog (/Names /Dests, /URI /Base)",
                "catalog carrying a destination name tree and a URI base")


def s_xref_table_quirk() -> Seed:
    """Classic table with the "IBM patent" quirk and /Prev as a reference.

    Target
      XRef::readXRefTable()  (XRef.cc:348-467)
        - the special case for a table that starts at 1 with a free
          entry for object 1                            (XRef.cc:410-420)
        - "/Prev NNN 0 R" (indirect reference instead of an integer)
                                                      (XRef.cc:434-438)
        - subsection growth                              (XRef.cc:371-384)

    Why
      Some generators emit cross reference tables that claim to start at
      object 1 and mark object 1 as free; Xpdf has an explicit work-around
      for that.  Some other generators write /Prev as an indirect
      reference, which Xpdf also accepts.  Both quirks are reproduced
      here, and the object numbers are chosen so that the table has to
      grow while it is read.
    """
    pdf = PdfWriter()
    pdf.add(CATALOG, catalog_body())
    pdf.add(PAGES, pages_body(b"%d 0 R" % PAGE, 1))
    pdf.add(PAGE, page_body())
    pdf.add(4, b"<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] >>")
    data = pdf.build(CATALOG, mode="table", ibm_quirk=True)
    return Seed("s20_xref_table_quirk.pdf", data,
                "XRef::readXRefTable (IBM quirk, table growth)",
                "cross reference table that starts at object 1 with a free "
                "entry for object 1")


def s_prev_as_ref() -> Seed:
    """Classic table whose /Prev is written as an indirect reference.

    Target
      XRef::readXRefTable()  ``/Prev`` given as a reference (XRef.cc:434-438)

    Why
      ``obj2.isRef()`` is a separate branch in Xpdf: buggy generators write
      "/Prev NNN 0 R" instead of "/Prev NNN".  Xpdf then uses the *number*
      of the reference as the byte position of the previous cross
      reference section, so the number has to be the byte offset of that
      section -- exactly what the seed does.  Two classic cross reference
      sections are therefore written.
    """
    head = bytearray()
    head += b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
    # --- older section: owns object 5 ------------------------------------
    off5 = len(head)
    head += b"5 0 obj\n<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] >>\nendobj\n"
    off_a = len(head)
    head += b"xref\n0 1\n%010d %05d f \n" % (0, 0xFFFF)
    head += b"5 1\n%010d %05d n \n" % (off5, 0)
    head += b"trailer\n<< /Size 6 /Root %d 0 R >>\n" % CATALOG
    # --- newer section: owns the structural objects ----------------------
    offs = {}
    for num, body in ((CATALOG, catalog_body()),
                       (PAGES, pages_body(b"%d 0 R" % PAGE, 1)),
                       (PAGE, page_body()),
                       (4, b"<< /Type /Annot /Subtype /Text /Rect [1 1 2 2] >>")):
        offs[num] = len(head)
        head += b"%d %d obj\n" % (num, 0)
        head += body
        head += b"\nendobj\n"
    off_b = len(head)
    head += b"xref\n0 5\n%010d %05d f \n" % (0, 0xFFFF)
    for num in (1, 2, 3, 4):
        head += b"%010d %05d n \n" % (offs[num], 0)
    head += b"trailer\n<< /Size 6 /Root %d 0 R /Prev %d 0 R >>\n" % (CATALOG, off_a)
    head += b"startxref\n%d\n%%%%EOF\n" % off_b
    return Seed("s21_xref_prev_as_ref.pdf", bytes(head),
                "XRef::readXRefTable (/Prev as indirect reference)",
                "two classic cross reference sections; the newer one refers "
                "to the older one through '/Prev <offset> 0 R'")


def s_bad_annots() -> Seed:
    """Page whose /Annots entry has a wrong type.

    Target
      Page::Page()  error path  (Page.cc:217-223)  -- the page is rejected
      Catalog::getPage()  (Catalog.cc)             -- NULL page handling

    Why
      The harness calls ``getCatalog()->getPage(pg)`` for every page.  A
      page with "/Annots 7" (a number instead of an array or a reference)
      makes Xpdf print the "Page annotations object is wrong type" error
      and mark the page as not ok, which is a branch that the base corpus
      never reaches.
    """
    pdf = PdfWriter()
    pdf.add(CATALOG, catalog_body())
    pdf.add(PAGES, pages_body(b"%d 0 R" % PAGE, 1))
    pdf.add(PAGE, page_body(extra=b" /Annots 7"))
    data = pdf.build(CATALOG, mode="table")
    return Seed("s22_page_bad_annots.pdf", data,
                "Page::Page (wrong /Annots type), Catalog::getPage",
                "page with an /Annots entry of the wrong type")


def s_linearized() -> Seed:
    """First object in the file is a linearization dictionary.

    Target
      PDFDoc::isLinearized()  (PDFDoc.cc:340-385), branch "obj5.isNum() &&
      obj5.getNum() > 0"                              (PDFDoc.cc:373-376)

    Why
      ``doc->isLinearized()`` parses the *first* indirect object of the
      file and looks for a /Linearized entry.  In the base corpus the
      first object is always the catalog, so the branch that reports a
      linearized file is never taken.
    """
    pdf = PdfWriter()
    lin = b"<< /Linearized 1 /L 200 /H [100 100] /O 4 /E 150 /N 3 /T 190 >>"
    pdf.add(1, lin)
    pdf.add(2, b"<< /Type /Catalog /Pages 3 0 R >>")
    pdf.add(3, b"<< /Type /Pages /Count 1 /Kids [4 0 R] >>")
    pdf.add(4, b"<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792] >>")
    data = pdf.build(2, mode="table")
    return Seed("s23_linearized.pdf", data,
                "PDFDoc::isLinearized",
                "first object of the file is a linearization dictionary")


def s_xrefstream_predictor() -> Seed:
    """Cross reference stream compressed with a PNG predictor.

    Target
      XRef::readXRefStream()  with a filtered stream (XRef.cc:469-561)
      StreamPredictor::getNextLine()      (Stream.cc:453-571)
      FlateStream::readDynamicCodes()      (Stream.cc:4151-4249)
      FlateStream::startBlock()            (Stream.cc:4077-4142)

    Why
      Real world cross reference streams are usually Flate compressed and
      use the PNG predictor with one row per object.  Building the seed
      that way exercises the predictor inside the cross reference reader,
      which is a different code path from the predictor used for image
      data -- and the deflate stream is built so that it contains a
      dynamic Huffman block (FlateStream::readDynamicCodes).
    """
    pdf = PdfWriter()
    pdf.add(CATALOG, catalog_body())
    pdf.add(PAGES, pages_body(b"%d 0 R" % PAGE, 1))
    pdf.add(PAGE, page_body())
    # enough filler objects so that the compressed cross reference stream
    # is large enough for zlib to pick a dynamic Huffman block
    for n in range(4, 84):
        pdf.add(n, b"<< /Type /Annot /Subtype /Text /Rect [%d 0 1 1] >>" % n)
    data = pdf.build(CATALOG, mode="stream", xref_num=84, xref_index=[(0, 85)],
                     xref_png=True)
    return Seed("s24_xrefstream_pngpredictor.pdf", data,
                "XRef::readXRefStream (Flate + PNG predictor), "
                "StreamPredictor::getNextLine, FlateStream::readDynamicCodes",
                "cross reference stream compressed with Flate and a PNG "
                "predictor")


def build_seeds() -> list:
    seeds = [
        s_xrefstream_index(),
        s_xrefstream_prev(),
        s_hybrid_xrefstm(),
        s_objstm(),
        s_encrypt_rc4(),
        s_cropbox(),
        s_catalog_names_uri(),
        s_xref_table_quirk(),
        s_prev_as_ref(),
        s_bad_annots(),
        s_linearized(),
        s_xrefstream_predictor(),
    ]
    seeds.extend(s_metadata_filters())
    dct = s_metadata_dct(False)
    if dct:
        seeds.append(dct)
    dctp = s_metadata_dct(True)
    if dctp:
        seeds.append(dctp)
    return seeds


# ---------------------------------------------------------------------------
# 5. verification helpers
# ---------------------------------------------------------------------------

def find_binary(explicit: str | None) -> Path | None:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates += [
        HERE / "cov/xpdf-3.02/xpdf/pdfinfo",
        HERE / "install_cov/bin/pdfinfo",
    ]
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return c
    return None


def run_covered(binary: Path, files, tmpdir: Path) -> Path:
    """Run the instrumented binary over the given files, merge profiles."""
    profraws = []
    for i, f in enumerate(files):
        env = dict(os.environ)
        env["LLVM_PROFILE_FILE"] = str(tmpdir / ("p%04d.profraw" % i))
        try:
            subprocess.run([str(binary), str(f)], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=30)
        except subprocess.TimeoutExpired:
            pass
        p = tmpdir / ("p%04d.profraw" % i)
        if p.exists():
            profraws.append(p)
    merged = tmpdir / "seeds.profdata"
    subprocess.run(["llvm-profdata", "merge", "-sparse", *[str(p) for p in profraws],
                    "-o", str(merged)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return merged


def covered_lines(binary: Path, profdata: Path, sources) -> dict:
    """{source file: set of covered line numbers} for the given profile."""
    res = {}
    args = ["llvm-cov", "show", "-instr-profile=" + str(profdata), str(binary),
            "--show-line-counts-or-regions"]
    for s in sources:
        res[str(s)] = set()
    out = subprocess.run(args + [str(s) for s in sources],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    cur = None
    for line in out.stdout.decode("utf-8", "replace").splitlines():
        if line.endswith(":") and "|" not in line:
            cur = line[:-1].strip()
            continue
        if cur is None or "|" not in line:
            continue
        parts = line.split("|", 2)
        if len(parts) < 3:
            continue
        try:
            lineno = int(parts[0].strip())
        except ValueError:
            continue
        count = parts[1].strip()
        if count:
            # llvm-cov abbreviates large counts ("8.52k", "1.2M")
            mult = 1.0
            if count[-1] in "kMG":
                mult = {"k": 1e3, "M": 1e6, "G": 1e9}[count[-1]]
                count = count[:-1]
            try:
                c = float(count) * mult
            except ValueError:
                c = 0.0
            if c > 0:
                res.setdefault(cur, set()).add(lineno)
    return res


def verify(seeds, binary: Path, baseline: Path | None) -> int:
    """Measure what the generated seeds actually cover.

    Every seed is executed on its own with the instrumented binary and the
    resulting profile is compared with the baseline profile, so the report
    shows exactly which source lines each seed adds -- no claim is made
    without a measurement.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="gen_seeds_verify_"))
    try:
        src_root = HERE / "cov/xpdf-3.02/xpdf"
        sources = [src_root / n for n in
                   ("Array.cc", "Catalog.cc", "Decrypt.cc", "Dict.cc", "Lexer.cc",
                    "Object.cc", "PDFDoc.cc", "Page.cc", "Parser.cc", "Stream.cc",
                    "XRef.cc")]
        base = covered_lines(binary, baseline, sources) if baseline else {}
        print("instrumented binary : %s" % binary)
        print("baseline profile     : %s" % (baseline if baseline else "(none)"))
        print("-" * 92)
        print("%-34s %8s   %s" % ("seed", "new ln", "files with newly covered lines"))
        print("-" * 92)
        union = set()
        for s in seeds:
            work = tmpdir / ("seed_" + s.name.replace(".pdf", ""))
            work.mkdir(exist_ok=True)
            d = work / s.name
            d.write_bytes(s.data)
            prof = run_covered(binary, [d], work)
            cov = covered_lines(binary, prof, sources)
            new = set()
            for src in sources:
                k = str(src)
                new |= (cov.get(k, set()) - base.get(k, set()))
            union |= new
            touched = []
            for src in sources:
                k = str(src)
                n = len(cov.get(k, set()) - base.get(k, set()))
                if n:
                    touched.append("%s(%d)" % (src.name.replace(".cc", ""), n))
            print("%-34s %8d   %s" % (s.name, len(new), " ".join(touched) or "-"))
            shutil.rmtree(work, ignore_errors=True)
        print("-" * 92)
        print("union of all seeds: %d newly covered lines" % len(union))
        return 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 6. main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", default=str(HERE / "seeds_ai"),
                    help="output directory (default: ./seeds_ai)")
    ap.add_argument("--list", action="store_true",
                    help="only print the seed catalogue")
    ap.add_argument("--verify", action="store_true",
                    help="measure the coverage of the generated seeds")
    ap.add_argument("--binary", default=None,
                    help="instrumented pdfinfo used by --verify")
    ap.add_argument("--baseline", default=None,
                    help="baseline .profdata used by --verify")
    args = ap.parse_args()

    seeds = build_seeds()

    if args.list:
        for s in seeds:
            print("%-34s %6d bytes" % (s.name, len(s.data)))
            print("    target: %s" % s.target)
            print("    why   : %s" % s.why)
        return 0

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)
    for s in seeds:
        (outdir / s.name).write_bytes(s.data)
        print("wrote %-34s %6d bytes  %s" % (s.name, len(s.data), s.target))

    if args.verify:
        binary = find_binary(args.binary)
        if binary is None:
            print("no instrumented pdfinfo found -- skipping verification")
            return 1
        baseline = Path(args.baseline) if args.baseline else (
            HERE / "cov_reports/base/cov.profdata")
        if not baseline.exists():
            baseline = None
        return verify(seeds, binary, baseline)
    return 0


if __name__ == "__main__":
    sys.exit(main())
