//========================================================================
//
// harness_ai.cc
//
// honggfuzz persistent-mode harness for Xpdf 3.02.
//
// The harness reproduces the code path of xpdf/pdfinfo.cc (document
// parsing + Info dictionary + page tree + metadata) but feeds the PDF
// bytes straight from memory (MemStream) instead of from a file.
//
// Ownership rules used here:
//   * globalParams is created once in main() and never touched again
//     inside the fuzzing loop (it caches Unicode maps / CMaps).
//   * every iteration owns its own copy of the input bytes; the copy is
//     released only after the PDFDoc (and therefore the MemStream that
//     points into that copy) has been destroyed.
//   * PDFDoc takes ownership of the BaseStream it is constructed with
//     (PDFDoc::~PDFDoc() deletes it), so the MemStream must NOT be
//     deleted by the harness.
//   * Objects returned by the Xpdf API (Object / GString) are freed by
//     the harness right after use, so no per-iteration leak is kept.
//
//========================================================================

#include <aconf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libhfuzz/libhfuzz.h>

#include "GString.h"
#include "gmem.h"
#include "gtypes.h"
#include "GlobalParams.h"
#include "Object.h"
#include "Dict.h"
#include "Stream.h"
#include "XRef.h"
#include "Catalog.h"
#include "Page.h"
#include "PDFDoc.h"
#include "Error.h"
#include "config.h"

//------------------------------------------------------------------------
// Walk the document Info dictionary, exactly like printInfoString() and
// printInfoDate() in pdfinfo.cc do (the strings are decoded/consumed
// instead of being printed).
//------------------------------------------------------------------------
static void touchInfoDict(Dict *infoDict) {
  // Dict::lookup() takes a non-const 'char *', so keep the keys in
  // writable char arrays.
  static char infoKeys[][16] = {
    "Title", "Subject", "Keywords", "Author",
    "Creator", "Producer", "CreationDate", "ModDate"
  };
  unsigned int i;

  if (!infoDict) {
    return;
  }
  for (i = 0; i < sizeof(infoKeys) / sizeof(infoKeys[0]); ++i) {
    Object obj;
    GString *s;
    int j, len;
    volatile int sum;

    if (infoDict->lookup(infoKeys[i], &obj)->isString()) {
      s = obj.getString();
      if (s) {
        // Touch every byte of the decoded string so that the string
        // decoding path is really executed.
        len = s->getLength();
        sum = 0;
        for (j = 0; j < len; ++j) {
          sum += s->getChar(j);
        }
        (void)sum;
      }
    }
    obj.free();
  }
}

//------------------------------------------------------------------------
// Process one fuzz input.
//------------------------------------------------------------------------
static void processInput(const uint8_t *data, size_t len) {
  Object dictObj;
  char *buf;
  MemStream *str;
  PDFDoc *doc;
  Object info;
  int numPages, lastPage, pg;
  GString *metadata;

  // Nothing to do for an empty input.
  if (len == 0) {
    return;
  }

  dictObj.initNull();

  // The MemStream keeps a raw pointer to the data, so the bytes must stay
  // alive (and must not move) until the document is destroyed.  Copy them
  // into a private heap buffer that is released at the end of this
  // function.
  buf = (char *)gmalloc((int)len);
  if (!buf) {
    return;
  }
  memcpy(buf, data, len);

  // The base stream over the in-memory PDF.  The dictionary argument is
  // copied by BaseStream, a null object is enough here.
  str = new MemStream(buf, 0, (Guint)len, &dictObj);

  // PDFDoc takes ownership of 'str' and frees it in its destructor.
  doc = new PDFDoc(str);
  if (!doc->isOk()) {
    // Invalid / broken PDF: nothing else may be accessed.
    delete doc;
    gfree(buf);
    return;
  }

  // --- document Info dictionary (pdfinfo.cc: doc->getDocInfo) -----------
  doc->getDocInfo(&info);
  if (info.isDict()) {
    touchInfoDict(info.getDict());
  }
  info.free();

  // --- tagging information (pdfinfo.cc: doc->getStructTreeRoot) ---------
  if (doc->getStructTreeRoot()) {
    (void)doc->getStructTreeRoot()->isDict();
  }

  // --- page count / page geometry (pdfinfo.cc: getNumPages, crop box) ---
  numPages = doc->getNumPages();
  if (numPages > 0) {
    // Only walk a bounded number of pages to keep the iteration time
    // predictable; getPage() does not do any bounds checking.
    lastPage = numPages > 4 ? 4 : numPages;
    for (pg = 1; pg <= lastPage; ++pg) {
      Page *page = doc->getCatalog()->getPage(pg);
      if (!page) {
        continue;
      }
      (void)doc->getPageCropWidth(pg);
      (void)doc->getPageCropHeight(pg);
      (void)page->getMediaBox();
      (void)page->getCropBox();
    }
  }

  // --- encryption information (pdfinfo.cc: isEncrypted/okTo*) -----------
  if (doc->isEncrypted()) {
    (void)doc->okToPrint(gTrue);
    (void)doc->okToCopy(gTrue);
    (void)doc->okToChange(gTrue);
    (void)doc->okToAddNotes(gTrue);
  }

  // --- linearization / version (pdfinfo.cc) ----------------------------
  (void)doc->isLinearized();
  (void)doc->getPDFVersion();

  // --- metadata stream (pdfinfo.cc -meta, readMetadata()) ---------------
  metadata = doc->readMetadata();
  if (metadata) {
    delete metadata;
  }

  // --- clean up --------------------------------------------------------
  // delete doc frees the catalog, the xref and the MemStream.
  delete doc;
  gfree(buf);
}

//------------------------------------------------------------------------
// Entry point.  main() is defined here (strong symbol), so the weak
// main() provided by libhfuzz's persistent.c is not used.
//------------------------------------------------------------------------
int main(int argc, char **argv) {
  char cfgFileName[256] = "";

  (void)argc;
  (void)argv;

  // Initialize globalParams exactly once, outside of the fuzzing loop.
  globalParams = new GlobalParams(cfgFileName);
  // Keep stderr clean: xpdf's error() only prints when errQuiet is false.
  globalParams->setErrQuiet(gTrue);

  // Persistent mode: honggfuzz hands us one input at a time.
  for (;;) {
    const uint8_t *buf = NULL;
    size_t len = 0;

    HF_ITER(&buf, &len);
    if (!buf) {
      continue;
    }
    processInput(buf, len);
  }

  // Not reached.
  return 0;
}
