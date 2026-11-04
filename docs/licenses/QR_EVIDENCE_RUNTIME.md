# M22 optional runtime - third-party licence notices

The M22 QR evidence module is opt-in and offline. Its runtime packages were
selected on 2026-11-04 after verifying every licence at source for
compatibility with TRACE-X's MIT licence. All are permissive; attribution
texts ship inside each installed distribution.

| Package | Version | Licence | Source |
|---|---|---|---|
| pypdf | 6.21.2 | BSD-3-Clause | https://raw.githubusercontent.com/py-pdf/pypdf/main/LICENSE |
| pypdfium2 (bindings) | 5.14.0 | BSD-3-Clause OR Apache-2.0 | https://github.com/pypdfium2-team/pypdfium2 (installed wheel `licenses/`) |
| PDFium (native, bundled by pypdfium2) | 5.14.0 wheel | BSD-3-Clause | bundled `pdfium.txt`, Copyright 2014 The PDFium Authors |
| pdfium-binaries (packaging) | n/a | MIT | https://raw.githubusercontent.com/bblanchon/pdfium-binaries/master/LICENSE |
| opencv-python-headless | 5.0.0.93 | Apache-2.0 (packaging MIT) | https://raw.githubusercontent.com/opencv/opencv/master/LICENSE |
| Pillow | 12.3.0 | MIT-CMU (HPND) | installed dist-info |
| numpy | 2.2.6 | BSD-3-Clause | https://raw.githubusercontent.com/numpy/numpy/main/LICENSE.txt |

pypdfium2's bundled transitive licences (FreeType, ICU, LLVM-libc, libpng,
zlib, lcms, libjpeg-turbo, libopenjpeg, abseil, fast_float, simdutf, agg23)
were audited in the shipped linux_x64 wheel: all permissive. The only GPL
text covers an ICU build-time Autoconf macro whose special exception is
fulfilled and which is not part of the shipped binary.

Alternative noted: pdf.js (Apache-2.0, Node-based) -
https://raw.githubusercontent.com/mozilla/pdf.js/master/LICENSE

Deliberately excluded: PyMuPDF (AGPL-3.0 or Artifex commercial -
https://pymupdf.io/licensing), Ghostscript (AGPL), poppler (GPL). None may
enter the TRACE-X dependency set.
