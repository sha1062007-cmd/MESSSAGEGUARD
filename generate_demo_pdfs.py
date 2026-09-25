"""Generate test PDFs for on-device FlateDecode verification and benign stress testing."""
import zlib
import struct
import os

OUTPUT_DIR = r"C:\POC1\demo_test_pdfs"

def flate_compress(data: bytes) -> bytes:
    """Compress data using zlib (DEFLATE) — matches PDF FlateDecode."""
    return zlib.compress(data)

def build_pdf_with_flatedecode_stream(compressed_content: str, dangerous_tag: str = "") -> bytes:
    """Build a PDF with a FlateDecode-compressed stream containing the given content.
    The tag is ONLY in the compressed stream, not in plaintext anywhere."""
    compressed = flate_compress(compressed_content.encode("iso-8859-1"))
    obj = (
        f"1 0 obj\n"
        f"<< /Type /EmbeddedFile /Filter /FlateDecode /Length {len(compressed)} >>\n"
        f"stream\n"
    ).encode("iso-8859-1")
    endstream = b"\nendstream\nendobj\n"
    header = b"%PDF-1.4\n"
    footer = b"\n%%EOF"
    return header + obj + compressed + endstream + footer

def build_clean_pdf(description: str = "clean document", extra_body: str = "") -> bytes:
    """Build a minimal clean PDF with proper structure."""
    body = f"""
2 0 obj
<< /Type /Catalog /Pages 3 0 R >>
endobj

3 0 obj
<< /Type /Pages /Kids [4 0 R] /Count 1 >>
endobj

4 0 obj
<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792]
   /Contents 5 0 R /Resources << /Font << /F1 6 0 R >> >> >>
endobj

5 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 100 700 Td ({description}) Tj ET
endstream
endobj

6 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
"""
    header = b"%PDF-1.4\n"
    footer = b"\n%%EOF"
    return header + body.encode("iso-8859-1") + footer

def build_pdf_with_openaction(target_page: int = 2) -> bytes:
    """Build a PDF with a legitimate /OpenAction GoTo page."""
    body = f"""
2 0 obj
<< /Type /Catalog /Pages 3 0 R /OpenAction << /Type /Action /S /GoTo /D [{target_page - 1} 0 R /Fit] >> >>
endobj

3 0 obj
<< /Type /Pages /Kids [4 0 R 7 0 R] /Count 2 >>
endobj

4 0 obj
<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792]
   /Contents 5 0 R /Resources << /Font << /F1 6 0 R >> >> >>
endobj

5 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 100 700 Td (Page 1 - Cover Page) Tj ET
endstream
endobj

6 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj

7 0 obj
<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792]
   /Contents 8 0 R /Resources << /Font << /F1 6 0 R >> >> >>
endobj

8 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 100 700 Td (Page 2 - Content) Tj ET
endstream
endobj
"""
    header = b"%PDF-1.4\n"
    footer = b"\n%%EOF"
    return header + body.encode("iso-8859-1") + footer

def build_pdf_with_embedded_xml() -> bytes:
    """Build a PDF with /EmbeddedFiles containing an XML file (ZUGFeRD/Factur-X style)."""
    body = """
1 0 obj
<< /Type /Catalog /Pages 2 0 R /Names 3 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [4 0 R] /Count 1 >>
endobj

3 0 obj
<< /EmbeddedFiles << /Names [(factur-x.xml) 5 0 R] >> >>
endobj

4 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj

5 0 obj
<< /Type /EmbeddedFile /Subtype /XML /Length 44 >>
stream
<?xml version="1.0"?><invoice>test</invoice>
endstream
endobj
"""
    header = b"%PDF-1.4\n"
    footer = b"\n%%EOF"
    return header + body.encode("iso-8859-1") + footer

def build_pdf_with_high_entropy_image() -> bytes:
    """Build a PDF simulating an embedded image (high entropy, compressed)."""
    import random
    random.seed(42)
    # Simulate a compressed image stream (high entropy binary data)
    image_data = bytes(random.getrandbits(8) for _ in range(8192))
    compressed = flate_compress(image_data)
    body = f"""
2 0 obj
<< /Type /Catalog /Pages 3 0 R >>
endobj

3 0 obj
<< /Type /Pages /Kids [4 0 R] /Count 1 >>
endobj

4 0 obj
<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792]
   /Contents 5 0 R /Resources << /XObject << /Img 6 0 R >> >> >>
endobj

5 0 obj
<< /Length 44 >>
stream
BT 100 700 Td (Image document) Tj ET
endstream
endobj

6 0 obj
<< /Type /XObject /Subtype /Image /Width 64 /Height 64
   /ColorSpace /DeviceRGB /BitsPerComponent 8
   /Filter /FlateDecode /Length {len(compressed)} >>
stream
"""
    header = b"%PDF-1.4\n"
    footer_data = b"\nendstream\nendobj\n\n%%EOF"
    return header + body.encode("iso-8859-1") + compressed + footer_data

def build_pdf_with_acroform() -> bytes:
    """Build a PDF with /AcroForm (interactive form fields — common in real PDFs)."""
    body = """
2 0 obj
<< /Type /Catalog /Pages 3 0 R /AcroForm 4 0 R >>
endobj

3 0 obj
<< /Type /Pages /Kids [5 0 R] /Count 1 >>
endobj

4 0 obj
<< /Fields [6 0 R 7 0 R] >>
endobj

5 0 obj
<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792]
   /Contents 8 0 R /Resources << /Font << /F1 9 0 R >> >> >>
endobj

6 0 obj
<< /Type /Annot /Subtype /Widget /FT /Tx /T (Name) /V (John Doe) /Rect [100 700 300 720] >>
endobj

7 0 obj
<< /Type /Annot /Subtype /Widget /FT /Tx /T (Email) /V (john@example.com) /Rect [100 670 300 690] >>
endobj

8 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 100 750 Td (Application Form) Tj ET
endstream
endobj

9 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
"""
    header = b"%PDF-1.4\n"
    footer = b"\n%%EOF"
    return header + body.encode("iso-8859-1") + footer

def build_pdf_with_fonts() -> bytes:
    """Build a PDF with embedded font subsets (common in Word/Google Docs exports)."""
    body = """
2 0 obj
<< /Type /Catalog /Pages 3 0 R >>
endobj

3 0 obj
<< /Type /Pages /Kids [4 0 R] /Count 1 >>
endobj

4 0 obj
<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792]
   /Contents 5 0 R /Resources << /Font << /F1 6 0 R /F2 7 0 R >> >> >>
endobj

5 0 obj
<< /Length 80 >>
stream
BT /F1 14 Tf 100 750 Td (Report Title) Tj ET
BT /F2 10 Tf 100 720 Td (This is body text in a different font.) Tj ET
endstream
endobj

6 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>
endobj

7 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman >>
endobj
"""
    header = b"%PDF-1.4\n"
    footer = b"\n%%EOF"
    return header + body.encode("iso-8859-1") + footer

def build_pdf_missing_eof() -> bytes:
    """Build a PDF without %%EOF — structurally malformed but common in truncated files."""
    body = """
2 0 obj
<< /Type /Catalog /Pages 3 0 R >>
endobj

3 0 obj
<< /Type /Pages /Kids [4 0 R] /Count 1 >>
endobj

4 0 obj
<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792] >>
endobj
"""
    header = b"%PDF-1.4\n"
    # No %%EOF — truncated
    return header + body.encode("iso-8859-1")

def build_pdf_with_embedded_exe() -> bytes:
    """Build a PDF with /EmbeddedFiles + .exe extension (MALICIOUS test)."""
    body = """
1 0 obj
<< /Type /Catalog /Pages 2 0 R /Names 3 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [4 0 R] /Count 1 >>
endobj

3 0 obj
<< /EmbeddedFiles << /Names [(invoice_malware.exe) 5 0 R] >> >>
endobj

4 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj

5 0 obj
<< /Type /EmbeddedFile /Length 44 >>
stream
MZ...this is not a real exe but has the extension
endstream
endobj
"""
    header = b"%PDF-1.4\n"
    footer = b"\n%%EOF"
    return header + body.encode("iso-8859-1") + footer


if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    test_cases = [
        # === MALICIOUS test cases ===
        ("demo_hidden_js_flatedecode.pdf",
         build_pdf_with_flatedecode_stream(
             "This stream contains /JS hidden payload. /JS app.alert('pwned')",
         ),
         "MALICIOUS — /JS hidden in FlateDecode stream"),

        ("demo_plaintext_js.pdf",
         build_pdf_with_flatedecode_stream("")[:10] + b"%PDF-1.4\n/JS app.alert('test')\n%%EOF",
         "MALICIOUS — /JS in plaintext"),

        ("demo_embedded_exe.pdf",
         build_pdf_with_embedded_exe(),
         "MALICIOUS — /EmbeddedFiles + .exe"),

        # === SAFE / SUSPICIOUS test cases (benign stress test) ===
        ("demo_clean_simple.pdf",
         build_clean_pdf("Simple clean document"),
         "SAFE — basic clean PDF"),

        ("demo_openaction_goto.pdf",
         build_pdf_with_openaction(target_page=2),
         "SAFE — legitimate /OpenAction GoTo page 2"),

        ("demo_embedded_xml_invoice.pdf",
         build_pdf_with_embedded_xml(),
         "SUSPICIOUS — /EmbeddedFiles with benign XML (ZUGFeRD style)"),

        ("demo_high_entropy_image.pdf",
         build_pdf_with_high_entropy_image(),
         "SAFE or SUSPICIOUS — high entropy from compressed image data"),

        ("demo_acroform_fields.pdf",
         build_pdf_with_acroform(),
         "SAFE — PDF with interactive form fields"),

        ("demo_embedded_fonts.pdf",
         build_pdf_with_fonts(),
         "SAFE — PDF with multiple font references"),

        ("demo_missing_eof.pdf",
         build_pdf_missing_eof(),
         "SUSPICIOUS — missing %%EOF (truncated)"),
    ]

    for filename, content, expected in test_cases:
        path = os.path.join(OUTPUT_DIR, filename)
        with open(path, "wb") as f:
            f.write(content)
        print(f"[OK] {filename} ({len(content)} bytes) — Expected: {expected}")

    print(f"\n{len(test_cases)} PDFs written to {OUTPUT_DIR}")
