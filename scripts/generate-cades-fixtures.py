#!/usr/bin/env python3
"""
CAdES binary fixture'larını deterministic üretir.

Üretilen dosyalar (resources/test-fixtures/cades/):

  Commit edilenler (küçük, < 100 KB):
    - sample.txt             UTF-8 Türkçe, ~2 KB — gerçekçi metin payload
    - sample.bin             Deterministic random binary, 10 KB
    - empty.bin              0 byte — signer'ın "boş input" davranışı
    - utf16-text.txt         UTF-16 LE BOM + Türkçe text, ~2 KB
    - zip-archive.zip        İçinde 3 küçük dosya olan nested binary
    - docx-sample.docx       Minimal valid Office Open XML (Word) belgesi
                              (Word/LibreOffice tarafından açılabilir; sentetik
                              ama "real-world zip-based binary" karakterinde)

  Generator-only (büyük, .gitignore'da):
    - large-10mb.bin         Deterministic 10 MB binary — perf / streaming
                              testi için. Her CI run'da generator script'i
                              tetiklenir (bkz. CI workflow / Maven phase
                              entegrasyonu).

Niye script ile?
  - Test fixture'larının üretim mantığı git history'de şeffaf kalır.
  - Yarın yeni bir varyant gerekirse template hazır.
  - "Magic" binary fixture'ları gözle review etmek imkansızdır; sentetik
    ve deterministic üretim hem reproducibility hem audit edilebilirlik
    sağlar.

Determinism nasıl sağlanır?
  - Random bytes için Python `random.Random(seed)` (Mersenne Twister)
    kullanılır. Aynı seed → aynı bayt akışı. Cross-platform deterministic
    (random.random PEP'leri stable).
  - Sabit string'ler hardcode'dur; tarih/saat içermez.

Çalıştırma:
  python3 scripts/generate-cades-fixtures.py            # küçükler
  python3 scripts/generate-cades-fixtures.py --large    # large-10mb.bin dahil
"""

import argparse
import datetime
import io
import pathlib
import random
import sys
import zipfile


DEST = pathlib.Path("resources/test-fixtures/cades")

# Determinism: seed sabittir; aynı script aynı baytı üretir.
RANDOM_SEED = 0xC0DE_CADE5  # "code cades"

# Türkçe metin payload — CAdES sample.txt için. UTF-8 multibyte
# karakter kapsamı (ç, ş, ğ, ü, ö, ı, İ) ve uzun ASCII genişliği için
# bilinçli olarak repetitive ama anlamlı.
TURKCE_TEXT = """\
Mersel DSS Sample Belge — UTF-8 Test Payload
============================================

Bu dosya CAdES imzalama akışı için kullanılan örnek bir metin payload'dır.
Türkçe karakterler (ç, ş, ğ, ü, ö, ı, İ), uzun paragraflar ve hem ASCII
hem de multi-byte UTF-8 sekansları içerir.

Madde 1. Tek mecra üzerinden gönderilen belgeler, ilgili mevzuat gereği
en az altı yıl süreyle saklanmalı ve denetim talebi halinde derhal
ibraz edilebilir vaziyette tutulmalıdır.

Madde 2. Belge bütünlüğünden imza sahibi sorumludur. İmzanın geçerlilik
süresi içinde belge üzerinde gerçekleştirilecek herhangi bir değişiklik,
imzanın geçersiz hâle gelmesine yol açar.

Madde 3. İşbu örnek belge yalnızca test amaçlıdır. Herhangi bir resmî
işlemde delil olarak kullanılamaz. Üretim sistemlerinin entegrasyon
testlerinde kullanılması yasaktır.

Genel Notlar
------------
- Karakter seti: UTF-8 (Latin-1 üst kümesi)
- Satır sonları: LF (Unix-style)
- Dil: Türkçe
- Konu başlıkları: Mali Mühür, e-İmza, e-Belge, Türkiye e-Fatura

Çeşitli sayısal değerler (precision varyasyonu için):
  • Tutar: 1.234.567,89 TL
  • KDV Oranı: %18
  • Açıklama: "Üç yüz yirmi adet ürün × 12,50 TL/adet = 4.000,00 TL"

Yedek satırlar (ASCII pad — dosya boyutunu ~2KB civarına getirmek için):
- The quick brown fox jumps over the lazy dog. 1234567890
- The quick brown fox jumps over the lazy dog. ABCDEFGHIJKLMNOPQRSTUVWXYZ
- The quick brown fox jumps over the lazy dog. abcdefghijklmnopqrstuvwxyz
- The quick brown fox jumps over the lazy dog. !@#$%^&*()_+-=[]{}|;:,.<>?

UTF-16 yan testi:
  Bu dosya UTF-8'dir. utf16-text.txt aynı içeriği UTF-16 LE + BOM ile sunar
  ve CAdES signer'ın "byte stream-agnostic" olduğunu doğrular.
"""


def write(path: pathlib.Path, data: bytes, label: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f"  wrote {path} ({len(data):>10,d} bytes)  — {label}")


def make_sample_txt() -> bytes:
    """UTF-8 Türkçe ~2 KB; çoğul karakter setlerini test etmek için."""
    raw = TURKCE_TEXT.encode("utf-8")
    # Padlayıp ~2KB hedefine ulaşalım (içerik anlamlı kalsın diye padding
    # da Türkçe karakterler içerir).
    pad_line = (
        "# Türkçe karakter sürekliliği için: "
        "şçığüöİÇŞĞÜÖ-ABCD-1234\n"
    ).encode("utf-8")
    while len(raw) < 2048:
        raw += pad_line
    return raw[:2048]


def make_sample_bin() -> bytes:
    """Deterministic random binary, 10 KB. Yüksek entropi → c14n yok,
    saf binary CMS attached/detached için."""
    rng = random.Random(RANDOM_SEED)
    return bytes(rng.getrandbits(8) for _ in range(10 * 1024))


def make_empty_bin() -> bytes:
    """0 byte. Signer kontratı: empty input'a anlamlı hata mı atar
    yoksa empty data üzerinden boş CMS mi üretir? Negatif test."""
    return b""


def make_utf16_text() -> bytes:
    """UTF-16 LE BOM + Türkçe text. Signer "byte stream agnostic"
    olmalı — encoding sniff'leyip değiştirmeden imzalamalı."""
    text = (
        "Bu dosya UTF-16 Little-Endian formatındadır.\n"
        "Türkçe karakterler: çşığüöİÇŞĞÜÖ\n"
        "Test payload: Mersel DSS — CAdES UTF-16 binary input.\n"
        "Tekrarlanan satırlar dosya boyutunu artırır:\n"
    )
    # ~2KB hedefi için tekrarla
    repeat = "Padding satırı — Türkçe: dünya merhaba. 1234567890\n"
    body = text + repeat * 30
    bom = b"\xff\xfe"  # UTF-16 LE BOM
    return bom + body.encode("utf-16-le")


def make_zip_archive() -> bytes:
    """Nested binary: zip içine 3 küçük dosya. Signer için tek bir
    .zip blob — CMS bu blob'u imzalar. İçeriği post-sign extract
    edilebilir mi (signature ayrı dosya olarak), bu test scope'unda
    değil; sadece "nested binary input" varyasyonunu temsil eder."""
    buf = io.BytesIO()
    # Sabit timestamp → deterministic zip; date_time=(1980,1,1,0,0,0)
    # ZIP epoch start.
    fixed_dt = (1980, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in [
            ("readme.txt", b"Mersel DSS CAdES zip-archive test fixture.\n"),
            ("payload.json", b'{"order_id":"DEMO-001","amount":"1234.56"}\n'),
            (
                "nested/data.csv",
                b"id,name,amount\n1,demo,100\n2,sample,200\n3,test,300\n",
            ),
        ]:
            zi = zipfile.ZipInfo(filename=name, date_time=fixed_dt)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16  # rw-r--r-- mod
            zf.writestr(zi, content)
    return buf.getvalue()


def make_docx_sample() -> bytes:
    """Minimal valid Office Open XML (Word .docx) belgesi.

    Word/LibreOffice'in 'open' kabul ettiği en küçük yapı:
      - [Content_Types].xml
      - _rels/.rels             — root relationships
      - word/document.xml       — gerçek içerik (1 paragraph)

    Test scope'u: zip-based binary input — CMS bu zip blob'u imzalar.
    Belgenin görsel render'ı önemsiz; ZIP yapısı + valid OOXML kontratı
    yeterli.
    """
    buf = io.BytesIO()
    fixed_dt = (1980, 1, 1, 0, 0, 0)

    content_types = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""

    root_rels = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""

    word_document = ("""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>Mersel DSS CAdES test belgesi (docx).</w:t>
      </w:r>
    </w:p>
    <w:p>
      <w:r>
        <w:t>Bu sentetik bir Word belgesidir; yalnızca CMS imzalama akışı için zip-based binary input olarak kullanılır.</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>
""").encode("utf-8")

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in [
            ("[Content_Types].xml", content_types),
            ("_rels/.rels", root_rels),
            ("word/document.xml", word_document),
        ]:
            zi = zipfile.ZipInfo(filename=name, date_time=fixed_dt)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, content)

    return buf.getvalue()


def make_large_10mb() -> bytes:
    """Deterministic 10 MB binary. Streaming/perf testleri için.

    Pure-random olsaydı disk üzerinde ~10 MB sıkıştırılamaz blob;
    .gitignore zorunlu. Generator script CI workflow'unda Maven
    `process-test-resources` fazından önce çalıştırılır (veya geliştirici
    `python3 scripts/generate-cades-fixtures.py --large` ile manuel).
    """
    rng = random.Random(RANDOM_SEED ^ 0xCAFE_BABE)
    chunk = bytearray(64 * 1024)
    out = bytearray()
    for _ in range(10 * 1024 * 1024 // len(chunk)):
        for i in range(len(chunk)):
            chunk[i] = rng.getrandbits(8)
        out.extend(chunk)
    return bytes(out)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--large",
        action="store_true",
        help="large-10mb.bin (10 MB) dosyasını da üret (default: hayır)",
    )
    args = parser.parse_args(argv)

    DEST.mkdir(parents=True, exist_ok=True)
    print(f"Generating CAdES binary fixtures into {DEST}/ ...")

    write(DEST / "sample.txt", make_sample_txt(),
          "UTF-8 Türkçe ~2KB")
    write(DEST / "sample.bin", make_sample_bin(),
          "deterministic random 10KB")
    write(DEST / "empty.bin", make_empty_bin(),
          "0 byte (negatif kontrat)")
    write(DEST / "utf16-text.txt", make_utf16_text(),
          "UTF-16 LE BOM + Türkçe")
    write(DEST / "zip-archive.zip", make_zip_archive(),
          "nested binary (3-file deflate zip)")
    write(DEST / "docx-sample.docx", make_docx_sample(),
          "minimal valid Office Open XML")

    if args.large:
        write(DEST / "large-10mb.bin", make_large_10mb(),
              "deterministic 10MB (generator-only, .gitignore)")
    else:
        print("  skipped large-10mb.bin (use --large to generate)")

    print(f"Done at {datetime.datetime.now().isoformat(timespec='seconds')}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
