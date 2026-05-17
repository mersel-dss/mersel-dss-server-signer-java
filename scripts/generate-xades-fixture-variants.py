#!/usr/bin/env python3
"""
Generate XAdES fixture variants from resources/test-fixtures/xades/efatura.xml.

Tekrarlanabilir üretici. Sonuç olarak şu dosyaları üretir/günceller:

  - efatura-mixed-newlines.xml     CRLF + LF karışık satır sonları
  - xml-with-cdata.xml             <cbc:Note> içine CDATA + ampersand
  - xml-with-comments.xml          birkaç noktada XML yorumu (<!-- -->)
  - xml-foreign-namespace-prefix.xml  cbc → tcbc, cac → tcac (NS URI aynı)
  - efatura-unicode-emoji.xml      UTF-8 4-byte (emoji + CJK + diakritik)

Niye script ile?
  Mevcut `efatura.xml`'i bayt-bayt değiştirerek üretiyoruz, "magic"
  fixture dosyaları değil. Üretim mantığı ve gerekçesi git history'de
  şeffaf kalır; yarın yeni bir varyant gerekirse template hazır.

Çalıştırma:
  python3 scripts/generate-xades-fixture-variants.py
"""

import pathlib
import sys


SRC = pathlib.Path("resources/test-fixtures/xades/efatura.xml")
DEST_DIR = pathlib.Path("resources/test-fixtures/xades")

# Hangi etiket içine emoji/CDATA enjekte ediliyor.
# Mevcut efatura.xml'deki Note satırı:
ORIGINAL_NOTE = "<cbc:Note>YALNIZ : ALTIYÜZ TL SIFIR Kr.</cbc:Note>"


def main() -> int:
    if not SRC.is_file():
        print(f"ERROR: source not found: {SRC}", file=sys.stderr)
        return 1

    raw = SRC.read_bytes()
    # Source dosyayı normalize edip LF üzerinden çalış: CRLF varsa LF'e indir,
    # böylece dönüşümler deterministic. Source halen LF olmalı zaten.
    text = raw.decode("utf-8").replace("\r\n", "\n")

    if ORIGINAL_NOTE not in text:
        print(f"ERROR: beklenen note satırı bulunamadı: {ORIGINAL_NOTE!r}", file=sys.stderr)
        print("       efatura.xml değişmiş olabilir; script'i güncelleyin.", file=sys.stderr)
        return 1

    DEST_DIR.mkdir(parents=True, exist_ok=True)

    _write_mixed_newlines(text)
    _write_cdata(text)
    _write_comments(text)
    _write_foreign_namespace_prefix(text)
    _write_unicode_emoji(text)

    print("Üretilen fixture'lar:")
    for name in [
        "efatura-mixed-newlines.xml",
        "xml-with-cdata.xml",
        "xml-with-comments.xml",
        "xml-foreign-namespace-prefix.xml",
        "efatura-unicode-emoji.xml",
    ]:
        p = DEST_DIR / name
        print(f"  - {p}: {p.stat().st_size} bytes")
    return 0


def _write_mixed_newlines(text: str) -> None:
    """İlk yarı CRLF, ikinci yarı LF.

    Niye: bazı XML serializer'lar/canonicalizer'lar satır sonu normalizasyonunu
    farklı yapar. XML 1.0 §2.11 LF zorunlu kılar (parser CRLF→LF normalize
    eder); imza akışı buna güvenmeli. Mixed input bir kaç katmanda regresyon
    yakalama vektörüdür.
    """
    lines = text.splitlines(keepends=False)
    mid = len(lines) // 2
    crlf_part = "\r\n".join(lines[:mid]) + "\r\n"
    lf_part = "\n".join(lines[mid:])
    # Son newline'ı koru
    if not lf_part.endswith("\n"):
        lf_part += "\n"
    (DEST_DIR / "efatura-mixed-newlines.xml").write_bytes(
        (crlf_part + lf_part).encode("utf-8")
    )


def _write_cdata(text: str) -> None:
    """Note alanını CDATA'ya çevir ve ampersand ekle.

    Niye: CDATA content c14n sonrası text content olarak normalize edilir
    (RFC 3076/XML c14n §1.1). Signer'ın CDATA'lı girdiyi tolere ettiğini,
    ampersand'in escape edildiğini ve verifier'ın matematiksel olarak
    aynı digest'i hesapladığını doğrular.
    """
    replaced = text.replace(
        ORIGINAL_NOTE,
        "<cbc:Note><![CDATA[YALNIZ : ALTIYÜZ TL & SIFIR Kr.]]></cbc:Note>",
    )
    (DEST_DIR / "xml-with-cdata.xml").write_bytes(replaced.encode("utf-8"))


def _write_comments(text: str) -> None:
    """Üç farklı noktaya XML yorumu ekle.

    Niye: Exclusive C14N (XAdES default) yorumları çıkarır;
    ``ExclusiveCanonicalizationMethod`` Algorithm URI tipik olarak
    ``…xml-exc-c14n#`` (with-comments DEĞİL). Yani yorumlar imza
    kapsamı dışındadır ve doğrulama bozulmamalı. Signer'ın XML
    parsing/serialize pipeline'ında yorumların hatalı yere taşınması /
    ID attribute resolution'ı bozması durumu burada yakalanır.
    """
    out = text.replace(
        '<?xml version="1.0" encoding="utf-8" standalone="no"?>\n',
        '<?xml version="1.0" encoding="utf-8" standalone="no"?>\n'
        "<!-- Test fixture: comments inside UBL Invoice (c14n exclusive should strip) -->\n",
    )
    out = out.replace(
        "<cac:InvoiceLine>",
        "<!-- comment: invoice line begin --><cac:InvoiceLine>",
    )
    out = out.replace(
        "</cac:InvoiceLine>",
        "</cac:InvoiceLine><!-- comment: invoice line end -->",
    )
    (DEST_DIR / "xml-with-comments.xml").write_bytes(out.encode("utf-8"))


def _write_foreign_namespace_prefix(text: str) -> None:
    """``cbc`` → ``tcbc``, ``cac`` → ``tcac`` (NS URI'leri aynı kalır).

    Niye: signer'ın UBL element'lerini namespace **URI** üzerinden
    çözmesi gerekir (prefix'ten bağımsız). Prefix sabit varsayan
    bir regression olursa (örn. ``DOMImplementation.lookupElement("cbc:Name")``
    gibi) bu fixture'da imza üretimi başarısız olur.

    ``ext``, ``ds``, ``xades`` prefix'lerine dokunulmaz çünkü:
      * ``ext:UBLExtensions`` UBL spec'inde sabit (signer placement
        servisi NS URI ile arıyor ama bu fixture'ı minimal değişikliklerle
        tutmak için ext'i değiştirmiyoruz);
      * ``ds`` ve ``xades`` zaten imza üretiminde DSS tarafından eklenir.
    """
    out = text
    out = out.replace("xmlns:cbc=", "xmlns:tcbc=")
    out = out.replace("<cbc:", "<tcbc:")
    out = out.replace("</cbc:", "</tcbc:")
    out = out.replace("xmlns:cac=", "xmlns:tcac=")
    out = out.replace("<cac:", "<tcac:")
    out = out.replace("</cac:", "</tcac:")
    (DEST_DIR / "xml-foreign-namespace-prefix.xml").write_bytes(out.encode("utf-8"))


def _write_unicode_emoji(text: str) -> None:
    """Note alanına emoji + CJK + diakritik karakterler ekle.

    Niye: UTF-8 multibyte (CJK 3-byte, emoji 4-byte / surrogate pair)
    handling. XML parser'lar bunları element text olarak korumalı;
    c14n sonrası bayt akışında doğru karakterler kalmalı; SignatureValue
    digest'i tüketicide aynı çıkmalı. Surrogate pair'leri yarım yutan
    bir serializer regresyonu burada yakalanır.

    Kullanılan karakterler:
      🚀 (U+1F680, 4-byte UTF-8)
      中文 (U+4E2D U+6587, 3-byte UTF-8 each)
      ñoño (U+00F1, 2-byte UTF-8 — Latin Extended)
    """
    replaced = text.replace(
        ORIGINAL_NOTE,
        "<cbc:Note>YALNIZ : ALTIYÜZ TL SIFIR Kr. 🚀 中文 ñoño</cbc:Note>",
    )
    (DEST_DIR / "efatura-unicode-emoji.xml").write_bytes(replaced.encode("utf-8"))


if __name__ == "__main__":
    sys.exit(main())
