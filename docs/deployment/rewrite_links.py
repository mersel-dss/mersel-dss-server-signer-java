#!/usr/bin/env python3
"""rewrite_links.py — pandoc HTML fragment'ında repo-içi .md linklerini rewrite eder.

Kurallar:
  1. `#fragment` (saf anchor) → aynen bırak (pandoc'un kendi anchor'ları).
  2. Aynı tab'a referans veren README anchor'ları:
        devops/systemd/README.md#foo          → #foo  (linux tab içindeysek)
        devops/windows-service/README.md#bar  → #bar  (windows tab içindeysek)
        ...
     Çünkü o anchor pandoc tarafından zaten aynı sayfaya inject edilmiş.
  3. Farklı tab'a referans (cross-tab):
        devops/systemd/README.md         → #linux
        devops/systemd/README.md#hard    → #linux  (anchor düşer — basit dav.)
        devops/windows-service/README.md → #windows
        devops/docker/README.md          → #docker
        docs/RUN_PROFILES.md             → #run-profiles
  4. Repo-içi diğer .md dosyaları (CHANGELOG.md, README.md vs.) →
        https://github.com/{REPO_SLUG}/blob/{GIT_REF}/path/to/file.md
  5. Repo-içi non-.md path'ler (src/, scripts/, devops/.../install.sh vs.) →
        https://github.com/{REPO_SLUG}/blob/{GIT_REF}/path
  6. http(s):// veya mailto: → aynen bırak.

ENV:
  REPO_SLUG  : github org/repo  (default: mersel-dss/mersel-dss-server-signer-java)
  GIT_REF    : branch / tag / sha (default: main)

Kullanım:
  python3 rewrite_links.py <input.html> <panel_id>
  panel_id: linux | windows | docker | run-profiles
"""

import os
import re
import sys
from html.parser import HTMLParser

REPO_SLUG = os.environ.get("REPO_SLUG", "mersel-dss/mersel-dss-server-signer-java")
GIT_REF = os.environ.get("GIT_REF", "main")
GITHUB_BLOB_BASE = f"https://github.com/{REPO_SLUG}/blob/{GIT_REF}"

# Tab id ↔ kaynak README mapping
TAB_TO_SOURCE = {
    "linux":         "devops/systemd/README.md",
    "windows":       "devops/windows-service/README.md",
    "docker":        "devops/docker/README.md",
    "run-profiles":  "docs/RUN_PROFILES.md",
}
SOURCE_TO_TAB = {v: k for k, v in TAB_TO_SOURCE.items()}


def rewrite_href(href: str, current_tab: str) -> str:
    """Bir href değerini panel_id bağlamında yeniden yazar."""
    # 1. Saf anchor — dokunma
    if href.startswith("#"):
        return href

    # 2. External — dokunma
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", href):
        # http://, https://, mailto:, data:, vs.
        return href

    # Markdown linklerinde göreceli yollar repo-relative olmayabilir
    # (örn. README'ler kendi içinde `../docker/README.md` yazıyor olabilir).
    # Önce normalize edelim.
    current_source = TAB_TO_SOURCE.get(current_tab, "")
    current_dir = os.path.dirname(current_source)

    # Anchor'ı ayır
    if "#" in href:
        path_part, _, anchor = href.partition("#")
        anchor = "#" + anchor
    else:
        path_part = href
        anchor = ""

    # Boş path → sadece anchor referansı
    if not path_part:
        return anchor

    # Relative path'i repo root'a göre normalize et
    if current_dir:
        normalized = os.path.normpath(os.path.join(current_dir, path_part))
    else:
        normalized = os.path.normpath(path_part)

    # POSIX separator (Windows'da bile)
    normalized = normalized.replace(os.sep, "/")

    # 3. Tab kaynaklarından birine referans
    if normalized in SOURCE_TO_TAB:
        target_tab = SOURCE_TO_TAB[normalized]
        if target_tab == current_tab:
            # Aynı sayfa — anchor varsa onu kullan, yoksa sayfa başına
            return anchor if anchor else f"#{target_tab}"
        # Cross-tab — anchor düşer (basitlik için; pandoc anchor'ları
        # tab-bağımsız değil çünkü ID'ler farklı section'larda overlap edebilir)
        return f"#{target_tab}"

    # 4 & 5. Repo-içi diğer dosya → GitHub blob URL
    # NOT: Eğer path normalize sonrası `..` ile başlıyorsa (repo dışına çıkış),
    # rewrite etmek hatalı; aynen bırak (pandoc warning verir, OK).
    if normalized.startswith(".."):
        return href

    return f"{GITHUB_BLOB_BASE}/{normalized}{anchor}"


class HrefRewriter(HTMLParser):
    """HTML fragment'ından geçer, <a href> attribute'larını rewrite eder.
    Diğer her şeyi aynen yeniden serialize eder.

    HTMLParser raw HTML üretmiyor; kendimiz reconstruct ediyoruz çünkü
    pandoc'un escape stratejisini bozmak istemiyoruz (örn. & → &amp;
    dönüşümünü tekrar yapmak duplicate escape üretir).
    """

    # HTML5 void elementleri — kapanış tag'i ALMAZ. Pandoc bunları bazen
    # `<br />` (XHTML stili) bazen de `<br>` (HTML5 stili) olarak üretir.
    # Eğer `<br>` formunda gelirse Python's HTMLParser bunu handle_starttag
    # ile bildirir; biz default olarak </br> kapatma eklersek tarayıcı
    # render eder ama HTML5 validity bozulur. Bu set'i kontrol ederek
    # void element'lerde end tag yazmayı bloke ediyoruz.
    VOID_ELEMENTS = {
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr"
    }

    def __init__(self, current_tab: str):
        super().__init__(convert_charrefs=False)
        self.current_tab = current_tab
        self.out = []
        # Hangi etiketlerin handle_starttag ile açıldığını takip et — void
        # element'in yanlışlıkla aynı tag adıyla "endtag" sinyali gelirse
        # (pandoc bazen üretebilir) onu da skip edebilelim.

    def _format_attrs(self, attrs, rewrite_href_attr=False):
        parts = []
        for name, value in attrs:
            if value is None:
                parts.append(name)
                continue
            if rewrite_href_attr and name.lower() == "href":
                value = rewrite_href(value, self.current_tab)
            # HTMLParser quote'ları soyar; biz çift tırnakla geri sar.
            # value içindeki " karakterini escape et.
            value_escaped = value.replace('"', "&quot;")
            parts.append(f'{name}="{value_escaped}"')
        return (" " + " ".join(parts)) if parts else ""

    def handle_starttag(self, tag, attrs):
        rewrite = (tag.lower() == "a")
        if tag.lower() in self.VOID_ELEMENTS:
            # `<br>` formunda gelirse → `<br />` (XHTML uyumlu, HTML5 valid)
            self.out.append(f"<{tag}{self._format_attrs(attrs, rewrite)} />")
        else:
            self.out.append(f"<{tag}{self._format_attrs(attrs, rewrite)}>")

    def handle_startendtag(self, tag, attrs):
        # <img />, <br />, vs. — self-closing (XHTML stili)
        rewrite = (tag.lower() == "a")
        self.out.append(f"<{tag}{self._format_attrs(attrs, rewrite)} />")

    def handle_endtag(self, tag):
        # Void element'lerin kapanış tag'i geçersizdir — atla.
        # Pandoc default'ta üretmiyor ama defansif.
        if tag.lower() in self.VOID_ELEMENTS:
            return
        self.out.append(f"</{tag}>")

    def handle_data(self, data):
        self.out.append(data)

    def handle_entityref(self, name):
        self.out.append(f"&{name};")

    def handle_charref(self, name):
        self.out.append(f"&#{name};")

    def handle_comment(self, data):
        self.out.append(f"<!--{data}-->")

    def handle_decl(self, decl):
        self.out.append(f"<!{decl}>")

    def result(self) -> str:
        return "".join(self.out)


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("Usage: rewrite_links.py <input.html> <panel_id>\n")
        sys.exit(2)

    input_path = sys.argv[1]
    panel_id = sys.argv[2]
    if panel_id not in TAB_TO_SOURCE:
        sys.stderr.write(f"Unknown panel_id: {panel_id}\n")
        sys.exit(2)

    with open(input_path, "r", encoding="utf-8") as f:
        html = f.read()

    parser = HrefRewriter(panel_id)
    parser.feed(html)
    parser.close()
    sys.stdout.write(parser.result())


if __name__ == "__main__":
    main()
