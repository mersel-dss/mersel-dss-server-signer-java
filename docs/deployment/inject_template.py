#!/usr/bin/env python3
"""inject_template.py — pandoc HTML fragment'larını template.html'e inject eder.

Sentinel'ler (template.html içinde):
    <!-- BEGIN_LINUX_CONTENT -->          ... <!-- END_LINUX_CONTENT -->
    <!-- BEGIN_WINDOWS_CONTENT -->        ... <!-- END_WINDOWS_CONTENT -->
    <!-- BEGIN_DOCKER_CONTENT -->         ... <!-- END_DOCKER_CONTENT -->
    <!-- BEGIN_RUN_PROFILES_CONTENT -->   ... <!-- END_RUN_PROFILES_CONTENT -->

Footer placeholder'ları:
    <!--BUILD_NUMBER-->...<!--/BUILD_NUMBER-->
    <!--GENERATED_AT-->...<!--/GENERATED_AT-->

Bu placeholder'lar HTML yorumu olarak yazıldığı için tarayıcıda template'i
direct açtığında bile (build edilmeden) syntactically valid kalır;
çıktıdaki render bozulmaz, sadece "dev" değerleri gözükür.

Kullanım:
  python3 inject_template.py <template.html> \
      <linux.html> <windows.html> <docker.html> <run-profiles.html>

ENV:
  BUILD_NUMBER  : footer'a yazılacak build numarası (default: dev)
  GENERATED_AT  : footer'a yazılacak ISO timestamp (default: local)
"""

import os
import re
import sys


def slurp(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def replace_block(html: str, marker: str, payload: str) -> str:
    """`<!-- BEGIN_{marker} -->...<!-- END_{marker} -->` arasını payload ile değiştir.

    re.sub'ın `\\1` / `\\g<name>` backreference syntax'ını trigger etmemesi için
    callable replacement kullanıyoruz — pandoc HTML'inde kod bloklarında
    `\\w` gibi ham backslash'lere rastlanabilir.
    """
    pattern = re.compile(
        r"<!--\s*BEGIN_" + re.escape(marker) + r"\s*-->"
        r".*?"
        r"<!--\s*END_" + re.escape(marker) + r"\s*-->",
        re.DOTALL,
    )
    full_replacement = (
        f"<!-- BEGIN_{marker} (otomatik üretildi, build.sh) -->\n"
        f"{payload}\n"
        f"<!-- END_{marker} -->"
    )
    new_html, count = pattern.subn(lambda _m: full_replacement, html, count=1)
    if count != 1:
        raise SystemExit(
            f"Sentinel bulunamadı veya birden fazla bulundu: BEGIN_{marker}/END_{marker} "
            f"(replace count = {count})"
        )
    return new_html


def replace_footer_placeholder(html: str, marker: str, value: str) -> str:
    """`<!--MARKER-->...<!--/MARKER-->` arasını value ile değiştir."""
    pattern = re.compile(
        r"<!--" + re.escape(marker) + r"-->"
        r".*?"
        r"<!--/" + re.escape(marker) + r"-->",
        re.DOTALL,
    )
    replacement = f"<!--{marker}-->{value}<!--/{marker}-->"
    return pattern.sub(lambda _m: replacement, html, count=1)


def main():
    if len(sys.argv) != 6:
        sys.stderr.write(
            "Usage: inject_template.py <template> <linux> <windows> <docker> <run-profiles>\n"
        )
        sys.exit(2)

    template_path, linux_path, windows_path, docker_path, run_profiles_path = sys.argv[1:6]

    html = slurp(template_path)
    html = replace_block(html, "LINUX_CONTENT",        slurp(linux_path))
    html = replace_block(html, "WINDOWS_CONTENT",      slurp(windows_path))
    html = replace_block(html, "DOCKER_CONTENT",       slurp(docker_path))
    html = replace_block(html, "RUN_PROFILES_CONTENT", slurp(run_profiles_path))

    html = replace_footer_placeholder(
        html, "BUILD_NUMBER", os.environ.get("BUILD_NUMBER", "dev")
    )
    html = replace_footer_placeholder(
        html, "GENERATED_AT", os.environ.get("GENERATED_AT", "local")
    )

    sys.stdout.write(html)


if __name__ == "__main__":
    main()
