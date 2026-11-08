"""make writeup-check: every [PASTE: ...] marker still in the write-up, by file and line. Exits 1 while any is
left, so the write-up cannot be called finished with a number, an excerpt or a table still missing."""
import re
import sys
from pathlib import Path

MARKER = re.compile(r"\[PASTE: [^\]]+\]")


def markers(paths: list[Path]) -> list[tuple[Path, int, str]]:
    """Each marker with the line it starts on. A marker may wrap across lines."""
    found = []
    for path in paths:
        text = path.read_text()
        for match in MARKER.finditer(text):
            found.append((path, text.count("\n", 0, match.start()) + 1, " ".join(match.group(0).split())))
    return found


def main(paths: list[Path]) -> int:
    left = markers(paths)
    for path, number, found in left:
        print(f"{path}:{number}: {found}")
    print(f"{len(left)} markers left in {len(paths)} files")
    return 1 if left else 0


if __name__ == "__main__":
    sys.exit(main([Path(arg) for arg in sys.argv[1:]]))
