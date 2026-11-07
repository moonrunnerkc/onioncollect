import gzip
import os
from pathlib import Path


class PageStore:
    def __init__(self, root: Path):
        self.root = root
        self.pages = root / "pages"
        self.pages.mkdir(parents=True, exist_ok=True)
        self.pages.chmod(0o700)

    def path_for(self, sha256: str) -> Path:
        return self.pages / sha256[:2] / sha256[2:4] / f"{sha256}.gz"

    def save(self, sha256: str, body: bytes) -> bool:
        path = self.path_for(sha256)
        if path.exists():
            return False
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temp = path.with_suffix(".tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(gzip.compress(body, compresslevel=6, mtime=0))
        os.replace(temp, path)
        return True

    def load(self, sha256: str) -> bytes:
        return gzip.decompress(self.path_for(sha256).read_bytes())

    def size_on_disk(self) -> int:
        return sum(path.stat().st_size for path in self.pages.rglob("*.gz"))
