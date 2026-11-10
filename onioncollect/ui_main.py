"""The search UI's own entry point: python -m onioncollect.ui_main --data-dir DIR --configs-dir DIR [--port N].

It never goes through cli.py, which imports every command and with them the network libraries. The process loads
the UI, its views and search, lifecycle's names, and the standard library, and nothing else."""
import argparse
import os
import pwd
import sqlite3
from pathlib import Path

from onioncollect import ui


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="onioncollect.ui_main")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--configs-dir", type=Path, required=True, help="shown on a source's page, never read")
    parser.add_argument("--port", type=int, default=ui.PORT)
    args = parser.parse_args(argv)
    uid = os.geteuid()
    if why := ui.refusal(args.data_dir, uid, pwd.getpwuid(uid).pw_name):
        raise SystemExit(f"onioncollect: {why}")
    if not args.data_dir.is_dir():
        raise SystemExit(f"onioncollect: no data directory at {args.data_dir}")
    stores = ui.Stores(args.data_dir)
    for name in ui.STORES:
        try:
            stores.rows(name, "SELECT count(*) FROM sqlite_master")
        except sqlite3.Error as exc:
            raise SystemExit(f"onioncollect: {name} unreadable ({type(exc).__name__}); the writer creates it when"
                             " it starts (onioncollect-writer.service)") from None
    ui.configure_logging(Path.home() / "ui.log")
    server = ui.UIServer(args.data_dir, args.configs_dir, args.port)
    ui.log.info("ui listening on port %d", server.server_address[1])
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
