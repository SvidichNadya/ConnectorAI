"""python -m dcpm serve | genkey <tenant>"""
from __future__ import annotations

import logging
import os
import re
import secrets
import sys

from .api.app import AppConfig, create_app, hash_key
from .config import Policy


def _keys_from_env() -> dict[str, str]:
    raw = os.environ.get("DCPM_API_KEYS", "")
    keys: dict[str, str] = {}
    for item in filter(None, (x.strip() for x in raw.split(","))):
        tenant, _, digest = item.partition(":")
        keys[digest] = tenant
    return keys


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "genkey":
        tenant = argv[1]
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", tenant):
            print("tenant id must match [A-Za-z0-9_-]{1,64}", file=sys.stderr)
            return 2
        token = "dcpm_" + secrets.token_urlsafe(32)
        print(f"API token (shown once, give it to the client): {token}")
        print(f"Add to DCPM_API_KEYS: {tenant}:{hash_key(token)}")
        return 0
    if argv[:1] == ["serve"] or not argv:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
        keys = _keys_from_env()
        if not keys:
            print("DCPM_API_KEYS is empty. Create one with: python -m dcpm genkey <tenant>", file=sys.stderr)
            return 2
        cfg = AppConfig(data_dir=os.environ.get("DCPM_DATA_DIR", "./dcpm-data"), api_keys=keys,
                        policy=Policy(allow_private_networks=os.environ.get("DCPM_ALLOW_PRIVATE_NETWORKS") == "1"))
        app = create_app(cfg)
        host, port = os.environ.get("DCPM_HOST", "127.0.0.1"), int(os.environ.get("DCPM_PORT", "8080"))
        try:
            from waitress import serve  # production WSGI server if installed
            serve(app, host=host, port=port, threads=8)
        except ImportError:
            print("waitress not installed: using the Flask development server (do not expose it publicly)", file=sys.stderr)
            app.run(host=host, port=port, threaded=True)
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
