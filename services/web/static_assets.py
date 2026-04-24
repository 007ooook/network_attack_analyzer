"""Serve built SPA assets from frontend/dist."""

import os
from http.server import SimpleHTTPRequestHandler

from .http_utils import content_type_for_path


def _frontend_dist(project_root: str) -> str:
    return os.path.join(project_root, "frontend", "dist")


_STATIC_DIR_PREFIXES = {
    "/assets/": "application/javascript",
    "/locales/": "application/json",
}


def _serve_static_file(handler: SimpleHTTPRequestHandler, frontend_dir: str, path: str, content_type: str) -> bool:
    full_path = os.path.join(frontend_dir, path.lstrip("/"))
    handler.send_response(200)
    handler.send_header("Content-type", content_type)
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    if os.path.exists(full_path):
        with open(full_path, "rb") as f:
            handler.wfile.write(f.read())
    else:
        handler.send_error(404, "Not Found")
    return True


def serve_spa_or_static(handler: SimpleHTTPRequestHandler, path: str, project_root: str) -> bool:
    """
    Handle GET for SPA shell, /assets/, /locales/, and other dist files.
    Returns True if a response was sent (including 404 for missing asset).
    """
    frontend_dir = _frontend_dist(project_root)

    if (
        path == "/"
        or path.startswith("/index.html")
        or (
            not path.startswith("/api/")
            and not path.startswith("/assets/")
            and not path.startswith("/locales/")
        )
    ):
        handler.send_response(200)
        handler.send_header("Content-type", "text/html")
        handler.send_header("Access-Control-Allow-Origin", "*")
        handler.end_headers()
        index_path = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_path):
            with open(index_path, "rb") as f:
                handler.wfile.write(f.read())
        else:
            handler.wfile.write(
                b"<html><head><title>Network Attack Analyzer</title></head><body>"
                b"<h1>Network Attack Analyzer</h1>"
                b"<p>Frontend files not found. Please run `npm run build` in the frontend directory.</p>"
                b"</body></html>"
            )
        return True

    for prefix, content_type in _STATIC_DIR_PREFIXES.items():
        if path.startswith(prefix):
            return _serve_static_file(handler, frontend_dir, path, content_type)

    return False


def serve_dist_fallback_file(handler: SimpleHTTPRequestHandler, path: str, project_root: str) -> None:
    """Try to serve a file from dist; otherwise 404."""
    frontend_dir = _frontend_dist(project_root)
    file_path = os.path.join(frontend_dir, path.lstrip("/"))
    if os.path.exists(file_path) and os.path.isfile(file_path):
        handler.send_response(200)
        handler.send_header("Content-type", content_type_for_path(file_path))
        handler.send_header("Access-Control-Allow-Origin", "*")
        handler.end_headers()
        with open(file_path, "rb") as f:
            handler.wfile.write(f.read())
    else:
        handler.send_error(404, "Not Found")
