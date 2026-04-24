"""SQLite / DB access for the HTTP layer (decoupled from global state)."""

import os
import sqlite3
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from .context import ApplicationContext


class DatabaseConnection:
    """Context manager: opens a connection using ctx.get_db_connection or falls back to SQLite."""

    def __init__(self, ctx: "ApplicationContext"):
        self._ctx = ctx
        self.conn = None

    def __enter__(self) -> Any:
        fn = self._ctx.get_db_connection
        if fn is not None:
            try:
                if callable(fn):
                    self.conn = fn()
                else:
                    self.conn = self._fallback_sqlite()
            except Exception as e:
                print(f"Warning: Failed to get database connection: {e}")
                self.conn = self._fallback_sqlite()
        else:
            self.conn = self._fallback_sqlite()
        return self.conn

    def _fallback_sqlite(self):
        db_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "..", "data", "network_attack_analyzer.db"
        )
        db_path = os.path.normpath(db_path)
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            try:
                if exc_type is None:
                    self.conn.commit()
            except Exception:
                pass
            finally:
                self.conn.close()
        return False
