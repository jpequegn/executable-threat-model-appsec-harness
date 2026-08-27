"""Disposable SQLite state for the synthetic order service."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Order:
    id: int
    owner: str
    description: str
    status: str


class OrderStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def reset(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                DROP TABLE IF EXISTS orders;
                CREATE TABLE orders (
                    id INTEGER PRIMARY KEY,
                    owner TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT NOT NULL
                );
                INSERT INTO orders VALUES
                    (1, 'buyer-a', 'Synthetic laptop', 'pending'),
                    (2, 'buyer-b', 'Synthetic monitor', 'pending'),
                    (3, 'buyer-c', 'Synthetic keyboard', 'approved');
                """
            )

    def search_vulnerable(self, query: str) -> list[Order]:
        # Deliberately unsafe inside this owned synthetic target. The protected variant is below.
        sql = (
            f"SELECT id, owner, description, status FROM orders WHERE description LIKE '%{query}%'"
        )
        with self._connect() as connection:
            rows = connection.execute(sql).fetchall()
        return [Order(*row) for row in rows]

    def search_protected(self, query: str) -> list[Order]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, owner, description, status FROM orders WHERE description LIKE ?",
                (f"%{query}%",),
            ).fetchall()
        return [Order(*row) for row in rows]

    def get(self, order_id: int) -> Order | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT id, owner, description, status FROM orders WHERE id = ?", (order_id,)
            ).fetchone()
        return Order(*row) if row else None

    def approve_vulnerable(self, order_id: int, actor: str) -> bool:
        # Deliberately misses the role and ownership policy for the authorization eval fixture.
        with self._connect() as connection:
            changed = connection.execute(
                "UPDATE orders SET status = 'approved' WHERE id = ? AND ? != ''",
                (order_id, actor),
            ).rowcount
        return changed == 1

    def approve_protected(self, order_id: int, actor: str, role: str) -> bool:
        order = self.get(order_id)
        if order is None or role != "approver" or actor == order.owner:
            return False
        with self._connect() as connection:
            changed = connection.execute(
                "UPDATE orders SET status = 'approved' WHERE id = ?", (order_id,)
            ).rowcount
        return changed == 1

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)
