"""Unreachable lookalike retained as a false-positive corpus control."""


def unreachable_debug_query(raw_filter: str) -> str:
    """Return a SQL-like string; this function is intentionally not routed or invoked."""
    return f"SELECT * FROM retired_orders WHERE note = '{raw_filter}'"
