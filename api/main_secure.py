"""
Analytics API - v2.2 SECURE
Patched version demonstrating correct mitigations for ORDER BY injection.
"""

import os
from typing import Literal, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import re

DATABASE_URL = os.environ["DATABASE_URL"].replace(
    "postgresql://", "postgresql+asyncpg://"
)
engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

@asynccontextmanager
async def lifespan(app):
    yield
    await engine.dispose()

app = FastAPI(title="Analytics API — Secure", version="2.2.0", lifespan=lifespan)

# ── MITIGATION 1: Explicit allowlist for sortable columns ────────────────────
# Never trust user input for structural SQL elements.
# A WAF/regex is NOT a substitute for whitelisting.

ALLOWED_SORT_COLUMNS = {
    "occurred_at", "event_type", "country",
    "product_name", "category", "sku"
}
ALLOWED_ORDER_DIRS = {"asc", "desc"}


class AnalyticsQuery(BaseModel):
    event_type: Optional[Literal["view", "add_to_cart", "purchase"]] = None
    country: Optional[str] = None
    sort_by: Optional[str] = "occurred_at"
    order: Optional[Literal["asc", "desc"]] = "desc"
    limit: Optional[int] = 50

    # ── MITIGATION 2: Pydantic strict validators ─────────────────────────────

    @field_validator("country")
    @classmethod
    def validate_country(cls, v):
        if v and not re.match(r"^[A-Z]{2,3}$", v):
            raise ValueError("Invalid country code")
        return v

    @field_validator("sort_by")
    @classmethod
    def validate_sort_by(cls, v):
        """
        CRITICAL FIX: validate against an explicit set of known-safe
        column names. Anything not in the set is rejected — not sanitised.
        """
        if v and v not in ALLOWED_SORT_COLUMNS:
            raise ValueError(
                f"Invalid sort column '{v}'. "
                f"Allowed: {sorted(ALLOWED_SORT_COLUMNS)}"
            )
        return v

    @field_validator("limit")
    @classmethod
    def validate_limit(cls, v):
        if v and (v < 1 or v > 200):
            raise ValueError("Limit must be between 1 and 200")
        return v


@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.2.0-secure"}


@app.post("/api/v1/analytics/events")
async def get_analytics_events(query: AnalyticsQuery):
    """
    SECURE version:
    - sort_by validated against an explicit allowlist by Pydantic
    - All filter values use bound parameters (:param) — never f-string interpolation
    - No WAF dependency: defense is structural, not pattern-based
    """

    # Both values already validated by Pydantic — safe to interpolate
    # because they can only be values from ALLOWED_SORT_COLUMNS /
    # ALLOWED_ORDER_DIRS (no user-controlled free text reaches the query).
    sort_column = query.sort_by or "occurred_at"
    order_dir   = query.order  or "desc"

    if sort_column not in ALLOWED_SORT_COLUMNS:
        raise HTTPException(status_code=422, detail="Invalid sort column")
    if order_dir not in ALLOWED_ORDER_DIRS:
        raise HTTPException(status_code=422, detail="Invalid order direction")

    # ── MITIGATION 3: Parameterised filters (bind variables) ─────────────────
    filters, params = [], {"limit_val": query.limit}

    if query.event_type:
        filters.append("ae.event_type = :event_type")
        params["event_type"] = query.event_type

    if query.country:
        filters.append("ae.country = :country")
        params["country"] = query.country

    where_clause = ("WHERE " + " AND ".join(filters)) if filters else ""

    # Only structural tokens (column name + direction) are interpolated,
    # and both have been validated against closed allowlists above.
    raw_sql = f"""
        SELECT
            ae.id,
            p.sku,
            p.name        AS product_name,
            p.category,
            ae.event_type,
            ae.country,
            ae.occurred_at
        FROM analytics_events ae
        JOIN products p ON p.id = ae.product_id
        {where_clause}
        ORDER BY {sort_column} {order_dir}
        LIMIT :limit_val
    """

    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(text(raw_sql), params)
            rows = result.mappings().all()
            return {"count": len(rows), "data": [dict(r) for r in rows]}
        except Exception:
            raise HTTPException(status_code=500, detail="Query execution error")
