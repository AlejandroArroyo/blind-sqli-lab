"""
Analytics API - v2.1
Provides aggregated product analytics with flexible sorting and filtering.
"""

import re
import os
from typing import Literal, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# ── DB setup ────────────────────────────────────────────────────────────────

DATABASE_URL = os.environ["DATABASE_URL"].replace(
    "postgresql://", "postgresql+asyncpg://"
)
engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await engine.dispose()

app = FastAPI(title="Analytics API", version="2.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ── Simple WAF middleware ────────────────────────────────────────────────────
# Developer note: "Basic protection against obvious SQL injection attempts"

BLOCKED_KEYWORDS = re.compile(
    r"\b(union|select|insert|delete|drop|exec|xp_|information_schema)\b",
    re.IGNORECASE,
)

def waf_check(value: str) -> bool:
    """Returns True if the value is suspicious."""
    return bool(BLOCKED_KEYWORDS.search(value))


# ── Request / Response models ─────────────────────────────────────────────

class AnalyticsQuery(BaseModel):
    """
    Query parameters for the analytics aggregation endpoint.
    Supports filtering by event type, country, and custom sort column.
    """
    event_type: Optional[Literal["view", "add_to_cart", "purchase"]] = None
    country: Optional[str] = None
    # sort_by accepts a column name from the result set
    sort_by: Optional[str] = "occurred_at"
    order: Optional[Literal["asc", "desc"]] = "desc"
    limit: Optional[int] = 50

    @field_validator("country")
    @classmethod
    def validate_country(cls, v):
        if v and not re.match(r"^[A-Z]{2,3}$", v):
            raise ValueError("Invalid country code")
        return v

    @field_validator("limit")
    @classmethod
    def validate_limit(cls, v):
        if v and (v < 1 or v > 200):
            raise ValueError("Limit must be between 1 and 200")
        return v


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.1.0"}


@app.post("/api/v1/analytics/events")
async def get_analytics_events(query: AnalyticsQuery):
    """
    Returns aggregated analytics events with optional filtering and sorting.
    The sort_by field allows dynamic column ordering for dashboard flexibility.
    """

    # WAF check on sort_by only (country is validated by Pydantic)
    if query.sort_by and waf_check(query.sort_by):
        raise HTTPException(status_code=400, detail="Invalid sort parameter")

    # Build base query using ORM-style parameters for filters (looks safe)
    filters = []
    params: dict = {"limit_val": query.limit}

    if query.event_type:
        filters.append("ae.event_type = :event_type")
        params["event_type"] = query.event_type

    if query.country:
        filters.append("ae.country = :country")
        params["country"] = query.country

    where_clause = ("WHERE " + " AND ".join(filters)) if filters else ""

    # ══════════════════════════════════════════════════════════════════
    # VULNERABILITY: sort_by is injected directly into the ORDER BY
    # clause without whitelisting. The WAF only blocks obvious keywords
    # but misses time-based payloads using pg_sleep / CASE expressions.
    # ══════════════════════════════════════════════════════════════════
    sort_column = query.sort_by or "occurred_at"
    order_dir   = query.order  or "desc"

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
            # Generic error — no information leakage
            raise HTTPException(status_code=500, detail="Query execution error")


@app.get("/api/v1/products")
async def list_products(
    category: Optional[str] = Query(None, max_length=64),
    min_price: Optional[float] = Query(None, ge=0),
    max_price: Optional[float] = Query(None, ge=0),
):
    """Safe endpoint — uses fully parameterised ORM queries (reference)."""
    async with AsyncSessionLocal() as session:
        filters, params = [], {}
        if category:
            filters.append("category = :category")
            params["category"] = category
        if min_price is not None:
            filters.append("price >= :min_price")
            params["min_price"] = min_price
        if max_price is not None:
            filters.append("price <= :max_price")
            params["max_price"] = max_price

        where = ("WHERE " + " AND ".join(filters)) if filters else ""
        sql = f"SELECT id, sku, name, category, price, stock FROM products {where} ORDER BY id"
        result = await session.execute(text(sql), params)
        return {"data": [dict(r) for r in result.mappings().all()]}
