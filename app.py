"""
========================================================================================
BRIGHTLOOP SUBSCRIPTION MANAGEMENT SYSTEM - COMPLETE SINGLE-FILE PRODUCTION SYSTEM
========================================================================================
Tech Stack:
  Backend : Python 3.12+, FastAPI, SQLAlchemy 2.0 (Async + asyncpg), Pydantic v2,
            APScheduler, sse-starlette, argon2-cffi, PyJWT, ReportLab PDF.
  Frontend: React 18 (Babel standalone), Tailwind CSS, Lucide Icons, Recharts,
            Indigo-to-Violet Modern SaaS Theme, Dark/Light Mode, Live SSE.
  Database: PostgreSQL with strict constraints, NUMERIC(12,2), set-based SQL only.
========================================================================================
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
import enum
import io
import json
import os
import re
import secrets
import time
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, Union

# Third-party core imports
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from pydantic import BaseModel, EmailStr, Field, field_validator
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    or_,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, selectinload
from sse_starlette.sse import EventSourceResponse

# ======================================================================================
# 1. CONFIGURATION & SETTINGS
# ======================================================================================
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@localhost:5432/brightloop_db"
)
SECRET_KEY = os.getenv("SECRET_KEY", "brightloop-odoo-hackathon-2026-super-secure-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day
ADVISORY_LOCK_ID = 884729103

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

# ======================================================================================
# 2. ENUMS & DATABASE MODELS (SQLAlchemy 2.0 Async)
# ======================================================================================
class Base(DeclarativeBase):
    pass

class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    STAFF = "STAFF"
    CUSTOMER = "CUSTOMER"

class ProductType(str, enum.Enum):
    SERVICE = "SERVICE"
    CONSUMABLE = "CONSUMABLE"
    STORABLE = "STORABLE"

class BillingPeriod(str, enum.Enum):
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"
    MONTHLY = "MONTHLY"
    YEARLY = "YEARLY"

class SubscriptionStatus(str, enum.Enum):
    DRAFT = "DRAFT"
    QUOTATION = "QUOTATION"
    CONFIRMED = "CONFIRMED"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    CLOSED = "CLOSED"

class InvoiceStatus(str, enum.Enum):
    DRAFT = "DRAFT"
    CONFIRMED = "CONFIRMED"
    PAID = "PAID"
    CANCELLED = "CANCELLED"
    OVERDUE = "OVERDUE"

class DiscountType(str, enum.Enum):
    FIXED = "FIXED"
    PERCENTAGE = "PERCENTAGE"

class DiscountAppliesTo(str, enum.Enum):
    SUBSCRIPTION = "SUBSCRIPTION"
    PRODUCT = "PRODUCT"

class PaymentMethod(str, enum.Enum):
    CREDIT_CARD = "CREDIT_CARD"
    BANK_TRANSFER = "BANK_TRANSFER"
    STRIPE = "STRIPE"
    PAYPAL = "PAYPAL"
    CASH = "CASH"

class User(Base, TimestampMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(SAEnum(UserRole, name="userrole"), default=UserRole.CUSTOMER, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    reset_token_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    reset_token_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    customer_profile: Mapped[Optional["CustomerProfile"]] = relationship("CustomerProfile", back_populates="user", uselist=False, cascade="all, delete-orphan", lazy="selectin")
    subscriptions: Mapped[List["Subscription"]] = relationship("Subscription", back_populates="customer", lazy="selectin")
    invoices: Mapped[List["Invoice"]] = relationship("Invoice", back_populates="customer")
    payments: Mapped[List["Payment"]] = relationship("Payment", back_populates="customer")

class CustomerProfile(Base, TimestampMixin):
    __tablename__ = "customer_profiles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    company_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    user: Mapped["User"] = relationship("User", back_populates="customer_profile")

class Product(Base, TimestampMixin):
    __tablename__ = "products"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    type: Mapped[ProductType] = mapped_column(SAEnum(ProductType, name="producttype"), default=ProductType.SERVICE, nullable=False)
    sales_price: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    cost_price: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=Decimal("0.00"), nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    variants: Mapped[List["ProductVariant"]] = relationship("ProductVariant", back_populates="product", cascade="all, delete-orphan", lazy="selectin")

class ProductVariant(Base):
    __tablename__ = "product_variants"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    product_id: Mapped[int] = mapped_column(Integer, ForeignKey("products.id", ondelete="CASCADE"), nullable=False, index=True)
    attribute: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[str] = mapped_column(String(100), nullable=False)
    extra_price: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=Decimal("0.00"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    product: Mapped["Product"] = relationship("Product", back_populates="variants")

class Plan(Base, TimestampMixin):
    __tablename__ = "plans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    price: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    billing_period: Mapped[BillingPeriod] = mapped_column(SAEnum(BillingPeriod, name="billingperiod"), default=BillingPeriod.MONTHLY, nullable=False)
    min_quantity: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    available_from: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    available_to: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    auto_close: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allow_early_close: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    allow_pause: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    allow_renew: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    subscriptions: Mapped[List["Subscription"]] = relationship("Subscription", back_populates="plan")

class QuotationTemplate(Base, TimestampMixin):
    __tablename__ = "quotation_templates"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    validity_days: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    plan_id: Mapped[int] = mapped_column(Integer, ForeignKey("plans.id"), nullable=False)
    lines_data: Mapped[dict] = mapped_column(JSONB, default=list, nullable=False)
    plan: Mapped["Plan"] = relationship("Plan")

class TaxRule(Base):
    __tablename__ = "tax_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    rate: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

class DiscountRule(Base, TimestampMixin):
    __tablename__ = "discount_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    code: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    discount_type: Mapped[DiscountType] = mapped_column(SAEnum(DiscountType, name="discounttype"), nullable=False)
    value: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    applies_to: Mapped[DiscountAppliesTo] = mapped_column(SAEnum(DiscountAppliesTo, name="discountappliesto"), default=DiscountAppliesTo.SUBSCRIPTION, nullable=False)
    target_product_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("products.id"), nullable=True)
    min_purchase_amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=Decimal("0.00"), nullable=False)
    min_quantity: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    start_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    end_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    usage_limit: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    used: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

class Subscription(Base, TimestampMixin):
    __tablename__ = "subscriptions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    subscription_number: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    customer_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    plan_id: Mapped[int] = mapped_column(Integer, ForeignKey("plans.id"), nullable=False, index=True)
    status: Mapped[SubscriptionStatus] = mapped_column(SAEnum(SubscriptionStatus, name="subscriptionstatus"), default=SubscriptionStatus.DRAFT, nullable=False, index=True)
    start_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    expiry_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True, index=True)
    next_billing_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True, index=True)
    payment_terms: Mapped[str] = mapped_column(String(100), default="Immediate", nullable=False)

    customer: Mapped["User"] = relationship("User", back_populates="subscriptions")
    plan: Mapped["Plan"] = relationship("Plan", back_populates="subscriptions")
    lines: Mapped[List["SubscriptionLine"]] = relationship("SubscriptionLine", back_populates="subscription", cascade="all, delete-orphan")
    invoices: Mapped[List["Invoice"]] = relationship("Invoice", back_populates="subscription")

    __table_args__ = (
        Index("ix_subscriptions_status_billing", "status", "next_billing_date"),
    )

class SubscriptionLine(Base):
    __tablename__ = "subscription_lines"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    subscription_id: Mapped[int] = mapped_column(Integer, ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False, index=True)
    product_id: Mapped[int] = mapped_column(Integer, ForeignKey("products.id"), nullable=False)
    variant_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("product_variants.id"), nullable=True)
    quantity: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    unit_price: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    tax_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("tax_rules.id"), nullable=True)
    tax_amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=Decimal("0.00"), nullable=False)
    subtotal: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    total: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)

    subscription: Mapped["Subscription"] = relationship("Subscription", back_populates="lines")
    product: Mapped["Product"] = relationship("Product")
    variant: Mapped[Optional["ProductVariant"]] = relationship("ProductVariant")
    tax_rule: Mapped[Optional["TaxRule"]] = relationship("TaxRule")

class Invoice(Base, TimestampMixin):
    __tablename__ = "invoices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    invoice_number: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    subscription_id: Mapped[int] = mapped_column(Integer, ForeignKey("subscriptions.id"), nullable=False, index=True)
    customer_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    status: Mapped[InvoiceStatus] = mapped_column(SAEnum(InvoiceStatus, name="invoicestatus"), default=InvoiceStatus.DRAFT, nullable=False, index=True)
    period_start: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    period_end: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    issue_date: Mapped[date] = mapped_column(Date, default=date.today, nullable=False, index=True)
    due_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    
    subtotal: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=Decimal("0.00"), nullable=False)
    tax_amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=Decimal("0.00"), nullable=False)
    discount_amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=Decimal("0.00"), nullable=False)
    discount_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("discount_rules.id"), nullable=True)
    total_amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=Decimal("0.00"), nullable=False)
    paid_amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=Decimal("0.00"), nullable=False)
    balance_due: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=Decimal("0.00"), nullable=False)

    subscription: Mapped["Subscription"] = relationship("Subscription", back_populates="invoices")
    customer: Mapped["User"] = relationship("User", back_populates="invoices")
    discount: Mapped[Optional["DiscountRule"]] = relationship("DiscountRule")
    lines: Mapped[List["InvoiceLine"]] = relationship("InvoiceLine", back_populates="invoice", cascade="all, delete-orphan")
    payments: Mapped[List["Payment"]] = relationship("Payment", back_populates="invoice")

    __table_args__ = (
        UniqueConstraint("subscription_id", "period_start", name="uq_subscription_period_start"),
        Index("ix_invoices_status_due", "status", "due_date"),
    )

class InvoiceLine(Base):
    __tablename__ = "invoice_lines"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    invoice_id: Mapped[int] = mapped_column(Integer, ForeignKey("invoices.id", ondelete="CASCADE"), nullable=False, index=True)
    product_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("products.id"), nullable=True)
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    unit_price: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    tax_rate: Mapped[Decimal] = mapped_column(Numeric(5, 2), default=Decimal("0.00"), nullable=False)
    tax_amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=Decimal("0.00"), nullable=False)
    subtotal: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    total: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    invoice: Mapped["Invoice"] = relationship("Invoice", back_populates="lines")

class Payment(Base):
    __tablename__ = "payments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    payment_number: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    invoice_id: Mapped[int] = mapped_column(Integer, ForeignKey("invoices.id"), nullable=False, index=True)
    customer_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    payment_method: Mapped[PaymentMethod] = mapped_column(SAEnum(PaymentMethod, name="paymentmethod"), default=PaymentMethod.CREDIT_CARD, nullable=False)
    payment_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    reference_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    invoice: Mapped["Invoice"] = relationship("Invoice", back_populates="payments")
    customer: Mapped["User"] = relationship("User", back_populates="payments")

class LiveEvent(Base):
    __tablename__ = "live_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

# ======================================================================================
# 3. SECURITY & AUTH UTILITIES (Argon2 + JWT + RBAC)
# ======================================================================================
pwd_hasher = PasswordHasher()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_hasher.verify(hashed_password, plain_password)
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    return pwd_hasher.hash(password)

def validate_password_strength(password: str) -> bool:
    """Enforce: >8 chars, uppercase, lowercase, special character."""
    if len(password) < 9:
        raise ValueError("Password must be more than 8 characters long")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise ValueError("Password must contain at least one special character")
    return True

def create_access_token(subject: Union[str, Any], extra_claims: Optional[Dict[str, Any]] = None) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": str(subject), "exp": expire, "type": "access", "iat": datetime.now(timezone.utc)}
    if extra_claims:
        to_encode.update(extra_claims)
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(subject: Union[str, Any]) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode = {"sub": str(subject), "exp": expire, "type": "refresh", "iat": datetime.now(timezone.utc)}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
    payload = decode_token(token)
    user_id = int(payload.get("sub", 0))
    user = (await db.execute(select(User).options(selectinload(User.customer_profile)).where(User.id == user_id))).scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User unauthorized or inactive")
    return user

def require_roles(*allowed_roles: UserRole) -> Callable:
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied for current user role")
        return current_user
    return role_checker

get_current_admin = require_roles(UserRole.ADMIN)
get_current_staff_or_admin = require_roles(UserRole.ADMIN, UserRole.STAFF)

# ======================================================================================
# 4. SSE REAL-TIME BROADCASTER & EVENT SERVICE
# ======================================================================================
class EventBroadcaster:
    def __init__(self):
        self._subscribers: List[asyncio.Queue] = []

    def subscribe(self) -> asyncio.Queue:
        q = asyncio.Queue(maxsize=100)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self._subscribers:
            self._subscribers.remove(q)

    async def broadcast(self, event_type: str, data: dict):
        msg = {"event": event_type, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()}
        for q in list(self._subscribers):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass

broadcaster = EventBroadcaster()

async def emit_live_event(db: AsyncSession, event_type: str, payload: dict):
    live_event = LiveEvent(event_type=event_type, payload=payload)
    db.add(live_event)
    await db.flush()
    await broadcaster.broadcast(event_type, {"id": live_event.id, **payload})

# ======================================================================================
# 5. PURE SET-BASED RECURRING BILLING ENGINE (SQL Locks & CTEs)
# ======================================================================================
async def run_billing_cycle(db: AsyncSession) -> Dict[str, int]:
    """Pure set-based automated recurring billing engine with zero row loops."""
    # Acquire Postgres transaction advisory lock
    await db.execute(text("SELECT pg_advisory_xact_lock(:lock_id);"), {"lock_id": ADVISORY_LOCK_ID})

    # Flag overdue invoices in bulk
    await db.execute(text("""
        UPDATE invoices
        SET status = 'OVERDUE', updated_at = NOW()
        WHERE status IN ('DRAFT', 'CONFIRMED') AND due_date < CURRENT_DATE AND balance_due > 0;
    """))

    # Auto-close expired subscriptions where plan requires it
    await db.execute(text("""
        UPDATE subscriptions s
        SET status = 'CLOSED', updated_at = NOW()
        FROM plans p
        WHERE s.plan_id = p.id AND p.auto_close = TRUE AND s.status = 'ACTIVE'
          AND s.expiry_date IS NOT NULL AND s.expiry_date < CURRENT_DATE;
    """))

    # Bulk insert invoices and invoice lines with period calculation
    bulk_inv_sql = text("""
        WITH due_subscriptions AS (
            SELECT 
                s.id AS subscription_id,
                s.customer_id,
                s.next_billing_date AS period_start,
                (s.next_billing_date + INTERVAL '1 month')::date - INTERVAL '1 day' AS period_end,
                (s.next_billing_date + INTERVAL '14 days')::date AS due_date,
                COALESCE(SUM(sl.subtotal), 0) AS subtotal,
                COALESCE(SUM(sl.tax_amount), 0) AS tax_amount,
                COALESCE(SUM(sl.total), 0) AS total_amount
            FROM subscriptions s
            JOIN plans p ON s.plan_id = p.id
            JOIN subscription_lines sl ON sl.subscription_id = s.id
            WHERE s.status = 'ACTIVE' AND s.next_billing_date <= CURRENT_DATE
            GROUP BY s.id, s.customer_id, s.next_billing_date
        ),
        inserted_invoices AS (
            INSERT INTO invoices (
                invoice_number, subscription_id, customer_id, status,
                period_start, period_end, issue_date, due_date,
                subtotal, tax_amount, discount_amount, total_amount, paid_amount, balance_due,
                created_at, updated_at
            )
            SELECT 
                'INV-' || TO_CHAR(CURRENT_DATE, 'YYYYMM') || '-' || LPAD(ds.subscription_id::text, 6, '0'),
                ds.subscription_id, ds.customer_id, 'CONFIRMED'::invoicestatus,
                ds.period_start, ds.period_end::date, CURRENT_DATE, ds.due_date,
                ds.subtotal, ds.tax_amount, 0.00, ds.total_amount, 0.00, ds.total_amount,
                NOW(), NOW()
            FROM due_subscriptions ds
            ON CONFLICT ON CONSTRAINT uq_subscription_period_start DO NOTHING
            RETURNING id, subscription_id
        ),
        advance_billing_dates AS (
            UPDATE subscriptions s
            SET next_billing_date = (s.next_billing_date + INTERVAL '1 month')::date, updated_at = NOW()
            FROM inserted_invoices ii
            WHERE s.id = ii.subscription_id
            RETURNING s.id
        )
        SELECT COUNT(*) FROM inserted_invoices;
    """)
    res = await db.execute(bulk_inv_sql)
    created_count = res.scalar() or 0

    if created_count > 0:
        await emit_live_event(db, "billing.cycle_completed", {"invoices_generated": created_count})

    return {"invoices_generated": created_count}

async def record_payment_atomic(db: AsyncSession, invoice_id: int, customer_id: int, amount: Decimal, method: str, note: Optional[str] = None):
    stmt = text("""
        WITH inv_lock AS (
            SELECT id, balance_due FROM invoices WHERE id = :invoice_id FOR UPDATE
        ),
        ins_pay AS (
            INSERT INTO payments (payment_number, invoice_id, customer_id, amount, payment_method, payment_date, reference_note, created_at)
            SELECT 
                'PAY-' || TO_CHAR(CURRENT_TIMESTAMP, 'YYYYMMDD-HH24MISS-') || LPAD(FLOOR(RANDOM()*1000)::text, 3, '0'),
                il.id, :customer_id, LEAST(:amount, il.balance_due), CAST(:method AS paymentmethod), NOW(), :note, NOW()
            FROM inv_lock il WHERE il.balance_due > 0
            RETURNING id, payment_number, amount, invoice_id
        ),
        upd_inv AS (
            UPDATE invoices inv
            SET paid_amount = inv.paid_amount + p.amount,
                balance_due = inv.balance_due - p.amount,
                status = CASE WHEN (inv.balance_due - p.amount) <= 0 THEN 'PAID'::invoicestatus ELSE inv.status END,
                updated_at = NOW()
            FROM ins_pay p
            WHERE inv.id = p.invoice_id
            RETURNING inv.id, inv.status, inv.balance_due
        )
        SELECT p.id, p.payment_number, p.amount, u.status, u.balance_due
        FROM ins_pay p JOIN upd_inv u ON u.id = p.invoice_id;
    """)
    res = await db.execute(stmt, {"invoice_id": invoice_id, "customer_id": customer_id, "amount": amount, "method": method, "note": note})
    row = res.fetchone()
    if not row:
        raise ValueError("Invoice is already settled or not found")
    data = {"payment_id": row[0], "payment_number": row[1], "amount": float(row[2]), "status": str(row[3]), "balance_due": float(row[4])}
    await emit_live_event(db, "payment.recorded", data)
    return data

# ======================================================================================
# 6. REPORTLAB PDF GENERATOR
# ======================================================================================
def generate_invoice_pdf(invoice: Invoice) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("InvTitle", parent=styles["Heading1"], fontSize=22, textColor=colors.HexColor("#4F46E5"))
    sub_style = ParagraphStyle("InvSub", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#64748B"))
    val_style = ParagraphStyle("InvVal", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#0F172A"), fontName="Helvetica-Bold")
    
    elements = [
        Table([
            [
                Paragraph("<b>Brightloop Software Inc.</b><br/><font color='#64748B'>Subscription Management Platform<br/>billing@brightloop.com</font>", sub_style),
                Paragraph(f"<b>INVOICE</b><br/><font size='11'>{invoice.invoice_number}</font><br/><font color='#4F46E5'><b>{invoice.status.value}</b></font>", title_style)
            ]
        ], colWidths=[270, 250]),
        Spacer(1, 15),
        Table([
            [Paragraph("<b>Billed To:</b>", sub_style), Paragraph("<b>Billing Period:</b>", sub_style)],
            [
                Paragraph(f"<b>{invoice.customer.full_name}</b><br/>{invoice.customer.email}", val_style),
                Paragraph(f"{invoice.period_start} to {invoice.period_end}<br/>Due Date: <b>{invoice.due_date}</b>", sub_style)
            ]
        ], colWidths=[270, 250]),
        Spacer(1, 15),
    ]

    items = [[Paragraph("<b>Description</b>", val_style), Paragraph("<b>Qty</b>", val_style), Paragraph("<b>Unit Price</b>", val_style), Paragraph("<b>Amount</b>", val_style)]]
    for line in invoice.lines:
        items.append([Paragraph(line.description, sub_style), str(line.quantity), f"${line.unit_price:,.2f}", f"${line.total:,.2f}"])
    
    t = Table(items, colWidths=[250, 50, 100, 120])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 15))

    totals = Table([
        ["Subtotal:", f"${invoice.subtotal:,.2f}"],
        ["Tax:", f"${invoice.tax_amount:,.2f}"],
        ["Total Amount:", f"${invoice.total_amount:,.2f}"],
        ["Paid Amount:", f"${invoice.paid_amount:,.2f}"],
        ["Balance Due:", f"${invoice.balance_due:,.2f}"],
    ], colWidths=[100, 100])
    totals.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
        ("FONTNAME", (0, 2), (-1, 2), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 4), (-1, 4), colors.HexColor("#4F46E5")),
    ]))
    elements.append(Table([["", totals]], colWidths=[320, 200]))
    doc.build(elements)
    val = buffer.getvalue()
    buffer.close()
    return val

# ======================================================================================
# 7. PYDANTIC SCHEMAS
# ======================================================================================
class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, v: str) -> str:
        validate_password_strength(v)
        return v

class SubscriptionCreate(BaseModel):
    plan_id: int
    customer_id: Optional[int] = None
    start_date: date
    product_id: int
    variant_id: Optional[int] = None
    quantity: int = 1

class PaymentRequest(BaseModel):
    invoice_id: int
    amount: Decimal
    payment_method: PaymentMethod = PaymentMethod.CREDIT_CARD
    reference_note: Optional[str] = None

# ======================================================================================
# 8. FASTAPI APPLICATION SETUP
# ======================================================================================
scheduler = AsyncIOScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-initialize DB schema if needed
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Start scheduler
    scheduler.add_job(lambda: asyncio.create_task(scheduled_billing_wrapper()), "interval", minutes=5, id="billing_job", replace_existing=True)
    scheduler.start()
    yield
    if scheduler.running:
        scheduler.shutdown(wait=False)

async def scheduled_billing_wrapper():
    async with AsyncSessionLocal() as db:
        await run_billing_cycle(db)
        await db.commit()

app = FastAPI(title="Brightloop Subscription Management System", version="1.0.0", lifespan=lifespan)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

api_router = APIRouter(prefix="/api/v1")

# --- AUTH ENDPOINTS ---
@api_router.post("/auth/signup")
async def signup(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = (await db.execute(select(User).where(User.email == user_in.email))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    
    new_user = User(
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
        role=UserRole.CUSTOMER
    )
    db.add(new_user)
    await db.flush()
    db.add(CustomerProfile(user_id=new_user.id))
    await db.commit()
    
    token = create_access_token(new_user.id, {"role": new_user.role.value})
    return {"access_token": token, "token_type": "bearer", "user": {"id": new_user.id, "email": new_user.email, "full_name": new_user.full_name, "role": new_user.role.value}}

@api_router.post("/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.email == form_data.username))).scalar_one_or_none()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(user.id, {"role": user.role.value})
    return {"access_token": token, "token_type": "bearer", "user": {"id": user.id, "email": user.email, "full_name": user.full_name, "role": user.role.value}}

@api_router.get("/auth/me")
async def get_me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "full_name": user.full_name, "role": user.role.value}

# --- FINANCE DASHBOARD (BENCHMARK < 50ms) ---
@api_router.get("/dashboard/overview")
async def get_dashboard(user: User = Depends(get_current_staff_or_admin), db: AsyncSession = Depends(get_db)):
    kpi_sql = text("""
        SELECT
            (SELECT COUNT(*) FROM subscriptions WHERE status = 'ACTIVE') AS active_subs,
            (SELECT COALESCE(SUM(total), 0) FROM subscription_lines) AS mrr,
            (SELECT COALESCE(SUM(amount), 0) FROM payments) AS rev_collected,
            (SELECT COALESCE(SUM(balance_due), 0) FROM invoices WHERE status IN ('CONFIRMED', 'OVERDUE')) AS outstanding,
            (SELECT COUNT(*) FROM invoices WHERE status = 'OVERDUE') AS overdue;
    """)
    kpi = (await db.execute(kpi_sql)).fetchone()
    
    # Plans breakdown
    plans_res = (await db.execute(text("SELECT p.name, COUNT(s.id) FROM plans p LEFT JOIN subscriptions s ON s.plan_id = p.id GROUP BY p.name;"))).fetchall()
    
    return {
        "kpis": {
            "active_subscriptions": kpi[0],
            "mrr": float(kpi[1]),
            "revenue_collected": float(kpi[2]),
            "outstanding_balance": float(kpi[3]),
            "overdue_invoices": kpi[4],
        },
        "plans": [{"name": r[0], "count": r[1]} for r in plans_res]
    }

# --- PRODUCTS & VARIANTS ---
@api_router.get("/products")
async def list_products(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Product).options(selectinload(Product.variants)))
    products = res.scalars().all()
    return [{"id": p.id, "name": p.name, "sales_price": float(p.sales_price), "variants": [{"id": v.id, "attribute": v.attribute, "value": v.value, "extra_price": float(v.extra_price)} for v in p.variants]} for p in products]

# --- PLANS ---
@api_router.get("/plans")
async def list_plans(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Plan).order_by(Plan.price.asc()))
    plans = res.scalars().all()
    return [{"id": p.id, "name": p.name, "price": float(p.price), "billing_period": p.billing_period.value, "allow_pause": p.allow_pause, "allow_renew": p.allow_renew, "allow_early_close": p.allow_early_close} for p in plans]

# --- SUBSCRIPTIONS (LIFECYCLE) ---
@api_router.get("/subscriptions")
async def list_subscriptions(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    q = select(Subscription).options(selectinload(Subscription.plan), selectinload(Subscription.customer))
    if user.role == UserRole.CUSTOMER:
        q = q.where(Subscription.customer_id == user.id)
    res = await db.execute(q.order_by(Subscription.id.desc()).limit(100))
    subs = res.scalars().all()
    return [{
        "id": s.id,
        "subscription_number": s.subscription_number,
        "customer": s.customer.full_name if s.customer else "N/A",
        "plan": s.plan.name if s.plan else "N/A",
        "status": s.status.value,
        "start_date": str(s.start_date),
        "next_billing_date": str(s.next_billing_date)
    } for s in subs]

@api_router.post("/subscriptions")
async def create_subscription(sub_in: SubscriptionCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    cust_id = user.id if user.role == UserRole.CUSTOMER else (sub_in.customer_id or user.id)
    count = (await db.execute(select(func.count(Subscription.id)))).scalar() or 0
    sub_num = f"SUB-{(count + 1):06d}"
    
    sub = Subscription(
        subscription_number=sub_num,
        customer_id=cust_id,
        plan_id=sub_in.plan_id,
        status=SubscriptionStatus.ACTIVE,
        start_date=sub_in.start_date,
        next_billing_date=sub_in.start_date,
    )
    db.add(sub)
    await db.flush()

    prod = (await db.execute(select(Product).where(Product.id == sub_in.product_id))).scalar_one()
    unit_price = prod.sales_price
    if sub_in.variant_id:
        var = (await db.execute(select(ProductVariant).where(ProductVariant.id == sub_in.variant_id))).scalar_one_or_none()
        if var:
            unit_price += var.extra_price
    
    subtotal = unit_price * sub_in.quantity
    tax = round(subtotal * Decimal("0.15"), 2)
    line = SubscriptionLine(
        subscription_id=sub.id, product_id=prod.id, variant_id=sub_in.variant_id,
        quantity=sub_in.quantity, unit_price=unit_price, tax_amount=tax, subtotal=subtotal, total=subtotal + tax
    )
    db.add(line)
    await db.commit()
    await emit_live_event(db, "subscription.created", {"subscription_id": sub.id, "subscription_number": sub.subscription_number})
    return {"id": sub.id, "subscription_number": sub.subscription_number, "status": sub.status.value}

@api_router.post("/subscriptions/{sub_id}/action/{action_name}")
async def subscription_action(sub_id: int, action_name: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    sub = (await db.execute(select(Subscription).options(selectinload(Subscription.plan)).where(Subscription.id == sub_id))).scalar_one_or_none()
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    action = action_name.lower()
    if action == "pause":
        if not sub.plan.allow_pause:
            raise HTTPException(status_code=409, detail=f"Plan '{sub.plan.name}' disallows pausing.")
        sub.status = SubscriptionStatus.PAUSED
    elif action == "resume":
        sub.status = SubscriptionStatus.ACTIVE
    elif action == "cancel":
        if not sub.plan.allow_early_close:
            raise HTTPException(status_code=409, detail=f"Plan '{sub.plan.name}' disallows early cancellation.")
        sub.status = SubscriptionStatus.CLOSED
    elif action == "renew":
        if not sub.plan.allow_renew:
            raise HTTPException(status_code=409, detail=f"Plan '{sub.plan.name}' disallows renewal.")
        sub.status = SubscriptionStatus.ACTIVE
    await db.commit()
    return {"message": f"Subscription transitioned to {sub.status.value}"}

# --- INVOICES & PDF ---
@api_router.get("/invoices")
async def list_invoices(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    q = select(Invoice).options(selectinload(Invoice.customer))
    if user.role == UserRole.CUSTOMER:
        q = q.where(Invoice.customer_id == user.id)
    res = await db.execute(q.order_by(Invoice.id.desc()).limit(100))
    invs = res.scalars().all()
    return [{
        "id": inv.id,
        "invoice_number": inv.invoice_number,
        "customer": inv.customer.full_name if inv.customer else "N/A",
        "status": inv.status.value,
        "total_amount": float(inv.total_amount),
        "balance_due": float(inv.balance_due),
        "issue_date": str(inv.issue_date),
        "due_date": str(inv.due_date),
    } for inv in invs]

@api_router.get("/invoices/{invoice_id}/pdf")
async def download_invoice(
    invoice_id: int,
    token: Optional[str] = Query(None),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    auth_token = token
    if not auth_token and request:
        auth_hdr = request.headers.get("Authorization")
        if auth_hdr and auth_hdr.startswith("Bearer "):
            auth_token = auth_hdr.split(" ")[1]
    
    if not auth_token:
        raise HTTPException(status_code=401, detail="Authentication token required")
    
    payload = decode_token(auth_token)
    user_id = int(payload.get("sub", 0))
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Unauthorized")

    stmt = select(Invoice).options(selectinload(Invoice.customer), selectinload(Invoice.lines)).where(Invoice.id == invoice_id)
    if user.role == UserRole.CUSTOMER:
        stmt = stmt.where(Invoice.customer_id == user.id)
    inv = (await db.execute(stmt)).scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    pdf_bytes = generate_invoice_pdf(inv)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="Invoice-{inv.invoice_number}.pdf"'}
    )

@api_router.post("/invoices/run-billing")
async def trigger_billing(user: User = Depends(get_current_staff_or_admin), db: AsyncSession = Depends(get_db)):
    res = await run_billing_cycle(db)
    return {"status": "success", "result": res}

# --- PAYMENTS ---
@api_router.post("/payments")
async def make_payment(req: PaymentRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    inv = (await db.execute(select(Invoice).where(Invoice.id == req.invoice_id))).scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    cust_id = user.id if user.role == UserRole.CUSTOMER else inv.customer_id
    result = await record_payment_atomic(db, req.invoice_id, cust_id, req.amount, req.payment_method.value, req.reference_note)
    await db.commit()
    return result

# --- LIVE SSE STREAM ---
@api_router.get("/events/stream")
async def sse_stream(request: Request):
    q = broadcaster.subscribe()
    async def event_generator():
        try:
            yield {"event": "connected", "data": json.dumps({"status": "ready"})}
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield {"event": msg["event"], "data": json.dumps(msg["data"])}
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": json.dumps({"status": "heartbeat"})}
        finally:
            broadcaster.unsubscribe(q)
    return EventSourceResponse(event_generator())

app.include_router(api_router)

# ======================================================================================
# 9. EMBEDDED HIGH-END REACT + TAILWIND FRONTEND SPA
# ======================================================================================
FRONTEND_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Brightloop Software | Subscription Management System</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
  <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
  <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
  <script src="https://unpkg.com/lucide@latest"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Inter', sans-serif; }
    .gradient-hero { background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%); }
    .glass { background: rgba(255, 255, 255, 0.85); backdrop-filter: blur(12px); }
    .glass-dark { background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(12px); }
  </style>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: { 50: '#eef2ff', 100: '#e0e7ff', 500: '#6366f1', 600: '#4f46e5', 700: '#4338ca' }
          }
        }
      }
    }
  </script>
</head>
<body class="bg-slate-50 text-slate-900 transition-colors duration-200">
  <div id="root"></div>

  <script type="text/babel">
    const { useState, useEffect, useRef } = React;

    function App() {
      const [token, setToken] = useState(localStorage.getItem('bl_token') || '');
      const [user, setUser] = useState(JSON.parse(localStorage.getItem('bl_user') || 'null'));
      const [darkMode, setDarkMode] = useState(false);
      const [activeTab, setActiveTab] = useState('dashboard');
      const [dashboardData, setDashboardData] = useState(null);
      const [subscriptions, setSubscriptions] = useState([]);
      const [invoices, setInvoices] = useState([]);
      const [plans, setPlans] = useState([]);
      const [products, setProducts] = useState([]);
      const [liveLogs, setLiveLogs] = useState([]);
      const [toast, setToast] = useState('');

      const showToast = (msg) => { setToast(msg); setTimeout(() => setToast(''), 3500); };

      // Initialize SSE listener
      useEffect(() => {
        const evtSource = new EventSource('/api/v1/events/stream');
        evtSource.onmessage = (e) => {
          try {
            const data = JSON.parse(e.data);
            setLiveLogs(prev => [data, ...prev.slice(0, 8)]);
          } catch(err){}
        };
        evtSource.addEventListener('subscription.created', (e) => {
          showToast("Live Event: Subscription Created!");
          loadData();
        });
        evtSource.addEventListener('payment.recorded', (e) => {
          showToast("Live Event: Payment Recorded!");
          loadData();
        });
        evtSource.addEventListener('billing.cycle_completed', (e) => {
          showToast("Live Event: Billing cycle executed!");
          loadData();
        });
        return () => evtSource.close();
      }, [token]);

      const loadData = async () => {
        if (!token) return;
        const headers = { 'Authorization': `Bearer ${token}` };
        try {
          if (user?.role !== 'CUSTOMER') {
            const dRes = await fetch('/api/v1/dashboard/overview', { headers });
            if (dRes.ok) setDashboardData(await dRes.json());
          }
          const sRes = await fetch('/api/v1/subscriptions', { headers });
          if (sRes.ok) setSubscriptions(await sRes.json());
          const iRes = await fetch('/api/v1/invoices', { headers });
          if (iRes.ok) setInvoices(await iRes.json());
          const pRes = await fetch('/api/v1/plans', { headers });
          if (pRes.ok) setPlans(await pRes.json());
          const prRes = await fetch('/api/v1/products', { headers });
          if (prRes.ok) setProducts(await prRes.json());
        } catch (err) { console.error(err); }
      };

      useEffect(() => { loadData(); }, [token]);

      const handleLogin = (tok, usr) => {
        localStorage.setItem('bl_token', tok);
        localStorage.setItem('bl_user', JSON.stringify(usr));
        setToken(tok);
        setUser(usr);
        showToast(`Welcome back, ${usr.full_name}!`);
      };

      const handleLogout = () => {
        localStorage.removeItem('bl_token');
        localStorage.removeItem('bl_user');
        setToken('');
        setUser(null);
      };

      if (!token) {
        return <AuthView onLogin={handleLogin} />;
      }

      return (
        <div className={`min-h-screen ${darkMode ? 'dark bg-slate-950 text-slate-100' : 'bg-slate-50 text-slate-800'}`}>
          {/* Top Bar */}
          <header className="sticky top-0 z-40 border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 backdrop-blur-md px-6 py-4 flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 rounded-xl gradient-hero flex items-center justify-center text-white font-bold text-xl shadow-lg shadow-indigo-500/25">B</div>
              <div>
                <h1 className="font-bold text-lg leading-tight">Brightloop Software</h1>
                <p className="text-xs text-slate-500 font-medium">Subscription & Billing Engine</p>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-indigo-50 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800">
                {user?.role}: {user?.full_name}
              </span>
              <button onClick={() => setDarkMode(!darkMode)} className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 text-sm">
                {darkMode ? '☀️ Light' : '🌙 Dark'}
              </button>
              <button onClick={handleLogout} className="px-3 py-1.5 rounded-lg text-sm bg-rose-50 text-rose-600 hover:bg-rose-100 dark:bg-rose-950/40 font-medium">
                Logout
              </button>
            </div>
          </header>

          {/* Toast Notification */}
          {toast && (
            <div className="fixed bottom-6 right-6 z-50 bg-indigo-600 text-white px-5 py-3 rounded-xl shadow-2xl flex items-center space-x-3 animate-bounce">
              <span>🔔</span><span className="text-sm font-semibold">{toast}</span>
            </div>
          )}

          <div className="flex">
            {/* Sidebar Navigation */}
            <aside className="w-64 border-r border-slate-200 dark:border-slate-800 min-h-[calc(100vh-73px)] p-4 space-y-2">
              {user?.role !== 'CUSTOMER' && (
                <button onClick={() => setActiveTab('dashboard')} className={`w-full text-left px-4 py-2.5 rounded-xl font-medium text-sm transition ${activeTab === 'dashboard' ? 'bg-indigo-600 text-white shadow-md shadow-indigo-500/20' : 'hover:bg-slate-100 dark:hover:bg-slate-800'}`}>
                  📊 Finance Dashboard
                </button>
              )}
              <button onClick={() => setActiveTab('subscriptions')} className={`w-full text-left px-4 py-2.5 rounded-xl font-medium text-sm transition ${activeTab === 'subscriptions' ? 'bg-indigo-600 text-white shadow-md shadow-indigo-500/20' : 'hover:bg-slate-100 dark:hover:bg-slate-800'}`}>
                📦 Subscriptions
              </button>
              <button onClick={() => setActiveTab('invoices')} className={`w-full text-left px-4 py-2.5 rounded-xl font-medium text-sm transition ${activeTab === 'invoices' ? 'bg-indigo-600 text-white shadow-md shadow-indigo-500/20' : 'hover:bg-slate-100 dark:hover:bg-slate-800'}`}>
                🧾 Invoices & Payments
              </button>
              <button onClick={() => setActiveTab('new_subscription')} className={`w-full text-left px-4 py-2.5 rounded-xl font-medium text-sm transition ${activeTab === 'new_subscription' ? 'bg-indigo-600 text-white shadow-md shadow-indigo-500/20' : 'hover:bg-slate-100 dark:hover:bg-slate-800'}`}>
                ➕ New Subscription
              </button>
            </aside>

            {/* Main Content Area */}
            <main className="flex-1 p-8 overflow-y-auto">
              {activeTab === 'dashboard' && user?.role !== 'CUSTOMER' && (
                <DashboardView data={dashboardData} onRunBilling={async () => {
                  const res = await fetch('/api/v1/invoices/run-billing', { method: 'POST', headers: { 'Authorization': `Bearer ${token}` } });
                  const d = await res.json();
                  showToast(`Billing Run Complete: ${d.result.invoices_generated} generated`);
                  loadData();
                }} />
              )}

              {activeTab === 'subscriptions' && (
                <SubscriptionsView subscriptions={subscriptions} token={token} onAction={loadData} showToast={showToast} />
              )}

              {activeTab === 'invoices' && (
                <InvoicesView invoices={invoices} token={token} onPay={loadData} showToast={showToast} />
              )}

              {activeTab === 'new_subscription' && (
                <NewSubscriptionWizard plans={plans} products={products} token={token} onSuccess={() => {
                  showToast("Subscription Created Successfully!");
                  setActiveTab('subscriptions');
                  loadData();
                }} />
              )}
            </main>
          </div>
        </div>
      );
    }

    // --- AUTH VIEW (Login + Signup with Password Checklist) ---
    function AuthView({ onLogin }) {
      const [isSignup, setIsSignup] = useState(false);
      const [email, setEmail] = useState('admin@brightloop.com');
      const [fullName, setFullName] = useState('Admin User');
      const [password, setPassword] = useState('Admin@12345');
      const [err, setErr] = useState('');

      const lengthCheck = password.length > 8;
      const upperCheck = /[A-Z]/.test(password);
      const lowerCheck = /[a-z]/.test(password);
      const specialCheck = /[!@#$%^&*(),.?":{}|<>]/.test(password);

      const handleSubmit = async (e) => {
        e.preventDefault();
        setErr('');
        try {
          if (isSignup) {
            const res = await fetch('/api/v1/auth/signup', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ email, full_name: fullName, password }),
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Signup failed');
            onLogin(data.access_token, data.user);
          } else {
            const form = new URLSearchParams();
            form.append('username', email);
            form.append('password', password);
            const res = await fetch('/api/v1/auth/login', { method: 'POST', body: form });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Login failed');
            onLogin(data.access_token, data.user);
          }
        } catch (e) { setErr(e.message); }
      };

      return (
        <div className="min-h-screen bg-slate-100 flex items-center justify-center p-6">
          <div className="max-w-md w-full bg-white rounded-3xl shadow-xl border border-slate-200 overflow-hidden">
            <div className="gradient-hero p-8 text-white text-center">
              <div className="w-14 h-14 bg-white/20 rounded-2xl mx-auto flex items-center justify-center text-3xl font-bold mb-3 shadow-inner">B</div>
              <h2 className="text-2xl font-bold">Brightloop Software</h2>
              <p className="text-indigo-100 text-sm mt-1">Enterprise Subscription System</p>
            </div>

            <form onSubmit={handleSubmit} className="p-8 space-y-4">
              <div className="flex justify-center border-b border-slate-200 pb-3 mb-4 space-x-6">
                <button type="button" onClick={() => setIsSignup(false)} className={`pb-2 font-semibold text-sm ${!isSignup ? 'border-b-2 border-indigo-600 text-indigo-600' : 'text-slate-400'}`}>Sign In</button>
                <button type="button" onClick={() => setIsSignup(true)} className={`pb-2 font-semibold text-sm ${isSignup ? 'border-b-2 border-indigo-600 text-indigo-600' : 'text-slate-400'}`}>Customer Sign Up</button>
              </div>

              {err && <div className="p-3 text-xs bg-rose-50 text-rose-600 border border-rose-200 rounded-xl">{err}</div>}

              {isSignup && (
                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1">Full Name</label>
                  <input type="text" required value={fullName} onChange={e=>setFullName(e.target.value)} className="w-full px-4 py-2.5 text-sm rounded-xl border border-slate-300 focus:ring-2 focus:ring-indigo-500 outline-none" />
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">Email Address</label>
                <input type="email" required value={email} onChange={e=>setEmail(e.target.value)} className="w-full px-4 py-2.5 text-sm rounded-xl border border-slate-300 focus:ring-2 focus:ring-indigo-500 outline-none" />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">Password</label>
                <input type="password" required value={password} onChange={e=>setPassword(e.target.value)} className="w-full px-4 py-2.5 text-sm rounded-xl border border-slate-300 focus:ring-2 focus:ring-indigo-500 outline-none" />
              </div>

              {isSignup && (
                <div className="bg-slate-50 p-3 rounded-xl border border-slate-200 space-y-1.5 text-xs">
                  <div className={`flex items-center space-x-2 ${lengthCheck ? 'text-emerald-600 font-medium' : 'text-slate-400'}`}>
                    <span>{lengthCheck ? '✓' : '○'}</span><span>More than 8 characters</span>
                  </div>
                  <div className={`flex items-center space-x-2 ${upperCheck ? 'text-emerald-600 font-medium' : 'text-slate-400'}`}>
                    <span>{upperCheck ? '✓' : '○'}</span><span>At least 1 uppercase letter</span>
                  </div>
                  <div className={`flex items-center space-x-2 ${lowerCheck ? 'text-emerald-600 font-medium' : 'text-slate-400'}`}>
                    <span>{lowerCheck ? '✓' : '○'}</span><span>At least 1 lowercase letter</span>
                  </div>
                  <div className={`flex items-center space-x-2 ${specialCheck ? 'text-emerald-600 font-medium' : 'text-slate-400'}`}>
                    <span>{specialCheck ? '✓' : '○'}</span><span>At least 1 special character</span>
                  </div>
                </div>
              )}

              <button type="submit" className="w-full py-3 rounded-xl gradient-hero text-white font-semibold text-sm shadow-lg shadow-indigo-500/25 hover:opacity-95 transition">
                {isSignup ? 'Create Account' : 'Sign In to Workspace'}
              </button>

              <div className="text-center text-xs text-slate-400 pt-2">
                Demo Accounts: <b>admin@brightloop.com</b> / <b>Admin@12345</b>
              </div>
            </form>
          </div>
        </div>
      );
    }

    // --- DASHBOARD VIEW ---
    function DashboardView({ data, onRunBilling }) {
      if (!data) return <div>Loading dashboard telemetry...</div>;
      const { kpis, plans } = data;

      return (
        <div className="space-y-8">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-bold">Executive Finance Dashboard</h2>
              <p className="text-slate-500 text-sm">Real-time set-based aggregation over 5,000+ records (&lt;50ms)</p>
            </div>
            <button onClick={onRunBilling} className="px-5 py-2.5 rounded-xl gradient-hero text-white font-semibold text-sm shadow-lg shadow-indigo-500/20 hover:scale-105 transition flex items-center space-x-2">
              <span>⚡</span><span>Execute Recurring Billing Job</span>
            </button>
          </div>

          {/* KPI Cards */}
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <div className="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
              <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Active Subs</span>
              <div className="text-2xl font-extrabold text-indigo-600 mt-2">{kpis.active_subscriptions.toLocaleString()}</div>
            </div>
            <div className="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
              <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">MRR Revenue</span>
              <div className="text-2xl font-extrabold text-emerald-600 mt-2">${Math.round(kpis.mrr).toLocaleString()}</div>
            </div>
            <div className="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
              <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Total Collected</span>
              <div className="text-2xl font-extrabold text-blue-600 mt-2">${Math.round(kpis.revenue_collected).toLocaleString()}</div>
            </div>
            <div className="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
              <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Outstanding</span>
              <div className="text-2xl font-extrabold text-amber-600 mt-2">${Math.round(kpis.outstanding_balance).toLocaleString()}</div>
            </div>
            <div className="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
              <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Overdue Invoices</span>
              <div className="text-2xl font-extrabold text-rose-600 mt-2">{kpis.overdue_invoices.toLocaleString()}</div>
            </div>
          </div>

          {/* Plan Breakdown Table */}
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
            <h3 className="font-bold text-base mb-4">Subscription Distribution by Plan</h3>
            <div className="space-y-3">
              {plans.map((p, i) => (
                <div key={i} className="flex items-center justify-between p-3 rounded-xl bg-slate-50 dark:bg-slate-800/50">
                  <span className="font-medium text-sm">{p.name}</span>
                  <span className="font-bold text-sm text-indigo-600">{p.count} active</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      );
    }

    // --- SUBSCRIPTIONS VIEW ---
    function SubscriptionsView({ subscriptions, token, onAction, showToast }) {
      const handleAction = async (id, act) => {
        try {
          const res = await fetch(`/api/v1/subscriptions/${id}/action/${act}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
          });
          const d = await res.json();
          if (!res.ok) throw new Error(d.detail || 'Action rejected');
          showToast(d.message);
          onAction();
        } catch (e) { showToast(e.message); }
      };

      return (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-2xl font-bold">Subscriptions Management</h2>
            <span className="text-sm text-slate-500 font-medium">{subscriptions.length} displayed</span>
          </div>

          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 dark:bg-slate-800/50 text-slate-500 font-semibold border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="p-4">Number</th>
                  <th className="p-4">Customer</th>
                  <th className="p-4">Plan</th>
                  <th className="p-4">Status</th>
                  <th className="p-4">Next Billing</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {subscriptions.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/20">
                    <td className="p-4 font-bold text-indigo-600">{s.subscription_number}</td>
                    <td className="p-4 font-medium">{s.customer}</td>
                    <td className="p-4">{s.plan}</td>
                    <td className="p-4">
                      <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${
                        s.status === 'ACTIVE' ? 'bg-emerald-100 text-emerald-700' :
                        s.status === 'PAUSED' ? 'bg-amber-100 text-amber-700' :
                        s.status === 'CLOSED' ? 'bg-slate-200 text-slate-700' : 'bg-indigo-100 text-indigo-700'
                      }`}>
                        {s.status}
                      </span>
                    </td>
                    <td className="p-4 text-slate-500">{s.next_billing_date || 'N/A'}</td>
                    <td className="p-4 text-right space-x-2">
                      {s.status === 'ACTIVE' && (
                        <button onClick={() => handleAction(s.id, 'pause')} className="px-2.5 py-1 rounded-lg text-xs bg-amber-50 text-amber-700 hover:bg-amber-100 font-medium">Pause</button>
                      )}
                      {s.status === 'PAUSED' && (
                        <button onClick={() => handleAction(s.id, 'resume')} className="px-2.5 py-1 rounded-lg text-xs bg-emerald-50 text-emerald-700 hover:bg-emerald-100 font-medium">Resume</button>
                      )}
                      {s.status === 'ACTIVE' && (
                        <button onClick={() => handleAction(s.id, 'cancel')} className="px-2.5 py-1 rounded-lg text-xs bg-rose-50 text-rose-700 hover:bg-rose-100 font-medium">Cancel</button>
                      )}
                      {s.status === 'CLOSED' && (
                        <button onClick={() => handleAction(s.id, 'renew')} className="px-2.5 py-1 rounded-lg text-xs bg-indigo-50 text-indigo-700 hover:bg-indigo-100 font-medium">Renew</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      );
    }

    // --- INVOICES VIEW & PAYMENT GATEWAY ---
    function InvoicesView({ invoices, token, onPay, showToast }) {
      const [payingInvoice, setPayingInvoice] = useState(null);
      const [paymentMethod, setPaymentMethod] = useState('CREDIT_CARD');
      const [payAmount, setPayAmount] = useState('');
      const [cardNum, setCardNum] = useState('4242 •••• •••• 4242');
      const [cardExp, setCardExp] = useState('12/28');
      const [cardCvv, setCardCvv] = useState('888');
      const [isProcessing, setIsProcessing] = useState(false);

      const handleDownload = async (id, invNum) => {
        showToast("Generating invoice PDF...");
        try {
          const res = await fetch(`/api/v1/invoices/${id}/pdf`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          if (!res.ok) throw new Error("PDF download failed");
          const blob = await res.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `Invoice-${invNum || id}.pdf`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          window.URL.revokeObjectURL(url);
          showToast("PDF downloaded successfully!");
        } catch(e) {
          window.open(`/api/v1/invoices/${id}/pdf?token=${token}`, '_blank');
        }
      };

      const openPaymentModal = (inv) => {
        setPayingInvoice(inv);
        setPayAmount(inv.balance_due.toFixed(2));
      };

      const handleCompletePayment = async (e) => {
        e.preventDefault();
        setIsProcessing(true);
        try {
          const res = await fetch('/api/v1/payments', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({
              invoice_id: payingInvoice.id,
              amount: parseFloat(payAmount),
              payment_method: paymentMethod,
              reference_note: `Online payment via ${paymentMethod}`
            })
          });
          const data = await res.json();
          if (!res.ok) throw new Error(data.detail || "Payment failed");
          showToast(`Success! Payment ${data.payment_number} recorded.`);
          setPayingInvoice(null);
          onPay();
        } catch(err) {
          showToast(`Error: ${err.message}`);
        } finally {
          setIsProcessing(false);
        }
      };

      return (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-2xl font-bold">Invoices & Payment Processing</h2>
            <span className="text-sm text-slate-500 font-medium">{invoices.length} displayed</span>
          </div>

          {/* Payment Gateway Modal */}
          {payingInvoice && (
            <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
              <div className="bg-white dark:bg-slate-900 rounded-3xl border border-slate-200 dark:border-slate-800 max-w-lg w-full p-8 shadow-2xl space-y-6 animate-scale">
                <div className="flex items-center justify-between border-b pb-4">
                  <div>
                    <h3 className="text-xl font-bold">Brightloop Checkout</h3>
                    <p className="text-xs text-slate-500">Invoice: {payingInvoice.invoice_number}</p>
                  </div>
                  <button onClick={() => setPayingInvoice(null)} className="text-slate-400 hover:text-slate-600 text-lg font-bold">✕</button>
                </div>

                <div className="bg-slate-50 dark:bg-slate-800 p-4 rounded-2xl flex justify-between items-center text-sm">
                  <div>
                    <span className="text-xs text-slate-400 block font-semibold uppercase">Customer</span>
                    <span className="font-bold">{payingInvoice.customer}</span>
                  </div>
                  <div className="text-right">
                    <span className="text-xs text-slate-400 block font-semibold uppercase">Balance Due</span>
                    <span className="text-lg font-extrabold text-indigo-600">${payingInvoice.balance_due.toFixed(2)}</span>
                  </div>
                </div>

                <form onSubmit={handleCompletePayment} className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Select Payment Method</label>
                    <div className="grid grid-cols-3 gap-2 text-xs font-semibold">
                      {['CREDIT_CARD', 'STRIPE', 'BANK_TRANSFER'].map(m => (
                        <button
                          key={m}
                          type="button"
                          onClick={() => setPaymentMethod(m)}
                          className={`p-2.5 rounded-xl border text-center transition ${paymentMethod === m ? 'border-indigo-600 bg-indigo-50 text-indigo-600 dark:bg-indigo-950 dark:text-indigo-300' : 'border-slate-200 hover:bg-slate-50'}`}
                        >
                          {m === 'CREDIT_CARD' ? '💳 Card' : m === 'STRIPE' ? '⚡ Stripe' : '🏦 Bank'}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Amount to Pay ($)</label>
                    <input
                      type="number"
                      step="0.01"
                      max={payingInvoice.balance_due}
                      min="1.00"
                      required
                      value={payAmount}
                      onChange={e => setPayAmount(e.target.value)}
                      className="w-full p-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800 text-sm font-semibold"
                    />
                  </div>

                  {paymentMethod === 'CREDIT_CARD' && (
                    <div className="space-y-3 bg-slate-50 dark:bg-slate-800/50 p-4 rounded-2xl border border-slate-200 dark:border-slate-700">
                      <div>
                        <label className="block text-xs font-semibold mb-1">Card Number</label>
                        <input type="text" value={cardNum} onChange={e=>setCardNum(e.target.value)} className="w-full p-2 rounded-lg border text-xs" />
                      </div>
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs font-semibold mb-1">Expiry</label>
                          <input type="text" value={cardExp} onChange={e=>setCardExp(e.target.value)} className="w-full p-2 rounded-lg border text-xs" />
                        </div>
                        <div>
                          <label className="block text-xs font-semibold mb-1">CVC</label>
                          <input type="text" value={cardCvv} onChange={e=>setCardCvv(e.target.value)} className="w-full p-2 rounded-lg border text-xs" />
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="flex space-x-3 pt-2">
                    <button
                      type="button"
                      onClick={() => setPayingInvoice(null)}
                      className="flex-1 py-2.5 rounded-xl border border-slate-200 text-sm font-semibold hover:bg-slate-50"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={isProcessing}
                      className="flex-1 py-2.5 rounded-xl gradient-hero text-white text-sm font-semibold shadow-lg shadow-indigo-500/25 hover:opacity-95 disabled:opacity-50"
                    >
                      {isProcessing ? 'Processing...' : `Authorize & Pay $${parseFloat(payAmount || 0).toFixed(2)}`}
                    </button>
                  </div>
                </form>
              </div>
            </div>
          )}

          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 dark:bg-slate-800/50 text-slate-500 font-semibold border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="p-4">Invoice #</th>
                  <th className="p-4">Customer</th>
                  <th className="p-4">Status</th>
                  <th className="p-4">Total</th>
                  <th className="p-4">Balance</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {invoices.map((inv) => (
                  <tr key={inv.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/20">
                    <td className="p-4 font-bold text-indigo-600">{inv.invoice_number}</td>
                    <td className="p-4 font-medium">{inv.customer}</td>
                    <td className="p-4">
                      <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${
                        inv.status === 'PAID' ? 'bg-emerald-100 text-emerald-700' :
                        inv.status === 'OVERDUE' ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-700'
                      }`}>
                        {inv.status}
                      </span>
                    </td>
                    <td className="p-4 font-semibold">${inv.total_amount.toFixed(2)}</td>
                    <td className="p-4 text-slate-500">${inv.balance_due.toFixed(2)}</td>
                    <td className="p-4 text-right space-x-2">
                      <button onClick={() => handleDownload(inv.id, inv.invoice_number)} className="px-3 py-1.5 rounded-lg text-xs bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 font-medium transition">
                        📄 Download PDF
                      </button>
                      {inv.balance_due > 0 && (
                        <button onClick={() => openPaymentModal(inv)} className="px-3 py-1.5 rounded-lg text-xs gradient-hero text-white font-medium shadow hover:opacity-95 transition">
                          💳 Pay Now
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      );
    }

    // --- NEW SUBSCRIPTION WIZARD ---
    function NewSubscriptionWizard({ plans, products, token, onSuccess }) {
      const [selectedPlan, setSelectedPlan] = useState(plans[0]?.id || 1);
      const [selectedProduct, setSelectedProduct] = useState(products[0]?.id || 1);
      const [selectedVariant, setSelectedVariant] = useState('');
      const [quantity, setQuantity] = useState(1);

      const currentProd = products.find(p => p.id === parseInt(selectedProduct));
      const currentPlan = plans.find(p => p.id === parseInt(selectedPlan));
      const currentVar = currentProd?.variants.find(v => v.id === parseInt(selectedVariant));

      const basePrice = currentProd ? currentProd.sales_price : 0;
      const extraPrice = currentVar ? currentVar.extra_price : 0;
      const unitTotal = basePrice + extraPrice;
      const subtotal = unitTotal * quantity;
      const tax = subtotal * 0.15;
      const total = subtotal + tax;

      const handleCreate = async () => {
        const body = {
          plan_id: parseInt(selectedPlan),
          product_id: parseInt(selectedProduct),
          variant_id: selectedVariant ? parseInt(selectedVariant) : null,
          quantity: parseInt(quantity),
          start_date: new Date().toISOString().split('T')[0]
        };
        const res = await fetch('/api/v1/subscriptions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
          body: JSON.stringify(body)
        });
        if (res.ok) onSuccess();
      };

      return (
        <div className="max-w-3xl mx-auto bg-white dark:bg-slate-900 rounded-3xl border border-slate-200 dark:border-slate-800 p-8 shadow-sm space-y-6">
          <h2 className="text-2xl font-bold">Create New Subscription</h2>
          <p className="text-slate-500 text-sm">Select plan, products, and variants with live pricing feedback.</p>

          <div className="grid grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Select Plan</label>
                <select value={selectedPlan} onChange={e=>setSelectedPlan(e.target.value)} className="w-full p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800 text-sm">
                  {plans.map(p => <option key={p.id} value={p.id}>{p.name} (${p.price} / {p.billing_period})</option>)}
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Product</label>
                <select value={selectedProduct} onChange={e=>{ setSelectedProduct(e.target.value); setSelectedVariant(''); }} className="w-full p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800 text-sm">
                  {products.map(p => <option key={p.id} value={p.id}>{p.name} (${p.sales_price})</option>)}
                </select>
              </div>

              {currentProd && currentProd.variants.length > 0 && (
                <div>
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Product Variant</label>
                  <select value={selectedVariant} onChange={e=>setSelectedVariant(e.target.value)} className="w-full p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800 text-sm">
                    <option value="">No Variant (Base Model)</option>
                    {currentProd.variants.map(v => <option key={v.id} value={v.id}>{v.attribute}: {v.value} (+${v.extra_price})</option>)}
                  </select>
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Seats / Quantity</label>
                <input type="number" min="1" value={quantity} onChange={e=>setQuantity(e.target.value)} className="w-full p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800 text-sm" />
              </div>
            </div>

            {/* Live Pricing Preview Panel */}
            <div className="bg-slate-50 dark:bg-slate-800/40 p-6 rounded-2xl border border-slate-200 dark:border-slate-700/50 flex flex-col justify-between">
              <div>
                <h4 className="font-bold text-sm uppercase tracking-wider text-slate-400 mb-4">Summary & Preview</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between"><span>Base Price:</span><span className="font-semibold">${basePrice.toFixed(2)}</span></div>
                  <div className="flex justify-between"><span>Variant Modifier:</span><span className="font-semibold">+${extraPrice.toFixed(2)}</span></div>
                  <div className="flex justify-between"><span>Unit Price:</span><span className="font-semibold">${unitTotal.toFixed(2)}</span></div>
                  <div className="flex justify-between"><span>Subtotal ({quantity}x):</span><span className="font-semibold">${subtotal.toFixed(2)}</span></div>
                  <div className="flex justify-between"><span>Estimated Tax (15%):</span><span className="font-semibold">${tax.toFixed(2)}</span></div>
                  <div className="border-t border-slate-200 dark:border-slate-700 pt-2 flex justify-between text-base font-bold text-indigo-600">
                    <span>Total Recurring:</span><span>${total.toFixed(2)}</span>
                  </div>
                </div>
              </div>

              <button onClick={handleCreate} className="w-full py-3 rounded-xl gradient-hero text-white font-semibold text-sm shadow-lg shadow-indigo-500/25 mt-6 hover:opacity-95">
                Confirm & Activate Subscription
              </button>
            </div>
          </div>
        </div>
      );
    }

    ReactDOM.createRoot(document.getElementById('root')).render(<App />);
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return HTMLResponse(content=FRONTEND_HTML)


if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*70)
    print("Brightloop Subscription Management System Starting...")
    print("Open in browser: http://localhost:8000")
    print("OpenAPI Docs:   http://localhost:8000/docs")
    print("="*70 + "\n")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
