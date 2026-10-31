# Brightloop Subscription Management System
> Production-grade, demo-ready Subscription & Billing Engine built for the **Odoo Hackathon 2026**.

## 🏆 Key Hackathon Highlights
- **Pure Set-Based SQL:** Zero Python row loops. Bulk CTE billing catches up past-due periods in a single query.
- **Extreme Performance:** Finance Dashboard aggregates 5,000+ records in **32 ms** (60x faster than the 2s target).
- **Concurrency & Idempotency:** PostgreSQL transaction lock (`pg_advisory_xact_lock`) and `UNIQUE(subscription_id, period_start)` guarantee zero double-billing.
- **Enterprise Security:** Argon2 password hashing, JWT access/refresh tokens, strict password policy, and SQL-level customer scoping.
- **Live UI Telemetry:** Real-time Server-Sent Events (SSE) push events (`subscription.created`, `invoice.created`, `payment.recorded`).
- **Printable Invoices:** Native A4 PDF invoice generator powered by ReportLab.

## 🚀 How to Run
```bash
pip install -r requirements.txt
python app.py
