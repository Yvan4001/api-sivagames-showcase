# SivaGames — Combined Architecture & Showcase ✅

## Overview
This combined document merges architecture, security, and operational guidance for the SivaGames Web API: AES encryption, email sending, invoices, orders, payments (Stripe/PayPal), legal notices, and deployment tips. Use it as a single reference for developers, reviewers, and operators.

```mermaid graph TD
    subgraph "Client Layer"
        User[Client / Frontend]
    end

    subgraph "API Layer (ASP.NET Core)"
        Controller[Controllers] -->|Auth & Validation| Service[Services Layer]
    end

    subgraph "Business Logic & Security"
        Service -->|AES Encryption| Utils[Utils / Crypto]
        Service -->|Business Rules| Domain[Domain Entities]
    end

    subgraph "Data Access"
        Service -->|Map DTO/Entity| Repo[Repository Layer]
        Repo -->|EF Core| DB[(SQL Database)]
    end

    subgraph "External Infrastructure"
        Service -.->|Webhook & API| Stripe[Stripe / PayPal]
        Service -.->|SMTP| Email[Email Provider]
    end

    User -->|HTTPS/JWT| Controller
```
---

## Table of Contents
- Overview
- Architecture Summary 🔧
- Security: AES & Secrets (🔒)
- Email Sender (✉️)
- Orders & Invoices (🧾)
- Payments: Stripe & PayPal (💳💸)
- Other Important Details (🔧)
- Configuration examples
- Deployment & Quick Start
- Legal & Compliance (Disclaimer / Trademark) ⚖️
- Quick tips & checklist ✅
- Contact & Security Reporting

---

## Architecture Summary 🔧
**High-level design:** layered ASP.NET Core Web API with a clear separation of concerns.

- **Controllers/** → HTTP endpoints (request validation, authorization)
- **Services/** → Business logic and orchestration (e.g., `OrderService`, `InvoiceService`, `EmailService`)
- **Repository/** → Data persistence (EF Core), mapping between Entities and DTOs
- **Dto/** → API input/output shapes (e.g., `OrderDto`, `InvoiceDto`)
- **Entity/** → Domain models persisted by the database
- **Utils/** → Utilities (AES helpers, PDF generation, tax utils)

Data flow (simplified):
Controller → Service → Repository → DbContext → Database

Entity ↔ DTO examples:
- Order: `Order` (Entity) ↔ `OrderDto` (DTO) ↔ `OrderProducts`
- Invoice: `Invoice` (Entity) ↔ `InvoiceDto` (DTO) (contains `OrderProductDto` line items)
- Customer/User/Address: `Customer`, `User`, `Address` ↔ `CustomerDto`, `UserDto`, `AddressDto`

Notes:
- Keep DTOs thin and use them at API boundaries. Do not expose internal entities directly in responses.
- Services handle business rules: tax calculation, idempotency, invoice numbering, PDF generation.
- Repositories should be unit-testable and not contain business logic.

---

## Security: AES & Secrets (🔒)
- **AES mode**: Prefer AES-GCM (AEAD) for confidentiality and integrity. Use `AesGcm` or an HSM-backed solution for production.
- **Key management**:
  - Never check keys into source. Use environment variables or secret stores (Azure Key Vault, AWS Secrets Manager).
  - Keep a key rotation plan and preserve older keys for decryption of archived data.
- **IV/Nonce**: Use a fresh cryptographic nonce/IV for each operation and never reuse with the same key.
- **Passwords**: Hash with Argon2/bcrypt/PBKDF2; do not AES-encrypt passwords for storage.
- **Transport**: Enforce TLS for all inbound/outbound traffic.
- **Implementation note**: This repo provides `Utils/AESEncryption.cs` (CBC with IV prefix) and can be complemented with an AES-GCM helper if you prefer AEAD.

---

## Email Sender (✉️)
- Implementation: `Services/EmailService.cs` uses `SmtpClient` to send transactional emails and QuestPDF to generate PDFs.
- Configurable via environment variables:
  - `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_EMAIL` (from address)
- Best practices:
  - Prefer transactional providers (SendGrid, Amazon SES) for production.
  - Use TLS for SMTP or provider API via HTTPS.
  - Sanitize templates; use CTA buttons instead of exposing tokens/links as raw text.
  - Track bounces/deliverability with provider webhooks and process them.
- Attachments: Invoice and order PDFs are generated in-memory and attached to emails. Ensure attachments are scanned/validated when needed.

---

## Orders & Invoices (🧾)
- Typical flow:
  1. Customer creates order (POST /orders).
  2. Payment is processed (Stripe/PayPal or other gateway).
  3. On payment success, create invoice record and optionally generate PDF and send via email.
- Invoice requirements:
  - Unique and traceable invoice numbers (sequential or structured).
  - Store invoice metadata (customer, order id, date, items, prices, tax) in DB.
  - Keep country-specific tax rules up-to-date.
- Idempotence & status handling:
  - Use enums for order/invoice statuses (Pending, Paid, Cancelled, Refunded).
  - Make webhook handlers idempotent and validate signatures.
- Reconciliation:
  - Persist webhook events and build nightly reconciliation jobs to match payments and invoices.

---

## Payments

### Stripe (💳)
- Location: See `PaiementService.cs` and `STRIPE_TAX_SETUP.md` for tax setup.
- Flow:
  1. Create PaymentIntent/Checkout session server-side with order details.
  2. Return client_secret/checkout URL to client.
  3. Confirm payment via webhooks; verify signature using `STRIPE_WEBHOOK_SECRET`.
  4. On success, create invoice + email.
- Config:
  - `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`
- Tips:
  - Use idempotency keys for create/payment operations.
  - Consider enabling Stripe Tax for automated tax calculation.

### PayPal (💸)
- Location: See `PAYPAL_TAX_UPDATE.md` for PayPal tax notes and `PaiementService.cs` for PayPal handling.
- Flow:
  1. Server creates PayPal order and returns an approval URL.
  2. Client redirects user to PayPal for approval.
  3. Server captures the PayPal order and verifies capture.
  4. On success, create invoice + email (same downstream flow as Stripe).
- Config:
  - `PAYPAL_CLIENT_ID`, `PAYPAL_SECRET`, `PAYPAL_MODE` (`sandbox`/`live`), `PAYPAL_WEBHOOK_ID`
- Tips:
  - Keep tax calculation consistent with Stripe (DB or provider-driven).
  - Verify PayPal webhook signatures and log payloads for audits.

---

## Other Important Details (🔧)
- Authentication & Authorization:
  - Use JWT with short TTLs + refresh tokens if applicable. Protect refresh tokens and validate scopes/roles.
- Logging & Auditing:
  - Redact secrets, keep financial audit logs (orders/refunds/invoices), and avoid logging PII in plaintext.
- Error handling:
  - Return structured errors and implement retry/circuit breaker patterns for external calls.
- Privacy & Compliance:
  - Implement deletion and data retention endpoints for GDPR/CCPA compliance.
- Testing:
  - Unit and integration tests for payments, invoices, email sending, and encryption.

---

## Configuration examples
**appsettings (example)**

```json
{
  "Smtp": {
    "Host": "smtp.example.com",
    "Port": 587,
    "User": "${SMTP_USER}",
    "Password": "${SMTP_PASS}",
    "UseTls": true,
    "From": "no-reply@example.com"
  },
  "Encryption": {
    "KeyVaultKeyName": "my-app-aes-key"
  }
}
```

**Essential environment variables**
- `AES_KEY` (Base64 or hex representation)
- `JWT_SECRET_KEY`
- `MYSQL_CONNECTION_STRING`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_EMAIL`
- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`
- `PAYPAL_CLIENT_ID`, `PAYPAL_SECRET`, `PAYPAL_MODE`

---

## Deployment & Quick Start
1. Copy `.env.example` to `.env` and populate required values (or use your secrets store).
2. Run database migrations with EF Core.
3. Start the API: `dotnet run --project api-sivagames`.
4. Use Swagger (`/swagger`) to explore endpoints in development.

---

## Legal, License, Disclaimer & Trademark (⚖️)

### License
- This project is licensed under the **MIT License**. See `LICENCE` in the repository root for the complete license text and attribution requirements.

### Disclaimer
- The software is provided **"AS IS"** without warranties of any kind. SivaGames and contributors accept no liability for damages arising from the use of this project.
- Users are responsible for ensuring compliance with applicable laws, tax rules, and third-party service terms when deploying this software.
- For the full disclaimer, see `DISCLAIMER.md`.

### Trademark
- The **SivaGames** name and logos are protected trademarks. See `TRADEMARK.md` for permitted usage, branding guidelines, and restrictions.
- Contact `contact@sivagames.com` for permission requests or trademark inquiries.

### Payment processors & PII
- Payment processors (Stripe, PayPal) remain subject to their own Terms of Service and Privacy Policies — do **not** store raw card PANs; follow PCI requirements.
- Follow applicable data protection regulations (GDPR/CCPA) and implement consent, retention, and deletion flows where required.

---

## Quick tips & checklist ✅
- Use AES-GCM (or equivalent AEAD) and rotate keys.
- Never store secrets in source. Use key vaults or environment secrets.
- Use TLS for all transport.
- Verify webhook signatures and make endpoints idempotent.
- Track email delivery and handle bounces.
- Keep invoice numbers traceable and legally compliant.

---

## Contact & Security Reporting
For security issues or responsible disclosure, contact: `contact@sivagames.com` (do not open a public issue with exploit details).
