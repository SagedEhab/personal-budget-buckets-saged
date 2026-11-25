# Saged Ehab (244694): Buckets service and infrastructure

Personal proof-of-work repository for **26CSCN29H Cloud Computing and Cloud Security**, Team 04,
project **Personal Budget Buckets**.

Team repository (the full, integrated application): https://github.com/SagedEhab/personal-budget-buckets

## My component

**Buckets service** (`services/buckets-service/`): users split their monthly budget into buckets
(e.g. Rent, Food, Transport), each with a monthly limit.

Business rules:
- **Effective limit per month:** monthly limit + rollover of last month's unused budget (if rollover is
  on) + transfers in - transfers out.
- **Hard limits:** a hard-limit bucket rejects an expense that would take it over its effective limit
  (`POST /api/buckets/:id/check-spend`, called by Transactions before an expense is saved).
- **Near-limit alerts:** when spending passes the bucket's alert threshold, an alert is stored and
  published to the SNS topic `pb-budget-alerts`, at most once per bucket, month and level.
- **Transfers:** move unused budget from one bucket to another (`POST /api/buckets/transfers`),
  with ownership checks on both buckets.
- **Archive / restore** buckets, and **templates** (managed by admins) to create a set of buckets in one step.
- **Admin statistics** (`GET /api/buckets/admin/stats`), admin role only.

Integration: the Transactions service calls Buckets (Lambda Invoke) to check and record spending, and
the Insights service reads buckets for the dashboard.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET / POST | `/api/buckets` | List / create buckets |
| GET / PATCH / DELETE | `/api/buckets/:id` | Read / update / delete one bucket |
| POST | `/api/buckets/:id/archive`, `/restore` | Archive or restore |
| POST | `/api/buckets/:id/check-spend`, `/evaluate` | Limit check and alert evaluation (called by Transactions) |
| GET / POST | `/api/buckets/transfers` | List / make transfers |
| GET / PATCH | `/api/buckets/alerts`, `/alerts/:id` | List alerts / mark as read |
| GET / POST / DELETE | `/api/buckets/templates`, `/templates/:id` | Bucket templates |
| GET | `/api/buckets/admin/stats` | Admin only |

All routes need a valid login token (401 without one), check that the record belongs to the user
(403/404 otherwise) and validate input (400).

## AWS services in my component (deployed on Floci)

Lambda (`pb-buckets-api`), API Gateway HTTP API, DynamoDB (`PBBuckets`), SNS (`pb-budget-alerts`),
Secrets Manager (JWT signing key), IAM (least-privilege role `pb-buckets-role`), CloudWatch Logs,
metric filters and alarms.

I also own the infrastructure for the whole team:
- `infra/deploy-floci.sh`, `check-floci.sh`, `destroy-floci.sh`: deploy and smoke-test the app on Floci
- `infra/iam/`: one least-privilege IAM policy per Lambda
- `infra/monitoring/setup-monitoring.sh`: CloudWatch metric filters and alarms
- `packages/pb-common/`: shared auth middleware, validation, logging and data store

## Run my service on a PC

```bash
cd services/buckets-service
npm install
npm run dev        # check: http://localhost:3002/api/buckets/health
```
