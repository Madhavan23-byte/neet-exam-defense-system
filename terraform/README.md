# B-SEA Phase 3C-2: AWS Terraform Staging Infrastructure

## 1. Overview

This directory contains the Infrastructure-as-Code (Terraform) specifications for the **Bharat Secure Examination Architecture (B-SEA)** staging deployment in AWS region `ap-south-1` (Mumbai).

The design implements the approved **BSEA-ARCH-P3C-REV-03** cloud foundation, establishing an isolated network perimeter, managed connection pooling, distributed in-memory rate limiting, containerized backend orchestration, edge content delivery, and regional web application firewall protection.

---

## 2. Directory Structure

```
terraform/
├── README.md            # Architectural documentation and operational runbook
├── modules/
│   ├── vpc/             # Dynamic 2-AZ VPC, subnets, route tables, single NAT Gateway
│   ├── security_groups/ # Strict SG rules chaining ALB -> ECS -> RDS Proxy -> RDS / Redis
│   ├── secrets/         # High-entropy Secrets Manager containers for DB, Redis, and JWT
│   ├── iam/             # Least-privilege roles: ECS Execution, ECS Task, RDS Proxy Assume
│   ├── ecr/             # Private ECR repository with scan-on-push and lifecycle rules
│   ├── rds/             # RDS PostgreSQL 16 instance, subnet group, parameter group
│   ├── rds_proxy/       # RDS Proxy, default target group, and target registration
│   ├── elasticache/     # ElastiCache Redis 7 replication group (TLS + AUTH, private subnet)
│   ├── alb/             # ALB, HTTPS:443 listener with ACM, HTTP:80 redirect, live target group
│   ├── ecs/             # ECS Cluster, Fargate Task Definition, ECS Service, autoscaling
│   └── s3_frontend/     # S3 bucket, OAC policy, CloudFront distribution with dual origins
│
└── environments/
    └── staging/
        ├── main.tf          # Module wiring & dependency graph
        ├── variables.tf     # Staging input variable declarations
        ├── outputs.tf       # Non-sensitive endpoints & resource identifiers
        ├── terraform.tfvars # Non-sensitive staging parameter values
        └── providers.tf     # AWS provider (~> 5.80) and backend configuration
```

---

## 3. Architecture & Security Invariants

### 3.1 Network Isolation & Security Groups
- **Public Subnets**: Ingress restricted to ALB port 80 (HTTP redirect) and port 443 (HTTPS).
- **Private Application Subnets**: ECS Fargate tasks reside with no public IP. Ingress is restricted **strictly to the ALB Security Group** on port 8000.
- **Isolated Database Subnets**: RDS PostgreSQL, RDS Proxy, and ElastiCache reside in private database subnets with no internet gateway route.
- **Strict Security Group Chaining**:
  - `ALB SG` $\rightarrow$ `ECS SG` (port 8000).
  - `ECS SG` $\rightarrow$ `RDS Proxy SG` (port 5432) and `Redis SG` (port 6379).
  - `RDS Proxy SG` $\rightarrow$ `RDS SG` (port 5432).
  - **Direct ECS $\rightarrow$ RDS access is blocked by security group rules.**

### 3.2 Database & Connection Layer
- **PostgreSQL 16**: Standard AWS RDS (Single-AZ for staging; gp3 storage; storage encryption enabled via AWS-managed key). **Not Aurora**.
- **AWS RDS Proxy**: Manages connection pooling between multi-worker ECS tasks and PostgreSQL.
- **Authentication**: RDS Proxy authenticates against PostgreSQL using master credentials stored in AWS Secrets Manager.

### 3.3 Redis TLS & Authentication
- **Engine**: Redis OSS 7.1 with cluster mode disabled (single primary node for staging).
- **In-Transit TLS**: `transit_encryption_enabled = true` is mandatory.
- **Client Authentication**: `auth_token` required for all connections.
- **Connection Scheme**: Container tasks connect via `rediss://` protocol.

### 3.4 Edge & Ingress Perimeter Protection
- **CloudFront Dual Origins**:
  - `/*`: Private S3 bucket via Origin Access Control (OAC) with `Managed-CachingOptimized`.
  - `/api/*` and `/health/*`: ALB origin with `Managed-CachingDisabled` (no-cache).
  - **Examination-Data Cache Invariant**: CloudFront never caches API responses, authentication tokens, question access grants, autosaves, or break-glass responses.
- **AWS WAFv2**: Regional Web ACL attached to ALB providing IP rate-limiting and AWS Managed Core and Known Bad Inputs rule sets.

### 3.5 Health Check Semantics
- **ALB Target Group Health Check**: Configured to `/health/live` (lightweight event-loop liveness probe).
- **Deep Dependency Check**: `/health/ready` (checks DB, Redis, and KMS) is preserved for monitoring, operations, and readiness orchestration, ensuring transient cache degradation does not evict healthy application instances from ALB routing.

---

## 4. Staging vs. Production Boundary

The staging configuration incorporates specific cost and teardown-friendly compromises that are explicitly restricted to staging:

| Component | Staging Configuration | Production Architecture Requirement |
|---|---|---|
| **Egress NAT** | Single NAT Gateway in AZ 1 | Multi-AZ NAT Gateways (one per AZ) |
| **PostgreSQL** | Single-AZ RDS (`db.t4g.medium`) | Multi-AZ RDS PostgreSQL with synchronous standby |
| **Redis Cache** | Single Primary Node (No Replica) | Multi-AZ Replication Group with Automatic Failover |
| **ECS Compute** | Min 2 / Max 4 Fargate Tasks | Dynamic auto-scaling (Min 4 / Max 20+ tasks across 3 AZs) |
| **Teardown Controls** | `skip_final_snapshot = true`, `force_destroy = true` | Snapshot retention policies, S3 Object Lock, deletion protection |

---

## 5. Secrets & State Security

1. **Zero Hardcoded Secrets**: All passwords, tokens, and keys are generated dynamically via `random_password` and stored in AWS Secrets Manager.
2. **State Protection**: Because generated secrets exist in plaintext inside the Terraform state file, remote state storage must be protected.
3. **Native S3 State Locking**: Remote state utilizes Terraform's native S3 state locking (`use_lockfile = true`) eliminating any DynamoDB dependency (DynamoDB locking is considered legacy/deprecated):
   - S3 State Bucket Architecture:
     - SSE-S3 / KMS encryption
     - Object versioning enabled
     - S3 Block Public Access (all 4 settings enabled)
     - Restricted IAM access policies
     - Terraform native `.tflock` state locking (`use_lockfile = true`)
4. **Local Safety**: `.gitignore` strictly excludes `*.tfstate`, `*.tfstate.*`, `*.tfplan`, and `.terraform/`. Dependency lock file (`.terraform.lock.hcl`) is committed and tracked.

---

## 6. Validation & Execution Runbook

To format, validate, and plan the staging infrastructure:

```bash
# 1. Format code across all modules
terraform fmt -check -recursive

# 2. Initialize and validate syntax
cd terraform/environments/staging
terraform init
terraform validate

# 3. Dry-run execution plan
terraform plan -var-file="terraform.tfvars" -out=tfplan
```
