# Floci deploy and screenshot checklist (do this yourself, before Wed 25 Nov 23:59)

The deploy scripts are an **AI-assisted draft that has never been run** (Docker and the AWS CLI were
not installed when they were written). Expect to fix a few things on the first run. Every fix you
make is real work to mention in your contribution statement and the "Difficulties" section.
Everything runs on your own PC: Floci is free and no AWS account or payment is involved.

Commands come from the module's *Quick Installation Guide: Docker, Git Bash and Floci* and Lab 7.

---

## Part A: install (once, about 30 minutes)

- [ ] **A1.** Right-click Start → **Terminal (Admin)**, run the line below, then restart the PC:
  ```powershell
  wsl --install --nodistribution
  ```
- [ ] **A2.** Install **Docker Desktop** from https://www.docker.com/products/docker-desktop (keep *Use WSL 2* ticked). Start it, accept the licence, skip sign-in, and wait for **Engine running** in the bottom-left corner.
- [ ] **A3.** In **Terminal (Admin)**, run the line below, then restart the PC. Node.js is already installed, so winget may skip it.
  ```powershell
  winget install Amazon.AWSCLI OpenJS.NodeJS.LTS Git.Git
  ```
- [ ] **A4.** Open **Git Bash** and check the four tools:
  ```bash
  docker --version && aws --version && node --version && git --version
  ```
- [ ] **A5.** Create the `floci` AWS profile. The keys are dummy values; `test` is not a secret.
  ```bash
  aws configure set aws_access_key_id test --profile floci
  aws configure set aws_secret_access_key test --profile floci
  aws configure set region us-east-1 --profile floci
  aws configure set endpoint_url http://localhost:4566 --profile floci
  echo 'export AWS_PROFILE=floci AWS_PAGER="" MSYS_NO_PATHCONV=1' >> ~/.bashrc
  source ~/.bashrc
  ```

## Part B: start Floci and deploy (Git Bash)

- [ ] **B1.** Go to your clone of the repository.
  ```bash
  cd personal-budget-buckets        # your clone of the repository
  ```
- [ ] **B2.** Start Floci and check that it answers. The second command should print `000000000000`.
  ```bash
  docker compose -f infra/floci/docker-compose.yml up -d
  aws sts get-caller-identity --query Account --output text
  ```
- [ ] **B3.** Run the local tests once more. They should show 39 passed.
  ```bash
  npm run sync && npm test && npm run evidence
  ```
- [ ] **B4.** Deploy everything: tables, secret, SNS, S3, IAM roles, 4 Lambdas, API Gateway, website and monitoring. **Save the full output.** It is the evidence for report §6.
  ```bash
  bash infra/deploy-floci.sh 2>&1 | tee evidence/floci-deploy-output.txt
  ```
  If a step fails, read the error, fix the script or the policy, and run it again (the script is safe to re-run). Note every fix you make.
- [ ] **B5.** Create the first admin. Use your own e-mail and a password of at least 10 characters with letters and digits. It is typed into your shell only and never saved in a file.
  ```bash
  cd services/auth-service
  USERS_TABLE=PBUsers AWS_ENDPOINT_URL=http://localhost:4566 ADMIN_EMAIL='you@example.com' ADMIN_PASSWORD='<your-own-password>' node scripts/seed-admin.js
  cd ../..
  ```
- [ ] **B6.** Run the smoke test and save the output:
  ```bash
  bash infra/check-floci.sh 2>&1 | tee evidence/floci-check-output.txt
  ```
- [ ] **B6b.** Governance checks (report §8): check the resource tags and whether Floci supports CloudTrail. Screenshot both outputs.
  ```bash
  aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=personal-budget-buckets --query "ResourceTagMappingList[].ResourceARN"
  aws cloudtrail describe-trails
  ```
  If either command says it is not supported, write that in the red note in report §8 and in the §16 limitations table.
- [ ] **B7.** Open the deployed website at http://localhost:4566/pb-web/index.html. Open Floci Dash at http://localhost:4566/_floci/ui.

## Part C: security checks against the Floci API (for report §4 and §12)

Set the API URL once. Use the ID printed by the deploy script.
```bash
API=$(aws apigatewayv2 get-apis --query "Items[?Name=='pb-http-api'].ApiId | [0]" --output text)
API=http://$API.execute-api.localhost.floci.io:4566
```
Run each line and screenshot the command together with its output. Get a user's TOKEN from the login response, or from the browser: DevTools → Application → Session Storage → `pb_token`.
- [ ] **ST-01 no token → 401:** `curl -i $API/api/buckets`
- [ ] **ST-04 user on an admin route → 403:** `curl -i $API/api/auth/users -H "Authorization: Bearer $TOKEN"`
- [ ] **ST-05 another user's bucket → 404:** log in as user B, then `curl -i $API/api/buckets/<user A's bucket id> -H "Authorization: Bearer $TOKEN_B"`
- [ ] **ST-08 invalid input → 400:** `curl -i -X POST $API/api/buckets -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"name":"X","monthlyLimit":-5}'`
- [ ] **ST-09 register as admin → 400:** `curl -i -X POST $API/api/auth/register -H 'Content-Type: application/json' -d '{"name":"Eve","email":"eve@example.com","password":"EvePass20266","role":"admin"}'`
- [ ] **ST-10 lockout → 401 ×5 then 429:** run the line below 6 times, then try the correct password.
  `curl -s -o /dev/null -w '%{http_code}\n' -X POST $API/api/auth/login -H 'Content-Type: application/json' -d '{"email":"<user>","password":"wrong-pass-1"}'`
- [ ] **ST-04 burst for the 403 alarm:** `for i in $(seq 12); do curl -s -o /dev/null -w '%{http_code} ' $API/api/auth/users -H "Authorization: Bearer $TOKEN"; done`

Copy the real results into the "Actual" column in report §12. Add a column or note saying "Floci re-run", next to the local results.

## Part D: every screenshot to take (one per red placeholder in the report)

| # | Report § | Screenshot |
|---|---|---|
| 1 | §4 | Normal user calling `GET /api/auth/users` and getting **403** (Part C, ST-04) |
| 2 | §5 | Deployed site: expense logged in **USD**, showing the converted EGP amount in the transactions list |
| 3 | §6 | Terminal output of `deploy-floci.sh` and `check-floci.sh` (all PASS), with the API and website URLs |
| 4 | §8 | Floci Dash / CLI: IAM role `pb-buckets-role` and its inline policy; S3 `pb-receipts-244694` Block Public Access plus encryption (`aws s3api get-public-access-block --bucket pb-receipts-244694`, `get-bucket-encryption`); Secrets Manager `pb/jwt-secret` (name only, **never the value**) |
| 5 | §9 | GitHub commit history / contributors graph showing each member's commits |
| 6 | §11 | CloudWatch Logs: JSON request lines from one Lambda (`aws logs tail /aws/lambda/pb-buckets-api` or Floci Dash). Check that no password or token appears |
| 7 | §11 | Metric filter `FailedLogins` and alarm `pb-failed-logins-spike` in **ALARM** after the ST-10 lockout run (`aws cloudwatch describe-alarms --alarm-names pb-failed-logins-spike`) |
| 8 | §11 | The burst of 403 responses (Part C) and the `AccessDenied` metric/alarm |
| 9 | §12 | ST-01, ST-04, ST-05, ST-08, ST-10 against Floci (Part C) |
| 10 | §13 | The deployed site: dashboard, buckets with a near-limit alert, the hard-limit block, a transfer, a CSV report download, the admin page |
| 11 | §15 | One recovery you actually tried, e.g. archive then restore a bucket, or `bash infra/destroy-floci.sh` then `deploy-floci.sh`, and `check-floci.sh` passing again |
| + | Statements | Each member: screenshots of their own service working on Floci, plus links to their commits |

Save them in `implementation-AI-assisted-draft/evidence/floci-screenshots/`. Paste each one into the
report in place of its red box (Insert → Pictures).

## Part E: repository, video, report, submission

- [ ] **E1.** Run a secret scan before pushing. It should find nothing except the dummy `test` profile keys, which live outside the repository.
  ```bash
  git init && git add -A && git status        # check that .env and node_modules are NOT listed
  grep -rIn --exclude-dir=node_modules -E "AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|JWT_SECRET=[^r]" . || echo "no secrets found"
  ```
- [ ] **E1b.** Dependency scan (report §9). It should report 0 high or critical issues.
  ```bash
  npm run audit
  ```
- [ ] **E2.** Create a **public** GitHub repository and push. Each member commits their own service and edits from their own account. Ask staff whether they want one repository per service (TA advice to other teams).
- [ ] **E2b.** On GitHub, open the **Actions** tab. Check that the `security-checks` workflow passed, and screenshot it for report §9.
- [ ] **E3.** Record a video of at most 5 minutes following the shot list in report §10. Upload it to Drive or YouTube and set it to **"anyone with the link can view"**.
- [ ] **E4.** Edit the shared report (on OneDrive/Google Drive) in Word:
  - Replace every red placeholder.
  - Fill in teammate names and IDs, and the repository, video and URL links.
  - Each member writes their own contribution statement from the template.
  - Complete Appendix A "What the team did".
  - Re-read everything in your own words.
  - Update the table of contents (right-click it → *Update field*).
  - Delete the red "AI-assisted draft" lines and the header text last.
- [ ] **E5.** Submit on Moodle ("Cloud Secuirty CW Final Phase submission") **yourselves**, before **Wed 25 Nov 2026, 23:59**. Then rehearse the live demo with `prep-pack/06-demo-and-viva-prep.md`.

To stop Floci, run `docker compose -f infra/floci/docker-compose.yml down`. Your data is kept in the Docker volume.
