#!/usr/bin/env bash
# Web application firewall (ENHANCEMENTS 2b, report sections 12 and 16).
#   bash infra/security/setup-waf.sh        (also run by infra/deploy-floci.sh)
#   RATE=500 bash infra/security/setup-waf.sh   per-IP limit per 5 minutes (default 300)
#
# Web ACL pb-web-acl, checked before any request reaches the API:
#   1. rate-limit-per-ip    block an IP that sends more than RATE requests in 5 minutes (stops password
#                           guessing and floods from one machine, before the 5-try account lock)
#   2. AWS common rules     SQL injection, cross-site scripting, bad bots, oversized bodies
#   3. known bad inputs     Log4j and similar exploit patterns
#   4. bad IP reputation    addresses AWS has seen attacking other customers
# Blocked requests get 403 and are counted in CloudWatch (metric per rule).
#
# Where it attaches: WAF works on CloudFront, REST APIs and load balancers, not on an API Gateway HTTP API
# like ours. On real AWS the ACL is created with scope CLOUDFRONT and attached to the CloudFront
# distribution in front of the API (ENHANCEMENTS 2a). Floci 2.5.0 has no CloudFront, so here the ACL is
# created and checked but not attached (report section 16).
# Safe to run again.
export AWS_PROFILE="${AWS_PROFILE:-floci}" AWS_PAGER="" MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/../.." || exit 1
ACL=pb-web-acl
SCOPE="${SCOPE:-REGIONAL}"     # CLOUDFRONT on real AWS (with --region us-east-1)
RATE="${RATE:-300}"

managed() {  # name priority -> a rule that uses an AWS managed rule group
  echo "{\"Name\":\"$1\",\"Priority\":$2,\"Statement\":{\"ManagedRuleGroupStatement\":{\"VendorName\":\"AWS\",\"Name\":\"$1\"}},
   \"OverrideAction\":{\"None\":{}},\"VisibilityConfig\":{\"SampledRequestsEnabled\":true,\"CloudWatchMetricsEnabled\":true,\"MetricName\":\"$1\"}}"
}
RULES="[
 {\"Name\":\"rate-limit-per-ip\",\"Priority\":0,
  \"Statement\":{\"RateBasedStatement\":{\"Limit\":$RATE,\"AggregateKeyType\":\"IP\"}},
  \"Action\":{\"Block\":{}},
  \"VisibilityConfig\":{\"SampledRequestsEnabled\":true,\"CloudWatchMetricsEnabled\":true,\"MetricName\":\"RateLimitPerIp\"}},
 $(managed AWSManagedRulesCommonRuleSet 1),
 $(managed AWSManagedRulesKnownBadInputsRuleSet 2),
 $(managed AWSManagedRulesAmazonIpReputationList 3)]"
VIS='SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=pbWebAcl'

echo "WAF web ACL $ACL (scope $SCOPE): $RATE requests per IP per 5 minutes + 3 AWS managed rule groups"
EXISTING=$(aws wafv2 list-web-acls --scope $SCOPE --query "WebACLs[?Name=='$ACL'] | [0].[Id,LockToken]" --output text)
if [ -z "$EXISTING" ] || [ "$EXISTING" = None ]; then
  aws wafv2 create-web-acl --name $ACL --scope $SCOPE --default-action Allow={} --rules "$RULES" \
    --visibility-config $VIS --description "Personal Budget Buckets API firewall" \
    --tags Key=Project,Value=personal-budget-buckets Key=Owner,Value=saged-ehab-244694 > /dev/null || exit 1
else
  read -r ID TOKEN <<< "$EXISTING"
  aws wafv2 update-web-acl --name $ACL --scope $SCOPE --id "$ID" --lock-token "$TOKEN" \
    --default-action Allow={} --rules "$RULES" --visibility-config $VIS > /dev/null || exit 1
fi
ID=$(aws wafv2 list-web-acls --scope $SCOPE --query "WebACLs[?Name=='$ACL'] | [0].Id" --output text)
aws wafv2 get-web-acl --name $ACL --scope $SCOPE --id "$ID" \
  --query 'WebACL.Rules[].[Priority,Name,Statement.RateBasedStatement.Limit || `AWS managed rule group`]' \
  --output text | sed 's/^/  rule /'
echo "  Not attached on Floci (no CloudFront). On AWS: attach to the CloudFront distribution with"
echo "  aws cloudfront update-distribution (WebACLId = the ACL ARN)."
