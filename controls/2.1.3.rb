# encoding: UTF-8

control 'C-2.1.3' do
  title 'Ensure Organizations management account is not used for workloads'
  desc  "
    Ensure that the AWS Organizations management account is used only for organizational governance tasks and does not host production workloads, applications, or business data. The management account is the most privileged account in an AWS Organization and performs sensitive administrative functions such as creating and managing member accounts, applying service control policies (SCPs), and managing consolidated billing. Workloads, applications, and associated data should be deployed in dedicated member accounts, not in the management account.

    The management account has unique privileges that cannot be restricted by SCPs, making it the highest-risk account in an organization. Deploying workloads or storing business data in the management account increases the attack surface and blast radius of a compromise. If a workload vulnerability or misconfiguration occurs in the management account, it could grant attackers access to organization-wide administrative capabilities.
  "
  desc  'rationale', "
    Ensure that the AWS Organizations management account is used only for organizational governance tasks and does not host production workloads, applications, or business data. The management account is the most privileged account in an AWS Organization and performs sensitive administrative functions such as creating and managing member accounts, applying service control policies (SCPs), and managing consolidated billing. Workloads, applications, and associated data should be deployed in dedicated member accounts, not in the management account.

    The management account has unique privileges that cannot be restricted by SCPs, making it the highest-risk account in an organization. Deploying workloads or storing business data in the management account increases the attack surface and blast radius of a compromise. If a workload vulnerability or misconfiguration occurs in the management account, it could grant attackers access to organization-wide administrative capabilities.
  "
  desc  'check', "
    1. Confirm which AWS account is the management account for the organization (for example, via AWS Organizations \"Overview\" page or organizational documentation).

    2. Ensure you have read‑only access to review resources in this account.

    3. Use your organization's standard discovery methods (for example, AWS Config, CMDB/asset inventory, or CSPM) to obtain a list of services and resources running in the management account.
    - At a minimum, identify compute, storage, database, and application services (for example, EC2, Lambda, ECS, S3, RDS, DynamoDB, API Gateway, load balancers).

    4. For each identified resource, determine whether it is:

    - Governance/security: resources that support centralized management, logging, audit, or security (for example, org‑wide CloudTrail, Config aggregator, Security Hub or GuardDuty delegated admin, billing/cost tooling).

    - Workload/business: resources that support business applications, production or non‑production workloads, or customer‑facing systems.

    5. If any workload/business resources are present in the management account, record this as a gap and document the affected services and resource types
  "
  desc  'fix', "
    1. Inventory all workload resources currently in the management account (compute, storage, databases, application services).

    2. For each class of workload resource (for example, production, non‑production, shared services), create or confirm dedicated member accounts within the organization and place them into the appropriate OUs.

    3. For each workload resource, design a migration plan to the appropriate member account. 
    - Execute the migrations in phases, starting with lower‑risk environments (for example, development/test) before production.

    4. Review and adjust IAM roles and permissions in the management account so that only personnel responsible for organization governance and security have access

    5. Update architecture diagrams, runbooks, and onboarding processes to state that new workloads must be deployed only into designated workload accounts, not the management account.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.1.3'
  tag cis_rid:               '2.1.3'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-020103r1_rule'
  tag cis_version:           '7.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  # Why this stays attestation (and not dual-mode like 2.1.2/2.1.5/2.1.6):
  # Determining whether the management account hosts "workloads" requires
  # enumerating compute (EC2, RDS, Lambda, ECS, EKS, …) IN THE MANAGEMENT
  # ACCOUNT and classifying each resource as workload vs.
  # infrastructure-support (the Organizations identity layer itself
  # implies *some* resources; the question is whether they go beyond
  # that). Automating this would require:
  #   (a) AssumeRole into the management account (already plumbed via
  #       aws_organizations_role_arn — see C-2.1.2 pattern),
  #   (b) Cross-service enumeration of every compute/storage type, and
  #   (c) A workload-vs-infra classifier — the semantic that's hard.
  #
  # (a) and (b) are mechanical but expensive (large new helper surface).
  # (c) is genuinely a governance judgement: a CI/CD bastion in the
  # mgmt account is arguably infra; a developer's test Lambda is a
  # workload. Periodic-review attestation lets the org owner make that
  # call without litigating it in code.
  describe 'Organizations management account not used for workloads (attestation-required)' do
    skip 'attestation-required: requires (1) AssumeRole into the management account via aws_organizations_role_arn, (2) cross-service compute enumeration in that account, and (3) a workload-vs-infrastructure classification judgement that is genuinely governance-bound. Periodic-review attestation per profiles/cis-aws-foundations/attestations.example.json control_id C-2.1.3.'
  end
end
