# encoding: UTF-8

control 'C-2.19' do
  title 'Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments'
  desc  "
    In multi-account environments, IAM user centralization facilitates greater user control. User access beyond the initial account is provided through role assumption. Centralization of users can be accomplished through federation with an external identity provider or through the use of AWS Organizations. AWS IAM Identity Center (formerly AWS SSO) is the recommended approach for centralized user management in AWS Organizations.

    Centralizing IAM user management to a single identity store reduces complexity and the likelihood of access management errors. Using AWS IAM Identity Center further simplifies access management and reduces reliance on legacy per-account federation configurations.
  "
  desc  'rationale', "
    In multi-account environments, IAM user centralization facilitates greater user control. User access beyond the initial account is provided through role assumption. Centralization of users can be accomplished through federation with an external identity provider or through the use of AWS Organizations. AWS IAM Identity Center (formerly AWS SSO) is the recommended approach for centralized user management in AWS Organizations.

    Centralizing IAM user management to a single identity store reduces complexity and the likelihood of access management errors. Using AWS IAM Identity Center further simplifies access management and reduces reliance on legacy per-account federation configurations.
  "
  desc  'check', "
    For multi-account AWS environments with an external identity provider:

    1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam 
    2. Click `Identity providers`
    3. Verify that federation is configured appropriately

    For environments using AWS IAM Identity Center (recommended):
    1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam 
    2. Navigate to `IAM Identity Center`
    3. Verify that IAM Identity Center is enabled
    4. Confirm that users and groups are centrally managed
    5. Confirm that access is assigned to accounts through IAM Identity Center

    For multi-account environments without centralized identity management:

    1. Identify accounts that should not contain local IAM users
    2. Sign in to the AWS Management Console
    3. Switch role into each identified account
    4. Navigate to the IAM console
    5. Select Users
    6. Confirm that no IAM users representing individuals are present
  "
  desc  'fix', "
    The remediation procedure will vary based on the organization's implementation of identity federation and or AWS Organizations.

    Ensure the following:

    1. IAM users are centrally managed through a single identity provider
    2. Local IAM users are removed from member accounts, except for service accounts where required
    3. Access to accounts is granted through role assumption
    4. Where possible, migrate to AWS IAM Identity Center for centralized access management
    5. Avoid legacy per-account federation configurations
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'RA-5 a']
  tag cci:                   ['CCI-000011', 'CCI-001054']
  tag cis_number:            '2.19'
  tag cis_rid:               '2.19'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0219r1_rule'
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

  describe 'IAM federation / centralized identity for multi-account (attestation-required)' do
    skip 'attestation-required: identity-provider architecture + account-mapping is a governance documentation concern — periodic-review attestation per docs/dev/Attestation_Strategy.md. Authoring template: profiles/cis-aws-foundations/attestations.example.json control_id C-2.19.'
  end
end
