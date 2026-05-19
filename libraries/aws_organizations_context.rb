# Custom resources for AWS Organizations context detection.
# Depends on `_aws_backend_bootstrap.rb` having been loaded first.
#
# Why local: the vendored aws_organizations_member wraps
# describe_organization in catch_aws_errors, which emits an
# Inspec::Log.warn when the scanner runs against a standalone account
# (Aws::Organizations::Errors::AWSOrganizationsNotInUseException). This
# resource catches that exception explicitly and exposes
# `in_organization?` / `connection_error` instead of producing a phantom
# WARN above an "is_master = nil" describe.
#
# Also surfaces FeatureSet (ALL vs. CONSOLIDATED_BILLING) — required by
# CIS 2.1.x because centralized root access management and SCPs require
# FeatureSet == ALL. This information is callable from any member
# account via organizations:DescribeOrganization.

class AwsOrganizationsContext < AwsResourceBase
  name "aws_organizations_context"
  desc "AWS Organizations enrollment context for the scanner's account."
  example "
    describe aws_organizations_context do
      it                  { should be_in_organization }
      its('feature_set')  { should eq 'ALL' }
    end
  "

  attr_reader :master_account_id, :master_account_arn, :feature_set,
              :organization_id, :connection_error

  def initialize(opts = {})
    opts ||= {}
    opts[:aws_region] = "us-east-1" # Organizations endpoint is us-east-1.
    super(opts)
    validate_parameters
    fetch_data
  end

  def in_organization?
    @in_organization == true
  end

  def exists?
    in_organization?
  end

  def master?
    return false unless in_organization?
    sts = @aws.sts_client.get_caller_identity
    sts.account == @master_account_id
  end

  def resource_id
    @organization_id || "aws_organizations_context"
  end

  def to_s
    "AWS Organizations Context"
  end

  private

  def fetch_data
    @in_organization = false
    begin
      resp = @aws.org_client.describe_organization
      org = resp.organization
      @in_organization    = true
      @organization_id    = org.id
      @master_account_id  = org.master_account_id
      @master_account_arn = org.master_account_arn
      @feature_set        = org.feature_set
    rescue Aws::Organizations::Errors::AWSOrganizationsNotInUseException => e
      @connection_error = "Account is not a member of any AWS Organization: #{e.message}"
    rescue Aws::Organizations::Errors::AccessDeniedException => e
      @connection_error = "Scanner role missing organizations:DescribeOrganization: #{e.message}"
    rescue Aws::Errors::ServiceError => e
      @connection_error = "Organizations describe_organization failed: #{e.message}"
    end
  end
end
