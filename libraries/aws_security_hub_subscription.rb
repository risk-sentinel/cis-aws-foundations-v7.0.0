# Custom resource: AWS Security Hub subscription state for the
# scanner's account + region.
#
# Why a local resource (and not the vendored aws_securityhub_hub):
# the vendored resource wraps describe_hub in catch_aws_errors, which
# emits `Inspec::Log.warn` for the InvalidAccessException raised when
# the account is not subscribed to Security Hub. The WARN appears on
# stdout above the control failure, polluting CI output even though
# the control is failing as designed. This resource catches the
# InvalidAccessException explicitly, sets `subscribed? == false`, and
# returns the AWS error message via `connection_error` per the
# `Vendored_Resource_Gaps.md` §5 precheck-via-connection_error pattern.
#
# Depends on `_aws_backend_bootstrap.rb` having been loaded first.

class AwsSecurityHubSubscription < AwsResourceBase
  name "aws_security_hub_subscription"
  desc "AWS Security Hub subscription state for the scanner's account + region."
  example "
    describe aws_security_hub_subscription do
      it { should be_subscribed }
    end
  "

  attr_reader :hub_arn, :subscribed_at, :auto_enable_controls, :connection_error

  def initialize(opts = {})
    super(opts)
    validate_parameters
    fetch_data
  end

  def subscribed?
    @subscribed == true
  end

  def not_subscribed?
    @subscribed == false
  end

  def exists?
    subscribed?
  end

  def resource_id
    @hub_arn || "aws_security_hub_subscription"
  end

  def to_s
    "AWS Security Hub Subscription"
  end

  private

  def fetch_data
    @subscribed = false
    begin
      resp = @aws.securityhub_client.describe_hub
      @subscribed          = true
      @hub_arn             = resp.hub_arn
      @subscribed_at       = resp.subscribed_at
      @auto_enable_controls = resp.auto_enable_controls
    rescue Aws::SecurityHub::Errors::InvalidAccessException => e
      @subscribed       = false
      @connection_error = e.message
    rescue Aws::Errors::ServiceError => e
      @connection_error = "Security Hub describe_hub failed: #{e.message}"
    end
  end
end
