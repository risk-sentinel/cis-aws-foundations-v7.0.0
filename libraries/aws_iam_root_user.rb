# Local override of the vendored inspec-aws resource of the same name.
# Depends on `_aws_backend_bootstrap.rb` having been loaded first (its
# leading underscore sorts it before this file in InSpec's alphabetical
# library-load order).
#
# The vendored initializer (at
# vendor/<sha>/libraries/aws_iam_root_user.rb:21) does
#   @serial_number = @virtual_devices.first.serial_number
# with no nil guard — NoMethodError when the account has zero virtual MFA
# devices (e.g., hardware-MFA-only environments). This override nil-guards
# both the list fetch and the serial-number read; the rest of the surface
# matches the vendored resource so existing describes keep working.
#
# Remove this file once upstream inspec-aws ships the fix.
# Context: docs/dev/issue_20_design.md.

class AwsIamRootUser < AwsResourceBase
  name "aws_iam_root_user"
  desc "Verifies settings for AWS Root Account."
  example "
    describe aws_iam_root_user do
      it { should have_mfa_enabled }
      it { should have_hardware_mfa_enabled }
      it { should_not have_access_key }
    end
  "

  attr_reader :summary_account, :virtual_devices,
              :password_last_used,
              :access_key_1_last_used_date,
              :access_key_2_last_used_date

  ROOT_USERNAME = "<root_account>".freeze
  CREDENTIAL_REPORT_RETRIES = 6
  CREDENTIAL_REPORT_RETRY_DELAY = 2

  def initialize(opts = {})
    super(opts)
    validate_parameters

    catch_aws_errors do
      @summary_account = @aws.iam_client.get_account_summary.summary_map
      @virtual_devices = @aws.iam_client.list_virtual_mfa_devices.virtual_mfa_devices || []
      @serial_number = @virtual_devices.first&.serial_number
      load_credential_report_row
    end
  end

  def resource_id
    @serial_number
  end

  def has_access_key?
    @summary_account["AccountAccessKeysPresent"] == 1
  end

  def has_mfa_enabled?
    @summary_account["AccountMFAEnabled"] == 1
  end

  def has_hardware_mfa_enabled?
    has_mfa_enabled? && !has_virtual_mfa_enabled?
  end

  # Virtual MFA for root carries the serial-number suffix
  # "root-account-mfa-device" (documented by AWS and used by CIS 2.6).
  def has_virtual_mfa_enabled?
    virtual_mfa_suffix = "root-account-mfa-device"
    @virtual_devices.any? { |device| device[:serial_number]&.end_with?(virtual_mfa_suffix) }
  end

  # Most recent of password_last_used, access_key_1_last_used_date,
  # access_key_2_last_used_date — nil if the root account has never been
  # used. Time instance.
  def last_used_at
    [@password_last_used,
     @access_key_1_last_used_date,
     @access_key_2_last_used_date].compact.max
  end

  # CIS 2.7 — true if the root account has been used in the last
  # `within_days` (any credential type). Default 90 days.
  def used_recently?(within_days: 90)
    return false if last_used_at.nil?
    last_used_at >= (Time.now - (within_days * 86_400))
  end

  def exists?
    !@summary_account.empty?
  end

  def to_s
    "AWS Root-User"
  end

  private

  # Fetches the IAM credential report and pulls the root row's
  # last-used fields. Generates the report if it's not yet present.
  # The credential report's "<root_account>" row is what CIS 2.7 keys
  # off — there is no API for "last time root logged in" outside this.
  def load_credential_report_row
    row = fetch_credential_report_row
    return if row.nil?
    @password_last_used          = parse_time(row["password_last_used"])
    @access_key_1_last_used_date = parse_time(row["access_key_1_last_used_date"])
    @access_key_2_last_used_date = parse_time(row["access_key_2_last_used_date"])
  end

  def fetch_credential_report_row
    require "csv"
    CREDENTIAL_REPORT_RETRIES.times do
      begin
        resp = @aws.iam_client.get_credential_report
        body = resp.content.to_s
        body = body.force_encoding("UTF-8")
        rows = CSV.parse(body, headers: true)
        return rows.find { |r| r["user"] == ROOT_USERNAME }
      rescue Aws::IAM::Errors::CredentialReportNotPresentException,
             Aws::IAM::Errors::CredentialReportExpiredException,
             Aws::IAM::Errors::CredentialReportNotReadyException,
             Aws::IAM::Errors::ReportNotPresent,
             Aws::IAM::Errors::ReportExpired,
             Aws::IAM::Errors::ReportInProgress
        # AWS SDK Ruby has historically published two different sets of
        # exception class names for the IAM credential-report error
        # codes — `Credential*Exception` (older shape) and `Report*`
        # without the prefix/suffix (newer shape, surfaced in
        # aws-sdk-iam ≥ 1.92.0 bundled with cinc-workstation 26.0.1).
        # Catch both. Either way, the recovery action is the same:
        # generate the report, sleep, retry.
        @aws.iam_client.generate_credential_report
        sleep CREDENTIAL_REPORT_RETRY_DELAY
      end
    end
    nil
  end

  def parse_time(value)
    return nil if value.nil? || value.empty? || value == "N/A" || value == "no_information" || value == "not_supported"
    Time.parse(value)
  rescue ArgumentError
    nil
  end
end
