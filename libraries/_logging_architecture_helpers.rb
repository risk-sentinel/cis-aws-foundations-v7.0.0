# Helpers for the §4 logging-architecture inputs (cloudtrail_mode,
# log_archive_account_id, expected_cloudtrail_destinations, etc.).
#
# Provides one method to control bodies:
#   in_log_archive_account?  — true if THIS account's ID (via STS
#   GetCallerIdentity) matches the `log_archive_account_id` input.
#   When the input is empty or STS is unreachable, returns false.
#
# Memoizes the STS call so multiple controls don't each pay the
# round-trip cost.
#
# Why a separate helper rather than calling aws_sts_caller_identity
# inline: the stock inspec-aws resource is per-control-instance and
# doesn't memoize across controls. The helper caches via a module
# constant for the lifetime of the InSpec run.
#
# See:
# - profiles/cis-aws-foundations/inspec.yml inputs `cloudtrail_mode`,
#   `aws_config_mode`, `vpc_flow_logs_mode`, `log_archive_account_id`
# - memory: feedback_inspec_na_via_impact_zero.md (canonical inline pattern)
#
# Loaded into Inspec::Rule via `::Inspec::Rule.include` per the
# Vendored_Resource_Gaps.md §6 pattern.

module LoggingArchitectureHelpers
  CACHE = { account_id: :uninitialized }

  def current_account_id
    return CACHE[:account_id] unless CACHE[:account_id] == :uninitialized
    CACHE[:account_id] =
      begin
        aws_sts_caller_identity.account
      rescue StandardError => e
        Inspec::Log.warn("current_account_id: STS GetCallerIdentity failed: #{e.class.name}: #{e.message}")
        nil
      end
  end

  def in_log_archive_account?
    archive = input('log_archive_account_id').to_s
    return false if archive.empty?
    cur = current_account_id
    return false if cur.nil?
    cur == archive
  end
end

::Inspec::Rule.include(LoggingArchitectureHelpers)
