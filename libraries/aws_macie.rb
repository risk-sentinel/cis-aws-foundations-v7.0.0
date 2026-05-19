# Custom resources for AWS Macie session + classification jobs.
# Depends on `_aws_backend_bootstrap.rb` having been loaded first.
#
# Why local: train-aws does not expose a macie2_client accessor, so we
# use the supported aws_client(klass) escape hatch (per the
# `feedback_inspec_aws_connection_closed_list` memory). The vendored
# inspec-aws set does not ship a Macie resource at all, so these fill
# the gap rather than override anything.
#
# Each resource follows the connection_error precheck pattern from
# `Vendored_Resource_Gaps.md` §5 so C-3.1.3 can degrade to a clear
# Skip if Macie permissions are missing rather than emit a phantom
# "no jobs found" PASS.

MACIE_GEM_LOAD_ERROR = begin
  require "aws-sdk-macie2"
  nil
rescue LoadError => e
  "aws-sdk-macie2 gem not installed: #{e.message}. File a tracking issue against the cinc-auditor docker image to bundle the gem."
end

class AwsMacieSession < AwsResourceBase
  name "aws_macie_session"
  desc "AWS Macie session state for the scanner's account + region."
  example "
    describe aws_macie_session do
      it { should be_enabled }
    end
  "

  attr_reader :status, :service_role, :finding_publishing_frequency,
              :created_at, :updated_at, :connection_error

  def initialize(opts = {})
    super(opts)
    validate_parameters
    @connection_error = MACIE_GEM_LOAD_ERROR
    return if @connection_error
    fetch_data
  end

  def enabled?
    @status == "ENABLED"
  end

  def paused?
    @status == "PAUSED"
  end

  def exists?
    !@status.nil?
  end

  def resource_id
    "aws_macie_session"
  end

  def to_s
    "AWS Macie Session"
  end

  private

  def fetch_data
    begin
      resp = macie_client.get_macie_session
      @status                       = resp.status
      @service_role                 = resp.service_role
      @finding_publishing_frequency = resp.finding_publishing_frequency
      @created_at                   = resp.created_at
      @updated_at                   = resp.updated_at
    rescue Aws::Macie2::Errors::AccessDeniedException => e
      # AccessDeniedException is what Macie returns when the account
      # has never enabled Macie — treat as not-enabled rather than as
      # an IAM-permissions problem (the scanner role HAS the perm; the
      # account just isn't enrolled).
      @status           = nil
      @connection_error = "Macie not enabled in this account/region: #{e.message}"
    rescue Aws::Errors::ServiceError => e
      @connection_error = "Macie get_macie_session failed: #{e.message}"
    end
  end

  def macie_client
    @aws.aws_client(Aws::Macie2::Client)
  end
end

class AwsMacieClassificationJobs < AwsResourceBase
  name "aws_macie_classification_jobs"
  desc "AWS Macie classification jobs (S3 data classification)."
  example "
    describe aws_macie_classification_jobs do
      its('active_count') { should be > 0 }
    end
  "

  filter_table_config = FilterTable.create
  filter_table_config.register_column(:job_ids,        field: :job_id)
                     .register_column(:names,          field: :name)
                     .register_column(:job_statuses,   field: :job_status)
                     .register_column(:job_types,      field: :job_type)
                     .register_column(:created_ats,    field: :created_at)
  filter_table_config.install_filter_methods_on_resource(self, :rows)

  attr_reader :connection_error

  def initialize(opts = {})
    super(opts)
    validate_parameters
    @connection_error = MACIE_GEM_LOAD_ERROR
    @rows = []
    return if @connection_error
    fetch_data
  end

  def rows
    @rows
  end

  def count
    @rows.length
  end

  def active_count
    @rows.count { |r| %w[RUNNING IDLE].include?(r[:job_status]) }
  end

  def resource_id
    "aws_macie_classification_jobs"
  end

  def to_s
    "AWS Macie Classification Jobs"
  end

  private

  def fetch_data
    begin
      pagination_token = nil
      loop do
        resp = macie_client.list_classification_jobs(
          max_results: 200,
          next_token:  pagination_token,
        )
        Array(resp.items).each do |item|
          @rows << {
            job_id:     item.job_id,
            name:       item.name,
            job_status: item.job_status,
            job_type:   item.job_type,
            created_at: item.created_at,
          }
        end
        pagination_token = resp.next_token
        break if pagination_token.nil? || pagination_token.empty?
      end
    rescue Aws::Macie2::Errors::AccessDeniedException => e
      @connection_error = "Macie not enabled in this account/region: #{e.message}"
    rescue Aws::Errors::ServiceError => e
      @connection_error = "Macie list_classification_jobs failed: #{e.message}"
    end
  end

  def macie_client
    @aws.aws_client(Aws::Macie2::Client)
  end
end
