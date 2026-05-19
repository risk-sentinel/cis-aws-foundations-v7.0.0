# Custom resources for AWS Organizations management-context API calls.
# Depends on `_aws_backend_bootstrap.rb` having been loaded first.
#
# These wrap APIs that are callable only from the Organizations
# management account or a delegated-administrator account:
#
#   - aws_organizations_policies                — ListPolicies
#   - aws_organizations_delegated_administrators — ListDelegatedAdministrators
#   - aws_organizations_aws_service_access      — ListAWSServiceAccessForOrganization
#
# Each takes a `role_arn:` opt naming a cross-account role in the
# management (or delegated-admin) account that the scanner can assume.
# When role_arn is empty, the resource sets connection_error to a
# "dual-mode disabled" message so the control degrades to a clean Skip
# rather than raising AccessDeniedException at exec time.
#
# AssumeRole is performed at resource-init time using the scanner's
# default credential chain. The resulting STS credentials are passed
# directly to a new Aws::Organizations::Client (us-east-1; Organizations'
# regional endpoint). Credentials are scoped per-resource-instance —
# no shared session caching across resources, since each resource
# typically runs once per profile execution.

module AwsOrganizationsManagement
  ROLE_SESSION_NAME = "sparc-validate-foundations".freeze
  SESSION_DURATION  = 900 # 15 minutes; matches the AssumeRole minimum.

  # Assume the management-account role and return an
  # Aws::Organizations::Client bound to the resulting credentials.
  # Returns [client, nil] on success, [nil, error_message] on failure.
  def self.management_organizations_client(role_arn)
    return [nil, "aws_organizations_role_arn input is empty; dual-mode disabled (control stays attestation-bound)"] if role_arn.to_s.empty?

    begin
      sts  = Aws::STS::Client.new(region: "us-east-1")
      resp = sts.assume_role(
        role_arn:          role_arn,
        role_session_name: ROLE_SESSION_NAME,
        duration_seconds:  SESSION_DURATION,
      )
      creds = Aws::Credentials.new(
        resp.credentials.access_key_id,
        resp.credentials.secret_access_key,
        resp.credentials.session_token,
      )
      client = Aws::Organizations::Client.new(
        region:      "us-east-1",
        credentials: creds,
      )
      [client, nil]
    rescue Aws::STS::Errors::ServiceError => e
      [nil, "AssumeRole(#{role_arn}) failed: #{e.class.name}: #{e.message}"]
    rescue Aws::Errors::ServiceError => e
      [nil, "Management-account Organizations client setup failed: #{e.class.name}: #{e.message}"]
    end
  end
end

class AwsOrganizationsPolicies < AwsResourceBase
  name "aws_organizations_policies"
  desc "AWS Organizations policies (SCPs, RCPs, tag policies, AI opt-out, backup policies) — requires management context."
  example "
    describe aws_organizations_policies(role_arn: input('aws_organizations_role_arn'), policy_type: 'SERVICE_CONTROL_POLICY') do
      its('count') { should be > 0 }
    end
  "

  VALID_POLICY_TYPES = %w[
    SERVICE_CONTROL_POLICY
    RESOURCE_CONTROL_POLICY
    TAG_POLICY
    AISERVICES_OPT_OUT_POLICY
    BACKUP_POLICY
    CHATBOT_POLICY
    DECLARATIVE_POLICY_EC2
  ].freeze

  filter_table_config = FilterTable.create
  filter_table_config.register_column(:ids,         field: :id)
                     .register_column(:names,       field: :name)
                     .register_column(:aws_managed, field: :aws_managed)
                     .register_column(:descriptions, field: :description)
  filter_table_config.install_filter_methods_on_resource(self, :rows)

  attr_reader :policy_type, :connection_error

  def initialize(opts = {})
    super(opts)
    validate_parameters(required: [:policy_type])
    @policy_type = opts[:policy_type].to_s
    @rows = []

    unless VALID_POLICY_TYPES.include?(@policy_type)
      raise ArgumentError, "policy_type must be one of: #{VALID_POLICY_TYPES.join(', ')}"
    end

    client, err = AwsOrganizationsManagement.management_organizations_client(opts[:role_arn])
    @connection_error = err
    return if @connection_error

    fetch_data(client)
  end

  def rows
    @rows
  end

  def count
    @rows.length
  end

  def resource_id
    "aws_organizations_policies(#{@policy_type})"
  end

  def to_s
    "AWS Organizations Policies (#{@policy_type})"
  end

  private

  def fetch_data(client)
    pagination_token = nil
    loop do
      resp = client.list_policies(filter: @policy_type, next_token: pagination_token)
      Array(resp.policies).each do |p|
        @rows << {
          id:          p.id,
          name:        p.name,
          aws_managed: p.aws_managed,
          description: p.description,
        }
      end
      pagination_token = resp.next_token
      break if pagination_token.nil? || pagination_token.empty?
    end
  rescue Aws::Organizations::Errors::PolicyTypeNotEnabledException => e
    @connection_error = "Policy type #{@policy_type} not enabled in this org: #{e.message}"
  rescue Aws::Errors::ServiceError => e
    @connection_error = "Organizations list_policies(#{@policy_type}) failed: #{e.class.name}: #{e.message}"
  end
end

class AwsOrganizationsDelegatedAdministrators < AwsResourceBase
  name "aws_organizations_delegated_administrators"
  desc "AWS Organizations delegated administrators — requires management context."
  example "
    describe aws_organizations_delegated_administrators(role_arn: input('aws_organizations_role_arn')) do
      its('count') { should be > 0 }
    end
  "

  filter_table_config = FilterTable.create
  filter_table_config.register_column(:ids,           field: :id)
                     .register_column(:emails,        field: :email)
                     .register_column(:names,         field: :name)
                     .register_column(:statuses,      field: :status)
                     .register_column(:joined_methods, field: :joined_method)
  filter_table_config.install_filter_methods_on_resource(self, :rows)

  attr_reader :connection_error

  def initialize(opts = {})
    super(opts)
    validate_parameters
    @rows = []

    client, err = AwsOrganizationsManagement.management_organizations_client(opts[:role_arn])
    @connection_error = err
    return if @connection_error

    fetch_data(client)
  end

  def rows
    @rows
  end

  def count
    @rows.length
  end

  def resource_id
    "aws_organizations_delegated_administrators"
  end

  def to_s
    "AWS Organizations Delegated Administrators"
  end

  private

  def fetch_data(client)
    pagination_token = nil
    loop do
      resp = client.list_delegated_administrators(next_token: pagination_token)
      Array(resp.delegated_administrators).each do |a|
        @rows << {
          id:            a.id,
          email:         a.email,
          name:          a.name,
          status:        a.status,
          joined_method: a.joined_method,
        }
      end
      pagination_token = resp.next_token
      break if pagination_token.nil? || pagination_token.empty?
    end
  rescue Aws::Errors::ServiceError => e
    @connection_error = "Organizations list_delegated_administrators failed: #{e.class.name}: #{e.message}"
  end
end

class AwsOrganizationsAwsServiceAccess < AwsResourceBase
  name "aws_organizations_aws_service_access"
  desc "AWS services with Organizations trusted-access registration — requires management context."
  example "
    describe aws_organizations_aws_service_access(role_arn: input('aws_organizations_role_arn')) do
      its('service_principals') { should include 'iam.amazonaws.com' }
    end
  "

  attr_reader :service_principals, :connection_error

  def initialize(opts = {})
    super(opts)
    validate_parameters
    @service_principals = []

    client, err = AwsOrganizationsManagement.management_organizations_client(opts[:role_arn])
    @connection_error = err
    return if @connection_error

    fetch_data(client)
  end

  def exists?
    !@service_principals.empty?
  end

  def count
    @service_principals.length
  end

  def resource_id
    "aws_organizations_aws_service_access"
  end

  def to_s
    "AWS Organizations Trusted-Service Access"
  end

  private

  def fetch_data(client)
    pagination_token = nil
    loop do
      resp = client.list_aws_service_access_for_organization(next_token: pagination_token)
      Array(resp.enabled_service_principals).each do |sp|
        @service_principals << sp.service_principal
      end
      pagination_token = resp.next_token
      break if pagination_token.nil? || pagination_token.empty?
    end
  rescue Aws::Errors::ServiceError => e
    @connection_error = "Organizations list_aws_service_access_for_organization failed: #{e.class.name}: #{e.message}"
  end
end
