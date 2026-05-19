# Custom resource exposing S3 bucket versioning + MFA-Delete state.
# Depends on `_aws_backend_bootstrap.rb` having been loaded first (its
# leading underscore sorts it before this file in InSpec's alphabetical
# library-load order).
#
# Why this exists: inspec-aws 1.83.63's aws_s3_bucket only surfaces
# has_versioning_enabled? (status == "Enabled"). CIS 3.1.2 also needs
# the MfaDelete flag from GetBucketVersioning, which is not exposed.
# Context: docs/dev/issue_20_design.md, audit recorded in
# docs/dev/Vendored_Resource_Gaps.md.

class AwsS3BucketVersioning < AwsResourceBase
  name "aws_s3_bucket_versioning"
  desc "S3 bucket versioning + MFA-Delete configuration."
  example "
    describe aws_s3_bucket_versioning(bucket_name: 'my-bucket') do
      it                  { should exist }
      its('status')       { should cmp 'Enabled' }
      its('mfa_delete')   { should cmp 'Enabled' }
      it                  { should have_versioning_enabled }
      it                  { should have_mfa_delete_enabled }
    end
  "

  attr_reader :bucket_name, :status, :mfa_delete

  def initialize(opts = {})
    opts = { bucket_name: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: [:bucket_name])
    @bucket_name = opts[:bucket_name]
    fetch_data
  end

  def exists?
    @exists == true
  end

  def has_versioning_enabled?
    @status == "Enabled"
  end

  def has_mfa_delete_enabled?
    @mfa_delete == "Enabled"
  end

  def to_s
    "AWS S3 Bucket Versioning '#{@bucket_name}'"
  end

  private

  def fetch_data
    @exists = false
    catch_aws_errors do
      begin
        resp = @aws.storage_client.get_bucket_versioning(bucket: @bucket_name)
        @exists     = true
        @status     = resp.status
        @mfa_delete = resp.mfa_delete
      rescue Aws::S3::Errors::NoSuchBucket
        @exists = false
      end
    end
  end
end
