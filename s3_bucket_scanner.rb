require 'msf/core'
require 'net/http'
require 'json'

# Definition of the Metasploit auxiliary module class
class MetasploitModule < Msf::Auxiliary
  Rank = ExcellentRanking

  def initialize
    super(
      'Name'        => 'AWS S3 Bucket Secrets Scanner',
      'Description' => 'Scan public AWS S3 Buckets for sensitive data like secrets, keys, and passwords.',
      'Author'      => ['n4n0n3t'],
      'License'     => MSF_LICENSE
    )

    # Declare configurable options for the module
    register_options(
      [
        OptString.new('BUCKET_NAME', [true, 'Public S3 Bucket Name (without .s3.amazonaws.com)']),
        OptInt.new('TIMEOUT', [false, 'Delay between requests in seconds', 2])
      ]
    )
  end

  def run
     # Get user-defined options
    bucket_name = datastore['BUCKET_NAME']
    timeout     = datastore['TIMEOUT'].to_i

    @json_results = [] # Initialize an array to store results for JSON export

    print_status("Starting scan on bucket: #{bucket_name}")

    files = list_bucket_files(bucket_name) # Attempt to list files from the bucket
    if files.empty?
      print_error("No files found or bucket listing disabled.")
      return
    end

    print_good("Found #{files.length} files in bucket #{bucket_name}")

    # Iterate over each file found and analyze it
    files.each do |file|
      print_status("Scanning file: #{file}")
      analyze_file(bucket_name, file)
      sleep(timeout) if timeout > 0
    end

    export_results_json(bucket_name) # Export results in JSON format

    print_good("Scan finished! Results saved in loot/s3_secrets_#{bucket_name}.txt and JSON file.")
  end

  def list_bucket_files(bucket)
    # Build the public URL of the S3 bucket
    url = "https://#{bucket}.s3.amazonaws.com/"
    uri = URI(url)
    files = [] # List to store found files

    begin
      response = Net::HTTP.get_response(uri) # Send HTTP GET request to the bucket URL

      # Check if the response includes the standard S3 XML list format
      if response.body.include?('<ListBucketResult')
        # Extract all filenames from <Key> tags
        response.body.scan(/<Key>(.*?)<\/Key>/).each do |match|
          files << match[0]
        end
      end
    rescue => e
      print_error("Error listing files: #{e.message}")
    end

    files # Return the list of files (or empty if none)
  end

  def analyze_file(bucket, file)
    # Construct the file's public URL
    url = "https://#{bucket}.s3.amazonaws.com/#{file}"
    uri = URI(url)

    begin
      # Send HTTP GET request to fetch the file content
      response = Net::HTTP.get_response(uri)

      # Proceed only if response is OK
      if response.code.to_i != 200
        print_error("Cannot access file #{file} (HTTP #{response.code})")
        return
      end

      content = response.body
      findings = scan_content(content) # Search for secrets in the file content

      if findings.empty?
        print_status("No secrets found in #{file}.")
      else
        # Report the findings
        print_warning("[!] Secrets found in #{file}:")
        findings.each { |f| print_good("    - #{f}") }

        save_result("[#{file}] #{findings.join(', ')}")
        @json_results << { file: file, secrets: findings } # Add to results for JSON export
      end

    rescue => e
      print_error("Error accessing file #{file}: #{e.message}")
    end
  end

  def scan_content(content)
    secrets = []

    # Search for AWS access keys (AKIA format)
    aws_access_keys = content.scan(/AKIA[0-9A-Z]{16}/)
    secrets << "AWS Access Key(s): #{aws_access_keys.join(', ')}" unless aws_access_keys.empty?

    # Search for JWT tokens (three segments separated by dots)
    jwt_tokens = content.scan(/eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/)
    secrets << "JWT Token(s): #{jwt_tokens.join(', ')}" unless jwt_tokens.empty?

    # Detect private keys (RSA, EC, DSA)
    private_keys = content.scan(/-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----/)
    secrets << "Private Key(s) Detected!" unless private_keys.empty?

    # Search for password patterns (e.g., password = "value")
    passwords = content.scan(/password\s*[:=]\s*['"]?[^'"\s]+['"]?/)
    secrets << "Password(s): #{passwords.join(', ')}" unless passwords.empty?

    # Search for API keys (e.g., api_key = "value")
    api_keys = content.scan(/(api[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9\-_]{16,}['"]?)/i)
    secrets << "API Key(s): #{api_keys.flatten.join(', ')}" unless api_keys.empty?

    secrets # Return all found secrets
  end

  def save_result(message)
    # Define the path to save results in plain text
    loot_file = ::File.join(Msf::Config.loot_directory, "s3_secrets_#{datastore['BUCKET_NAME']}.txt")

    # Append results to the loot file
    ::File.open(loot_file, 'a') do |f|
      f.puts message
    end
  end

  def export_results_json(bucket_name)
    # Skip if no results to export
    return if @json_results.empty?

    # Define the JSON output path
    loot_file = ::File.join(Msf::Config.loot_directory, "s3_secrets_#{bucket_name}.json")

    # Write the JSON-formatted results to file
    ::File.open(loot_file, 'w') do |f|
      f.write(JSON.pretty_generate(@json_results))
    end

    print_good("Exported JSON results to #{loot_file}")
  end
end
