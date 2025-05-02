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
      'Author'      => ['GIN963'],
      'License'     => MSF_LICENSE
    )

    # Declare configurable options for the module
    register_options(
      [
        OptString.new('BUCKET_NAME', [true, 'Public S3 Bucket Name (without .s3.amazonaws.com)']),
        OptInt.new('TIMEOUT', [false, 'Delay between requests in seconds', 2]),
        OptPath.new('WORDLIST', [false, 'Path to a wordlist to bruteforce file names'])
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
      print_warning("No files found or bucket listing disabled.")
    else
      print_good("Found #{files.length} files in bucket #{bucket_name}")
    end

    # Bruteforce additional files if a wordlist is provided
    if datastore['WORDLIST'] && ::File.exist?(datastore['WORDLIST'])
      print_status("Bruteforcing files using wordlist: #{datastore['WORDLIST']}")
      bruteforced_files = bruteforce_files(bucket_name, datastore['WORDLIST'])
      files.concat(bruteforced_files).uniq!
    end

    if files.empty?
      print_error("No files to analyze.")
      return
    end

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
    url = "https://#{bucket}.s3.amazonaws.com/"
    uri = URI(url)
    files = []

    begin
      response = Net::HTTP.get_response(uri)

      if response.body.include?('<ListBucketResult')
        response.body.scan(/<Key>(.*?)<\/Key>/).each do |match|
          files << match[0]
        end
      end
    rescue => e
      print_error("Error listing files: #{e.message}")
    end

    files
  end

  def bruteforce_files(bucket, wordlist_path)
    found_files = []
    timeout = datastore['TIMEOUT'].to_i

    ::File.readlines(wordlist_path).each do |line|
      filename = line.strip
      next if filename.empty?

      url = "https://#{bucket}.s3.amazonaws.com/#{filename}"
      uri = URI(url)

      begin
        response = Net::HTTP.get_response(uri)
        case response.code.to_i
        when 200
          print_good("Discovered file via bruteforce: #{filename}")
          found_files << filename
        when 403
          print_warning("Access denied (403) for file: #{filename}")
        end
      rescue => e
        print_error("Error during bruteforce request: #{e.message}")
      end

      sleep(timeout) if timeout > 0
    end

    found_files
  end

  def analyze_file(bucket, file)
    url = "https://#{bucket}.s3.amazonaws.com/#{file}"
    uri = URI(url)

    begin
      response = Net::HTTP.get_response(uri)

      if response.code.to_i != 200
        print_error("Cannot access file #{file} (HTTP #{response.code})")
        return
      end

      content = response.body
      findings = scan_content(content)

      if findings.empty?
        print_status("No secrets found in #{file}.")
      else
        print_warning("[!] Secrets found in #{file}:")
        findings.each { |f| print_good("    - #{f}") }

        save_result("[#{file}] #{findings.join(', ')}")
        @json_results << { file: file, secrets: findings }
      end

    rescue => e
      print_error("Error accessing file #{file}: #{e.message}")
    end
  end

  def scan_content(content)
    secrets = []

    # AWS Access Keys
    aws_access_keys = content.scan(/AKIA[0-9A-Z]{16}/)
    secrets << "AWS Access Key(s): #{aws_access_keys.join(', ')}" unless aws_access_keys.empty?

    # JWT Tokens
    jwt_tokens = content.scan(/eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/)
    secrets << "JWT Token(s): #{jwt_tokens.join(', ')}" unless jwt_tokens.empty?

    # Private Keys
    private_keys = content.scan(/-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----/)
    secrets << "Private Key(s) Detected!" unless private_keys.empty?

    # Passwords
    passwords = content.scan(/password\s*[:=]\s*['"]?[^'"\s]+['"]?/)
    secrets << "Password(s): #{passwords.join(', ')}" unless passwords.empty?

    # API Keys
    api_keys = content.scan(/(api[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9\-_]{16,}['"]?)/i)
    secrets << "API Key(s): #{api_keys.flatten.join(', ')}" unless api_keys.empty?

    secrets
  end

  def save_result(message)
    loot_file = ::File.join(Msf::Config.loot_directory, "s3_secrets_#{datastore['BUCKET_NAME']}.txt")

    ::File.open(loot_file, 'a') do |f|
      f.puts message
    end
  end

  def export_results_json(bucket_name)
    return if @json_results.empty?

    loot_file = ::File.join(Msf::Config.loot_directory, "s3_secrets_#{bucket_name}.json")

    ::File.open(loot_file, 'w') do |f|
      f.write(JSON.pretty_generate(@json_results))
    end

    print_good("Exported JSON results to #{loot_file}")
  end
end

