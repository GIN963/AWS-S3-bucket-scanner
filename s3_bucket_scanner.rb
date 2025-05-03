require 'msf/core'
require 'net/http'
require 'json'

class MetasploitModule < Msf::Auxiliary
  Rank = ExcellentRanking

  def initialize
    super(
      'Name'        => 'AWS S3 Bucket Secrets Scanner',
      'Description' => 'Scan public AWS S3 Buckets for sensitive data like secrets, keys, and passwords.',
      'Author'      => ['GIN963'],
      'License'     => MSF_LICENSE
    )

    # Define module options
    register_options(
      [
        OptString.new('BUCKET_NAME', [true, 'Public S3 Bucket Name (without .s3.amazonaws.com)']),
        OptInt.new('TIMEOUT', [false, 'Delay between requests in seconds', 2]),
        OptPath.new('WORDLIST', [false, 'Path to a wordlist to bruteforce file names'])
      ]
    )
  end

  def run
    bucket_name = datastore['BUCKET_NAME']
    timeout     = datastore['TIMEOUT'].to_i
    @json_results = []

    print_status("Starting scan on bucket: #{bucket_name}")

    # List files available in the bucket (if listing is allowed)
    files = list_bucket_files(bucket_name)

    # Optionally bruteforce files using wordlist
    if datastore['WORDLIST'] && ::File.exist?(datastore['WORDLIST'])
      print_status("Bruteforcing files using wordlist: #{datastore['WORDLIST']}")
      files += bruteforce_files(bucket_name, datastore['WORDLIST'])
      files.uniq!
    else
      print_status("No wordlist provided — skipping bruteforce.")
    end

    # Exit if no files were found
    if files.empty?
      print_error("No files found or bucket listing disabled.")
      print_error("No files to analyze.")
      return
    end

    print_good("Found #{files.length} files in bucket #{bucket_name}")

    # Analyze each file
    files.each do |file|
      print_status("Scanning file: #{file}")
      analyze_file(bucket_name, file)
      sleep(timeout) if timeout > 0
    end

    export_results_json(bucket_name)
    print_good("Scan finished! Results saved in loot/s3_secrets_#{bucket_name}.txt and JSON file.")
  end

  # Fetch the list of files from the bucket if listing is enabled
  def list_bucket_files(bucket)
    url = "https://#{bucket}.s3.amazonaws.com/"
    uri = URI(url)
    files = []

    begin
      response = Net::HTTP.get_response(uri)
      if response.body.include?('<ListBucketResult')
        response.body.scan(/<Key>(.*?)<\\/Key>/).each do |match|
          files << match[0]
        end
      end
    rescue => e
      print_error("Error listing files: #{e.message}")
    end

    files
  end

  # Attempt to brute-force filenames if listing is not allowed
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
        else
          print_status("Not found (#{response.code}) for: #{filename}")
        end
      rescue => e
        print_error("Error during bruteforce request: #{e.message}")
      end

      sleep(timeout) if timeout > 0
    end

    found_files
  end

  # Analyze a given file by requesting it and scanning its content
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

  # Scan the content of a file for secrets using regex patterns
  def scan_content(content)
    secrets = []

    aws_keys = content.scan(/\bAKIA[0-9A-Z]{16}\b/)
    secrets << "AWS Access Key(s): #{aws_keys.uniq.join(', ')}" unless aws_keys.empty?

    jwt_tokens = content.scan(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/)
    secrets << "JWT Token(s): #{jwt_tokens.uniq.join(', ')}" unless jwt_tokens.empty?

    secrets << "Private Key(s) Detected!" if content.include?("-----BEGIN ")

    password_lines = content.scan(/(?i)(pass(word)?|motdepasse|mdp)[^=:\n]{0,10}[:=]\s*['"]?([^\s'"]{4,})['"]?/)
    passwords = password_lines.map { |m| m[2] }
    secrets << "Password(s): #{passwords.uniq.join(', ')}" unless passwords.empty?

    api_lines = content.scan(/(?i)(api[_-]?key|token|bearer)[^=:\n]{0,10}[:=]\s*['"]?([A-Za-z0-9\-_\.]{10,})['"]?/)
    apis = api_lines.map { |m| m[1] }
    secrets << "API Key(s) / Token(s): #{apis.uniq.join(', ')}" unless apis.empty?

    db_uris = content.scan(/\b(?:mongodb|mysql|postgres|oracle|sqlserver):\/\/[^"]{6,}\b/i)
    secrets << "Database URI(s): #{db_uris.uniq.join(', ')}" unless db_uris.empty?

    generic = content.scan(/(?i)(secret|key|token|pass)[^=:\n]{0,10}[:=]\s*['"]?([A-Za-z0-9_\-\/\.\=\+]{8,})['"]?/)
    generic_values = generic.map { |m| m[1] }
    secrets << "Generic Secrets: #{generic_values.uniq.join(', ')}" unless generic_values.empty?

    # Match INSERT INTO SQL lines with possible credentials
    sql_user_creds = content.scan(/INSERT INTO.*?\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)/i)

    sql_user_creds.each do |columns, values|
      cols = columns.split(',').map(&:strip).map(&:downcase)
      vals = values.split(',').map(&:strip).map { |v| v.gsub(/^'|'$/, '') }

      next unless cols.include?("password")

      idx_user = cols.index("username") || cols.index("user")
      idx_pass = cols.index("password")
      idx_id   = cols.index("id")

      user = idx_user && vals[idx_user] ? vals[idx_user] : "?"
      pass = idx_pass && vals[idx_pass] ? vals[idx_pass] : "?"
      id   = idx_id && vals[idx_id] ? vals[idx_id] : "?"

      secrets << "SQL Credential: id=#{id}, user=#{user}, pass=#{pass}"
    end

    secrets
  end

  # Save plain text results to loot
  def save_result(message)
    loot_file = ::File.join(Msf::Config.loot_directory, "s3_secrets_#{datastore['BUCKET_NAME']}.txt")
    ::File.open(loot_file, 'a') { |f| f.puts message }
  end

  # Save structured JSON results to loot
  def export_results_json(bucket_name)
    return if @json_results.empty?
    loot_file = ::File.join(Msf::Config.loot_directory, "s3_secrets_#{bucket_name}.json")
    ::File.open(loot_file, 'w') { |f| f.write(JSON.pretty_generate(@json_results)) }
    print_good("Exported JSON results to #{loot_file}")
  end
end
