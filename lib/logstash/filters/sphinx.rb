# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"


require 'pg'
require 'redis'
require 'connection_pool'
require 'ipaddress'


class SphinxDataAccessor

  def initialize(config)

    @redis_user_conn = Redis.new(:host => config["redis_host"], :port => config["redis_port"], :db => config["redis_user_db"])
    @redis_record_conn = Redis.new(:host => config["redis_host"], :port => config["redis_port"], :db => config["redis_record_db"])
    @redis_host_conn = Redis.new(:host => config["redis_host"], :port => config["redis_port"], :db => config["redis_host_db"])
    @pg_conn = ConnectionPool::Wrapper.new(size: 8, timeout: 3) { PG::connect(:host => config["pg_host"], :user => config["pg_user"], :password => config["pg_password"], :dbname => config["pg_dbname"]) }

  end

  public
  def get_user(access_id, access_key)

    # sanity check for user inputs
    if access_id.nil? || access_key.nil?
      return nil
    end

    if access_id.strip == '' || access_key == ''
      return nil
    end

    # check redis first
    user = get_user_from_redis(access_id, access_key)
    return user if user

    user = get_user_from_pg(access_id, access_key)

    if user
      set_user_in_redis(access_id, access_key, user)
    end

    return user
  end


  public
  def add_host(user_id, hostname)

    # check redis cache first
    host = get_host_from_redis(user_id, hostname)
    return if host

    # create a host entry if not in the database
    begin
      host = create_host(user_id, hostname)
      insert_host_into_pg(host)

      set_host_in_redis(user_id, hostname, host)

    rescue => e
      puts e.message

    end



  end


  public
  def get_record(md5)


    # check the redis cache
    record = get_record_from_redis(md5)
    if record

      # Return it only if the record contains reputation meta data.
      # We learn this by checking the existence of the 'reputation_timestamp' key
      # which is only set by the backend after checking with VT (or other data source)
      if record["reputation_timestamp"]
        puts "#{md5}: Cache hit with data"
        return record
      else
        puts "#{md5}: Cache hit with no data"
        return nil
      end

    end


    # we couldn't find it in the cache. Check the db
    record = get_record_from_pg(md5)

    if record


      # Return it only if the record contains reputation meta data.
      # We learn this by checking the existence of the 'reputation_timestamp' key
      # which is only set by the backend after checking with VT (or other data source)
      if record["reputation_timestamp"]
        puts "#{md5}: DB hit with data"

        # cache it in redis
        set_record_in_redis(md5, record)
        return record

      else
        puts "#{md5}: DB hit with no data"

        empty_record = create_new_record(md5)
        set_record_in_redis(md5, empty_record)
        return nil
      end

    else

      puts "#{md5}: NO hit. Inserting a new record into DB and Cache"

      # Insert this md5 entry into the reference_hash table with a blank reputation timestamp.
      # This way the backend can update this entry accordingly
      record = create_new_record(md5)
      insert_record_into_pg(record)

      # Insert this into
      set_record_in_redis(md5, record)

      # NOTE: this new record is not returned to the user as it contains no reputation meta data.
      return nil

    end

    return nil

  end

  private
  def redis_host_db_key(user_id, hostname)
    "#{user_id}-#{hostname}".strip
  end

  private
  def get_host_from_redis(user_id, hostname)
    begin

      key = redis_host_db_key(user_id, hostname)

      host = @redis_host_conn.hgetall(key) #hgetall returns all fields and values of the hash stored at key

      return host if host != {}

    rescue => e
      puts e.message
    end

    nil
  end

  private
  def create_host(user_id, hostname)
    {'user_id' => user_id, 'hostname' => hostname}
  end

  private
  def set_host_in_redis(user_id, hostname, host)
    begin
      key = redis_host_db_key(user_id, hostname)
      @redis_host_conn.mapped_hmset(key, host)
    rescue => e
      puts e.message
    end
    nil
  end

  private
  def redis_user_db_key(access_id, access_key)
    "#{access_id}-#{access_key}"
  end


  private
  def get_user_from_redis(access_id, access_key)
    key = redis_user_db_key(access_id, access_key)

    begin

      user = @redis_user_conn.hgetall(key) #hgetall returns all fields and values of the hash stored at key
      return user if user != {}

    rescue => e
      puts e.message
    end

    nil
  end





  private
  def get_user_from_pg(access_id, access_key)

    begin
      #TODO
      #      @pg_conn.prepare('stmt1', "SELECT * FROM reference_hashes WHERE md5 = $1 LIMIT 1")
      #      result = @pg_conn.exec_prepared('stmt1', [md5])
      result = @pg_conn.exec("SELECT users.* from users, data_forwarder_keys WHERE users.id = data_forwarder_keys.user_id AND access_id = '#{access_id}' AND access_key = '#{access_key}' LIMIT 1")
      row = result.first

      if row
        user = {
            "email" => row['email'],
            'id' => row["id"],
        }
        return user
      end

      return nil

    rescue => e
      puts e.message
    end

    nil
  end

  private
  def set_user_in_redis(access_id, access_key, user)
    key = redis_user_db_key(access_id, access_key)

    begin
      @redis_user_conn.mapped_hmset(key, user)
    rescue => e
      puts e.message
    end
    nil
  end

  private
  def create_new_host(user_id, hostname)
    {"user_id" => user_id, "hostname" => hostname}
  end

  def insert_host_into_pg(host)
    timestamp = Time.now.strftime("%Y-%m-%d %H:%M:%S")
    sql = "INSERT INTO hosts (user_id, hostname, created_at, updated_at) VALUES ('#{host['user_id']}', '#{host['hostname']}', '#{timestamp}', '#{timestamp}')"
    result = @pg_conn.exec(sql)

    nil
  end



  private
  def set_record_in_redis(md5, record)

    begin

      @redis_record_conn.mapped_hmset(md5, record)

    rescue => e
      puts e.message
    end

  end



  private
  def create_new_record(md5)
#    {"md5" => md5, "wtf_timestamp" => @wtf_ts}
    {"md5" => md5}
  end

  private
  def insert_record_into_pg(record)

    md5 = record["md5"]

    begin
      timestamp = Time.now.strftime("%Y-%m-%d %H:%M:%S")
      sql = "INSERT INTO reference_hashes (md5, source, created_at, updated_at) VALUES ('#{md5}', 'wtf', '#{timestamp}', '#{timestamp}')"
      result = @pg_conn.exec(sql)

    rescue => e
      puts e.message
    end

    nil
  end


  private
  def get_record_from_redis(md5)

    begin

      record = @redis_record_conn.hgetall(md5) #hgetall returns all fields and values of the hash stored at key

      return record if record != {}

    rescue => e
      puts e.message
    end

    nil
  end

  private
  def get_record_from_pg(md5)

    begin

      #TODO
      #      @pg_conn.prepare('stmt1', "SELECT * FROM reference_hashes WHERE md5 = $1 LIMIT 1")
      #      result = @pg_conn.exec_prepared('stmt1', [md5])
      result = @pg_conn.exec("SELECT * FROM reference_hashes WHERE md5 = '#{md5}' LIMIT 1")
      row = result.first


      if row

        record = {
            "md5" => row['md5'],
            'source' => row["source"],
            'reputation' => row["reputation"],
            'vt_score' => row["vt_score"],
            'vt_total' => row["vt_total"],
            'vt_sub_score' => row["vt_sub_score"],
            'vt_scan_date' => row["vt_scan_date"],
            'has_vulnerability' => row["has_vulnerability"],
            'has_verified_signature' => row["has_verified_signature"],
            'signing_vendor' => row["signing_vendor"],
            'reputation_timestamp' => row["reputation_timestamp"]
        }

        return record

      end

      return nil

    rescue => e

      puts e.message

    end

    nil

  end



end


class SphinxEventFilterFactory

  public
  def initialize(config)
    @config = config
    @event_filter_base = SphinxEventFilter.new(config)
    @event_filter_windows = SphinxWindowsEventFilter.new(config)
    @event_filter_windows_sysmon = SphinxWindowsSysmonEventFilter.new(config)
    @event_filter_linux = SphinxLinuxEventFilter.new(config) #TODO
    @event_filter_mac = SphinxMacEventFilter.new(config) #TODO
  end

  public
  def get_filter(event)

    platform = event["SphinxPlatform"]

    case platform
      when 'windows'
        return get_windows_filter(event)
      when 'linux'
        return @event_filter_linux
      when 'mac'
        return @event_filter_mac
    end

    nil
  end

  private
  def get_windows_filter(event)

    event_source = event['SourceName']

    if event_source == 'Microsoft-Windows-Sysmon'
      return @event_filter_windows_sysmon
    end


    return @event_filter_windows
  end

end

class SphinxEventType

  PROCESS_CREATION = 'ProcessCreation'
  FILE_CREATION_TIME_CHANGE = 'FileCreationTimeChange'
  NETWORK_CONNECTION = 'NetworkConnection'
  SERVICE_STATE_CHANGE = 'ServiceStateChange'
  PROCESS_TERMINATION = 'ProcessTermination'
  DRIVER_LOAD = 'DriverLoad'
  IMAGE_LOAD = 'ImageLoad'
  REMOTE_THREAD_CREATION = 'RemoteThreadCreation'

end


class SphinxEventFilter

  SPHINX_FILTER_VERSION = 1
  SPHINX_FILTER_NAME = 'SphinxEventFilter'

  def initialize(config)

    @data_accessor = SphinxDataAccessor.new(config)

  end


  def apply(event)
    raise "Not implemented"
  end


  def finalize(event)
    event['SphinxFilterVersion'] = self.class::SPHINX_FILTER_VERSION
    event['SphinxFilterName'] = self.class::SPHINX_FILTER_NAME
  end

end

class SphinxLinuxEventFilter < SphinxEventFilter

  SPHINX_FILTER_VERSION = 1
  SPHINX_FILTER_NAME = 'LinuxEventFilter'
end

class SphinxMacEventFilter < SphinxEventFilter
  SPHINX_FILTER_VERSION = 1
  SPHINX_FILTER_NAME = 'MacEventFilter'
end


class SphinxWindowsEventFilter < SphinxEventFilter
  SPHINX_FILTER_VERSION = 1
  SPHINX_FILTER_NAME = 'WindowsEventFilter'

  def apply(event)


  end
end

class SphinxWindowsSysmonEventFilter < SphinxWindowsEventFilter
  SPHINX_FILTER_VERSION = 1
  SPHINX_FILTER_NAME = 'SysmonEventFilter'

  def apply(event)


    case event['EventID'].to_i

      # process creation
      when 1
        set_document_id(event)
        set_document_type(event, SphinxEventType::PROCESS_CREATION)
        add_process_name(event)
        add_reputation_data(event)


      # file creation
      when 2
        set_document_type(event, SphinxEventType::FILE_CREATION_TIME_CHANGE)
        set_document_parent(event)
        add_process_name(event)
        add_target_file_name(event)
        add_reputation_data(event)

      # network conn
      when 3
        set_document_type(event, SphinxEventType::NETWORK_CONNECTION)
        set_document_parent(event)
        extend_ipaddress(event)
        add_process_name(event)

      # process termination
      when 5
        set_document_type(event, SphinxEventType::PROCESS_TERMINATION)
        set_document_parent(event)

      # driver load
      when 6
        set_document_type(event, SphinxEventType::DRIVER_LOAD)
        set_document_parent(event)
        add_file_name(event)
        add_reputation_data(event)


      # dll load
      when 7
        set_document_type(event, SphinxEventType::IMAGE_LOAD)        
        set_document_parent(event)
        add_process_name(event)
        add_file_name(event)
        add_reputation_data(event)

      # remote thread
      when 8
        set_document_type(event, SphinxEventType::REMOTE_THREAD_CREATION)
        set_document_parent(event)
        #TODO

    end

    nil

  end

  def set_document_id(event)
    event['_id'] = event['ProcessGuid']
  end

  def set_document_type(event, type)
    event['type'] = type
  end

  def set_document_parent(event)
    event['parent'] = event['ProcessGuid']
  end

  def extend_ipaddress(event)

    # src ip
    begin
      ip_str = event['SourceIp']
      ip_addr = IPAddress(ip_str)

      if ip_addr.ipv6?
        event['SourceIpv6'] = ip_addr.address
      else
        event['SourceIpv4'] = ip_addr.address
      end

    rescue => e
      puts e.message
    end

    # dst ip
    begin
      ip_str = event['DestinationIp']
      ip_addr = IPAddress(ip_str)

      if ip_addr.ipv6?
        event['DestinationIpv6'] = ip_addr.address
      else
        event['DestinationIpv4'] = ip_addr.address
      end

    rescue => e
      puts e.message
    end


  end



  def add_target_file_name(event)

    image = event['TargetFilename']
    file_name = File.basename(image.gsub("\\","/"))
    event['FileName'] = file_name

    nil
  end

  def add_file_name(event)

    image = event['ImageLoaded']
    file_name = File.basename(image.gsub("\\","/"))
    event['FileName'] = file_name

    nil
  end

  def add_process_name(event)

    image = event['Image']
    process_name = File.basename(image.gsub("\\","/"))
    event['ProcessName'] = process_name

    nil
  end

  def add_reputation_data(event)

    # downcase hash
    md5 = get_downcase_hash(event)
    return nil if (md5.nil? || (md5.strip == ""))

    event['Hash'] = md5

    data = @data_accessor.get_record(md5)


    if data

      event['reputation'] = data['reputation']
      event['source'] = data['source']
      event['reputation_timestamp'] = data["reputation_timestamp"]
      event['vt_score'] = data["vt_score"]
      event['vt_total'] = data["vt_total"]
      event['vt_sub_score'] = data["vt_sub_score"]
      event['vt_scan_date'] = data["vt_scan_date"]
      event['has_vulnerability'] = data["has_vulnerability"]
      event['has_verified_signature'] = data["has_verified_signature"]
      event['signing_vendor'] = data["signing_vendor"]

    end

    nil
  end

  def get_downcase_hash(event)

    if event['Hash']
      return event['Hash'].downcase

    elsif event['Hashes']
      return event['Hashes'][4,32].downcase #NOTE  hardcoded for MD5
    end

    nil
  end


end




# This example filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
class LogStash::Filters::Sphinx < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   example {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "sphinx"

  config :pg_host, :required => false, :default => 'localhost'
  config :pg_port, :required => false, :default => 5432
  config :pg_user, :required => true
  config :pg_password, :required => true
  config :pg_dbname, :required => true

  config :redis_host, :required => false, :default => 'localhost'
  config :redis_port, :required => false, :default => 6379
  config :redis_user_db, :required => false, :default => 1
  config :redis_host_db, :required => false, :default => 2
  config :redis_record_db, :required => false, :default => 3



  public
  def register

    @data_accessor = SphinxDataAccessor.new(@config)
    @event_filter_factory = SphinxEventFilterFactory.new(@config)
    @logger.debug("Registered sphinx plugin", :type => @type, :config => @config)


  end # def register


  public
  def filter(event)



    begin

      # drop nxlog related events
      if is_nxlog_event?(event)
        event.cancel
        return
      end


      # auth key check
      user = get_user(event)
      if user
        event['SphinxUserId'] = user["id"]
      else
        event.cancel
        return
      end

      # insert host to database
      hostname = event["Hostname"]
      add_host_to_db(user['id'], hostname)

      # remove access_key
      remove_data_forwarder_credential(event)

      # get event filter
      event_filter = @event_filter_factory.get_filter(event)

      # apply the filter
      event_filter.apply(event)
      event_filter.finalize(event)

    rescue => e
      @logger.error("SphinxPlugin: #{e.message}")
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter

  private
  def add_host_to_db(user_id, hostname)
    @data_accessor.add_host(user_id, hostname)
    nil
  end

  private
  def get_user(event)
    access_id = event['SphinxAccessId']
    access_key = event['SphinxAccessKey']
    return @data_accessor.get_user(access_id, access_key)
  end


  private
  def is_nxlog_event?(event)
    event['SourceName'] == 'nxlog-ce'
  end

  private
  def remove_data_forwarder_credential(event)
    event.remove('SphinxAccessId')
    event.remove('SphinxAccessKey')
  end

end # class LogStash::Filters::Example
