# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "logstash/environment"
require "logstash/patterns/core"
require "json"
require "set"

# This filter use the Grok method to parse arbitrary text and structure it.
# Then, provide the sql-stream function to support period/sub-records queries
# based on light SQL engine, e.g. SQLite.
#
class LogStash::Filters::Sqlstream < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.

  config_name "sqlstream"

  # the internal table name
  SINCE_TABLE = :since_table

  DEFAULT_ROWS_WINDOW = 5
  DEFAULT_TIME_WINDOW_SECONDS = 0
  # @@table_primary_key = "Internal_SQL_Id_"
  # @@internal_data_blob_col = "Internal_SQL_Serialized_Data_"

  config :time_window_seconds, :validate => :number, :default => DEFAULT_TIME_WINDOW_SECONDS

  config :rows_window, :validate => :number, :default => DEFAULT_ROWS_WINDOW

  # Call the filter flush method at regular interval. (Optional)
  config :periodic_flush, :validate => :boolean, :default => true

  # database config

  # Column names which is extract from the message. This will be used for CREATE TABLE
  config :table_column_names, :validate => :array, :required => true, :default => []

  config :output_query, :validate => :string, :required => true

  # Column alias names of the output_query clause. These will be added as fields into the event object.
  config :output_column_names, :validate => :array, :default => []

  config :table_primary_key, :validate => :string, :default => "Internal_SQL_Id_"

  config :internal_data_blob_col, :validate => :string, :default => "Internal_SQL_Serialized_Data_"

  # config :table_name, :validate => :string, :required => true, :default => "since_table"
  # config :output_select, :validate => :array, :required => true, :default => []
  # config :output_group_by, :validate => :string, :required => true, :default => nil
  # config :output_where, :validate => :string, :required => true, :default => nil
  # config :insert_select_cols, :validate => :array, :default => []

  # once database_path is nil, use memory mode as default.
  config :database_path, :validate => :string, :default => nil

  ################################
  # Grok config
  ################################
  config :match, :validate => :hash, :default => {}

  config :named_captures_only, :validate => :boolean, :default => true

  config :patterns_dir, :validate => :array, :default => []

  config :overwrite, :validate => :array, :default => []

  config :tag_on_failure, :validate => :array, :default => ["_grokparsefailure"]

  config :keep_empty_captures, :validate => :boolean, :default => false

  config :break_on_match, :validate => :boolean, :default => true

  # Register default pattern paths
  @@patterns_path ||= Set.new
  @@patterns_path += [
      LogStash::Patterns::Core.path,
      LogStash::Environment.pattern_path("*")
  ]
  # end grok config
  ################################

  public
  def initialize(params)
    super(params)
    if @time_window_seconds < 0
      @logger.warn("time_window_seconds can not be negative, set the time_window_seconds to default #{DEFAULT_TIME_WINDOW_SECONDS}.")
      @time_window_seconds = DEFAULT_TIME_WINDOW_SECONDS
    end

    if @rows_window < 0
      @logger.warn("rows_window can not be negative, set the rows_window to default #{DEFAULT_ROWS_WINDOW}.")
      @rows_window = DEFAULT_ROWS_WINDOW
    end

    if (@time_window_seconds > 0 and ! @periodic_flush)
      @periodic_flush = true
      @logger.warn("reset the periodic_flush to true, because of the time window is enable.")
    elsif (@time_window_seconds == 0 and @periodic_flush)
      @periodic_flush = false
      @logger.warn("reset the periodic_flush to false, because of the time window is disable.")
    end

    if (@time_window_seconds ==0) and (@rows_window == 0)
      @rows_window = 1
      @logger.warn("Both of time window and rows window are disable, set the rows window as default 1, make sure output every row.")
    end

    # if not @memory and not @database_path
    #   @logger.error("Need to either set memory => true, or a valid database_path.")
    #   teardown
    # end

    # if @output_group_by and (not @time_window_seconds and not @rows_window)
    #   @logger.error("When groupby is set, need to also set time_window_seconds or row_window.")
    #   teardown
    # end

    # TODO check the query sql is validate

    uuid = SecureRandom.uuid
    @table_primary_key = @table_primary_key + uuid
    @internal_data_blob_col = @internal_data_blob_col + uuid
  end

  public
  def register
    # add grok support
    require "grok-pure" # rubygem 'jls-grok'
    require "sequel"
    require "jdbc/sqlite3"

    @patternfiles = []

    # Have @@patterns_path show first. Last-in pattern definitions win; this
    # will let folks redefine built-in patterns at runtime.
    @patterns_dir = @@patterns_path.to_a + @patterns_dir
    @logger.info? and @logger.info("patterns path", :patterns_dir => @patterns_dir)
    @patterns_dir.each do |path|
      if File.directory?(path)
        path = File.join(path, "*")
      end

      Dir.glob(path).each do |file|
        @logger.info? and @logger.info("loading patterns from file", :path => file)
        @patternfiles << file
      end
    end

    @patterns = Hash.new { |h, k| h[k] = [] }

    @logger.info? and @logger.info("Match data", :match => @match)

    @match.each do |field, patterns|
      patterns = [patterns] if patterns.is_a?(String)

      @logger.info? and @logger.info("pattern compile", :field => field, :patterns => patterns)
      patterns.each do |pattern|
        @logger.debug? and @logger.debug("regexp: #{@type}/#{field}", :pattern => pattern)
        grok = Grok.new
        grok.logger = @logger unless @logger.nil?
        add_patterns_from_files(@patternfiles, grok)
        grok.compile(pattern, @named_captures_only)
        @patterns[field] << grok
      end
    end # @match.each

    # add sqlite support
    if @database_path.nil?
      # use the JDBC adapter to connect to sqlite
      # Because of JRuby does not support the native SQLite3
      # very well, we can not use `Sequel.sqlite` here.
      @db = Sequel.connect("jdbc:sqlite::memory:")
    else
      @db = Sequel.connect("jdbc:sqlite:#{@database_path}")
    end

    internal_primary_key = @table_primary_key.to_sym
    internal_data = @internal_data_blob_col.to_sym

    @db.create_table!(SINCE_TABLE) do
      primary_key internal_primary_key
      String internal_data, :text => true # used to cache the json data of the event
    end

    @table_column_names.each do |col_name|
      @db.add_column SINCE_TABLE, col_name.to_sym, String, :text => true
    end

    @output_column_names << @internal_data_blob_col

    # output_select = "`" + @output_select.join("`,`") + "`"
    # @output_query = "SELECT #{output_select} FROM #{SINCE_TABLE}"
    #
    # if @output_where
    #   @output_query = @output_query + " WHERE #{@output_where}"
    # end
    #
    # if @output_group_by
    #   @output_query = @output_query + " GROUP BY #{@output_group_by}"
    # end

    # TODO we use the replacement to construct the query. Is it really the good for us?
    @output_query = @output_query.sub("%{INTERAL_DATA_BLOB_COL}", "`#{@internal_data_blob_col}`")
    @output_query = @output_query.sub("%{INTERNAL_TABLE}", "`#{SINCE_TABLE}`")
    @output_query = @output_query.sub("%{INTERAL_PRIMARY_KEY}", "`#{@table_primary_key}`")

    @logger.debug("sql query: #{@output_query}")

    @table = @db[SINCE_TABLE]
    @rows_since_last_flush = 0
    @last_flush_sec = Time.now.to_i

  end # def register

  public
  def filter(event)
    return unless filter?(event)

    matched = false
    done = false

    @logger.debug? and @logger.debug("Running sql stream filter", :event => event);
    @patterns.each do |field, groks|
      if match(groks, field, event)
        matched = true
        break if @break_on_match
      end
      #break if done
    end # @patterns.each

    if matched
      insert_row(event)
      check_and_output.each do |sql_event|
        # process the generated new event
        filter_matched(sql_event)
        yield sql_event
      end
      # cancel the original event
      event.cancel
    else
      # Tag this event if we can't parse it. We can use this later to
      # reparse+reindex logs if we improve the patterns given.
      @tag_on_failure.each do |tag|
        event["tags"] ||= []
        event["tags"] << tag unless event["tags"].include?(tag)
      end
    end

    @logger.debug? and @logger.debug("Event now: ", :event => event)
  end

  # This is called by the pipeline engine every 5 seconds and also when shutting down.
  public
  def flush(options = {})
    return check_and_output
  end

  ################################
  # SQLite support
  ################################

  # generate the events which contains the new field,
  # once the elapse time reach the time window or
  # the input records reach the row window
  private
  def check_and_output
    if ready_for_output
      begin
        return query_and_new_events
      ensure
        # clean the table
        truncate
        # reset the status
        @last_flush_sec = Time.now.to_i
        @rows_since_last_flush = 0
      end
    else
      return []
    end
  end

  private
  def truncate
    @logger.debug("delete the records in table #{SINCE_TABLE}")
    @table.delete
  end

  private
  def insert_row(event)
    event_text = event.to_json
    json_event = JSON.parse(event_text)

    # By default, the primary key and the event text will be stored in the database.
    cols = {@table_primary_key.to_sym => @rows_since_last_flush, @internal_data_blob_col.to_sym => event_text}

    # The column fields which should be stored in the database.
    @table_column_names.each do |col|
      cols[col] = json_event[col]
    end

    begin
      @logger.debug("Insert the records #{@table.insert_sql(cols)}.")
      @table.insert(cols)
      @rows_since_last_flush = @rows_since_last_flush + 1
    rescue StandardError => e
      @logger.error("Exception occured in executing insert.", :exception => e)
    end
  end

  private
  def ready_for_output
    return (ready_for_output_rows or ready_for_output_time)
  end

  private
  def ready_for_output_rows
    if @rows_window == 0
      return false
    end

    @logger.debug("current rows: #{@rows_since_last_flush}, rows window: #{@rows_window}.")
    return @rows_since_last_flush >= @rows_window
  end

  private
  def ready_for_output_time
    if @time_window_seconds == 0
      return false
    end

    elapse_time_seconds = Time.now.to_i - @last_flush_sec
    @logger.debug("elapse time: #{elapse_time_seconds} sec, time window: #{@time_window_seconds} sec.")
    return elapse_time_seconds >= @time_window_seconds
  end

  private
  def query_and_new_events
    new_events = []
    begin
      ary = @db.fetch(@output_query).all
      @logger.debug("Get #{ary.length} records with query \"#{@output_query}\".")
    rescue StandardError => e
      @logger.error("Exception occured in executing select. The query is \"#{@output_query}\".", :exception => e)
    end

    ary.each do |row|
      event_text = row[@internal_data_blob_col.to_sym]
      event_json = JSON.parse(event_text)

      # update the fields
      @output_column_names.each do |col|
        event_json[col] = row[col.to_sym]
      end

      event = LogStash::Event.new(event_json)

      # LogStash::Util::Decorators.add_fields(new_field_hash, event, "filters/#{self.class.name}")
      new_events << event
    end

    return new_events
  end

  ################################
  # based on grok
  ################################
  private
  def match(groks, field, event)
    input = event[field]
    if input.is_a?(Array)
      success = false
      input.each do |input|
        success |= match_against_groks(groks, input, event)
      end
      return success
    else
      return match_against_groks(groks, input, event)
    end
  rescue StandardError => e
    @logger.warn("match regexp threw exception", :exception => e.message)
  end

  private
  def match_against_groks(groks, input, event)
    matched = false
    groks.each do |grok|
      # Convert anything else to string (number, hash, etc)
      matched = grok.match_and_capture(input.to_s) do |field, value|
        matched = true
        handle(field, value, event)
      end
      break if matched and @break_on_match
    end
    return matched
  end

  private
  def handle(field, value, event)
    return if (value.nil? || (value.is_a?(String) && value.empty?)) unless @keep_empty_captures

    if @overwrite.include?(field)
      event[field] = value
    else
      v = event[field]
      if v.nil?
        event[field] = value
      elsif v.is_a?(Array)
        event[field] << value
      elsif v.is_a?(String)
        # Promote to array since we aren't overwriting.
        event[field] = [v, value]
      end
    end
  end

  private
  def add_patterns_from_files(paths, grok)
    paths.each do |path|
      if !File.exists?(path)
        raise "pattern file does not exist: #{path}"
      end
      grok.add_patterns_from_file(path)
    end
  end # def add_patterns_from_files
  ################################

end # class LogStash::Filters::SqlStream
