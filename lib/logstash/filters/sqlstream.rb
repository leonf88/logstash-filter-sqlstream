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
  #
  # filter {
  #   sqlite {
  #     # common config
  #     memory => true            (optional)
  #     time_window_seconds => 5  (optional)
  #     records_window => 10      (optional)
  #     match => { "message" => "%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}" }  (required)
  #     output_select => "client, method"       (required)
  #     output_groupby => "duration"            (optional)
  #
  #     # sqlite jdbc config
  #
  #   }
  # }
  #
  config_name "sqlstream"

  config :time_window_seconds, :validate => :number, :default => 5

  config :rows_window, :validate => :number, :default => 10

  config :output_select, :validate => :array, :required => true, :default => []

  config :output_groupby, :validate => :string, :required => true, :default => nil

  # Call the filter flush method at regular interval. (Optional)
  config :periodic_flush, :validate => :boolean, :default => true

  # Sqlite config
  config :memory, :validate => :boolean, :default => false

  config :db_path, :validate => :string, :default => nil

  # config :table_name, :validate => :string, :required => true, :default => "since_table"

  config :table_cols, :validate => :array, :required => true, :default => []

  config :insert_select_cols, :validate => :array, :default => []

  SINCE_TABLE = :since_table
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
    if not @memory and not @db_path
      @logger.error("Need to either set memory => true, or a valid db_path.")
      teardown
    end

    if @output_groupby and (not @time_window_seconds and not @records_window)
      @logger.error("When groupby is set, need to also set time_window_seconds or row_window.")
      teardown
    end
    uuid = SecureRandom.uuid
#   @table_primary_key = @table_primary_key + uuid
#   @internal_data_blob_col = @internal_data_blob_col + uuid
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
    @logger.info? and @logger.info("Grok patterns path", :patterns_dir => @patterns_dir)
    @patterns_dir.each do |path|
      if File.directory?(path)
        path = File.join(path, "*")
      end

      Dir.glob(path).each do |file|
        @logger.info? and @logger.info("Grok loading patterns from file", :path => file)
        @patternfiles << file
      end
    end

    @patterns = Hash.new { |h, k| h[k] = [] }

    @logger.info? and @logger.info("Match data", :match => @match)

    @match.each do |field, patterns|
      patterns = [patterns] if patterns.is_a?(String)

      @logger.info? and @logger.info("Grok compile", :field => field, :patterns => patterns)
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

    if @memory
      # TODO => LoadError: no such file to load -- sqlite3
      @db = Sequel.sqlite
    else
      @db = Sequel.connect("jdbc:sqlite:#{@db_path}")
    end

    # TODO handle table_cols is empty
    @db.create_table!(SINCE_TABLE) do
      primary_key :id
    end

    @table_cols.each do |col_name|
      @db.add_column SINCE_TABLE, col_name, String, :text => true
    end

    @table = @db[SINCE_TABLE]
    @rows_since_last_flush = 0

    # p @table.insert_sql([1, "hello", "a", "b", "c", "d", "e"])
    # @table.insert([1, "hello", "a", "b", "c", "d", "e"])
    # p @table.all

    # tbl = :test
    # @db.create_table!(tbl) do
    #   primary_key :id
    #   String :message, :text => true
    # end
    #
    # @db[tbl].insert([1, "hello"])
    # p @db[tbl].all
  end

  # def register

  # TODO why not use the default
  # public
  # def multi_filter(events)
  # end

  public
  def filter(event)
    return unless filter?(event)

    matched = false

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
      @rows_since_last_flush = @rows_since_last_flush + 1
      check_and_output.each do |sql_event|
        filter_matched(sql_event)
        yield sql_event
      end
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

  def teardown
    # Nothing to do by default.
  end

  ################################
  # SQLite support
  ################################
  # private
  # def group_rows(event)
  #   if @output_groupby
  #     p 321
  #   end
  # end

  private
  def check_and_output
    if ready_for_output
      begin
        return output
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
    @table.delete
  end

  private
  def insert_row(event)
    json_message = event.to_json
    if @insert_select_cols.empty?
      return json_message
    end

    json_event = JSON.parse(json_message)

    cols = {:id => @rows_since_last_flush}
    @insert_select_cols.each do |col|
      cols[col] = json_event[col]
    end

    begin
      @table.insert(cols)
    rescue StandardError => e
      @logger.error("Exception occured in executing insert.", e)
    end
  end

  private
  def ready_for_output
    return (ready_for_output_rows and ready_for_output_time)
  end

  private
  def ready_for_output_rows
    if @rows_window.nil?
      return false
    end

    return @rows_since_last_flush >= @rows_window
  end

  private
  def ready_for_output_time
    if @time_window_seconds.nil?
      return false
    end

    return (Time.now.to_i - @last_flush_sec) >= @time_window_seconds
  end

  # This is called by the pipeline engine every 5 seconds and also when shutting down.
  private
  def flush(options = {})
    return check_and_output
  end

  private
  def output
    results = []
    output_select = @output_select.join(",")
    output_query = "SELECT #{output_select} FROM #{SINCE_TABLE}"
    if @output_groupby
      output_query = output_query + " GROUP BY #{@output_groupby}"
    end
    ary = @db.fetch(output_query).all
    ary.each do |row|
      event_json = row[0]
      event_hash = JSON.parse(event_json)
      event = LogStash::Event.new(event_hash)
      new_field_hash = {}
      next_col = 1
      @output_columns_names.each do |output_col|
        new_field_hash[output_col] = row[next_col]
        next_col = next_col + 1
      end
      LogStash::Util::Decorators.add_fields(new_field_hash, event, "filters/#{self.class.name}")
      results << event
    end
    return results
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
    @logger.warn("Grok regexp threw exception", :exception => e.message)
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
        raise "Grok pattern file does not exist: #{path}"
      end
      grok.add_patterns_from_file(path)
    end
  end # def add_patterns_from_files
  ################################

end # class LogStash::Filters::SqlStream
