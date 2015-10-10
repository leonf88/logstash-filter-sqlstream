# logstash-filter-sqlstream Plugin

This is a plugin for [Logstash](https://github.com/elastic/logstash).

It is owned by HoneycombData. If you have any question, you can contact `chcdlf@gmail.com`.

## Documents

This filter is used for parse the input records to structured data and provide stream-sql support.

Firstly, it parses the records in the Grok way and generate several new fields which may be inserted in the database with lightweight local sql engine, e.g. SQLite3.
Then, the filter will select the database according to the user-defined query.
The records selected from the database finally generate new events and passed to the next component in Logstash.
The generated event is based on the original event which has be serialized into the database in processing insert.

When the query will group by several records (say m recs), and generate new events (say n events, m != n).
The new event is based on the serialized data selected from database, which may be the latest one.

We have three reserved words in the database, e.g.

* %{INTERNAL_DATA_BLOB_COL} => the column which is used to store the serialized event
* %{INTERNAL_TABLE} => the table name
* %{INTERNAL_PRIMARY_KEY} =>

So, the simplest query should be like

    "select %{INTERNAL_DATA_BLOB_COL} from %{INTERNAL_TABLE}"

!!!When user define the self-query, the column field `%{INTERNAL_DATA_BLOB_COL}` should be remained. The query may looks like:

    "select %{INTERNAL_DATA_BLOB_COL}, col1, col2 from %{INTERNAL_TABLE} where ... group by ..."

## Usage

Set the conf/shipper.conf like these below.

```
filter {
    sqlstream {
        # the match pattern which is as the same as grok
        match => ... # hash (optional), default: {}
        # when the database_path is not set, the SQLite3 will use in memory mode.
        database_path => # string (optional), default: "/var/logs/logstash/sqlstream.db"
        # one of the time_window_seconds and rows_window should be set
        # if the value is 0, it means the disable this field
        time_window_seconds => ... # number (required), default: 0
        rows_window => ... # number (required), default: 5
        # periodically check whether the query condition has been reached.
        # if the time window is enable, the periodic flush will also be set as true.
        periodic_flush => ... # boolean (optional), default: true
        # the internal table column names
        table_column_names => ... # array (required), default: []
        # the output column names based on the query
        output_column_names => ... # array (required), default: []
        # the query
        output_query => ... # string (required), default: "select %{INTERNAL_DATA_BLOB_COL} from %{INTERNAL_TABLE}"
    }
}
```

```
filter {
    sqlstream {

        match => {
            "message" => "%{ip:client} %{word:method} %{uripathparam:request} %{number:bytes} %{number:duration}"
        }

        database_path => "/var/log/logstash/sqlstream.db"

        time_window_seconds => 10
        rows_window => 3

        periodic_flush => true
        table_column_names => ["client", "method", "request", "bytes", "duration"]

#       output_column_names => ["client", "method", "duration"]
#       output_query => "select %{INTERNAL_DATA_BLOB_COL}, client, method, duration from %{INTERNAL_TABLE} where %{INTERNAL_PRIMARY_KEY} = 0"

        output_column_names => ["NumberOfMethod"]
        output_query => "select %{INTERNAL_DATA_BLOB_COL}, count(method) as NumberOfMethod from %{INTERNAL_TABLE} group by client"
    }
}
```

## Running logstash-filter-sqlstream

### 1 Run in a local Logstash clone

- Edit Logstash `Gemfile` and add the local plugin path, for example:
```ruby
gem "logstash-filter-sqlstream", :path => "/your/local/logstash-filter-sqlstream"
```
- Install plugin
```sh
bin/plugin install --no-verify
```
- Run Logstash with your plugin
```sh
bin/logstash -e 'filter {sqlstream {}}'
```
At this point any modifications to the plugin code will be applied to this local Logstash setup. After modifying the plugin, simply rerun Logstash.

### 2 Run in an installed Logstash

You can use the same **2.1** method to run your plugin in an installed Logstash by editing its `Gemfile` and pointing the `:path` to your local plugin development directory or you can build the gem and install it using:

- Build your plugin gem
```sh
gem build logstash-filter-sqlstream.gemspec
```
- Install the plugin from the Logstash home
```sh
bin/plugin install /your/local/plugin/logstash-filter-sqlstream.gem
```
- Start Logstash and proceed to test the plugin

