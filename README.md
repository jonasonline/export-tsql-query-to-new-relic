# export-tsql-query-to-new-relic

Executes a t-sql script on a given Microsoft SQL Server instance from a pre-configured script file and posts the result as events to New Relic INSIGHTS.

Exported events are logged as hashes in a local log file to prevent duplicate events in New Relic. 