# export-tsql-query-to-new-relic

Executes a t-sql script from a pre-configured script file on a given Microsoft SQL Server instance and posts the result as events to New Relic INSIGHTS.

Exported events are logged as hashes in a local log file to prevent duplicate events in New Relic. 