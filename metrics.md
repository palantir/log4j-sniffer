# Metrics

## Log4j-sniffer 

`github.com/palantir/log4j-sniffer`

### com.palantir.log4j-sniffer.crawl
Metrics reflecting state of log4j-sniffer crawls.
- `com.palantir.log4j-sniffer.crawl.duration_milliseconds` (gauge): Gauge value containing the duration in milliseconds of the most recent crawl.
- `com.palantir.log4j-sniffer.crawl.status` (gauge): Value representing status of most recent crawl. Zero for success, non-zero for error.

### com.palantir.log4j-sniffer.report
Metrics regarding vulnerabilities.
- `com.palantir.log4j-sniffer.report.vulnerable_files_found` (gauge): Number of vulnerable files found on host.
