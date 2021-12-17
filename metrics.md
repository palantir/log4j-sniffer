# Metrics

## Log4j-scanner 

`github.com/palantir/log4j-scanner`

### com.palantir.log4j-scanner.crawl
Metrics reflecting state of log4j-scanner crawls.
- `com.palantir.log4j-scanner.crawl.duration_milliseconds` (gauge): Gauge value containing the duration in milliseconds of the most recent crawl.
- `com.palantir.log4j-scanner.crawl.status` (gauge): Value representing status of most recent crawl. Zero for success, non-zero for error.

### com.palantir.log4j-scanner.report
Metrics regarding vulnerabilities.
- `com.palantir.log4j-scanner.report.vulnerable_files_found` (gauge): Number of vulnerable files found on host.
