<p align="right">
<a href="https://autorelease.general.dmz.palantir.tech/palantir/log4j-sniffer"><img src="https://img.shields.io/badge/Perform%20an-Autorelease-success.svg" alt="Autorelease"></a>
</p>

log4j-sniffer
============

log4j-sniffer pulls your archives apart looking for bad log4j versions.

What this does
==============

log4j-sniffer will scan a filesystem looking for all files of the following types:
- Zips: zip, par
- Java archives: jar, war, ear
- Tar: .tar.gz, .tgz

It will look for the following:
- Jar files matching `log4j-core-<version>.jar`, including those nested with one other archive
- Class files named `org.apache.logging.log4j.core.lookup.JndiLookup` within Jar files or other archives
- Class files named `JndiLookup` in other package hierarchies

Downloads
=========

log4j-sniffer executables compiled for linux-amd64, darwin-amd64, and darwin-arm64 architectures are available on the [releases page](https://github.com/palantir/log4j-sniffer/releases).

Running
=======

This tool is intensive and is recommended to be run with low priority settings.

On Linux:
```
ionice -c 3 nice -n 19 log4j-sniffer crawl /path/to/a/directory
```

Output for vulnerable files looks as follows:

```
INFO  [2021-12-17T14:10:10.046706-08:00] github.com/palantir/log4j-sniffer/vendor/github.com/palantir/witchcraft-go-logging/wlog-tmpl/logger.go:48: Crawl started (runID: 0132794a-6b5a-4632-b7ee-7e92672990ee)
INFO  [2021-12-17T14:10:10.053085-08:00] github.com/palantir/log4j-sniffer/vendor/github.com/palantir/witchcraft-go-logging/wlog-tmpl/logger.go:48: Vulnerable file found (classNameMatched: false, classPackageAndNameMatch: true, filename: log4j-core-2.14.1.jar, jarNameInsideArchiveMatched: false, jarNameMatched: true, runID: 0132794a-6b5a-4632-b7ee-7e92672990ee) (path: examples/single_bad_version/log4j-core-2.14.1.jar)
INFO  [2021-12-17T14:10:10.053327-08:00] github.com/palantir/log4j-sniffer/vendor/github.com/palantir/witchcraft-go-logging/wlog-tmpl/logger.go:48: Crawl complete (crawlDuration: 6.867927ms, filesScanned: 1, permissionDeniedCount: 0, runID: 0132794a-6b5a-4632-b7ee-7e92672990ee)
INFO  [2021-12-17T14:10:10.053455-08:00] github.com/palantir/log4j-sniffer/vendor/github.com/palantir/witchcraft-go-logging/wlog-tmpl/logger.go:48: Vulnerable files found (runID: 0132794a-6b5a-4632-b7ee-7e92672990ee, vulnerableFileCount: 1)
[2021-12-17T14:10:10.053568-08:00] METRIC com.palantir.log4j-sniffer.crawl.duration_milliseconds gauge (value: 6)
[2021-12-17T14:10:10.053664-08:00] METRIC com.palantir.log4j-sniffer.crawl.status gauge (value: 0)
[2021-12-17T14:10:10.053741-08:00] METRIC com.palantir.log4j-sniffer.report.vulnerable_files_found gauge (value: 1)
```

With the following meaning:
- classNameMatched: there was a .class file called `JndiLookup` 
- classPackageAndNameMatched: there was a .class file called `JndiLookup` with a package of `org.apache.logging.log4j.core.lookup`
- jarNameInsideArchiveMatched: there was a .jar file called `log4j-core-<version>.jar` inside the archive
- jarNameMatched: the file scanned was a .jar file called `log4j-core-<version>.jar`
- filename: the filename matched
- path: the full path on disk for the file
