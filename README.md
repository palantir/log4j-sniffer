<p align="right">
<a href="https://autorelease.general.dmz.palantir.tech/palantir/log4j-sniffer"><img src="https://img.shields.io/badge/Perform%20an-Autorelease-success.svg" alt="Autorelease"></a>
</p>

log4j-sniffer
============

log4j-sniffer crawls for all instances of log4j that are earlier than version 2.16 on disk within a specified directory.
It can be used to determine whether there are any vulnerable instances of log4j within a directory tree.

What this does
==============

log4j-sniffer will scan a filesystem looking for all files of the following types based upon suffix:
- Zips: .zip
- Java archives: .jar, .war, .ear
- Tar: .tar.gz, .tgz

It will look for the following:
- Jar files matching `log4j-core-<version>.jar`, including those nested within another archive
- Class files named `org.apache.logging.log4j.core.net.JndiManager` within Jar files or other archives and check against md5 hashes of known versions
- Class files named `JndiManager` in other package hierarchies and check against md5 hashes of known versions

Installing
==========
If Go is available on the host system, the following command can be used to install this program:

```
go install github.com/palantir/log4j-sniffer@latest
```

This repository also publishes binaries that can be downloaded and executed.

Downloads
=========

log4j-sniffer executables compiled for linux-amd64, darwin-amd64, darwin-arm64 and windows-amd64 architectures are available on the [releases page](https://github.com/palantir/log4j-sniffer/releases).

Running
=======

This tool is intensive and is recommended to be run with low priority settings.

On Linux:
```
ionice -c 3 nice -n 19 log4j-sniffer crawl /path/to/a/directory
```

Output for vulnerable files looks as follows:

```
INFO  [2021-12-17T14:10:10.046706-08:00] github.com/palantir/log4j-sniffer/pkg/crawl/crawler.go:50: Crawl started (runID: 0132794a-6b5a-4632-b7ee-7e92672990ee)
INFO  [2021-12-17T14:10:10.053085-08:00] github.com/palantir/log4j-sniffer/pkg/crawl/report.go:44: CVE-2021-45046 detected (classFileMd5Matched: true, classNameMatched: false, classPackageAndNameMatch: true, filename: log4j-core-2.14.1.jar, jarNameInsideArchiveMatched: false, jarNameMatched: true, runID: 0132794a-6b5a-4632-b7ee-7e92672990ee) (log4jVersions: [2.14.0 - 2.14.1 2.14.1]) (path: examples/single_bad_version/log4j-core-2.14.1.jar)
INFO  [2021-12-17T14:10:10.053327-08:00] github.com/palantir/log4j-sniffer/pkg/crawl/crawler.go:54: Crawl complete (crawlDuration: 6.867927ms, filesScanned: 1, permissionDeniedCount: 0, runID: 0132794a-6b5a-4632-b7ee-7e92672990ee)
INFO  [2021-12-17T14:10:10.053455-08:00] github.com/palantir/log4j-sniffer/internal/crawler/crawl.go:46: Files affected by CVE-2021-45046 detected (runID: 0132794a-6b5a-4632-b7ee-7e92672990ee, vulnerableFileCount: 1)
```

With the following meaning:
- classFileMd5Matched: there was a .class file called `JndiManager` that matched the md5 hash of a known version
- classNameMatched: there was a .class file called `JndiManager`
- classPackageAndNameMatched: there was a .class file called `JndiManager` with a package of `org.apache.logging.log4j.core.net`
- jarNameInsideArchiveMatched: there was a .jar file called `log4j-core-<version>.jar` inside the archive
- jarNameMatched: the file scanned was a .jar file called `log4j-core-<version>.jar`
- log4jVersions: the versions detected at this location based on a combination of filenames and md5 hash matching
- filename: the filename matched
- path: the full path on disk for the file
