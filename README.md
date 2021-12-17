<p align="right">
<a href="https://autorelease.general.dmz.palantir.tech/palantir/log4j-sniffer"><img src="https://img.shields.io/badge/Perform%20an-Autorelease-success.svg" alt="Autorelease"></a>
</p>

log4j-sniffer
============

log4j-sniffer searches for all instances log4j that are earlier than version 2.16 on disk within a specified directory.
It can be used to determine whether there are any vulnerable instances of log4j within a directory tree.

What this does
==============

log4j-sniffer will scan a filesystem looking for all files of the following types:
- Zips: .zip, .par
- Java archives: .jar, .war, .ear
- Tar: .tar.gz, .tgz

It will look for the following:
- Jar files matching `log4j-core-<version>.jar`, including those nested within another archive
- Class files named `org.apache.logging.log4j.core.lookup.JndiLookup` within Jar files or other archives
- Class files named `JndiLookup` in other package hierarchies

Installing
==========
If Go is available on the host system, the following command can be used to install this program:

```
go install github.com/palantir/log4j-sniffer@latest
```

This repository also publishes binaries that can be downloaded and executed.

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
{"entityName":"log4j-sniffer","entityVersion":"0.13.0-3-gc305bc9.dirty","payload":{"serviceLogV1":
 {"level":"INFO","message":"Vulnerable file found","
  origin":"github.com/palantir/log4j-sniffer/pkg/crawl/report.go:30",
  "params":{
    "classNameMatched":true,
    "classPackageAndNameMatch":false,
    "jarNameInsideArchiveMatched":false,
    "jarNameMatched":false,
    "runID":"2d41fd5c-aa26-4ed7-a7bd-7dd55e72fc4b"},
    "time":"2021-12-17T16:57:49.400357Z"
,"type":"service.1","unsafeParams":{
  "filename":"shadow-7.1.1.jar",
  "path":"/Users/hpryce/.gradle/caches/jars-9/2a8699f09955b409cbe629136c2ce07c/shadow-7.1.1.jar"
}},"type":"serviceLogV1"},"time":"2021-12-17T16:57:49.400348Z","type":"wrapped.1"}
```

With the following meaning:
- classNameMatched: there was a .class file called `JndiLookup` 
- classPackageAndNameMatched: there was a .class file called `JndiLookup` with a package of `org.apache.logging.log4j.core.lookup`
- jarNameInsideArchiveMatched: there was a .jar file called `log4j-core-<version>.jar` inside the archive
- jarNameMatched: the file scanned was a .jar file called `log4j-core-<version>.jar`
- filename: the filename matched
- path: the full path on disk for the file
