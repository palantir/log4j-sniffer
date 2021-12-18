<p align="right">
<a href="https://autorelease.general.dmz.palantir.tech/palantir/log4j-sniffer"><img src="https://img.shields.io/badge/Perform%20an-Autorelease-success.svg" alt="Autorelease"></a>
</p>

log4j-sniffer
============

log4j-sniffer crawls for all instances of log4j that are earlier than version 2.16 on disk within a specified directory.
It can be used to determine whether there are any vulnerable instances of log4j within a directory tree.

Scanning for CVE-2021-45046 and CVE-2021-45105 is currently supported.

What this does
==============

log4j-sniffer will scan a filesystem looking for all files of the following types based upon suffix:
- Zips: .zip
- Java archives: .jar, .war, .ear
- Tar: .tar.gz, .tgz

Zips and Java archives containing other zips and Java archives will be recursively inspected up to a maximum depth of 2.

It will look for the following:
- Jar files matching `log4j-core-<version>.jar`, including those nested within another archive
- Class files named `org.apache.logging.log4j.core.net.JndiManager` within Jar files or other archives and check against md5 hashes of known versions
- Class files named `JndiManager` in other package hierarchies and check against md5 hashes of known versions
- Matching of the bytecode of classes named JndiManager against known patterns (see below for more details)

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
CVE-2021-45046 and CVE-2021-45105 detected in file examples/single_bad_version/log4j-core-2.14.1.jar. log4j versions: 2.14.0 - 2.14.1, 2.14.1. Reasons: jar name matched, class and package name matched, class file MD5 matched
Files affected by CVE-2021-45046 or CVE-2021-45105 detected: 1 file(s) impacted by CVE-2021-45046 or CVE-2021-45105
1 total files scanned, skipped 0 paths due to permission denied errors, encountered 0 errors processing paths
```

CVE-2021-45105
==============

If you do not wish to report results for CVE-2021-45105 then pass the `--disable-cve-2021-45105-detection` flag to the crawl command.

By default, both CVE-2021-45046 and CVE-2021-45105 will be reported.

Usage
=====
The primary command for the tool is `crawl` which takes an argument that is the path to the directory to be crawled.
Thus, the standard usage is:

```
log4j-sniffer crawl [pathToDirectory]
```

The standard mode prints output in a human-readable format and prints a summary that states the number of
vulnerabilities found after running.

Specifying the `--json` flag makes it such that the output of the program is all in JSON: each line of output is JSON
that describes the vulnerability that is found, and if summary mode is enabled then the final summary is also output as
a line of JSON.

Here is an example of the output with `--json`:

```
{"message":"CVE-2021-45046 and CVE-2021-45105 detected","filePath":"examples/single_bad_version/log4j-core-2.14.1.jar","classNameMatched":false,"classPackageAndNameMatch":true,"classFileMd5Matched":true,"bytecodeInstructionMd5Matched":false,"jarNameMatched":true,"jarNameInsideArchiveMatched":false,"log4jVersions":["2.14.0 - 2.14.1","2.14.1"]}
{"filesScanned":1,"permissionDeniedErrors":0,"pathErrors":0,"numImpactedFiles":1}
```

The JSON fields have the following meaning:
- message: information about the output
- filePath: the path to the file in which the vulnerability was detected 
- classNameMatched: there was a .class file called `JndiLookup`
- classPackageAndNameMatched: there was a .class file called `JndiLookup` with a package of `org.apache.logging.log4j.core.lookup`
- classFileMd5Matched: there was a .class file called JndiManager that matched the md5 hash of a known version
- bytecodeInstructionMd5Matched: the bytecode of a .class file called JndiManager exactly matched a known version, see [Bytecode matching](#bytecode-matching) section for more details
- jarNameMatched: the file scanned was a .jar file called `log4j-core-<version>.jar`
- jarNameInsideArchiveMatched: there was a .jar file called `log4j-core-<version>.jar` inside the archive
- log4jVersions: the versions detected at this location based on a combination of filenames and md5 hash matching

Specifying `--summary=false` makes it such that the program does not output a summary line at the end. In this case,
the program will only print output if vulnerabilities are found.

Bytecode matching
=================

If a class is shaded (for example, to build a fat jar), then the bytecode is rewritten to update the package. This means the hash of the class will no longer match against known versions, nor will the class appear where expected within a jar.

To account for this, we perform a less accurate hash of a class file: we only hash the fixed parts of the bytecode defining each method, ignoring all parts that might vary upon shading. We take an md5 hash of the resulting bytecode and compare against known versions.

Testing against shaded jars shows this matches when the package version has been changed but the class otherwise left intact. Shading which further modifies classes, such as by removing methods, will not be found with this approach.
