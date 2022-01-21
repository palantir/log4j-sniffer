# Walking zipped content in a memory optimised manner

### Intent
The following modifications have been made to the original standard zip package to allow for iterating through zipped content in a memory considerate manner.

The standard package has been optimised for goals other than what we required.
The upstream implementation collects a slice of `*File` with a size equal to the number of files contained within a zip.
This implementation works in a iterative/streaming manner where upon encountering a `*File` in the zip directory tree, the file is immediately passed to a function provided by the user for processing.

### Package API
Two top-level functions have been introduced `zip.WalkZipFile` and `WalkZipReaderAt` that are akin to the standard package `zip.OpenReader` and `zip.NewReader` functions, respectively, but accepting another parameter, a `WalkFn`, and immediately walking through the contents of the zip file provided by the file or reader, passing each entry to the given `WalkFn`.

The `WalkFn`, when passed a `*File` should return a bool and an error. A false bool or a non-nil error will cause the walk to stop and return the error to the user.

### Changes made relative to the codebase in the standard `zip` package
* All Write-related code has been removed where possible. We are only interested in reading.
* All ways to create a `Reader/ReadCloser` have been removed from the package API, allowing only a single entrypoint to the Walk functions that we have implemented.
* After making the above changes, all unused code has been removed apart from some constants that were part of constant groups.
* The `Reader.init` method has been renamed to `Reader.walk` to reperesent the functionality that it now holds. More details on the cahnges for this can be found below.
* The `Reader.Files` field, a `[]*File` has been removed to make it impossible to incur the memory penalty of accumulating a slice of `*File` details.
* All tests that are appropriate to keep have been migrated to represent equivalents of their original but using the new `Walk` methods. An extra test file `reader_local_test.go` has been introduced, containing tests specific for our implementation.
* Some tests that use standard `internal` package have been removed as it is impossible for us to reference them.
* Examples have been removed.
* Some general changes have been made to make the codebase meet some of our linter requirements, i.e. Matching names of method receivers in method definitions, some extra error checking and removal of unnecessary conversions between value types.

### Changes to Reader.init/Reader.walk
* `Reader.init` is where the standard package reads through the directory tree of the zip file to accumulate a slice of `*File` for each file in the zip. This method has been changed to accept a `WalkFn` which each `*File` is passed to instead of appending it to a slice. The `WalkFn` is passed into the two top-level `Walk` functions by the caller.
* All logic related to `Reader.Files` has been removed.
* The given WalkFn, when passed a `*File` should return a bool and an error. A false bool or a non-nil error will cause the walk to stop and return the error to the user.
* If the WalkFn never returns a false or non-nil error, the expected number of directory records is compared against the number of files iterated through, in a similar manner that the length of `Reader.Files` was previously checked. If the numbers do not match, an error is returned from the top-level `Walk` functions.
* `File.readDataDescriptor` is no longer called on each file as it is iterated, this change has been made for performance reasons as it is an expensive call and the information populated by `File.readDataDescriptor` is not required unless the File is being open. This is now called within the `File.Open` method so that it is only called if the file is going to be opened.
  A user can now determine whether the file should be opened from the filename or size, for example, and then only have `f.readDataDescriptor` called for those that are opened.

### Changes to File
* `File.readDataDescriptor` now accepts a `bodyOffset` rather than calling `findBodyOffset` to determine it. This change was made because in `File.Open`, we now find the body offset when `Open` is called and can inject it into `readDataDescriptor` to avoid `findBodyOffset` being called multiple times per `Open`.
