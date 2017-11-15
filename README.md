# Dgraph Client for Java

A minimal, basic implementation for a Dgraph client in Java using [grpc].

[grpc]: https://grpc.io/

This client follows the [Dgraph Go client][goclient] closely.

[goclient]: https://github.com/dgraph-io/dgraph/tree/master/client

Before using this client, it is highly recommended that you go through [docs.dgraph.io],
and make sure you understand what Dgraph is all about, and how to run it.

[docs.dgraph.io]:https://docs.dgraph.io

## Quickstart

### Start Dgraph Server
You will need to install [Dgraph v0.9][releases] and run it. After installing
the server, running the following commands:

[releases]: https://github.com/dgraph-io/dgraph/releases

First, create two separate directories for `dgraph zero` and `dgraph server`.

```
mkdir -p dgraphdata/zero dgraphdata/data
```

Then start `dgraph zero`:

```
cd dgraphdata/zero
rm -r zw; dgraph zero
```

Finally, start the `dgraph server`:

```
cd dgraphdata/data
rm -r p w; dgraph server --memory_mb=1024
```

For more configuration options, and other details, refer to [docs.dgraph.io]

### Using the Java client
Checkout the [dgraph-io/DgraphJavaSample] project.

[dgraph-io/DgraphJavaSample]: https://github.com/dgraph-io/DgraphJavaSample

```
$ git clone https://github.com/dgraph-io/DgraphJavaSample
$ cd Dgraph
$ ./gradlew run

> Task :run 
Alice


BUILD SUCCESSFUL in 1s
2 actionable tasks: 2 executed

```

If you see `Alice` in the output, you have a working client. You can explore the source code in `src/main/java/App.java` file.

## Client API
_TODO_
### alter()
### newTransaction()
### Transaction::query()
### Transaction::mutate()
### Transaction::commit()
### Transaction::discard()

## Development

### Building the source

```
./gradlew build
```
If you have made changes to the `task.proto` file, this step will also regenerate the source files
generated by Protocol Buffer tools.

### Code Style
We use [google-java-format] to format the source code. If you run `./gradlew build`, you will be warned
if there is code that is not conformant. You can run `./gradlew goJF` to format the source code, before
commmitting it.

[google-java-format]:https://github.com/google/google-java-format

### Running unit tests
Make sure you have a Dgraph server running on localhost before you run this task.

```
./gradlew test
```

