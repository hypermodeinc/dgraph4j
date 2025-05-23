# Dgraph Client for Java

A minimal implementation for a Dgraph client for Java 11 and above, using [grpc].

**Note:** v24.0.0 features an upgraded protobuf dependency which requires an upgrade to JDK 11. On
account of this breaking change, all legacy applications built upon JDK 8 would be impacted.

[grpc]: https://grpc.io/

This client follows the [Dgraph Go client][goclient] closely.

[goclient]: https://github.com/dgraph-io/dgo

Before using this client, we highly recommend that you go through [docs.dgraph.io], and understand
how to run and work with Dgraph.

[docs.dgraph.io]: https://docs.dgraph.io

**Use [Discuss Issues](https://discuss.dgraph.io/c/issues/35/clients/46) for reporting issues about
this repository.**

## Table of Contents

- [Dgraph Client for Java](#dgraph-client-for-java)

  - [Table of Contents](#table-of-contents)
  - [Download](#download)
  - [Supported Versions](#supported-versions)
    - [Note regarding Java 1.8.x support:](#note-regarding-java-18x-support)
  - [Quickstart](#quickstart)
  - [Intro](#intro)
  - [Using the Synchronous Client](#using-the-synchronous-client)
    - [Creating a Client](#creating-a-client)
    - [Creating a Client for Dgraph Cloud](#creating-a-client-for-dgraph-cloud)
    - [Creating a Secure Client using TLS](#creating-a-secure-client-using-tls)
    - [Check Dgraph version](#check-dgraph-version)
    - [Login Using ACL](#login-using-acl)
    - [Altering the Database](#altering-the-database)
    - [Creating a Transaction](#creating-a-transaction)
    - [Running a Mutation](#running-a-mutation)
    - [Committing a Transaction](#committing-a-transaction)
    - [Running a Query](#running-a-query)
    - [Running a Query with RDF response](#running-a-query-with-rdf-response)
    - [Running an Upsert: Query + Mutation](#running-an-upsert-query--mutation)
    - [Running a Conditional Upsert](#running-a-conditional-upsert)
    - [Setting Deadlines](#setting-deadlines)
      - [Setting deadlines for all requests](#setting-deadlines-for-all-requests)
      - [Setting deadlines for a single request](#setting-deadlines-for-a-single-request)
    - [Setting Metadata Headers](#setting-metadata-headers)
    - [Helper Methods](#helper-methods)
      - [Delete multiple edges](#delete-multiple-edges)
    - [Closing the DB Connection](#closing-the-db-connection)
  - [Using the Asynchronous Client](#using-the-asynchronous-client)
  - [Checking the request latency](#checking-the-request-latency)
  - [Development](#development)
    - [Building the source](#building-the-source)
    - [Code Style](#code-style)
    - [Running unit tests](#running-unit-tests)

- [Using the Asynchronous Client](#using-the-asynchronous-client)
- [Checking the request latency](#checking-the-request-latency)

- [Development](#development)
  - [Building the source](#building-the-source)
  - [Code Style](#code-style)
  - [Running unit tests](#running-unit-tests)

## Download

grab via Maven:

```xml
<dependency>
  <groupId>io.dgraph</groupId>
  <artifactId>dgraph4j</artifactId>
  <version>24.2.0</version>
</dependency>
```

or Gradle:

```groovy
compile 'io.dgraph:dgraph4j:24.2.0'
```

## Supported Versions

Depending on the version of Dgraph that you are connecting to, you will have to use a different
version of this client.

| Dgraph version  | dgraph4j version | java version |
| :-------------: | :--------------: | :----------: |
|      1.0.X      |      1.X.X       |    1.9.X     |
|  1.1.0 - 2.X.X  |      2.X.X       |    1.9.X     |
| 20.03.X-20.07.X |     20.03.X      |    1.9.X     |
|     20.11.X     |     20.11.X      |    1.9.X     |
|   >= 21.XX.X    |     21.XX.X      |    1.9.X     |
|    >= 24.X.X    |      24.X.X      |      11      |

### Note regarding Java 1.8.x support

v24.0.0 features an upgraded protoc-protobuf dependency that requires an upgrade to JDK 11. This
version is incompatible with Java 1.8 and and requires an upgrade to Java 11.

The following is only applicable to dgraph4j versions < v24.X.X.

- If you aren't using gRPC with TLS, then the above version table will work for you with Java 1.8.x
  too.
- If you're using gRPC with TLS on Java 1.8.x, then you will need to follow gRPC docs
  [here](https://github.com/grpc/grpc-java/blob/master/SECURITY.md#tls-on-non-android). Basically,
  it will require you to add the following dependency in your app with correct version for the
  corresponding `grpc-netty` version used by `dgraph4j`. You can find out the correct version of the
  dependency to use from the version combination table in [this section] in `grpc-netty` docs.

  For maven:

  ```xml
  <dependency>
    <groupId>io.netty</groupId>
    <artifactId>netty-tcnative-boringssl-static</artifactId>
    <version><!-- See table in gRPC docs for correct version --></version>
  </dependency>
  ```

  For Gradle:

  ```groovy
  compile 'io.netty:netty-tcnative-boringssl-static:<See table in gRPC docs for correct version>'
  ```

  The following table lists the `grpc-netty` versions used by different `dgraph4j` versions over
  time, along with the supported versions of `netty-tcnative-boringssl-static` for the corresponding
  `grpc-netty` version:

  | dgraph4j version | grpc-netty version | netty-tcnative-boringssl-static version |
  | :--------------: | :----------------: | :-------------------------------------: |
  |    >= 24.0.0     |       1.65.1       |              4.1.100.Final              |
  |    >= 24.1.1     |       1.68.2       |              4.1.110.Final              |
  |    >= 24.2.0     |       1.69.1       |              4.1.111.Final              |

  For example, when using `dgraph4j v24.0.0`, the version of the `netty-tcnative-boringssl-static`
  dependency to be used is `4.1.100.Final`, as suggested by gRPC docs for `grpc-netty v1.65.1`.

[this section]: https://github.com/grpc/grpc-java/blob/master/SECURITY.md#netty

## Quickstart

Build and run the [DgraphJavaSample] project in the `samples` folder, which contains an end-to-end
example of using the Dgraph Java client. Follow the instructions in the README of that project.

[DgraphJavaSample]: https://github.com/hypermodeinc/dgraph4j/tree/master/samples/DgraphJavaSample

## Intro

This library supports two styles of clients, the synchronous client `DgraphClient` and the async
client `DgraphAsyncClient`. A `DgraphClient` or `DgraphAsyncClient` can be initialised by passing it
a list of `DgraphBlockingStub` clients. The `anyClient()` API can randomly pick a stub, which can
then be used for GRPC operations. In the next section, we will explain how to create a synchronous
client and use it to mutate or query dgraph. For the async client, more details can be found in the
[Using the Asynchronous Client](#using-the-asynchronous-client) section.

## Using the Synchronous Client

### Creating a Client

#### Using a Connection String

This library supports connecting to a Dgraph cluster using connection strings. Dgraph connections
strings take the form `dgraph://{username:password@}host:port?args`.

`username` and `password` are optional. If username is provided, a password must also be present. If
supplied, these credentials are used to log into a Dgraph cluster through the ACL mechanism.

Valid connection string args:

| Arg         | Value                           | Description                                                                                                                                                   |
| ----------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| apikey      | \<key\>                         | a Dgraph Cloud API Key                                                                                                                                        |
| bearertoken | \<token\>                       | an access token                                                                                                                                               |
| sslmode     | disable \| require \| verify-ca | TLS option, the default is `disable`. If `verify-ca` is set, the TLS certificate configured in the Dgraph cluster must be from a valid certificate authority. |

Note that using `sslmode=require` disables certificate validation and significantly reduces the
security of TLS. This mode should only be used in non-production (e.g., testing or development)
environments.

Some example connection strings:

| Value                                                                                                        | Explanation                                                                         |
| ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| dgraph://localhost:9080                                                                                      | Connect to localhost, no ACL, no TLS                                                |
| dgraph://sally:supersecret@dg.example.com:443?sslmode=verify-ca                                              | Connect to remote server, use ACL and require TLS and a valid certificate from a CA |
| dgraph://foo-bar.grpc.us-west-2.aws.cloud.dgraph.io:443?sslmode=verify-ca&apikey=\<your-api-connection-key\> | Connect to a Dgraph Cloud cluster                                                   |
| dgraph://foo-bar.grpc.hypermode.com?sslmode=verify-ca&bearertoken=\<some access token\>                      | Connect to a Dgraph cluster protected by a secure gateway                           |

Using the `DgraphClient.open` function with a connection string:

```java
// open a connection to an ACL-enabled, non-TLS cluster and login as groot
DgraphClient client = DgraphClient.open("dgraph://groot:password@localhost:8090");

// some time later...
client.shutdown();
```

#### Using Managed Channels

The following code snippet shows how to create a synchronous client using three connections.

```java
ManagedChannel channel1 = ManagedChannelBuilder
    .forAddress("localhost", 9080)
    .usePlaintext().build();
DgraphStub stub1 = DgraphGrpc.newStub(channel1);

ManagedChannel channel2 = ManagedChannelBuilder
    .forAddress("localhost", 9082)
    .usePlaintext().build();
DgraphStub stub2 = DgraphGrpc.newStub(channel2);

ManagedChannel channel3 = ManagedChannelBuilder
    .forAddress("localhost", 9083)
    .usePlaintext().build();
DgraphStub stub3 = DgraphGrpc.newStub(channel3);

DgraphClient dgraphClient = new DgraphClient(stub1, stub2, stub3);
```

### Creating a Client for Dgraph Cloud

If you want to connect to Dgraph running on a [Dgraph Cloud](https://cloud.dgraph.io) instance, then
all you need is the URL of your Dgraph Cloud instance and the API key. You can get a client with
them as follows :

```java
DgraphStub stub = DgraphClient.clientStubFromCloudEndpoint("https://your-instance.cloud.dgraph.io/graphql", "your-api-key");
DgraphClient dgraphClient = new DgraphClient(stub);
```

Note the `DgraphClient.open` method can be used if you have a Dgraph connection string (see above).

### Creating a Secure Client using TLS

To setup a client using TLS, you could use the following code snippet. The server needs to be setup
using the instructions provided [here](https://docs.dgraph.io/deploy/#tls-configuration).

If you are doing client verification, you need to convert the client key from PKCS#1 format to
PKCS#8 format. By default, grpc doesn't support reading PKCS#1 format keys. To convert the format,
you could use the `openssl` tool.

First, let's install the `openssl` tool:

```sh
apt install openssl
```

Now, use the following command to convert the key:

```sh
openssl pkcs8 -in client.name.key -topk8 -nocrypt -out client.name.java.key
```

Now, you can use the following code snippet to connect to Alpha over TLS:

```java
SslContextBuilder builder = GrpcSslContexts.forClient();
builder.trustManager(new File("<path to ca.crt>"));
// Skip the next line if you are not performing client verification.
builder.keyManager(new File("<path to client.name.crt>"), new File("<path to client.name.java.key>"));
SslContext sslContext = builder.build();

ManagedChannel channel = NettyChannelBuilder.forAddress("localhost", 9080)
    .sslContext(sslContext)
    .build();
DgraphGrpc.DgraphStub stub = DgraphGrpc.newStub(channel);
DgraphClient dgraphClient = new DgraphClient(stub);
```

### Check Dgraph version

Checking the version of the Dgraph server this client is interacting with is as easy as:

```java
Version v = dgraphClient.checkVersion();
System.out.println(v.getTag());
```

Checking the version, before doing anything else can be used as a test to find out if the client is
able to communicate with the Dgraph server. This will also help reduce the latency of the first
query/mutation which results from some dynamic library loading and linking that happens in JVM (see
[this issue](https://github.com/hypermodeinc/dgraph4j/issues/108) for more details).

### Login Using ACL

If ACL is enabled then you can log-in to the default namespace (0) with following:

```java
dgraphClient.login(USER_ID, USER_PASSWORD);
```

For logging-in to some other namespace, use the `loginIntoNamespace` method on the client:

```java
dgraphClient.loginIntoNamespace(USER_ID, USER_PASSWORD, NAMESPACE);
```

Once logged-in, the `dgraphClient` object can be used to do any further operations.

### Altering the Database

To set the schema, create an `Operation` object, set the schema and pass it to `DgraphClient#alter`
method.

```java
String schema = "name: string @index(exact) .";
Operation operation = Operation.newBuilder().setSchema(schema).build();
dgraphClient.alter(operation);
```

Starting Dgraph version 20.03.0, indexes can be computed in the background. You can call the
function `setRunInBackground(true)` as shown below before calling `alter`. You can find more details
[here](https://docs.dgraph.io/master/query-language/#indexes-in-background).

```java
String schema = "name: string @index(exact) .";
Operation operation = Operation.newBuilder()
        .setSchema(schema)
        .setRunInBackground(true)
        .build();
dgraphClient.alter(operation);
```

`Operation` contains other fields as well, including drop predicate and drop all. Drop all is useful
if you wish to discard all the data, and start from a clean slate, without bringing the instance
down.

```java
// Drop all data including schema from the dgraph instance. This is useful
// for small examples such as this, since it puts dgraph into a clean
// state.
dgraphClient.alter(Operation.newBuilder().setDropAll(true).build());
```

### Creating a Transaction

There are two types of transactions in dgraph, i.e. the read-only transactions that only include
queries and the transactions that change data in dgraph with mutate operations. Both the synchronous
client `DgraphClient` and the async client `DgraphAsyncClient` support the two types of transactions
by providing the `newTransaction` and the `newReadOnlyTransaction` APIs. Creating a transaction is a
local operation and incurs no network overhead.

In most of the cases, the normal read-write transactions is used, which can have any number of query
or mutate operations. However, if a transaction only has queries, you might benefit from a read-only
transaction, which can share the same read timestamp across multiple such read-only transactions and
can result in lower latencies.

For normal read-write transactions, it is a good practise to call `Transaction#discard()` in a
`finally` block after running the transaction. Calling `Transaction#discard()` after
`Transaction#commit()` is a no-op and you can call `discard()` multiple times with no additional
side-effects.

```java
Transaction txn = dgraphClient.newTransaction();
try {
    // Do something here
    // ...
} finally {
    txn.discard();
}
```

For read-only transactions, there is no need to call `Transaction.discard`, which is equivalent to a
no-op.

```java
Transaction readOnlyTxn = dgraphClient.newReadOnlyTransaction();
```

Read-only transactions can be set as best-effort. Best-effort queries relax the requirement of
linearizable reads. This is useful when running queries that do not require a result from the latest
timestamp.

```java
Transaction bestEffortTxn = dgraphClient.newReadOnlyTransaction()
    .setBestEffort(true);
```

### Running a Mutation

`Transaction#mutate` runs a mutation. It takes in a `Mutation` object, which provides two main ways
to set data: JSON and RDF N-Quad. You can choose whichever way is convenient.

We're going to use JSON. First we define a `Person` class to represent a person. This data will be
serialized into JSON.

```java
class Person {
    String name
    Person() {}
}
```

Next, we initialise a `Person` object, serialize it and use it in `Mutation` object.

```java
// Create data
Person person = new Person();
person.name = "Alice";

// Serialize it
Gson gson = new Gson();
String json = gson.toJson(person);
// Run mutation
Mutation mu = Mutation.newBuilder()
    .setSetJson(ByteString.copyFromUtf8(json.toString()))
    .build();
// mutationResponse stores a Response protocol buffer object
Response mutationResponse = txn.mutate(mu);
// eg: to get the UIDs created in this mutation
System.out.println(mutationResponse.getUidsMap())
```

Sometimes, you only want to commit mutation, without querying anything further. In such cases, you
can use a `CommitNow` field in `Mutation` object to indicate that the mutation must be immediately
committed.

Mutation can be run using the `doRequest` function as well.

```java
Request request = Request.newBuilder()
    .addMutations(mu)
    .build();
txn.doRequest(request);
```

### Committing a Transaction

A transaction can be committed using the `Transaction#commit()` method. If your transaction
consisted solely of calls to `Transaction#query()`, and no calls to `Transaction#mutate()`, then
calling `Transaction#commit()` is not necessary.

An error will be returned if other transactions running concurrently modify the same data that was
modified in this transaction. It is up to the user to retry transactions when they fail.

```java
Transaction txn = dgraphClient.newTransaction();

try {
    // …
    // Perform any number of queries and mutations
    // …
    // and finally …
    txn.commit()
} catch (TxnConflictException ex) {
    // Retry or handle exception.
} finally {
    // Clean up. Calling this after txn.commit() is a no-op
    // and hence safe.
    txn.discard();
}
```

### Running a Query

You can run a query by calling `Transaction#query()`. You will need to pass in a GraphQL+- query
string, and a map (optional, could be empty) of any variables that you might want to set in the
query.

The response would contain a `JSON` field, which has the JSON encoded result. You will need to
decode it before you can do anything useful with it.

Let’s run the following query:

```java
query all($a: string) {
  all(func: eq(name, $a)) {
            name
  }
}
```

First we must create a `People` class that will help us deserialize the JSON result:

```java
class People {
    List<Person> all;
    People() {}
}
```

Then we run the query, deserialize the result and print it out:

```java
// Query
String query =
"query all($a: string){\n" +
"  all(func: eq(name, $a)) {\n" +
"    name\n" +
"  }\n" +
"}\n";

Map<String, String> vars = Collections.singletonMap("$a", "Alice");
Response response = dgraphClient.newReadOnlyTransaction().queryWithVars(query, vars);

// Deserialize
People ppl = gson.fromJson(response.getJson().toStringUtf8(), People.class);

// Print results
System.out.printf("people found: %d\n", ppl.all.size());
ppl.all.forEach(person -> System.out.println(person.name));
```

This should print:

```sh
people found: 1
Alice
```

You can also use `doRequest` function to run the query.

```java
Request request = Request.newBuilder()
    .setQuery(query)
    .build();
txn.doRequest(request);
```

### Running a Query with RDF response

You can get query results as an RDF response by calling either `queryRDF()` or `queryRDFWithVars()`.
The response contains the `getRdf()` method, which will provide the RDF encoded output.

**Note**: If you are querying for `uid` values only, use a JSON format response

```java
// Query
String query = "query me($a: string) { me(func: eq(name, $a)) { name }}";
Map<String, String> vars = Collections.singletonMap("$a", "Alice");
Response response =
    dgraphAsyncClient.newReadOnlyTransaction().queryRDFWithVars(query, vars).join();

// Print results
System.out.println(response.getRdf().toStringUtf8());
```

This should print (assuming Alice's `uid` is `0x2`):

```sh
<0x2> <name> "Alice" .
```

### Running an Upsert: Query + Mutation

The `txn.doRequest` function allows you to run upserts consisting of one query and one mutation.
Variables can be defined in the query and used in the mutation. You could also use `txn.doRequest`
to perform a query followed by a mutation.

To know more about upsert, we highly recommend going through the docs at
https://docs.dgraph.io/mutations/#upsert-block.

```java
String query = "query {\n" +
  "user as var(func: eq(email, \"wrong_email@dgraph.io\"))\n" +
  "}\n";
Mutation mu = Mutation.newBuilder()
    .setSetNquads(ByteString.copyFromUtf8("uid(user) <email> \"correct_email@dgraph.io\" ."))
    .build();
Request request = Request.newBuilder()
    .setQuery(query)
    .addMutations(mu)
    .setCommitNow(true)
    .build();
txn.doRequest(request);
```

### Running a Conditional Upsert

The upsert block also allows specifying a conditional mutation block using an `@if` directive. The
mutation is executed only when the specified condition is true. If the condition is false, the
mutation is silently ignored.

See more about Conditional Upsert [Here](https://docs.dgraph.io/mutations/#conditional-upsert).

```java
String query = "query {\n" +
    "user as var(func: eq(email, \"wrong_email@dgraph.io\"))\n" +
    "}\n";
Mutation mu = Mutation.newBuilder()
    .setSetNquads(ByteString.copyFromUtf8("uid(user) <email> \"correct_email@dgraph.io\" ."))
    .setCond("@if(eq(len(user), 1))")
    .build();
Request request = Request.newBuilder()
    .setQuery(query)
    .addMutations(mu)
    .setCommitNow(true)
    .build();
txn.doRequest(request);
```

### Setting Deadlines

It is recommended that you always set a deadline for each client call, after which the client
terminates. This is in line with the recommendation for any gRPC client. Read [this forum
post][deadline-post] for more details.

#### Setting deadlines for all requests

```java
channel = ManagedChannelBuilder.forAddress("localhost", 9080).usePlaintext(true).build();
DgraphGrpc.DgraphStub stub = DgraphGrpc.newStub(channel);
ClientInterceptor timeoutInterceptor = new ClientInterceptor(){
    @Override
    public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(
            MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {
        return next.newCall(method, callOptions.withDeadlineAfter(500, TimeUnit.MILLISECONDS));
    }
};
stub = stub.withInterceptors(timeoutInterceptor);
DgraphClient dgraphClient = new DgraphClient(stub);
```

#### Setting deadlines for a single request

```java
dgraphClient.newTransaction().query(query, 500, TimeUnit.MILLISECONDS);
```

[deadline-post]: https://discuss.dgraph.io/t/dgraph-java-client-setting-deadlines-per-call/3056

### Setting Metadata Headers

Certain headers such as authentication tokens need to be set globally for all subsequent calls.
Below is an example of setting a header with the name "auth-token":

```java
// create the stub first
ManagedChannel channel =
ManagedChannelBuilder.forAddress(TEST_HOSTNAME, TEST_PORT).usePlaintext(true).build();
DgraphStub stub = DgraphGrpc.newStub(channel);

// use MetadataUtils to augment the stub with headers
Metadata metadata = new Metadata();
metadata.put(
        Metadata.Key.of("auth-token", Metadata.ASCII_STRING_MARSHALLER), "the-auth-token-value");
stub = MetadataUtils.attachHeaders(stub, metadata);

// create the DgraphClient wrapper around the stub
DgraphClient dgraphClient = new DgraphClient(stub);

// trigger a RPC call using the DgraphClient
dgraphClient.alter(Operation.newBuilder().setDropAll(true).build());
```

### Helper Methods

#### Delete multiple edges

The example below uses the helper method `Helpers#deleteEdges` to delete multiple edges
corresponding to predicates on a node with the given uid. The helper method takes an existing
mutation, and returns a new mutation with the deletions applied.

```java
Mutation mu = Mutation.newBuilder().build()
mu = Helpers.deleteEdges(mu, uid, "friends", "loc");
dgraphClient.newTransaction().mutate(mu);
```

### Closing the DB Connection

To disconnect from Dgraph, call `ManagedChannel#shutdown` on the gRPC channel object created when
[creating a Dgraph client](#creating-a-client).

```java
channel.shutdown();
```

You can also close all channels in from the client object:

```java
dgraphClient.shutdown();
```

## Using the Asynchronous Client

Dgraph Client for Java also bundles an asynchronous API, which can be used by instantiating the
`DgraphAsyncClient` class. The usage is almost exactly the same as the `DgraphClient` (show in
previous section) class. The main differences is that the `DgraphAsyncClient#newTransacation()`
returns an `AsyncTransaction` class. The API for `AsyncTransaction` is exactly `Transaction`. The
only difference is that instead of returning the results directly, it returns immediately with a
corresponding `CompletableFuture<T>` object. This object represents the computation which runs
asynchronously to yield the result in the future. Read more about `CompletableFuture<T>` in the
[Java 8 documentation][futuredocs].

[futuredocs]: https://docs.oracle.com/javase/8/docs/api/java/util/concurrent/CompletableFuture.html

Here is the asynchronous version of the code above, which runs a query.

```java
// Query
String query =
"query all($a: string){\n" +
"  all(func: eq(name, $a)) {\n" +
"    name\n" +
 "}\n" +
"}\n";

Map<String, String> vars = Collections.singletonMap("$a", "Alice");

AsyncTransaction txn = dgraphAsyncClient.newTransaction();
txn.query(query).thenAccept(response -> {
    // Deserialize
    People ppl = gson.fromJson(res.getJson().toStringUtf8(), People.class);

    // Print results
    System.out.printf("people found: %d\n", ppl.all.size());
    ppl.all.forEach(person -> System.out.println(person.name));
});
```

## Checking the request latency

If you would like to see the latency for either a mutation or query request, the latency field in
the returned result can be helpful. Here is an example to log the latency of a query request:

```java
Response resp = txn.query(query);
Latency latency = resp.getLatency();
logger.info("parsing latency:" + latency.getParsingNs());
logger.info("processing latency:" + latency.getProcessingNs());
logger.info("encoding latency:" + latency.getEncodingNs());
```

Similarly you can get the latency of a mutation request:

```java
Assigned assignedIds = dgraphClient.newTransaction().mutate(mu);
Latency latency = assignedIds.getLatency();
```

## Development

### Building the source

**Warning**: The gradle build runs integration tests on a locally running Dgraph server. The tests
will remove all data from your Dgraph instance. So make sure that you don't have any important data
on your Dgraph instance.

```sh
./gradlew build
```

If you have made changes to the `task.proto` file, this step will also regenerate the source files
generated by Protocol Buffer tools.

### Code Style

We use [google-java-format] to format the source code. If you run `./gradlew build`, you will be
warned if there is code that is not conformant. You can run `./gradlew goJF` to format the source
code, before committing it.

[google-java-format]: https://github.com/google/google-java-format

### Running unit tests

**Warning**: This command will runs integration tests on a locally running Dgraph server. The tests
will remove all data from your Dgraph instance. So make sure that you don't have any important data
on your Dgraph instance.

Make sure you have a Dgraph server running on localhost before you run this task.

```sh
./gradlew test
```
