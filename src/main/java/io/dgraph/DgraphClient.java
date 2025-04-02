/*
 * SPDX-FileCopyrightText: © Hypermode Inc. <hello@hypermode.com>
 * SPDX-License-Identifier: Apache-2.0
 */

package io.dgraph;

import io.dgraph.DgraphProto.Operation;
import io.dgraph.DgraphProto.TxnContext;
import io.dgraph.DgraphProto.Version;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.GrpcSslContexts;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.grpc.stub.MetadataUtils;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.Executor;
import java.util.HashMap;
import java.util.Map;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLException;

/**
 * Implementation of a DgraphClient using grpc.
 *
 * <p>Queries, mutations, and most other types of admin tasks can be run from the client.
 *
 * @author Edgar Rodriguez-Diaz
 * @author Deepak Jois
 * @author Michail Klimenkov
 * @author Neeraj Battan
 * @author Abhimanyu Singh Gaur
 */
public class DgraphClient {
  private static final String gRPC_AUTHORIZATION_HEADER_NAME = "authorization";

  private final DgraphAsyncClient asyncClient;

  /**
   * Creates a new DgraphClient instance from a connection string.
   *
   * <p>This method attempts to authenticate via Dgraph's ACL mechanism if
   * username and password are provided.
   * <p>The connection string has the format: "dgraph://[username:password@]host:port[?params]"
   * <p>Supported query parameters:
   * <ul>
   *   <li>sslmode - SSL connection mode. Supported values:
   *     <ul>
   *       <li>"disable" - No encryption, uses plaintext</li>
   *       <li>"require" - Uses TLS encryption without certificate verification</li>
   *       <li>"verify-ca" - Uses TLS encryption with certificate verification</li>
   *     </ul>
   *   </li>
   *   <li>apikey - API key for authorization from Dgraph Cloud</li>
   *   <li>bearertoken - Bearer token for authorization</li>
   * </ul>
   *
   * @param connectionString The connection string to connect to Dgraph
   * @return A new DgraphClient instance
   * @throws IllegalArgumentException If the connection string is invalid
   * @throws MalformedURLException If the connection string cannot be parsed as a URL
   * @throws SSLException If there's an error configuring the SSL context for sslmode=require
   */
  public static DgraphClient open(String connectionString)
      throws IllegalArgumentException, MalformedURLException, SSLException {
    if (connectionString == null || connectionString.isEmpty()) {
      throw new IllegalArgumentException("Connection string cannot be null or empty");
    }

    // Connection string format: dgraph://[username:password@]host:port[?params]
    if (!connectionString.startsWith("dgraph://")) {
      throw new IllegalArgumentException("Invalid connection string: scheme must be 'dgraph'");
    }
    // Parse the URL (Use java.net.URL initially to validate the basic structure)
    URL url;
    try {
      // Replace dgraph:// with http:// for proper URL parsing
      url = new URL(connectionString.replace("dgraph://", "http://"));
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException("Failed to parse connection string: " + e.getMessage(), e);
    }

    // Extract host and port
    String host = url.getHost();
    int port = url.getPort();

    if (host == null || host.isEmpty()) {
      throw new IllegalArgumentException("Invalid connection string: hostname required");
    }
    if (port == -1) {
      throw new IllegalArgumentException("Invalid connection string: port required");
    }

    // Extract username and password
    String username = null;
    String password = null;
    if (url.getUserInfo() != null) {
      String[] userInfo = url.getUserInfo().split(":", 2);
      username = userInfo[0];
      if (userInfo.length > 1) {
        password = userInfo[1];
      }
    }

    if (username != null && (password == null || password.isEmpty())) {
      throw new IllegalArgumentException(
          "Invalid connection string: password required when username is provided");
    }

    // Parse parameters into a Map (crazy that there's no built-in support for this in net.URL)
    Map<String, String> params = new HashMap<>();
    if (url.getQuery() != null) {
      String[] pairs = url.getQuery().split("&");
      for (String pair : pairs) {
        int idx = pair.indexOf("=");
        if (idx > 0) {
          try {
            String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.toString());
            String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.toString());
            params.put(key, value);
          } catch (UnsupportedEncodingException e) {
            throw new AssertionError(e);
          }
        }
      }
    }

    ManagedChannelBuilder<?> channelBuilder = ManagedChannelBuilder
        .forAddress(host, port);

    if (params.containsKey("sslmode")) {
      String sslmode = params.get("sslmode");
      if ("disable".equals(sslmode)) {
        channelBuilder.usePlaintext();
      } else if ("require".equals(sslmode)) {
        // create a new channel builder for tls minus the CA checks
        try {
          SslContext sslContext = GrpcSslContexts.forClient()
            .trustManager(InsecureTrustManagerFactory.INSTANCE)
            .build();
          channelBuilder = NettyChannelBuilder.forAddress(host, port)
            .sslContext(sslContext);
        } catch (SSLException e) {
          throw e;
        }
      } else if ("verify-ca".equals(sslmode)) {
        channelBuilder.useTransportSecurity();
      } else {
        throw new IllegalArgumentException("Invalid sslmode: " + sslmode);
      }
    } else {
      channelBuilder.usePlaintext();
    }

    if (params.containsKey("apikey") && params.containsKey("bearertoken")) {
      throw new IllegalArgumentException(
          "apikey and bearertoken cannot both be provided");
    }

    String authHeader = null;
    if (params.containsKey("apikey")) {
      authHeader = params.get("apikey");
    } else if (params.containsKey("bearertoken")) {
      authHeader = "Bearer " + params.get("bearertoken");
    }

    DgraphGrpc.DgraphStub stub;
    if (authHeader != null) {
      Metadata metadata = new Metadata();
      metadata.put(
          Metadata.Key.of(gRPC_AUTHORIZATION_HEADER_NAME, Metadata.ASCII_STRING_MARSHALLER),
          authHeader);
      stub = DgraphGrpc.newStub(channelBuilder.build())
          .withInterceptors(MetadataUtils.newAttachHeadersInterceptor(metadata));
    } else {
      stub = DgraphGrpc.newStub(channelBuilder.build());
    }

    DgraphClient client = new DgraphClient(stub);

    if (username != null) {
      client.login(username, password);
    }
    return client;
  }

  /**
   * Creates a gRPC stub that can be used to construct clients to connect with Slash GraphQL.
   *
   * @param slashEndpoint The url of the Slash GraphQL endpoint. Example:
   *     https://your-slash-instance.cloud.dgraph.io/graphql
   * @param apiKey The API key used to connect to your Slash GraphQL instance.
   * @return A new DgraphGrpc.DgraphStub object to be used with DgraphClient/DgraphAsyncClient.
   * @deprecated This method will be removed in v21.07 release. Please use {@link
   *     #clientStubFromCloudEndpoint(String, String) clientStubFromCloudEndpoint} instead.
   */
  @Deprecated
  public static DgraphGrpc.DgraphStub clientStubFromSlashEndpoint(
      String slashEndpoint, String apiKey) throws MalformedURLException {
    return clientStubFromCloudEndpoint(slashEndpoint, apiKey);
  }

  /**
   * Creates a gRPC stub that can be used to construct clients to connect with Dgraph Cloud.
   *
   * @param cloudEndpoint The url of the Dgraph Cloud instance. Example:
   *     https://your-instance.cloud.dgraph.io/graphql
   * @param apiKey The API key used to connect to your Dgraph Cloud instance.
   * @return A new {@link io.dgraph.DgraphGrpc.DgraphStub} object to be used with {@link
   *     DgraphClient}/{@link DgraphAsyncClient}.
   * @since v21.03.1
   */
  public static DgraphGrpc.DgraphStub clientStubFromCloudEndpoint(
      String cloudEndpoint, String apiKey) throws MalformedURLException {
    String[] parts = new URL(cloudEndpoint).getHost().split("[.]", 2);
    if (parts.length < 2) {
      throw new MalformedURLException("Invalid Dgraph Cloud URL.");
    }
    String gRPCAddress = parts[0] + ".grpc." + parts[1];

    Metadata metadata = new Metadata();
    metadata.put(
        Metadata.Key.of(gRPC_AUTHORIZATION_HEADER_NAME, Metadata.ASCII_STRING_MARSHALLER), apiKey);
    return DgraphGrpc.newStub(
            ManagedChannelBuilder.forAddress(gRPCAddress, 443).useTransportSecurity().build())
        .withInterceptors(MetadataUtils.newAttachHeadersInterceptor(metadata));
  }

  /**
   * Creates a new client for interacting with a Dgraph store.
   *
   * <p>A single client is thread safe.
   *
   * @param stubs - an array of grpc stubs to be used by this client. The stubs to be used are
   *     chosen at random per transaction.
   */
  public DgraphClient(DgraphGrpc.DgraphStub... stubs) {
    this.asyncClient = new DgraphAsyncClient(stubs);
  }

  /**
   * Creates a new client for interacting with a Dgraph store.
   *
   * <p>A single client is thread safe.
   *
   * @param executor - the executor to use for various asynchronous tasks executed by the underlying
   *     asynchronous client.
   * @param stubs - an array of grpc stubs to be used by this client. The stubs to be used are
   *     chosen at random per transaction.
   */
  public DgraphClient(Executor executor, DgraphGrpc.DgraphStub... stubs) {
    this.asyncClient = new DgraphAsyncClient(executor, stubs);
  }

  /**
   * Creates a new Transaction object. All operations performed by this transaction are synchronous.
   *
   * <p>A transaction lifecycle is as follows:
   *
   * <p>- Created using AsyncTransaction#newTransaction()
   *
   * <p>- Various AsyncTransaction#query() and AsyncTransaction#mutate() calls made.
   *
   * <p>- Commit using Transacation#commit() or Discard using AsyncTransaction#discard(). If any
   * mutations have been made, It's important that at least one of these methods is called to clean
   * up resources. Discard is a no-op if Commit has already been called, so it's safe to call it
   * after Commit.
   *
   * @return a new Transaction object.
   */
  public Transaction newTransaction() {
    return new Transaction(asyncClient.newTransaction());
  }

  /**
   * Creates a new Transaction object from a TxnContext. All operations performed by this
   * transaction are synchronous.
   *
   * <p>A transaction lifecycle is as follows:
   *
   * <p>- Created using AsyncTransaction#newTransaction()
   *
   * <p>- Various AsyncTransaction#query() and AsyncTransaction#mutate() calls made.
   *
   * <p>- Commit using Transacation#commit() or Discard using AsyncTransaction#discard(). If any
   * mutations have been made, It's important that at least one of these methods is called to clean
   * up resources. Discard is a no-op if Commit has already been called, so it's safe to call it
   * after Commit.
   *
   * @return a new Transaction object.
   */
  public Transaction newTransaction(TxnContext context) {
    return new Transaction(asyncClient.newTransaction(context));
  }

  /**
   * Creates a new AsyncTransaction object that only allows queries. Any Transaction#mutate() or
   * Transaction#commit() call made to the read only transaction will result in
   * TxnReadOnlyException. All operations performed by this transaction are synchronous.
   *
   * @return a new AsyncTransaction object
   */
  public Transaction newReadOnlyTransaction() {
    return new Transaction(asyncClient.newReadOnlyTransaction());
  }

  /**
   * Creates a new AsyncTransaction object from a TnxContext that only allows queries. Any
   * Transaction#mutate() or Transaction#commit() call made to the read only transaction will result
   * in TxnReadOnlyException. All operations performed by this transaction are synchronous.
   *
   * @return a new AsyncTransaction object
   */
  public Transaction newReadOnlyTransaction(TxnContext context) {
    return new Transaction(asyncClient.newReadOnlyTransaction(context));
  }

  /**
   * Alter can be used to perform the following operations, by setting the right fields in the
   * protocol buffer Operation object.
   *
   * <p>- Modify a schema.
   *
   * <p>- Drop predicate.
   *
   * <p>- Drop the database.
   *
   * @param op a protocol buffer Operation object representing the operation being performed.
   */
  public void alter(Operation op) {
    ExceptionUtil.withExceptionUnwrapped(
        () -> {
          asyncClient.alter(op).join();
        });
  }

  /**
   * checkVersion can be used to find out the version of the Dgraph instance this client is
   * interacting with.
   *
   * @return A Version object which represents the version of Dgraph instance.
   */
  public Version checkVersion() {
    return asyncClient.checkVersion().join();
  }

  /**
   * login sends a LoginRequest to the server using the given userid and password for the default
   * namespace (0). If the LoginRequest is processed successfully, the response returned by the
   * server will contain an access JWT and a refresh JWT, which will be stored in the jwt field of
   * this class, and used for authorizing all subsequent requests sent to the server.
   *
   * @param userid the id of the user who is trying to login, e.g. Alice
   * @param password the password of the user
   */
  public void login(String userid, String password) {
    asyncClient.login(userid, password).join();
  }

  /**
   * loginIntoNamespace sends a LoginRequest to the server using the given userid, password and
   * namespace. If the LoginRequest is processed successfully, the response returned by the server
   * will contain an access JWT and a refresh JWT, which will be stored in the jwt field of this
   * class, and used for authorizing all subsequent requests sent to the server.
   *
   * @param userid the id of the user who is trying to login, e.g. Alice
   * @param password the password of the user
   * @param namespace the namespace in which to login
   */
  public void loginIntoNamespace(String userid, String password, long namespace) {
    asyncClient.loginIntoNamespace(userid, password, namespace).join();
  }

  /** Calls %{@link io.grpc.ManagedChannel#shutdown} on all connections for this client */
  public void shutdown() {
    asyncClient.shutdown().join();
  }
}
