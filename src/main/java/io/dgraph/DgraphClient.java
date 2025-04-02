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
  private static final String DGRAPH_SCHEME = "dgraph";
  private static final String SSLMODE_DISABLE = "disable";
  private static final String SSLMODE_REQUIRE = "require";
  private static final String SSLMODE_VERIFY_CA = "verify-ca";

  private final DgraphAsyncClient asyncClient;

  /**
   * Options for configuring a Dgraph client connection.
   */
  public static class ClientOptions {
    private final ManagedChannelBuilder<?> channelBuilder;
    private String username;
    private String password;
    private String authorizationToken;
    private final String host;
    private final int port;

    private ClientOptions(String host, int port) {
      this.host = host;
      this.port = port;
      this.channelBuilder = ManagedChannelBuilder.forAddress(host, port);
      // Default to plaintext
      this.channelBuilder.usePlaintext();
    }

    /**
     * Creates a new ClientOptions instance for the given host and port.
     *
     * @param host The hostname of the Dgraph server.
     * @param port The port of the Dgraph server.
     * @return A new ClientOptions instance.
     */
    public static ClientOptions forAddress(String host, int port) {
      return new ClientOptions(host, port);
    }

    /**
     * Sets username and password for ACL authentication.
     *
     * @param username The username for ACL authentication.
     * @param password The password for ACL authentication.
     * @return This ClientOptions instance for chaining.
     */
    public ClientOptions withACLCredentials(String username, String password) {
      this.username = username;
      this.password = password;
      return this;
    }

    /**
     * Sets an API key for authorization.
     *
     * @param apiKey The API key to use for authorization.
     * @return This ClientOptions instance for chaining.
     */
    public ClientOptions withApiKey(String apiKey) {
      this.authorizationToken = apiKey;
      return this;
    }

    /**
     * Sets a bearer token for authorization.
     *
     * @param token The bearer token to use for authorization.
     * @return This ClientOptions instance for chaining.
     */
    public ClientOptions withBearerToken(String token) {
      this.authorizationToken = "Bearer " + token;
      return this;
    }

    /**
     * Configures the client to use plaintext communication (no encryption).
     *
     * @return This ClientOptions instance for chaining.
     */
    public ClientOptions withPlaintext() {
      this.channelBuilder.usePlaintext();
      return this;
    }

    /**
     * Configures the client to use TLS but skip certificate validation.
     * Be aware this disables certificate validation and significantly reduces the
     * security of TLS. This mode should only be used in non-production
     * (e.g., testing or development) environments.
     *
     * @return A new ClientOptions instance with TLS but without certificate validation.
     * @throws SSLException If there's an error configuring the SSL context.
     */
    public ClientOptions withTLSSkipVerify() throws SSLException {
      SslContext sslContext = GrpcSslContexts.forClient()
          .trustManager(InsecureTrustManagerFactory.INSTANCE)
          .build();

      // Create a new options object with the same credentials
      ClientOptions newOptions = new ClientOptions(host, port) {
        @Override
        public DgraphGrpc.DgraphStub createStub() {
          NettyChannelBuilder nettyBuilder = NettyChannelBuilder.forAddress(host, port);
          nettyBuilder.sslContext(sslContext);
          return DgraphGrpc.newStub(nettyBuilder.build());
        }
      };

      // Copy over the auth settings
      newOptions.username = this.username;
      newOptions.password = this.password;
      newOptions.authorizationToken = this.authorizationToken;
      return newOptions;
    }

    /**
     * Configures the client to use TLS with certificate validation.
     *
     * @return This ClientOptions instance for chaining.
     */
    public ClientOptions withTLS() {
      this.channelBuilder.useTransportSecurity();
      return this;
    }

    /**
     * Creates the gRPC stub based on the channel builder.
     * This method can be overridden by subclasses to customize stub creation.
     */
    protected DgraphGrpc.DgraphStub createStub() {
      return DgraphGrpc.newStub(channelBuilder.build());
    }

    /**
     * Creates a new DgraphClient with the configured options.
     *
     * @return A new DgraphClient instance.
     */
    public DgraphClient build() {
      DgraphGrpc.DgraphStub stub = createStub();

      // Apply authorization if present
      if (authorizationToken != null) {
        Metadata metadata = new Metadata();
        metadata.put(
            Metadata.Key.of(gRPC_AUTHORIZATION_HEADER_NAME, Metadata.ASCII_STRING_MARSHALLER),
            authorizationToken);
        stub = stub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(metadata));
      }

      DgraphClient client = new DgraphClient(stub);

      // Apply ACL login if credentials are provided
      if (username != null && password != null) {
        client.login(username, password);
      }

      return client;
    }
  }

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
    if (!connectionString.startsWith(DGRAPH_SCHEME + "://")) {
      throw new IllegalArgumentException("Invalid connection string: scheme must be '" + DGRAPH_SCHEME + "'");
    }

    URL url;
    try {
      // Replace dgraph:// with http:// for proper URL parsing
      url = new URL(connectionString.replace(DGRAPH_SCHEME + "://", "http://"));
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException("Failed to parse connection string: " + e.getMessage(), e);
    }

    String host = url.getHost();
    int port = url.getPort();

    if (host == null || host.isEmpty()) {
      throw new IllegalArgumentException("Invalid connection string: hostname required");
    }
    if (port == -1) {
      throw new IllegalArgumentException("Invalid connection string: port required");
    }

    ClientOptions options = ClientOptions.forAddress(host, port);

    if (url.getUserInfo() != null) {
      String[] userInfo = url.getUserInfo().split(":", 2);
      String username = userInfo[0];
      String password = null;
      if (userInfo.length > 1) {
        password = userInfo[1];
      }
      if (username != null && (password == null || password.isEmpty())) {
        throw new IllegalArgumentException(
            "Invalid connection string: password required when username is provided");
      }
      if (username != null && password != null) {
        options.withACLCredentials(username, password);
      }
    }

    // Parse URL parameters
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

    if (params.containsKey("sslmode")) {
      String sslmode = params.get("sslmode");
      if (SSLMODE_DISABLE.equals(sslmode)) {
        options.withPlaintext();
      } else if (SSLMODE_REQUIRE.equals(sslmode)) {
        options.withTLSSkipVerify();
      } else if (SSLMODE_VERIFY_CA.equals(sslmode)) {
        options.withTLS();
      } else {
        throw new IllegalArgumentException("Invalid sslmode: " + sslmode);
      }
    }

    if (params.containsKey("apikey") && params.containsKey("bearertoken")) {
      throw new IllegalArgumentException(
          "apikey and bearertoken cannot both be provided");
    }

    if (params.containsKey("apikey")) {
      options.withApiKey(params.get("apikey"));
    } else if (params.containsKey("bearertoken")) {
      options.withBearerToken(params.get("bearertoken"));
    }

    // Build and return the client
    return options.build();
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
