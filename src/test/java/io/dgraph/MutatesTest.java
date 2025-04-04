/*
 * SPDX-FileCopyrightText: © Hypermode Inc. <hello@hypermode.com>
 * SPDX-License-Identifier: Apache-2.0
 */

package io.dgraph;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import io.dgraph.DgraphProto.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.testng.annotations.Test;

public class MutatesTest extends DgraphIntegrationTest {
  private static String[] data = new String[] {"200", "300", "400"};
  private static Map<String, String> uidsMap;

  @Test
  public void testInsert3Quads() {
    Operation op =
        Operation.newBuilder().setSchema("name: string @index(fulltext) @upsert .").build();
    dgraphClient.alter(op);

    Transaction txn = dgraphClient.newTransaction();
    uidsMap = new HashMap<>();
    for (String datum : data) {
      NQuad quad =
          NQuad.newBuilder()
              .setSubject(String.format("_:%s", datum))
              .setPredicate("name")
              .setObjectValue(Value.newBuilder().setStrVal(String.format("ok %s", datum)).build())
              .build();

      Mutation mu = Mutation.newBuilder().addSet(quad).build();

      Response resp = txn.mutate(mu);
      uidsMap.put(datum, resp.getUidsOrThrow(datum));
    }

    txn.commit();
  }

  @Test
  public void testQuery3Quads() {
    List<String> uids = Arrays.stream(data).map(d -> uidsMap.get(d)).collect(Collectors.toList());

    String query = String.format("{ me(func: uid(%s)) { name }}", String.join(",", uids));
    logger.debug("Query: {}\n", query);

    Transaction txn = dgraphClient.newTransaction();
    Response response = txn.query(query);
    String res = response.getJson().toStringUtf8();
    logger.debug("Response JSON: {}\n", res);

    String expected =
        "{\"me\":[{\"name\":\"ok 200\"},{\"name\":\"ok 300\"},{\"name\":\"ok 400\"}]}";
    assertEquals(res, expected);
    assertTrue(response.getTxn().getStartTs() > 0);
    txn.discard();
  }
}
