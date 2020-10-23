/*
 * Copyright (C) 2020 Dgraph Labs, Inc. and Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.dgraph;

import org.testng.annotations.Test;

import java.net.MalformedURLException;

import static org.testng.Assert.fail;

public class DgraphClientStubTest {

    @Test
    public void testFromSlashEndpoint_ValidURL() {
        try {
            DgraphGrpc.DgraphStub stub =
                    DgraphClient.clientStubFromSlashEndpoint(
                            "https://your-slash" + "-instance.cloud.dgraph.io/graphql", "");
        } catch (MalformedURLException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testFromSlashEndpoint_InValidURL() {
        try {
            DgraphGrpc.DgraphStub stub = DgraphClient.clientStubFromSlashEndpoint("https://a-bad-url", "");
            fail("Invalid Slash URL should not be accepted.");
        } catch (MalformedURLException e) {
        }
    }
}
