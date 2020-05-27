/*
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.geode.tools.security;

import static org.apache.geode.tools.security.GeodeAuthoritiesMapper.INVALID_AUTHORITY_ERROR;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.Before;
import org.junit.Test;

import org.apache.geode.security.ResourcePermission;

public class GeodeAuthoritiesMapperTest {
  private GeodeAuthoritiesMapper authoritiesMapper;

  @Before
  public void setUp() {
    authoritiesMapper = new GeodeAuthoritiesMapper();
  }

  @Test
  public void parseAuthorityThrowExceptionForInvalidAuthorities() {
    assertThatThrownBy(() -> authoritiesMapper.parseAuthority("UNKNOWN"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage(INVALID_AUTHORITY_ERROR + "UNKNOWN")
        .hasCauseInstanceOf(IllegalArgumentException.class)
        .hasRootCauseMessage("No enum constant org.apache.geode.security.ResourcePermission.Resource.UNKNOWN");
  }

  @Test
  public void parseAuthorityGeneratesCorrectResourcePermission() {
    ResourcePermission permission;
    GeodeGrantedAuthority geodeGrantedAuthority;

    permission = new ResourcePermission();
    geodeGrantedAuthority = authoritiesMapper.parseAuthority("NULL:NULL");
    assertThat(geodeGrantedAuthority.getResourcePermission()).isEqualTo(permission);

    permission = new ResourcePermission(ResourcePermission.Resource.DATA, null);
    geodeGrantedAuthority = authoritiesMapper.parseAuthority("DATA");
    assertThat(geodeGrantedAuthority.getResourcePermission()).isEqualTo(permission);

    permission = new ResourcePermission(ResourcePermission.Resource.CLUSTER, null);
    geodeGrantedAuthority = authoritiesMapper.parseAuthority("CLUSTER");
    assertThat(geodeGrantedAuthority.getResourcePermission()).isEqualTo(permission);

    permission = new ResourcePermission(ResourcePermission.Resource.DATA, ResourcePermission.Operation.MANAGE);
    geodeGrantedAuthority = authoritiesMapper.parseAuthority("DATA:MANAGE");
    assertThat(geodeGrantedAuthority.getResourcePermission()).isEqualTo(permission);

    permission = new ResourcePermission(ResourcePermission.Resource.CLUSTER, ResourcePermission.Operation.MANAGE);
    geodeGrantedAuthority = authoritiesMapper.parseAuthority("CLUSTER:MANAGE");
    assertThat(geodeGrantedAuthority.getResourcePermission()).isEqualTo(permission);

    permission = new ResourcePermission(ResourcePermission.Resource.DATA, ResourcePermission.Operation.READ, "RegionA");
    geodeGrantedAuthority = authoritiesMapper.parseAuthority("DATA:READ:RegionA");
    assertThat(geodeGrantedAuthority.getResourcePermission()).isEqualTo(permission);

    permission = new ResourcePermission(ResourcePermission.Resource.CLUSTER, ResourcePermission.Operation.MANAGE, ResourcePermission.Target.GATEWAY);
    geodeGrantedAuthority = authoritiesMapper.parseAuthority("CLUSTER:MANAGE:GATEWAY");
    assertThat(geodeGrantedAuthority.getResourcePermission()).isEqualTo(permission);

    permission = new ResourcePermission(ResourcePermission.Resource.DATA, ResourcePermission.Operation.READ, "ALL");
    geodeGrantedAuthority = authoritiesMapper.parseAuthority("DATA:READ:ALL");
    assertThat(geodeGrantedAuthority.getResourcePermission()).isEqualTo(permission);

    permission = new ResourcePermission(ResourcePermission.Resource.CLUSTER, ResourcePermission.Operation.READ, "ALL");
    geodeGrantedAuthority = authoritiesMapper.parseAuthority("CLUSTER:READ:ALL");
    assertThat(geodeGrantedAuthority.getResourcePermission()).isEqualTo(permission);

    permission = new ResourcePermission(ResourcePermission.Resource.DATA, ResourcePermission.Operation.READ, "Region", "Key1");
    geodeGrantedAuthority = authoritiesMapper.parseAuthority("DATA:READ:Region:Key1");
    assertThat(geodeGrantedAuthority.getResourcePermission()).isEqualTo(permission);

    permission = new ResourcePermission(ResourcePermission.Resource.DATA, ResourcePermission.Operation.WRITE, "Region", "Key1");
    geodeGrantedAuthority = authoritiesMapper.parseAuthority("DATA:WRITE:Region:Key1");
    assertThat(geodeGrantedAuthority.getResourcePermission()).isEqualTo(permission);

    permission = new ResourcePermission("*", "*");
    geodeGrantedAuthority = authoritiesMapper.parseAuthority("ALL:ALL:*:*");
    assertThat(geodeGrantedAuthority.getResourcePermission()).isEqualTo(permission);
  }
}
