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

import static org.apache.geode.tools.security.SpringSecurityManager.INVALID_CREDENTIALS_ERROR;
import static org.apache.geode.tools.security.SpringSecurityManager.NO_SECURITY_CONFIGURATION_FOUND_ERROR;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import org.apache.geode.security.AuthenticationFailedException;
import org.apache.geode.security.ResourcePermission;

public class SpringSecurityManagerTest {
  private AuthenticationManager mockManager;
  private SpringSecurityManager securityManager;

  @Before
  public void setUp() {
    mockManager = mock(AuthenticationManager.class);
    securityManager = new SpringSecurityManager(mockManager);
  }

  @Test
  public void initShouldThrowExceptionWhenSecurityConfigurationPathIsNotSet() {
    assertThatThrownBy(() -> securityManager.init(new Properties()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage(NO_SECURITY_CONFIGURATION_FOUND_ERROR);
  }

  @Test
  public void authenticateShouldThrowExceptionWhenAuthenticationAuthenticationManagerReturnsNullAuthentication() {
    doReturn(null).when(mockManager).authenticate(any());
    assertThatThrownBy(() -> securityManager.authenticate(new Properties()))
        .isInstanceOf(AuthenticationFailedException.class)
        .hasMessage(INVALID_CREDENTIALS_ERROR);
  }

  @Test
  public void authenticateShouldReturnAuthenticationObjectReturnedByAuthenticationManager() {
    Authentication authentication = new TestingAuthenticationToken("user", "password");
    doReturn(authentication).when(mockManager).authenticate(any());

    Object authenticatedUser = securityManager.authenticate(new Properties());
    assertThat(authenticatedUser)
        .isInstanceOf(Authentication.class)
        .isEqualTo(authentication);
  }

  @Test
  public void authorizeShouldReturnFalseIfThereAreNoGeodeGrantedAuthorities() {
    List<GrantedAuthority> grantedAuthorityList = Collections.singletonList(mock(GrantedAuthority.class));
    Authentication authentication = new TestingAuthenticationToken("user", "password", grantedAuthorityList);

    assertThat(securityManager.authorize(authentication, new ResourcePermission("CLUSTER", "MANAGE", "GATEWAY"))).isFalse();
  }

  @Test
  public void authorizeShouldReturnFalseIfThereAreNoGeodePermissionsGranted() {
    List<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
    grantedAuthorityList.add(new GeodeGrantedAuthority("CLUSTER", "READ", "*", "*"));
    Authentication authentication = new TestingAuthenticationToken("user", "password", grantedAuthorityList);

    assertThat(securityManager.authorize(authentication, new ResourcePermission("CLUSTER", "MANAGE", "GATEWAY"))).isFalse();
  }

  @Test
  public void authorizeShouldReturnTrueIfThereIsAtLeastOneGeodePermissionGranted() {
    List<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
    grantedAuthorityList.add(new GeodeGrantedAuthority("CLUSTER", "MANAGE", "*", "*"));
    Authentication authentication = new TestingAuthenticationToken("user", "password", grantedAuthorityList);

    assertThat(securityManager.authorize(authentication, new ResourcePermission("CLUSTER", "MANAGE", "GATEWAY"))).isTrue();
  }
}
