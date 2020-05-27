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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

/**
 * An {@link AuthenticationProvider} implementation that simply delegates to the default
 * {@link DaoAuthenticationProvider} (Username & Password authentication).
 * Only overridden to correctly configure the {@link GrantedAuthoritiesMapper}, as the setter is
 * only exposed for the ldap provider.
 */
public class GeodeAuthenticationProvider extends DaoAuthenticationProvider {

  @Override
  public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
    super.setAuthoritiesMapper(authoritiesMapper);
  }
}
