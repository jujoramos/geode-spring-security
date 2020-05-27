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

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

/**
 * Implementation of {@link GrantedAuthoritiesMapper} to map the regular authorities to those
 * used by Geode Security.
 * This class can be modified at will for your use case, transforming your stored authorities into
 * those supported by Geode.
 */
public class GeodeAuthoritiesMapper implements GrantedAuthoritiesMapper {
  public static final String INVALID_AUTHORITY_ERROR = "The authority can not be mapped to a valid Geode ResourcePermission: ";

  GeodeGrantedAuthority parseAuthority(String stringAuthority) {
    try {
      String[] parts = stringAuthority.split(":");
      String resource = (parts.length > 0) ? parts[0] : null;
      String operation = (parts.length > 1) ? parts[1] : null;
      String region = (parts.length > 2) ? parts[2] : "*";
      String key = (parts.length > 3) ? parts[3] : "*";

      return new GeodeGrantedAuthority(resource, operation, region, key);
    } catch (Exception exception) {
      throw new IllegalArgumentException(INVALID_AUTHORITY_ERROR + stringAuthority, exception);
    }
  }

  @Override
  public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
    Collection<GeodeGrantedAuthority> geodeGrantedAuthorities = new ArrayList<>();
    authorities.forEach(grantedAuthority -> geodeGrantedAuthorities.add(parseAuthority(grantedAuthority.getAuthority())));

    return geodeGrantedAuthorities;
  }
}
