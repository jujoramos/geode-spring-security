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

import java.util.Collection;
import java.util.Properties;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.FileSystemXmlApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import org.apache.geode.distributed.ConfigurationProperties;
import org.apache.geode.security.AuthenticationFailedException;
import org.apache.geode.security.ResourcePermission;
import org.apache.geode.security.SecurityManager;

/**
 * Geode {@link SecurityManager} that simply delegates authentication to the
 * configured Spring {@link AuthenticationManager}.
 */
public class SpringSecurityManager implements SecurityManager {
  public static final String SECURITY_CONFIGURATION_XML = ConfigurationProperties.SECURITY_PREFIX + "spring-security-xml";
  public static final String INVALID_CREDENTIALS_ERROR = "Invalid Credentials";
  public static final String NO_SECURITY_CONFIGURATION_FOUND_ERROR = "Please set the " + SECURITY_CONFIGURATION_XML + " property.";
  private static final Object LOCK = new Object();
  private static ConfigurableApplicationContext springContext;
  private AuthenticationManager authenticationManager;

  @SuppressWarnings("unused")
  public SpringSecurityManager() {
  }

  public SpringSecurityManager(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

  @Override
  public void init(Properties securityProps) {
    if (!securityProps.containsKey(SECURITY_CONFIGURATION_XML)) {
      throw new IllegalArgumentException(NO_SECURITY_CONFIGURATION_FOUND_ERROR);
    }

    if (springContext == null) {
      synchronized (LOCK) {
        if (springContext == null) {
          String springConfigurationPath = securityProps.getProperty(SECURITY_CONFIGURATION_XML);
          springContext = new FileSystemXmlApplicationContext(springConfigurationPath);
          springContext.registerShutdownHook();
        }
      }
    }

    authenticationManager = springContext.getBean(AuthenticationManager.class);
  }

  @Override
  public Object authenticate(Properties credentials) throws AuthenticationFailedException {
    String user = credentials.getProperty(USER_NAME);
    String password = credentials.getProperty(PASSWORD);
    Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user, password));

    if (authentication == null) {
      throw new AuthenticationFailedException(INVALID_CREDENTIALS_ERROR);
    }

    return authentication;
  }

  @Override
  public boolean authorize(Object principal, ResourcePermission context) {
    Authentication authentication = (Authentication) principal;
    Collection<? extends GrantedAuthority> grantedAuthorities = authentication.getAuthorities();

    for (GrantedAuthority grantedAuthority : grantedAuthorities) {
      if (grantedAuthority instanceof GeodeGrantedAuthority) {
        GeodeGrantedAuthority geodeGrantedAuthority = (GeodeGrantedAuthority) grantedAuthority;

        if (geodeGrantedAuthority.getResourcePermission().implies(context)) {
          return true;
        }
      }
    }

    return false;
  }

  @Override
  public void close() {
  }
}
