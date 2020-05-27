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

import static org.apache.geode.distributed.ConfigurationProperties.SECURITY_MANAGER;
import static org.apache.geode.distributed.ConfigurationProperties.SERIALIZABLE_OBJECT_FILTER;
import static org.apache.geode.tools.security.SpringSecurityManager.SECURITY_CONFIGURATION_XML;
import static org.assertj.core.api.Assertions.as;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.THROWABLE;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Properties;

import org.apache.shiro.authz.UnauthorizedException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.security.authentication.BadCredentialsException;

import org.apache.geode.cache.Cache;
import org.apache.geode.cache.RegionShortcut;
import org.apache.geode.cache.client.ClientCache;
import org.apache.geode.cache.client.ClientRegionFactory;
import org.apache.geode.cache.client.ClientRegionShortcut;
import org.apache.geode.distributed.internal.InternalDistributedSystem;
import org.apache.geode.management.cli.Result;
import org.apache.geode.management.internal.cli.result.CommandResult;
import org.apache.geode.management.internal.cli.util.CommandStringBuilder;
import org.apache.geode.management.internal.i18n.CliStrings;
import org.apache.geode.security.AuthenticationFailedException;
import org.apache.geode.security.GemFireSecurityException;
import org.apache.geode.security.NotAuthorizedException;
import org.apache.geode.security.SecurityManager;
import org.apache.geode.test.dunit.rules.ClientVM;
import org.apache.geode.test.dunit.rules.ClusterStartupRule;
import org.apache.geode.test.dunit.rules.MemberVM;
import org.apache.geode.test.junit.assertions.CommandResultAssert;
import org.apache.geode.test.junit.rules.GfshCommandRule;

@RunWith(Parameterized.class)
public class SpringSecurityManagerDistributedTest implements Serializable {
  private static final String REGION_NAME = "TestRegion";
  private MemberVM securedLocator, securedServer;

  @Rule
  public ClusterStartupRule clusterStartupRule = new ClusterStartupRule(3);

  @Rule
  public transient GfshCommandRule gfshCommandRule = new GfshCommandRule();

  @Parameterized.Parameter
  public String springConfiguration;

  @Parameterized.Parameters(name = "{index}: spring-configuration-file={0}")
  public static Iterable<String> data() {
    return Arrays.asList(
        "classpath:ldap-security-config.xml",
        "classpath:inMemory-security-config.xml",
        "classpath:dataBase-security-config.xml"
    );
  }

  @Before
  public void setUp() {
    Properties locatorProperties = new Properties();
    locatorProperties.setProperty(SECURITY_MANAGER, SpringSecurityManager.class.getName());
    locatorProperties.setProperty(SECURITY_CONFIGURATION_XML, springConfiguration);
    securedLocator = clusterStartupRule.startLocatorVM(0, locatorProperties);

    Properties serverProperties = new Properties();
    serverProperties.setProperty(SecurityManager.USER_NAME, "clusterManager");
    serverProperties.setProperty(SecurityManager.PASSWORD, "clusterManagerPassword");
    serverProperties.setProperty(SECURITY_CONFIGURATION_XML, springConfiguration);

    securedServer = clusterStartupRule.startServerVM(1, serverProperties, securedLocator.getPort());
    securedServer.invoke(() -> {
      Cache cache = ClusterStartupRule.getCache();
      assertThat(cache).isNotNull();
      cache.createRegionFactory(RegionShortcut.REPLICATE).create(REGION_NAME);
    });
  }

  @Test
  public void gfshConnectFailsToConnectWhenNoCredentialsAreProvided() {
    CommandStringBuilder commandStringBuilder = new CommandStringBuilder("connect")
        .addOption("locator", "localhost[" + securedLocator.getPort() + "]");

    CommandResultAssert commandResultAssert = gfshCommandRule.executeAndAssertThat(commandStringBuilder.toString());
    CommandResult commandResult = commandResultAssert.getCommandResult();
    assertThat(commandResult.getStatus()).isEqualTo(Result.Status.ERROR);
    assertThat(commandResult.asString()).contains("Authentication error. Please check your credentials.");
  }

  @Test
  public void gfshConnectFailsToConnectWhenInvalidCredentialsAreProvided() {
    CommandStringBuilder commandStringBuilder = new CommandStringBuilder("connect")
        .addOption("locator", "localhost[" + securedLocator.getPort() + "]")
        .addOption(CliStrings.CONNECT__USERNAME, "user")
        .addOption(CliStrings.CONNECT__PASSWORD, "password");

    CommandResultAssert commandResultAssert = gfshCommandRule.executeAndAssertThat(commandStringBuilder.toString());
    CommandResult commandResult = commandResultAssert.getCommandResult();
    assertThat(commandResult.getStatus()).isEqualTo(Result.Status.ERROR);
    assertThat(commandResult.asString()).contains("Authentication error. Please check your credentials.");
  }

  @Test
  public void gfshSuccessfullyConnectsWhenValidCredentialsAreProvided() {
    CommandStringBuilder commandStringBuilder = new CommandStringBuilder("connect")
        .addOption("locator", "localhost[" + securedLocator.getPort() + "]")
        .addOption(CliStrings.CONNECT__USERNAME, "clusterReader")
        .addOption(CliStrings.CONNECT__PASSWORD, "clusterReaderPassword");

    CommandResultAssert commandResultAssert = gfshCommandRule.executeAndAssertThat(commandStringBuilder.toString());
    CommandResult commandResult = commandResultAssert.getCommandResult();
    assertThat(commandResult.getStatus()).isEqualTo(Result.Status.OK);
  }

  @Test
  public void serverWithInvalidCredentialsCanNotJoinTheCluster() {
    Properties serverProperties = new Properties();
    serverProperties.setProperty(SecurityManager.USER_NAME, "user");
    serverProperties.setProperty(SecurityManager.PASSWORD, "password");

    assertThatThrownBy(() -> clusterStartupRule.startServerVM(2, serverProperties, securedLocator.getPort()))
        .hasCauseInstanceOf(GemFireSecurityException.class)
        .extracting(Throwable::getCause, as(THROWABLE))
        .hasMessage("Security check failed. Authentication error. Please check your credentials.");
  }

  @Test
  public void serverWithValidCredentialsAndNoClusterManageAuthorityCanNotJoinTheCluster() {
    Properties serverProperties = new Properties();
    serverProperties.setProperty(SecurityManager.USER_NAME, "clusterReader");
    serverProperties.setProperty(SecurityManager.PASSWORD, "clusterReaderPassword");
    serverProperties.setProperty(SECURITY_CONFIGURATION_XML, springConfiguration);

    assertThatThrownBy( () -> clusterStartupRule.startServerVM(2, serverProperties, securedLocator.getPort()))
        .hasCauseInstanceOf(GemFireSecurityException.class)
        .extracting(Throwable::getCause, as(THROWABLE))
        .hasMessageMatching("Security check failed\\..*not authorized for CLUSTER:MANAGE");
  }

  @Test
  public void serverWithValidCredentialsAndClusterManageGrantedAuthorityCanJoinTheClusterSuccessfully() {
    Properties serverProperties = new Properties();
    serverProperties.setProperty(SecurityManager.USER_NAME, "clusterManager");
    serverProperties.setProperty(SecurityManager.PASSWORD, "clusterManagerPassword");
    serverProperties.setProperty(SECURITY_CONFIGURATION_XML, springConfiguration);

    MemberVM memberVM = clusterStartupRule.startServerVM(2, serverProperties, securedLocator.getPort());
    memberVM.invoke(() -> {
      assertThat(InternalDistributedSystem.getConnectedInstance()).isNotNull();
      assertThat(InternalDistributedSystem.getConnectedInstance().getAllOtherMembers()).hasSize(2);
    });
  }

  @Test
  public void clientWithInvalidCredentialsCanNotExecuteOperationsThroughLocatorConnection() throws Exception {
    final int locatorPort = securedLocator.getPort();
    ClientVM clientVM = clusterStartupRule.startClientVM(2,
        c -> c.withLocatorConnection(locatorPort)
            .withCredential("client", "invalidPassword")
            .withProperty(SERIALIZABLE_OBJECT_FILTER, "org.springframework.security.**"));

    clientVM.invoke(() -> {
      ClientCache clientCache = ClusterStartupRule.getClientCache();
      ClientRegionFactory<String, String> clientRegionFactory = clientCache.createClientRegionFactory(ClientRegionShortcut.PROXY);
      assertThatThrownBy(() -> clientRegionFactory.create(REGION_NAME).put("key1", "value1"))
          .hasCauseInstanceOf(AuthenticationFailedException.class)
          .hasRootCauseInstanceOf(BadCredentialsException.class)
          .hasRootCauseMessage("Bad credentials");
    });
  }

  @Test
  public void clientWithInvalidCredentialsCanNotExecuteOperationsThroughServerConnection() throws Exception {
    final int serverPort = securedServer.getPort();
    ClientVM clientVM = clusterStartupRule.startClientVM(2,
        c -> c.withServerConnection(serverPort)
            .withCredential("client", "invalidPassword")
            .withProperty(SERIALIZABLE_OBJECT_FILTER, "org.springframework.security.**"));

    clientVM.invoke(() -> {
      ClientCache clientCache = ClusterStartupRule.getClientCache();
      ClientRegionFactory<String, String> clientRegionFactory = clientCache.createClientRegionFactory(ClientRegionShortcut.PROXY);
      assertThatThrownBy(() -> clientRegionFactory.create(REGION_NAME).put("key1", "value1"))
          .hasCauseInstanceOf(AuthenticationFailedException.class)
          .hasRootCauseInstanceOf(BadCredentialsException.class)
          .hasRootCauseMessage("Bad credentials");
    });
  }

  @Test
  public void clientWithValidCredentialsAndNoDataWriteAuthorityCanNotExecuteOperationsThroughLocatorConnection() throws Exception {
    final int locatorPort = securedLocator.getPort();
    ClientVM clientVM = clusterStartupRule.startClientVM(2,
        c -> c.withLocatorConnection(locatorPort)
            .withCredential("clientReader", "clientReaderPassword")
            .withProperty(SERIALIZABLE_OBJECT_FILTER, "org.springframework.security.**"));

    clientVM.invoke(() -> {
      ClientCache clientCache = ClusterStartupRule.getClientCache();
      ClientRegionFactory<String, String> clientRegionFactory = clientCache.createClientRegionFactory(ClientRegionShortcut.PROXY);
      assertThatThrownBy(() -> clientRegionFactory.create(REGION_NAME).put("key1", "value1"))
          .hasCauseInstanceOf(NotAuthorizedException.class)
          .hasRootCauseInstanceOf(UnauthorizedException.class)
          .hasRootCauseMessage("Subject does not have permission [DATA:WRITE:" + REGION_NAME + ":key1]");
    });
  }

  @Test
  public void clientWithValidCredentialsAndNoDataWriteAuthorityCanNotExecuteOperationsThroughServerConnection() throws Exception {
    final int serverPort = securedServer.getPort();
    ClientVM clientVM = clusterStartupRule.startClientVM(2,
        c -> c.withServerConnection(serverPort)
            .withCredential("clientReader", "clientReaderPassword")
            .withProperty(SERIALIZABLE_OBJECT_FILTER, "org.springframework.security.**"));

    clientVM.invoke(() -> {
      ClientCache clientCache = ClusterStartupRule.getClientCache();
      ClientRegionFactory<String, String> clientRegionFactory = clientCache.createClientRegionFactory(ClientRegionShortcut.PROXY);
      assertThatThrownBy(() -> clientRegionFactory.create(REGION_NAME).put("key1", "value1"))
          .hasCauseInstanceOf(NotAuthorizedException.class)
          .hasRootCauseInstanceOf(UnauthorizedException.class)
          .hasRootCauseMessage("Subject does not have permission [DATA:WRITE:" + REGION_NAME + ":key1]");
    });
  }

  @Test
  public void clientWithValidCredentialsAndDataWriteAuthorityCanExecuteOperationsThroughLocatorConnection() throws Exception {
    final int locatorPort = securedLocator.getPort();
    ClientVM clientVM = clusterStartupRule.startClientVM(2,
        c -> c.withLocatorConnection(locatorPort)
            .withCredential("clientWriter", "clientWriterPassword"));

    clientVM.invoke(() -> {
      ClientCache clientCache = ClusterStartupRule.getClientCache();
      ClientRegionFactory<String, String> clientRegionFactory = clientCache.createClientRegionFactory(ClientRegionShortcut.PROXY);
      clientRegionFactory.create(REGION_NAME).put("key1", "value1");
    });
  }

  @Test
  public void clientWithValidCredentialsAndDataWriteAuthorityCanExecuteOperationsThroughServerConnection() throws Exception {
    final int serverPort = securedServer.getPort();
    ClientVM clientVM = clusterStartupRule.startClientVM(2,
        c -> c.withServerConnection(serverPort)
            .withCredential("clientWriter", "clientWriterPassword"));

    clientVM.invoke(() -> {
      ClientCache clientCache = ClusterStartupRule.getClientCache();
      ClientRegionFactory<String, String> clientRegionFactory = clientCache.createClientRegionFactory(ClientRegionShortcut.PROXY);
      clientRegionFactory.create(REGION_NAME).put("key1", "value1");
    });
  }
}
