[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0) 

# Spring Security & Geode
1. [Overview](#overview)
2. [Building From Source](#building)
3. [Example Usage](#exampleUsage)

## <a name="overview"></a>Overview

[Apache Geode](http://geode.apache.org/) is a data management platform that provides real-time, 
consistent access to data-intensive applications throughout widely distributed cloud architectures.

To secure access to the Geode cluster, users must implement the `SecurityManager` interface, but why
would someone want to reinvent the wheel?... This project shows how [Spring Security](https://spring.io/projects/spring-security) and its many
out of the box implemented `AuthenticationProviders` can be used to authenticate and authorize 
access to a running [Apache Geode](http://geode.apache.org/) Cluster.

## <a name="building"></a>Building From Source

All platforms require a Java installation with JDK 1.8 or more recent version. The JAVA\_HOME 
environment variable can be set as below:

| Platform | Command |
| :---: | --- |
|  Unix    | ``export JAVA_HOME=/usr/java/jdk1.8.0_121``            |
|  OSX     | ``export JAVA_HOME=/usr/libexec/java_home -v 1.8``     |
|  Windows | ``set JAVA_HOME="C:\Program Files\Java\jdk1.8.0_121"`` |

Clone the current repository in your local environment and, within the directory containing the 
source code, run gradle build:
```
$ ./gradlew build
```

## <a name="exampleUsage"></a>Example Usage

- Check out this repository.
- Build the project using `$ ./gradlew build copyDependencies`.
- Create the root `workspace` directory. Add `extraLibs` and `config` directories under it. 
- Move the following jars to `/workspace/extraLibs`:
  ```
  geode-spring-security-1.0.0.jar
  spring-aop-5.2.1.RELEASE.jar
  spring-beans-5.2.1.RELEASE.jar
  spring-context-5.2.1.RELEASE.jar
  spring-expression-5.2.1.RELEASE.jar
  spring-security-config-5.2.1.RELEASE.jar
  spring-security-core-5.2.1.RELEASE.jar
  ```
- Copy the file `src/test/resources/inMemory-security-config.xml` to `/workspace/config`.
- Create a `locator.properties` file with the following contents under `/workspace/config`:
    ```
    security-manager=org.apache.geode.tools.security.SpringSecurityManager
    security-spring-security-xml=file:/workspace/config/inMemory-security-config.xml
    ```
- Create a `server.properties` file with the following contents under `/workspace/config`:
    ```
    security-username=clusterManager
    security-password=clusterManagerPassword
    security-spring-security-xml=file:/workspace/config/inMemory-security-config.xml
    ```
- Start `gfsh`.
- Set the `CURRENT_DIRECTORY` variable.
    ```
    set variable --name=CURRENT_DIRECTORY --value=/workspace
    ```
- Start locator:
    ```
    start locator --name=locator1 --security-properties-file=${CURRENT_DIRECTORY}/config/locator.properties --classpath=${CURRENT_DIRECTORY}/extraLibs/geode-spring-security-1.0.0.jar:${CURRENT_DIRECTORY}/extraLibs/spring-security-core-5.2.1.RELEASE.jar:${CURRENT_DIRECTORY}/extraLibs/spring-security-config-5.2.1.RELEASE.jar:${CURRENT_DIRECTORY}/extraLibs/spring-context-5.2.1.RELEASE.jar:${CURRENT_DIRECTORY}/extraLibs/spring-beans-5.2.1.RELEASE.jar:${CURRENT_DIRECTORY}/extraLibs/spring-aop-5.2.1.RELEASE.jar:${CURRENT_DIRECTORY}/extraLibs/spring-expression-5.2.1.RELEASE.jar
    ```
- Start server:
    ```
    start server --name=server1 --security-properties-file=${CURRENT_DIRECTORY}/config/server.properties --locators=localhost[10334] --classpath=${CURRENT_DIRECTORY}/extraLibs/geode-spring-security-1.0.0.jar:${CURRENT_DIRECTORY}/extraLibs/spring-security-core-5.2.1.RELEASE.jar:${CURRENT_DIRECTORY}/extraLibs/spring-security-config-5.2.1.RELEASE.jar:${CURRENT_DIRECTORY}/extraLibs/spring-context-5.2.1.RELEASE.jar:${CURRENT_DIRECTORY}/extraLibs/spring-beans-5.2.1.RELEASE.jar:${CURRENT_DIRECTORY}/extraLibs/spring-aop-5.2.1.RELEASE.jar:${CURRENT_DIRECTORY}/extraLibs/spring-expression-5.2.1.RELEASE.jar
    ```
- Connect to as the `clusterManager` user:
    ```
    gfsh>connect --user=clusterManager --password=clusterManagerPassword
    Connecting to Locator at [host=localhost, port=10334] ..
    Connecting to Manager at [host=192.168.8.102, port=1099] ..
    Successfully connected to: [host=192.168.8.102, port=1099]
    ```
