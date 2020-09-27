/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.dubbo.demo.provider;

import com.google.common.collect.Lists;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.dubbo.config.ApplicationConfig;
import org.apache.dubbo.config.ArgumentConfig;
import org.apache.dubbo.config.MethodConfig;
import org.apache.dubbo.config.ProtocolConfig;
import org.apache.dubbo.config.ProviderConfig;
import org.apache.dubbo.config.RegistryConfig;
import org.apache.dubbo.config.ServiceConfig;
import org.apache.dubbo.config.spring.context.annotation.EnableDubbo;

import org.apache.dubbo.demo.DemoService;
import org.apache.dubbo.rpc.Protocol;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

public class Application {
  public static void main(String[] args) throws Exception {
    AnnotationConfigApplicationContext context =
        new AnnotationConfigApplicationContext(ProviderConfiguration.class);
    context.start();
    System.in.read();
  }

  @Configuration
  @EnableDubbo(scanBasePackages = "org.apache.dubbo.demo.provider")
  @PropertySource("classpath:/spring/dubbo-provider.properties")
  static class ProviderConfiguration {

    @Bean
    public DemoService demoService() {
      return new DemoServiceImpl();
    }

    @Bean
    public ApplicationConfig applicationConfig() {
      ApplicationConfig applicationConfig = new ApplicationConfig();
      applicationConfig.setName("test");
      return applicationConfig;
    }

    @Bean
    public RegistryConfig registryConfig() {
      RegistryConfig registryConfig = new RegistryConfig();
      registryConfig.setId("r1");
      registryConfig.setAddress("zookeeper://47.99.108.26:2181");
      return registryConfig;
    }

    @Bean
    public ProviderConfig providerConfig() {
      ProviderConfig providerConfig = new ProviderConfig();
      providerConfig.setExport(true);
      return providerConfig;
    }

    @Bean
    public ServiceConfig<DemoService> demoServiceServiceConfig(DemoService demoService) {
      ServiceConfig<DemoService> demoServiceServiceConfig = new ServiceConfig<>();
      demoServiceServiceConfig.setProvider(providerConfig());
      demoServiceServiceConfig.setRef(demoService);
      demoServiceServiceConfig.setInterface(DemoService.class);
      return demoServiceServiceConfig;
    }

  }
}
