package com.camunda.example.oauth2.config;

import com.azure.spring.aad.webapi.AADResourceServerWebSecurityConfigurerAdapter;
import com.camunda.example.oauth2.filter.RestAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import static org.springframework.boot.autoconfigure.security.SecurityProperties.BASIC_AUTH_ORDER;
import static org.springframework.security.config.http.SessionCreationPolicy.NEVER;

@Configuration
@Order(BASIC_AUTH_ORDER - 20)
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class RestSecurityConfig extends AADResourceServerWebSecurityConfigurerAdapter {

    private final Logger logger = LoggerFactory.getLogger(RestSecurityConfig.class.getName());

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        logger.info("++++++++ RestSecurityConfig.configure()....");

        super.configure(http);
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(NEVER);
        http.authorizeRequests().antMatchers("/rest/**", "/engine-rest/**").authenticated();

    }

    @Bean
    public FilterRegistrationBean<RestAuthenticationFilter> statelessUserAuthenticationFilter() {

        logger.info("++++++++ RestSecurityConfig.statelessUserAuthenticationFilter()....");

        FilterRegistrationBean<RestAuthenticationFilter> filterRegistration = new FilterRegistrationBean<>();
        filterRegistration.setFilter(new RestAuthenticationFilter());
        filterRegistration.setOrder(102); // make sure the filter is registered after the Spring Security Filter Chain
        filterRegistration.addUrlPatterns("/rest/*", "/engine-rest/*");
        return filterRegistration;
    }

}
