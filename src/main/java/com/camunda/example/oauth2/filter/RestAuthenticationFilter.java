package com.camunda.example.oauth2.filter;

import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.util.EngineUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import javax.servlet.*;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class RestAuthenticationFilter implements Filter {

    private final Logger logger = LoggerFactory.getLogger(RestAuthenticationFilter.class.getName());

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        logger.info("++ RestAuthenticationFilter.doFilter()....");
        // Current limitation: Only works for the default engine
        ProcessEngine engine = EngineUtil.lookupProcessEngine("default");
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username;

        if (principal instanceof OAuth2AuthenticatedPrincipal) {
            username = ((OAuth2AuthenticatedPrincipal) principal).getName();
        } else {
            username = principal.toString();
        }

        try {
            engine.getIdentityService().setAuthentication(username, getUserGroups());
            chain.doFilter(request, response);
        } finally {
            clearAuthentication(engine);
        }

    }

    @Override
    public void destroy() {

    }

    private void clearAuthentication(ProcessEngine engine) {
        engine.getIdentityService().clearAuthentication();
    }

    private List<String> getUserGroups() {

        logger.info("++ RestAuthenticationFilter.getUserGroups()....");

        List<String> groupIds;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        groupIds = authentication.getAuthorities().stream()
                .map(res -> res.getAuthority())
                .map(res -> res.substring(5)) // Strip "ROLE_"
                .collect(Collectors.toList());
        logger.debug("++ groupIds = " + groupIds);

        return groupIds;

    }

}
