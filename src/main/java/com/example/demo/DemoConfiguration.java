package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.client.RestClient;

@Configuration(proxyBeanMethods = false)
public class DemoConfiguration
{

    // must match name configured in application.yaml
    public static final String MANAGEMENT_SERVICE_REGISTRATION_ID = "management-service";

    @Bean
    RestClient managementServiceRestClient(final RestClient.Builder builder,
                                           final OAuth2AuthorizedClientService authorizedClientService,
                                           final ClientRegistrationRepository clientRegistrationRepository)
    {

        final AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager
                        = new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository,
                                                                                   authorizedClientService);

        OAuth2ClientHttpRequestInterceptor requestInterceptor = new OAuth2ClientHttpRequestInterceptor(
                        authorizedClientManager, MANAGEMENT_SERVICE_REGISTRATION_ID);
        return builder.baseUrl("http://localhost:8095")
                      .requestInterceptor(requestInterceptor)
                      .build();
    }

}
