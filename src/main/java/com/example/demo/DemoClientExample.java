package com.example.demo;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public class DemoClientExample implements CommandLineRunner
{
    private final RestClient restClient;

    public DemoClientExample(@Qualifier("managementServiceRestClient") RestClient restClient)
    {
        this.restClient = restClient;
    }

    @Override
    public void run(String... args)
                    throws Exception
    {
        System.out.println("Calling option one:");
        RestClient.ResponseSpec retrieve = restClient.get()
                                                     .uri("/history/TEST1234567891234")
                                                     .retrieve();
        System.out.println(retrieve.toEntity(String.class));
    }

}
