package com.goit;

import com.goit.Conf.FlywayConfigurations;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.io.IOException;

@SpringBootApplication
@EnableJpaRepositories("com/goit/Repository")
public class JavaDevModule15Application {

    public static void main(String[] args) throws IOException {
        new FlywayConfigurations().setup().migrate();
        SpringApplication.run(JavaDevModule15Application.class, args);
    }
}
