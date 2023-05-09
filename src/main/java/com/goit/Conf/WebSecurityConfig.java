package com.goit.Conf;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig{
    @Autowired
    private DataSource dataSource;

//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth.jdbcAuthentication()
//                .passwordEncoder(new BCryptPasswordEncoder())
//                .dataSource(dataSource)
//                .usersByUsernameQuery("select username, password, enabled from users where username=?")
//                .authoritiesByUsernameQuery("select username, role from users where username=?");
//    }


//        @Autowired
//        private BCryptPasswordEncoder passwordEncoder;
//
//        @Override
//        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//
//            auth.jdbcAuthentication()
//                    .dataSource(dataSource) //creates database connection
//                    .usersByUsernameQuery("select user_name,user_pwd,user_enabled from user where user_name=?")
//                    .authoritiesByUsernameQuery("select user_name,user_role from user where user_name=?")
//                    .passwordEncoder(passwordEncoder);
//
//        }


        @Bean
        public UserDetailsManager authenticateUsers() {

//            UserDetails user = User.withUsername("username")
//                    .password(PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("password")).build();
            JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
            users.setAuthoritiesByUsernameQuery("select username, password, enabled from users where username=?");
            users.setUsersByUsernameQuery("select username, authority from authorities where username=?");
//            users.createUser(user);
            return users;
        }


//    @Bean
//    public UserDetailsManager users(DataSource dataSource) {
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//        JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
//        users.createUser(user);
//        return users;
//    }


//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin().permitAll()
//                .and()
//                .logout().permitAll();
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().permitAll()
                .and()
                .logout().permitAll();
        return http.build();
    }
}