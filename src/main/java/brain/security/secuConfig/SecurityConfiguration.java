package brain.security.secuConfig;




import java.util.Arrays;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }
    
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.setExposedHeaders(Arrays.asList("Authorization", "content-type"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "content-type"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	http.cors().configurationSource(corsConfigurationSource())
    	.and().csrf().disable().authorizeRequests()
    	// http.authorizeRequests()
    	 .antMatchers("/**").fullyAuthenticated()
    	 .antMatchers("/admin").hasRole("ADMIN")
    	 .antMatchers("/api/**").hasAnyRole("ADMIN", "USER")
    	 .and().httpBasic().and().formLogin(); 
    	 //.antMatchers("/home").permitAll()
    	/* .antMatchers("/admin").hasRole("ADMIN")
    	 .antMatchers("/api/**").hasAnyRole("ADMIN", "USER")
    	 .and().formLogin();*/
    	 
    	//System.out.println("we are in http method");
       /* http.authorizeRequests()
        authorizeRequests()
        .antMatchers("/admin").hasAuthority("ADMIN")
        .antMatchers("/user").hasAnyAuthority("USER","ADMIN")
                .antMatchers("/hello").permitAll()
                .antMatchers("/user/**").hasAnyRole("ADMIN", "USER")
                .hasAnyRole("ROLE_ADMIN", "USER")
                .and().formLogin();*/
                
                /*.and().formLogin();*/
    }
}
