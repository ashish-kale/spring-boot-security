package demo;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.Http401AuthenticationEntryPoint;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@EnableWebSecurity
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	private final UserService userService;
	private final ObjectMapper objectMapper;

	public SecurityConfiguration(UserService userService, ObjectMapper objectMapper) {
		this.userService = userService;
		this.objectMapper = objectMapper;
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userService);
	}

	private void loginSuccessHandler(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {

		response.setStatus(HttpStatus.OK.value());
		objectMapper.writeValue(response.getWriter(), "Yayy you logged in!");
	}

	private void loginFailureHandler(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException {

		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		objectMapper.writeValue(response.getWriter(), "Nopity nop!");
	}
	
	  private void logoutSuccessHandler(
		        HttpServletRequest request,
		        HttpServletResponse response,
		        Authentication authentication) throws IOException {
		 
		        response.setStatus(HttpStatus.OK.value());
		        objectMapper.writeValue(response.getWriter(), "Bye!");
		    }

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.csrf().disable() // We don't need CSRF for this example
				.authorizeRequests().anyRequest().authenticated() // all request requires a logged in user
				.and()
				//.addFilterBefore(new CustomUsernamePasswordAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
				.formLogin().loginProcessingUrl("/authenticate") // the URL on which the clients should post the																		
				.usernameParameter("username") // the username parameter in the queryString, default is 'username'
				.passwordParameter("password")// the password
				.successHandler(this::loginSuccessHandler).failureHandler(this::loginFailureHandler).and().logout()
				.logoutUrl("/logout") // the URL on which the clients should post if they want to logout
				.logoutSuccessHandler(this::logoutSuccessHandler)
				.invalidateHttpSession(true)
				.and()
				.exceptionHandling()
				.authenticationEntryPoint(new Http401AuthenticationEntryPoint("401"));
	}
}