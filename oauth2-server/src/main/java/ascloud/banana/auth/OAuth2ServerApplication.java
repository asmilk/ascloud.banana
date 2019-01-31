package ascloud.banana.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.extras.springsecurity5.dialect.SpringSecurityDialect;
import org.thymeleaf.spring5.SpringTemplateEngine;

import ascloud.banana.auth.conf.FormLoginFilter;
import ascloud.banana.auth.conf.OAuth2LogoutSuccessHandler;

@SpringBootApplication
@EnableEurekaClient
public class OAuth2ServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(OAuth2ServerApplication.class, args);
	}

	@Bean
	public TemplateEngine templateEngine() {
		SpringTemplateEngine springTemplateEngine = new SpringTemplateEngine();
		springTemplateEngine.addDialect(new SpringSecurityDialect());
		return springTemplateEngine;
	}

	@Bean
	public RoleHierarchy roleHierarchy() {
		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_STAFF and ROLE_STAFF > ROLE_USER");
		return roleHierarchy;
	}

	@Bean
	public UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager();
		userDetailsService.createUser(User.withUsername("admin").password("{noop}123456").roles("ADMIN").build());
		userDetailsService.createUser(User.withUsername("staff").password("{noop}123456").roles("STAFF").build());
		userDetailsService.createUser(User.withUsername("user").password("{noop}123456").roles("USER").build());
		userDetailsService.createUser(User.withUsername("guest").password("{noop}123456").roles("GUEST").build());
		userDetailsService.createUser(
				User.withUsername("hacker").password("{noop}123456").roles("HACKER").disabled(true).build());
		return userDetailsService;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Configuration
	@EnableAuthorizationServer
	static class AuthServerConfig extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private AuthenticationManager authenticationManager;

		@Autowired
		private UserDetailsService userDetailsService;

		@Autowired
		private PasswordEncoder passwordEncoder;

		@Autowired
		private RedisConnectionFactory redisConnectionFactory;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints//
					.authenticationManager(this.authenticationManager).userDetailsService(this.userDetailsService)
					.tokenStore(new RedisTokenStore(this.redisConnectionFactory));
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
			security//
					.passwordEncoder(this.passwordEncoder)//
					.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients//
					.inMemory()//
					.withClient("uaa").secret("{noop}s3cr3t").scopes("all")
					.authorizedGrantTypes("authorization_code", "password", "refresh_token").autoApprove(true)
					.accessTokenValiditySeconds(300).refreshTokenValiditySeconds(600)
					.redirectUris("http://oauth2.client:8080/login", "http://oauth2.com/login/oauth2/code/uaa");
		}

	}

	@Configuration
	@EnableWebSecurity
	static class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		private static final String REMEMBER_ME_KEY = "ascloudAppleOauth2Server";
		private static final String URL_LOGIN = "/oauth/login";
		private static final String URL_LOGOUT = "/oauth/logout";

		@Autowired
		private UserDetailsService userDetailsService;

		@Autowired
		private PasswordEncoder passwordEncoder;

		@Autowired
		private OAuth2LogoutSuccessHandler oAuth2LogoutSuccessHandler;
		
//		@Autowired
//		private OAuth2LogoutHandler oAuth2LogoutHandler;

		@Autowired
		private RoleHierarchy roleHierarchy;

		@Bean
		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
			return super.authenticationManagerBean();
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth//
					.authenticationProvider(new RememberMeAuthenticationProvider(REMEMBER_ME_KEY))
					.eraseCredentials(true).userDetailsService(this.userDetailsService)
					.passwordEncoder(this.passwordEncoder);
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			TokenBasedRememberMeServices rememberMeServices = new TokenBasedRememberMeServices(REMEMBER_ME_KEY,
					this.userDetailsService);
			rememberMeServices.setTokenValiditySeconds(300);

			FormLoginFilter formLoginFilter = new FormLoginFilter();
			formLoginFilter.setAuthenticationManager(super.authenticationManagerBean());
			formLoginFilter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(URL_LOGIN, "POST"));
			formLoginFilter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler(URL_LOGIN));
			formLoginFilter.setRememberMeServices(rememberMeServices);

			http//
					.antMatcher("/oauth/**").authorizeRequests().anyRequest().authenticated().and()//
					.formLogin().loginPage(URL_LOGIN).permitAll().and()//
					.addFilterBefore(formLoginFilter, UsernamePasswordAuthenticationFilter.class)//
					.csrf().ignoringAntMatchers(URL_LOGIN).and()//
					.rememberMe().rememberMeServices(rememberMeServices).and()//
					.logout().logoutRequestMatcher(new AntPathRequestMatcher(URL_LOGOUT))
//					.addLogoutHandler(this.oAuth2LogoutHandler)
					.logoutSuccessHandler(this.oAuth2LogoutSuccessHandler);
		}

		@Override
		public void configure(WebSecurity web) throws Exception {
			OAuth2WebSecurityExpressionHandler expressionHandler = new OAuth2WebSecurityExpressionHandler();
			expressionHandler.setRoleHierarchy(this.roleHierarchy);
			web.expressionHandler(expressionHandler).ignoring().antMatchers("/user/**", "/actuator/**", "/favicon.ico");
		}

	}

	@Configuration
	@EnableResourceServer
	static class ResourceServerConfig extends ResourceServerConfigurerAdapter {

		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.antMatcher("/uaa/**").authorizeRequests().anyRequest().authenticated();
		}

	}

}
