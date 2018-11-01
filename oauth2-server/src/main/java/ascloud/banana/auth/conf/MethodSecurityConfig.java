package ascloud.banana.auth.conf;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {

	@Autowired
	private RoleHierarchy roleHierarchy;

	@Override
	protected MethodSecurityExpressionHandler createExpressionHandler() {
		OAuth2MethodSecurityExpressionHandler expressionHandler = new OAuth2MethodSecurityExpressionHandler();
		expressionHandler.setRoleHierarchy(this.roleHierarchy);
		return expressionHandler;
	}

}
