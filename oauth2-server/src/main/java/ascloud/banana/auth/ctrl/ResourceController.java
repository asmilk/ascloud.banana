package ascloud.banana.auth.ctrl;

import java.security.Principal;

import javax.servlet.ServletException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/uaa")
public class ResourceController {

	private static final Logger LOG = LoggerFactory.getLogger(ResourceController.class);

	@Autowired
	ConsumerTokenServices consumerTokenServices;

	@RequestMapping("/revoke_token")
	public boolean revoke(Principal principal) throws ServletException {
		boolean result = false;
		if (principal instanceof OAuth2Authentication) {
			OAuth2Authentication authentication = (OAuth2Authentication) principal;
			Object details = authentication.getDetails();
			if (details instanceof OAuth2AuthenticationDetails) {
				OAuth2AuthenticationDetails authenticationDetails = (OAuth2AuthenticationDetails) details;
				String tokenValue = authenticationDetails.getTokenValue();
				LOG.info("tokenValue:{}", tokenValue);
				result = this.consumerTokenServices.revokeToken(tokenValue);
			}
		}
		return result;
	}

	@RequestMapping("/user_info")
	public Principal userInfo(Principal principal) {
		return principal;
	}

	@RequestMapping("/role/user")
	@PreAuthorize("hasRole('USER')")
	public boolean hasRoleUser(Principal principal) throws ServletException {
		LOG.info("principal:{}", principal);
		return true;
	}

	@RequestMapping("/role/admin")
	@PreAuthorize("hasRole('ADMIN')")
	public boolean hasRoleAdmin(Principal principal) throws ServletException {
		LOG.info("principal:{}", principal);
		return true;
	}

}
