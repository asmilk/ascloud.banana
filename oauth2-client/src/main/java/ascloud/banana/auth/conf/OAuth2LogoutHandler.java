package ascloud.banana.auth.conf;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Component
public class OAuth2LogoutHandler implements LogoutHandler {

	private static final Logger LOG = LoggerFactory.getLogger(OAuth2LogoutHandler.class);

	@Value("${ascloud.banana.auth.server.resource.revoke-token-uri}")
	private String revokeTokenUrl;

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		LOG.info("====OAuth2LogoutHandler.logout()====");
		LOG.info("authentication:{}", authentication);
		if (authentication instanceof OAuth2Authentication) {
			OAuth2Authentication principal = (OAuth2Authentication) authentication;
			Object details = principal.getDetails();
			if (details instanceof OAuth2AuthenticationDetails) {
				OAuth2AuthenticationDetails authenticationDetails = (OAuth2AuthenticationDetails) details;
				String tokenValue = authenticationDetails.getTokenValue();
				LOG.info("tokenValue:{}", tokenValue);

				HttpGet req = new HttpGet(this.revokeTokenUrl + "?token=" + tokenValue);
				req.setHeader("Authorization", "Bearer " + tokenValue);

				try (CloseableHttpClient client = HttpClientBuilder.create().build();
						CloseableHttpResponse res = client.execute(req);) {
					res.getEntity().writeTo(System.out);
					System.out.println();
				} catch (IOException e) {
					LOG.error(e.getMessage(), e);
				}
			}
		}

	}

}
