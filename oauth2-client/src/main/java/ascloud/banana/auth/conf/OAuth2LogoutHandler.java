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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Component
public class OAuth2LogoutHandler implements LogoutHandler {

	private static final Logger LOG = LoggerFactory.getLogger(OAuth2LogoutHandler.class);

	@Value("${ascloud.banana.auth.server.resource.revoke-token-uri}")
	private String revokeTokenUrl;

	@Autowired
	private OAuth2RestTemplate oAuth2RestTemplate;

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		OAuth2AccessToken accessToken = this.oAuth2RestTemplate.getAccessToken();
		LOG.info("accessToken:{}", accessToken);
		HttpGet req = new HttpGet(this.revokeTokenUrl + "?token=" + accessToken.getValue());
		req.setHeader("Authorization", "Bearer " + accessToken.getValue());

		try (CloseableHttpClient client = HttpClientBuilder.create().build();
				CloseableHttpResponse res = client.execute(req);) {
			res.getEntity().writeTo(System.out);
		} catch (IOException e) {
			LOG.error(e.getMessage(), e);
		}
	}

}
