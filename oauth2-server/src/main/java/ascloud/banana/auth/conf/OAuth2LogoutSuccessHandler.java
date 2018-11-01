package ascloud.banana.auth.conf;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class OAuth2LogoutSuccessHandler implements LogoutSuccessHandler {
	
	private static final Logger LOG = LoggerFactory.getLogger(OAuth2LogoutSuccessHandler.class);

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {
		Principal principal = request.getUserPrincipal();
		LOG.info("principal:{}", principal);
		LOG.info("authentication:{}", authentication);
		String referer = request.getHeader("Referer");
		LOG.info("referer:{}", referer);
		response.sendRedirect(referer);
	}

}
