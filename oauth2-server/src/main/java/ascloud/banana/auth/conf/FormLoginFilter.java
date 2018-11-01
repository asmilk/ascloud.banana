package ascloud.banana.auth.conf;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

public class FormLoginFilter extends UsernamePasswordAuthenticationFilter {

	private static final Logger LOG = LoggerFactory.getLogger(FormLoginFilter.class);

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		LOG.info("====FormLoginFilter.attemptAuthentication====");
		String captcha = request.getParameter("captcha");
		LOG.info("captcha:{}", captcha);

		String redirectUrl = request.getParameter("redirectUrl");
		LOG.info("redirectUrl:{}", redirectUrl);

		UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(redirectUrl).build();
		DefaultSavedRequest savedRequest = new DefaultSavedRequest.Builder().setScheme(uriComponents.getScheme())
				.setServerName(uriComponents.getHost()).setServerPort(uriComponents.getPort())
				.setRequestURI(uriComponents.getPath()).setQueryString(uriComponents.getQuery()).build();
		LOG.info("redirectUrl:{}", savedRequest.getRedirectUrl());
		request.getSession().setAttribute("SPRING_SECURITY_SAVED_REQUEST", savedRequest);
		return super.attemptAuthentication(request, response);
	}

}
