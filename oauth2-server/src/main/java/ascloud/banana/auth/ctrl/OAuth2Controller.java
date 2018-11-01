package ascloud.banana.auth.ctrl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttribute;

import ascloud.banana.auth.enty.UserEntity;

@Controller
@RequestMapping("/oauth")
public class OAuth2Controller {

	private static final Logger LOG = LoggerFactory.getLogger(OAuth2Controller.class);

	@GetMapping("/login")
	public String login(@ModelAttribute("user") UserEntity user,
			@SessionAttribute("SPRING_SECURITY_SAVED_REQUEST") DefaultSavedRequest savedRequest) {
		String view = "login";
		LOG.info("savedRequest:{}", savedRequest);
		String query = savedRequest.getQueryString();
		if (query.contains("http://zuul.proxy:8080/login")) {
			view = "login/zuul.proxy";
		} else if (query.contains("http://oauth2.com/login/oauth2/code/uaa")) {
			view = "login/oauth2.com";
		} else if (query.contains("http://oauth2.client:8080/login")) {
			view = "login/oauth2.client";
		}
		return view;
	}

}
