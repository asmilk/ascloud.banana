package ascloud.banana.auth.ctrl;

import java.security.Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

	private static final Logger LOG = LoggerFactory.getLogger(ResourceController.class);
	
	@Value("${security.oauth2.resource.user-info-uri}")
	private String userInfoUrl;

	@Autowired
	private OAuth2RestTemplate oAuth2RestTemplate;

	@GetMapping("/user_info")
	public Principal getUserInfo(Principal principal) {
		LOG.info("principal : {}", principal);
		
		String result = this.oAuth2RestTemplate.getForObject(this.userInfoUrl, String.class);
		LOG.info("result:{}", result);
		
		result = this.oAuth2RestTemplate.getForObject("http://oauth2.resource:8081/user_info", String.class);
		LOG.info("result:{}", result);
		
		return principal;
	}

}
