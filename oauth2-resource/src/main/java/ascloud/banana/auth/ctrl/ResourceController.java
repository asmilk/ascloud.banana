package ascloud.banana.auth.ctrl;

import java.security.Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

	private static final Logger LOG = LoggerFactory.getLogger(ResourceController.class);

	@RequestMapping("/user_info")
	public Principal userInfo(Principal principal) {
		String name = principal.getClass().getName();
		LOG.info("name:{}", name);
		return principal;
	}

}
