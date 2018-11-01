package ascloud.banana.auth.ctrl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class IndexController {

	private static final Logger LOG = LoggerFactory.getLogger(IndexController.class);

	@RequestMapping({ "/", "/index" })
	public String index() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		LOG.info("authentication:{}", authentication);
		return "index";
	}

}
