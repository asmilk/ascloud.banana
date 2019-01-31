package ascloud.banana.auth.ctrl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

	private static final Logger LOG = LoggerFactory.getLogger(OAuth2Controller.class);
	
	@Autowired
	private InMemoryUserDetailsManager userDetailsService;

	@RequestMapping("/register")
	public boolean register(@RequestParam String username, @RequestParam String password) {
		LOG.info("====AccountController.register====");
		LOG.info("userDetailsService:{}", userDetailsService);
		LOG.info("username:{}", username);
		LOG.info("password:{}", password);
		this.userDetailsService.createUser(User.withUsername(username).password("{noop}" + password).roles("USER").build());
		return true;
	}
	
	@RequestMapping("/{username}")
	public UserDetails load(@PathVariable("username") String username) {
		return this.userDetailsService.loadUserByUsername(username);
	}

}
