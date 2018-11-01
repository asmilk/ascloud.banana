package ascloud.banana.auth.enty;

import java.io.Serializable;
import java.util.Set;

public class UserEntity implements Serializable {

	private static final long serialVersionUID = -3239618935152846776L;

	private String username;

	private String password;

	private Boolean enabled;
	
	private Set<AuthoritieEntity> authorities;

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Boolean getEnabled() {
		return enabled;
	}

	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}

	public Set<AuthoritieEntity> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(Set<AuthoritieEntity> authorities) {
		this.authorities = authorities;
	}

	@Override
	public String toString() {
		return "UserEntity [username=" + username + ", password=" + password + ", enabled=" + enabled + ", authorities="
				+ authorities + "]";
	}

}
