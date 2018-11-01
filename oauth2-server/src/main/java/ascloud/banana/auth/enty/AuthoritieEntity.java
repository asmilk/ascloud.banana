package ascloud.banana.auth.enty;

import java.io.Serializable;

public class AuthoritieEntity implements Serializable {

	private static final long serialVersionUID = -8501938302723407482L;

	private Long id;
	
	private UserEntity user;

	private String authority;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public UserEntity getUser() {
		return user;
	}

	public void setUser(UserEntity user) {
		this.user = user;
	}

	public String getAuthority() {
		return authority;
	}

	public void setAuthority(String authority) {
		this.authority = authority;
	}

	@Override
	public String toString() {
		return "AuthoritieEntity [id=" + id + ", user=" + user + ", authority=" + authority + "]";
	}

}
