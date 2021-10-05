package br.ufsc.tsp.controller.request;

public class RoleToUserForm {

	private String username;
	private String roleName;

	/**
	 * 
	 */
	public RoleToUserForm() {
		super();
	}

	/**
	 * @param username
	 * @param roleName
	 */
	public RoleToUserForm(String username, String roleName) {
		super();
		this.username = username;
		this.roleName = roleName;
	}

	/**
	 * @return the username
	 */
	public String getUsername() {
		return username;
	}

	/**
	 * @param username the username to set
	 */
	public void setUsername(String username) {
		this.username = username;
	}

	/**
	 * @return the roleName
	 */
	public String getRoleName() {
		return roleName;
	}

	/**
	 * @param roleName the roleName to set
	 */
	public void setRoleName(String roleName) {
		this.roleName = roleName;
	}

}
