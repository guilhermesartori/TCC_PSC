package br.ufsc.tsp.controller.request;

public class RoleToUserForm {

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
	public RoleToUserForm(String roleName) {
		super();
		this.roleName = roleName;
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
