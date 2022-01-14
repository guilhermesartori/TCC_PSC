package br.ufsc.tsp.entity;

import java.util.Collection;

import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import br.ufsc.tsp.entity.enums.Authority;


// TODO alterar colecao de autorities para uma unica authority
@Entity
@Table
public class AppUser {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;
	@Column(nullable = false)
	private String name;
	@Column(nullable = false, unique = true)
	private String username;
	@Column(nullable = false)
	private String password;
	@ElementCollection(targetClass = Authority.class, fetch = FetchType.EAGER)
	@Enumerated(EnumType.STRING)
	private Collection<Authority> authorities;

	/**
	 * 
	 */
	public AppUser() {
		super();
	}

	/**
	 * 
	 * @param name
	 * @param username
	 * @param password
	 * @param authorities
	 */
	public AppUser(String name, String username, String password, Collection<Authority> authorities) {
		super();
		this.name = name;
		this.username = username;
		this.password = password;
		this.authorities = authorities;
	}

	/**
	 * @return the id
	 */
	public Long getId() {
		return id;
	}

	/**
	 * @param id the id to set
	 */
	public void setId(Long id) {
		this.id = id;
	}

	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * @param name the name to set
	 */
	public void setName(String name) {
		this.name = name;
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
	 * @return the password
	 */
	public String getPassword() {
		return password;
	}

	/**
	 * @param password the password to set
	 */
	public void setPassword(String password) {
		this.password = password;
	}

	/**
	 * @return the authorities
	 */
	public Collection<Authority> getAuthorities() {
		return authorities;
	}

	/**
	 * @param authorities the authorities to set
	 */
	public void setAuthorities(Collection<Authority> authorities) {
		this.authorities = authorities;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AppUser))
			return false;
		var other = (AppUser) obj;
		return other.username.equals(username) && other.password.equals(password) && other.name.equals(name)
				&& other.authorities.containsAll(authorities) && authorities.containsAll(other.authorities);
	}

}
