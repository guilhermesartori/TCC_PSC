package br.ufsc.tsp.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import br.ufsc.tsp.entity.enums.Authority;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AppUser {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;
	@Column(nullable = false, unique = true)
	private String username;
	@Column(nullable = false)
	private String password;
	@Column(nullable = false)
	private Authority authority;

	public AppUser(String username, String password, Authority authority) {
		this.username = username;
		this.password = password;
		this.authority = authority;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AppUser))
			return false;
		var other = (AppUser) obj;
		return other.username.equals(username) && other.password.equals(password) && other.authority == authority;
	}

	@Override
	public int hashCode() {
		return (int) username.hashCode() * password.hashCode();
	}

}
