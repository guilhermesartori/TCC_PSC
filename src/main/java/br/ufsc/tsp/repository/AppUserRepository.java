package br.ufsc.tsp.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.domain.enums.Authority;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {

	public AppUser findAppUserByUsername(String username);

	public Integer deleteAppUserByUsername(String username);

	public Optional<AppUser> findAppUserByAuthorities(Authority authority);

}
