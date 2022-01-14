package br.ufsc.tsp.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.ufsc.tsp.entity.AppUser;
import br.ufsc.tsp.entity.enums.Authority;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser, Long> {

	public AppUser findAppUserByUsername(String username);

	public Integer deleteAppUserByUsername(String username);

	public Optional<AppUser> findAppUserByAuthorities(Authority authority);

}
