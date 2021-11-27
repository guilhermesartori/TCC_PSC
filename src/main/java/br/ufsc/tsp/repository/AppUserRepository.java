package br.ufsc.tsp.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import br.ufsc.tsp.domain.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {

	public AppUser findAppUserByUsername(String username);

	public Integer deleteAppUserByUsername(String username);
	
}
