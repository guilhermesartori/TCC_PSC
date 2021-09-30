package br.ufsc.tsp.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import br.ufsc.tsp.domain.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {

	public Role findByName(String name);

}
