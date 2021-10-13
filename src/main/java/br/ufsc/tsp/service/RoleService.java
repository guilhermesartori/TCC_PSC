package br.ufsc.tsp.service;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.tsp.domain.Role;
import br.ufsc.tsp.repository.RoleRepository;

@Service
@Transactional
public class RoleService {

	private final RoleRepository roleRepository;

	@Autowired
	public RoleService(RoleRepository roleRepository) {
		super();
		this.roleRepository = roleRepository;
	}

	public Role saveRole(Role role) {
		return roleRepository.save(role);
	}

}
