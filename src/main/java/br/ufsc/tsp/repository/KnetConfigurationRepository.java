package br.ufsc.tsp.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.ufsc.tsp.entity.KnetConfiguration;

@Repository
public interface KnetConfigurationRepository extends JpaRepository<KnetConfiguration, Long> {

}
