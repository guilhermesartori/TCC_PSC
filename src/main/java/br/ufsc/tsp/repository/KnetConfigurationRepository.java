package br.ufsc.tsp.repository;

import org.springframework.context.annotation.Lazy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.ufsc.tsp.entity.KnetConfiguration;

@Lazy
@Repository
public interface KnetConfigurationRepository extends JpaRepository<KnetConfiguration, Long> {

}
