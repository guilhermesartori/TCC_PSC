package br.ufsc.tsp.student;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface StudentRepository extends JpaRepository<Student, Long> {

//	@Query("SELECT s from Student s WHERE s.email = ?1")
	public Optional<Student> findStudentByEmail(String email);

}
