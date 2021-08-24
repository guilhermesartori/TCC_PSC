package br.ufsc.tsp.student;

import java.util.List;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class StudentService {

	private final StudentRepository studentRepository;

	/**
	 * @param studentRepository
	 */
	@Autowired
	public StudentService(StudentRepository studentRepository) {
		super();
		this.studentRepository = studentRepository;
	}

	public List<Student> getStudents() {
		return studentRepository.findAll();
	}

	public void addNewStudent(Student student) {
		var studentByEmail = studentRepository.findStudentByEmail(student.getEmail());
		if (studentByEmail.isPresent())
			throw new IllegalStateException("email taken");
		else
			studentRepository.save(student);
	}

	public void deleteStudent(Long studentId) {
		if (!studentRepository.existsById(studentId))
			throw new IllegalStateException(String.format("student with id %d does not exist", studentId));
		else
			studentRepository.deleteById(studentId);
	}

	@Transactional
	public void updateStudent(Long studentId, String name, String email) {
		var student = studentRepository.findById(studentId).orElseThrow(
				() -> new IllegalStateException(String.format("student with id %d does not exist", studentId)));

		if (name != null && name.length() > 0 && !name.equals(student.getName()))
			student.setName(name);

		if (email != null && email.length() > 0 && !email.equals(student.getEmail())) {
			if (studentRepository.findStudentByEmail(email).isPresent())
				throw new IllegalStateException("email taken");
			else
				student.setEmail(email);
		}

	}

}
