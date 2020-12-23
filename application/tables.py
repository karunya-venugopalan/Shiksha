from application import db,app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from datetime import datetime
from sqlalchemy_utils import PhoneNumber
from application import db, login_manager
from flask_login import UserMixin
from sqlalchemy.orm import relationship
from sqlalchemy import Table, Column, Integer, ForeignKey

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(120), unique=True, nullable=False)
	password = db.Column(db.String(60), nullable=False)
	role = db.Column(db.String(20), nullable=False)
	
	principal_user = db.relationship('Principal', backref='principal_user', lazy=True)
	teacher_user = db.relationship('Teacher', backref='teacher_user', lazy=True)
	student_user = db.relationship('Student', backref='student_user', lazy=True)

	def __repr__(self):
		return f"User( ID : '{self.id} ', Username :'{self.email}', Role: '{self.role}')"
	

	def get_reset_token(self, expires_sec=1800):
		s = Serializer(app.config['SECRET_KEY'], expires_sec)
		return s.dumps({'user_id': self.id}).decode('utf-8')

	@staticmethod
	def verify_reset_token(token):
		s = Serializer(app.config['SECRET_KEY'])
		try:
			user_id = s.loads(token)['user_id']
		except:
			return None
		return User.query.get(user_id)




class Principal(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	first_name = db.Column(db.String(20), nullable=False)
	last_name = db.Column(db.String(20),  nullable=False)
	phone = db.Column(db.Numeric(10,0), nullable=False)
	dob = db.Column(db.Date,nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
	gender = db.Column(db.String(20),  nullable=False)

	def __repr__(self):
		return f"Principal(ID: '{self.id}', First Name: '{self.first_name}', Last Name: '{self.last_name}', Phone: '{self.phone}', DOB: ,'{self.dob}', UserID: '{self.user_id}', Gender: '{self.gender}')"





class Teacher(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	first_name = db.Column(db.String(20), nullable=False)
	last_name = db.Column(db.String(20),  nullable=False)
	phone = db.Column(db.Numeric(10,0), nullable=False)
	dob = db.Column(db.Date,nullable=False)
	is_ct = db.Column(db.Boolean, nullable=False)
	gender = db.Column(db.String(20),  nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
	

	ct = db.relationship('Class', backref='ct_class', lazy=True)
	teach_sub = db.relationship('Subject_handler', backref='teach_sub', lazy=True)

	def __repr__(self):
		return f"Teacher(ID: '{self.id}', First Name: '{self.first_name}', Last Name: '{self.last_name}', Phone: '{self.phone}', DOB: ,'{self.dob}', UserID: '{self.user_id}', Gender: '{self.gender}', IS CT: '{self.is_ct}')"

	def __str__(self):
		return str(self.first_name) + ' ' + str(self.last_name)


class Student(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	first_name = db.Column(db.String(20), nullable=False)
	last_name = db.Column(db.String(20),  nullable=False)
	phone = db.Column(db.Numeric(10,0), nullable=False)
	dob = db.Column(db.Date,nullable=False)
	gender = db.Column(db.String(20),  nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
	class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=True)
	
	second_language = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True)
	third_language = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True)
	elective = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True)
	
	second_language_sub = db.relationship("Subject_master", backref="second_language_sub", foreign_keys=[second_language])
	third_lang_sub = db.relationship("Subject_master", backref = "third_lang_sub", foreign_keys=[third_language])
	elective_sub = db.relationship("Subject_master", backref = "elective_sub", foreign_keys=[elective])
	submit_attendance = db.relationship('Submitted_attendance', backref='submit_attendance', lazy=True)
	

	def __repr__(self):
		return f"Student(ID: '{self.id}', First Name: '{self.first_name}', Last Name: '{self.last_name}', Phone: '{self.phone}', DOB: ,'{self.dob}', UserID: '{self.user_id}', Gender: '{self.gender}', ClassID: '{self.class_id}', Second lang '{self.second_language}', Third lang: '{self.third_language}', Elective: '{self.elective}' )"
	
	def __str__(self):
		return str(self.first_name) + ' ' + str(self.last_name)


class Subject_master(db.Model):
	code = db.Column(db.String(5),primary_key=True)
	name = db.Column(db.String(20), nullable=False)
	description = db.Column(db.String(20),  nullable=False)
	
	class_subjects = db.relationship("Subject_handler", backref="class_subjects", lazy = True)

	def __repr__(self):
		return f"Subject_master(Subject code:'{self.code}', Subject Name: '{self.name}', Subject Description: '{self.description}' )"


class Class(db.Model):
	id = db.Column(db.Integer, primary_key=True)	
	grade = db.Column(db.Integer, nullable=False)
	section = db.Column(db.String(5), nullable=True)
	class_teacher = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=True)

	member = db.relationship('Student', backref='member', lazy=True)
	class_sub = db.relationship('Subject_handler', backref='class_sub', lazy=True)
	class_subjects = db.relationship('Subjects', backref='class_subjects', lazy=True)

	def __repr__(self):
		return f"Class(ID: '{self.id}', Grade: '{self.grade}', Section: '{self.section}', Class Teacher ID: '{self.class_teacher}' )"

	def __str__(self):
		return str(self.grade) + ' - ' + str(self.section)





class Subjects(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=True, default='-')
	core1 = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True, default='-')
	core2 = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True, default='-')
	core3 = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True, default='-')
	first_language = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True, default='-')
	second_language1 = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True, default='-')
	second_language2 = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True, default='-')
	second_language3 = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True, default='-')
	third_language1 = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True, default='-')
	third_language2 = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True, default='-')
	third_language3 = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True, default='-')
	elective1 = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True, default='-')
	elective2 = db.Column(db.String, db.ForeignKey('subject_master.code'), nullable=True, default='-')
	
	core1_subject = db.relationship("Subject_master", backref="core1_subject" , foreign_keys=[core1])
	core2_subject = db.relationship("Subject_master", backref="core2_subject",foreign_keys=[core2])
	core3_subject = db.relationship("Subject_master", backref = "core3_subject", foreign_keys=[core3])
	first_language_subject = db.relationship("Subject_master", backref = "first_language_subject", foreign_keys=[first_language])
	second_language1_subject = db.relationship("Subject_master", backref = "second_language1_subject", foreign_keys=[second_language1])
	second_language2_subject = db.relationship("Subject_master", backref = "second_language2_subject", foreign_keys=[second_language2])
	second_language3_subject = db.relationship("Subject_master", backref = "second_language3_subject", foreign_keys=[second_language3])
	third_lang_subject1 = db.relationship("Subject_master", backref = "third_lang_subject1", foreign_keys=[third_language1])
	third_lang_subject2 = db.relationship("Subject_master", backref = "third_lang_subject2", foreign_keys=[third_language2])
	third_lang_subject3 = db.relationship("Subject_master", backref = "third_lang_subject3", foreign_keys=[third_language3])
	elective_subject1 = db.relationship("Subject_master", backref = "electve_subject1", foreign_keys=[elective1])
	elective_subject2 = db.relationship("Subject_master", backref = "electve_subject2", foreign_keys=[elective2])

	def __repr__(self):
		return f"Subjects(Class id: '{self.class_id}')"



class Subject_handler(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=True)
	subject_code = db.Column(db.String(20), db.ForeignKey('subject_master.code'), nullable=True)
	teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=True)
	online_class_link = db.Column(db.String, nullable=True)

	mat = db.relationship('Material', backref='mat', lazy=True)
	
	def __repr__(self):
		return f"Subject_handler(ID: '{self.id}', Class ID: '{self.class_id}', Subject: '{self.subject_code}', Teacher ID: '{self.teacher_id}' )"



class Material(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(50), nullable=False)
	link = db.Column(db.String(50), nullable=False)
	sub_hand_id = db.Column(db.Integer, db.ForeignKey('subject_handler.id'), nullable=False)
	start_date = db.Column(db.Date, nullable=True)
	start_time = db.Column(db.Time, nullable=True)
	end_date = db.Column(db.Date, nullable=True)
	end_time = db.Column(db.Time, nullable=True)
	report_gen = db.Column(db.Integer, nullable=False, default=-1)
	material_type = db.Column(db.String, nullable=False)

	submit_att = db.relationship('Submitted_attendance', backref='submit_att', lazy=True)

	def __repr__(self):
		return f"Material(ID: '{self.id}', Name: '{self.name}', Subject Handler ID: '{self.sub_hand_id}',Start Date: '{self.start_date}', Start Time: '{self.start_time}',End Date: '{self.end_date}', End Time: '{self.end_time}', Link: '{self.link}' , Report_gen: '{self.report_gen}' )"
		
		

class Submitted_attendance(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	student_id = db.Column(db.Integer, db.ForeignKey('student.id'))	
	material_id = db.Column(db.Integer, db.ForeignKey('material.id'))
	submitted = db.Column(db.String, nullable=True)

	def __repr__(self):
		return f"Attendence (Student ID: '{self.student_id}', Material ID: '{self.material_id}', Status: '{self.submitted}' )"
    	


