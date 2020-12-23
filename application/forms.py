from flask_wtf import FlaskForm
from wtforms import StringField, DateField, PasswordField, SubmitField, BooleanField, SelectField, IntegerField,FieldList,FormField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from wtforms.fields.html5 import TelField, DateField, DateTimeLocalField, DateTimeField, TimeField
from flask_wtf.file import FileField, FileAllowed, FileRequired
import phonenumbers
from application.tables import *
from wtforms_sqlalchemy.fields import QuerySelectField
from flask_login import UserMixin,login_user, current_user, logout_user, login_required
import application.routes


class LoginForm(FlaskForm):
    username = StringField('Username:', validators=[DataRequired(), Length(min=11, max=50), Email()])
    password = PasswordField('Password:', validators=[DataRequired()])
    captcha = StringField('Captcha:', validators=[DataRequired()])
    submit = SubmitField('Login')


class RegistrationForm(FlaskForm):
    first_name = StringField('First Name:', validators=[DataRequired()])
    last_name = StringField('Last Name:', validators=[DataRequired()])
    phone_number = StringField('Phone Number:', validators=[DataRequired()])
    dob = DateField('Date of Birth:', validators=[DataRequired()], format='%Y-%m-%d')
    gender = SelectField('Gender:', choices=[('Male','Male'),('Female','Female'),('Transgender','Transgender'),('Rather not say','Rather not say')])
    username = StringField('Username(Email):', validators=[DataRequired(), Length(min=11, max=50), Email()])
    submit = SubmitField('Register')
    def validate_username(self, username):
        user = User.query.filter_by(email=username.data).first()
        if user:
            raise ValidationError('User already registered')
    
    def validate_phone_number(self, phone_number):
        try:
            val = int(phone_number.data)
        except ValueError:
            raise ValidationError('Invalid Phone Number')
        else:
            if len(str(phone_number.data)) != 10:
                raise ValidationError('Invalid phone number')

    def validate_dob(self, dob):
        if dob.data > datetime.date(datetime.now()):
            raise ValidationError('Invalid DOB')




class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')



class PrincipalForm(FlaskForm):
    role = SelectField('Role  :', choices=[('Principal', 'Principal'), ('Teacher', 'Teacher')])
    submit = SubmitField('OK')



class UpdateAccountForm(FlaskForm):
    first_name = StringField('First Name:', validators=[DataRequired()])
    last_name = StringField('Last Name:', validators=[DataRequired()])
    phone_number = IntegerField('Phone Number:', validators=[DataRequired()])
    dob = DateField('Date of Birth:', validators=[DataRequired()], format='%Y-%m-%d')
    gender = SelectField('Gender:', choices=[('Male','Male'),('Female','Female'),('Transgender','Transgender'),('Rather not say','Rather not say')])
    submit = SubmitField('Update')

    
    def validate_phone_number(self, phone_number):
        if len(str(phone_number.data)) != 10:
            raise ValidationError('Invalid phone number')

    def validate_dob(self, dob):
        if dob.data > datetime.date(datetime.now()):
            raise ValidationError('Invalid DOB')



class EditUserForm(FlaskForm):
    first_name = StringField('First Name:', validators=[DataRequired()])
    last_name = StringField('Last Name:', validators=[DataRequired()])
    username = StringField('Username(Email):', validators=[DataRequired(), Length(min=11, max=50), Email()])
    phone_number = IntegerField('Phone Number:', validators=[DataRequired()])
    dob = DateField('Date of Birth:', validators=[DataRequired()], format='%Y-%m-%d')
    gender = SelectField('Gender:', choices=[('Male','Male'),('Female','Female'),('Transgender','Transgender'),('Rather not say','Rather not say')])
    submit = SubmitField('Update')

    
    def validate_phone_number(self, phone_number):
        if len(str(phone_number.data)) != 10:
            raise ValidationError('Invalid phone number')

    def validate_dob(self, dob):
        if dob.data > datetime.date(datetime.now()):
            raise ValidationError('Invalid DOB')

class ChangePassword(FlaskForm):
    old_password = PasswordField('Old Password:', validators=[DataRequired()])
    new_password = PasswordField('New Password:', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password:', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')



class UploadForm(FlaskForm):
    input_file = FileField('Choose File :', validators=[FileRequired(), FileAllowed(['csv'], 'CSV File Only')])
    upload = SubmitField('Upload File')


class ClassForm(FlaskForm):
    grade_opts = SelectField('Grade :', choices =[])
    submit = SubmitField('GO')

class SectionForm(FlaskForm):
    section = StringField('Section :', validators=[DataRequired()])
    submit = SubmitField('Submit')

def class_teacher_query():
    return Teacher.query.filter_by(is_ct = False)


class ClassTeacherForm(FlaskForm):
    class_teacher_opts = SelectField('Teacher :', choices = [] )
    submit = SubmitField('Submit')

class AddSubjectMasterForm(FlaskForm):
    code = StringField('Code:', validators=[DataRequired()])
    name = StringField('Name:', validators=[DataRequired()])
    description = StringField('Description:', validators=[DataRequired()])
    submit = SubmitField('Submit')
     


class EditSubjectMasterForm(FlaskForm):
    name = StringField('Name:', validators=[DataRequired()])
    description = StringField('Description:', validators=[DataRequired()])
    submit = SubmitField('Submit')
    
class SelectGradeSection(FlaskForm):
    class_opts =  SelectField('Class :', choices=[])
    submit = SubmitField('Submit')

def core_query():
    return Subject_master.query.filter_by(description = 'CORE').all()

def first_language_query():
    return Subject_master.query.filter_by(description = 'FIRST LANGUAGE').all()

def second_language_query():
    return Subject_master.query.filter_by(description = 'SECOND LANGUAGE').all()

def third_language_query():
    return Subject_master.query.filter_by(description = 'THIRD LANGUAGE').all()

def elective_query():
    return Subject_master.query.filter_by(description = 'ELECTIVE').all()


class RegisterSubjectsForm(FlaskForm):
    core1 = QuerySelectField('Core 1:', query_factory = core_query, allow_blank=True, get_label = 'name')
    core2 = QuerySelectField('Core 2:', query_factory = core_query, allow_blank=True, get_label = 'name')
    core3 = QuerySelectField('Core 3:', query_factory = core_query, allow_blank=True, get_label = 'name')
    first_lang = QuerySelectField('First Language:', query_factory = first_language_query, allow_blank=True, get_label = 'name')
    second_lang1 = QuerySelectField('Second Language 1:', query_factory = second_language_query, allow_blank=True, get_label = 'name')
    second_lang2 = QuerySelectField('Second Language 2:', query_factory = second_language_query, allow_blank=True, get_label = 'name')
    second_lang3 = QuerySelectField('Second Language 3:', query_factory = second_language_query, allow_blank=True, get_label = 'name')
    third_lang1 = QuerySelectField('Third Language 1:', query_factory = third_language_query, allow_blank=True, get_label = 'name')
    third_lang2 = QuerySelectField('Third Language 2:', query_factory = third_language_query, allow_blank=True, get_label = 'name')
    third_lang3 = QuerySelectField('Third Language 3:', query_factory = third_language_query, allow_blank=True, get_label = 'name')
    elective1 = QuerySelectField('Elective1:', query_factory = elective_query, allow_blank=True, get_label = 'name') 
    elective2 = QuerySelectField('Elective2:', query_factory = elective_query, allow_blank=True, get_label = 'name') 
    submit = SubmitField('Submit')  


class AddClassSubject(FlaskForm):
    description = SelectField('Description:', choices=[])
    name = SelectField('Name:', choices=[])
    submit = SubmitField('Submit') 

    
def teacher_query():
    return Teacher.query

class UpdateSubjectTeacherForm(FlaskForm):
    teacher = QuerySelectField('Select:',query_factory = teacher_query,allow_blank=True)
    submit = SubmitField('Submit') 

class AddSubjectTeacherForm(FlaskForm):
    subject = SelectField('Subject: ', choices=[])
    teacher = QuerySelectField('Teacher:',query_factory = teacher_query,allow_blank=True)
    submit = SubmitField('Submit') 


class EditStudentSubjectForm(FlaskForm):
    email = StringField('Email:', validators=[DataRequired()])
    second_lang = SelectField('Second Language: ', choices =[])
    third_lang = SelectField('Third Language: ', choices =[])
    elective = SelectField('Elective: ', choices =[])
    submit = SubmitField('Submit') 


class ViewSubjectStudents(FlaskForm):
    class_opts =  SelectField('Class :', choices=[])
    subject_opts = SelectField('Subject:', choices=[])


class MaterialForm(FlaskForm):
    class_opts =  SelectField('Class:', choices=[])
    subject_opts = SelectField('Subject:', choices=[])
    name = StringField('Enter link name:', validators=[DataRequired()])
    link = StringField('Enter drive link:', validators=[DataRequired()])
    start_date = DateField('Start date:', validators=[DataRequired()], format='%Y-%m-%d')
    start_time = TimeField('Start time:', validators=[DataRequired()])
    end_date = DateField('End date:', validators=[DataRequired()], format='%Y-%m-%d')
    end_time = TimeField('End time:', validators=[DataRequired()])

class StudyMaterialForm(FlaskForm):
    class_opts =  SelectField('Class:', choices=[])
    subject_opts = SelectField('Subject:', choices=[])
    name = StringField('Enter link name:', validators=[DataRequired()])
    link = StringField('Enter drive link:', validators=[DataRequired()])
    
class ViewMaterialsForm(FlaskForm):
    class_opts =  SelectField('Class:', choices=[])
    subject_opts = SelectField('Subject:', choices=[])
    submit = SubmitField('Submit')

class UpdateMaterialsForm(FlaskForm):
    name = StringField('Material name:', validators=[DataRequired()])
    link = StringField('Drive link:', validators=[DataRequired()])
    start_date = DateField('Start date:', validators=[DataRequired()], format='%Y-%m-%d')
    start_time = TimeField('Start time:', validators=[DataRequired()])
    end_date = DateField('End date:', validators=[DataRequired()], format='%Y-%m-%d')
    end_time = TimeField('End time:', validators=[DataRequired()])
    submit = SubmitField('Submit')

class UpdateStudyMaterialsForm(FlaskForm):
    name = StringField('Enter link name:', validators=[DataRequired()])
    link = StringField('Enter drive link:', validators=[DataRequired()])
    submit = SubmitField('Submit')

class SelectRole(FlaskForm):
    role_opts = SelectField('Role:',choices=[(0,'--Select--'), ('Principal','Principal'),('Teacher','Teacher')])
    person_opts = SelectField('User:',choices=[])
    submit = SubmitField('GO')


class StudentSubjects(FlaskForm):
    subject_opts = SelectField('Subject :', choices=[])

class LinkSubmission(FlaskForm):
    link = StringField('Enter drive link:', validators=[DataRequired()])
    submit = SubmitField('Submit')

class AddOnlineClass(FlaskForm):
    class_opts =  SelectField('Class:', choices=[])
    subject_opts = SelectField('Subject:', choices=[])
    link = StringField('Meeting link:', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ViewSubmissionsForm(FlaskForm):
    class_opts =  SelectField('Class:', choices=[])
    subject_opts = SelectField('Subject:', choices=[])
    name_opts = SelectField('Name:', choices=[])
    submit = SubmitField('Submit')

class MailForm(FlaskForm):
    message = TextAreaField('Message:', validators=[DataRequired()])
    submit = SubmitField('Mail')