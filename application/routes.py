from application import app, db, bcrypt, captcha, mail
from application.forms import *
from application.tables import *
from flask import Flask, render_template, url_for, flash, redirect, request,session, make_response, jsonify
from flask_login import UserMixin,login_user, current_user, logout_user, login_required
from flask_mail import Message

from datetime import datetime
from io import TextIOWrapper
import csv
import pandas as pd
import string
import webbrowser 
import pdfkit

from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm.exc import UnmappedInstanceError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func



# hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
# user = User(email = "shikshanoreply@gmail.com", role = 'Super User', password=hashed_password)
#db.session.add(user)
# db.session.commit()

# ---------------------------------------SIGN IN-----------------------------------------------------------------
@app.route("/")
def home():    
    return redirect(url_for('login'))


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():            
        user = User.query.filter_by(email = form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if captcha.validate():
                user_role = user.role
                login_user(user, remember=1)
                if user_role == 'Student':
                    return redirect(url_for('student', personid = user.id))
                elif user_role == 'Teacher':
                    return redirect(url_for('teacher', personid = user.id))
                elif user_role == 'Principal':
                    return redirect(url_for('principal_select_role', personid = user.id))
                elif user_role == 'Super User':
                    return redirect(url_for('super_user', personid = user.id))
            else:
                flash('Invalid Captcha', 'danger')
                return render_template('login.html', title='Login', form=form)
        else:
            flash('Login Unsuccessful. Please check the login credentials', 'danger')
            return render_template('login.html', title='Login', form=form)
    return render_template('login.html', title='Login', form=form)

@app.route("/welcome")
@login_required
def welcome():
    if current_user.role == 'Principal':
        return redirect(url_for('principal_select_role', personid = current_user.id))
    elif current_user.role == 'Teacher':
        return redirect(url_for('teacher', personid = current_user.id))
    elif current_user.role == 'Student':
        return redirect(url_for('student', personid = current_user.id))
    elif current_user.role == 'Super User':
        return redirect(url_for('super_user', personid = current_user.id))


# --------------------------------------------------------USERs HOME PAGE-----------------------------------------------------------------------
@app.route("/principal_select_role/<personid>", methods=['GET', 'POST'])
@login_required
def principal_select_role(personid):   
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        form = PrincipalForm() 
        if form.validate_on_submit():
            role = request.form.get('role')
            if role == 'Teacher':
                return redirect(url_for('teacher', personid=personid))
            elif role == 'Principal':
                return redirect(url_for('principal', personid=personid))
        return render_template('principal_select_role.html', title='Login', form=form) 
    else:
        return render_template('error.html', title='Error Page')




@app.route("/principal/<personid>")
@login_required
def principal(personid):    
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        principal = Principal.query.filter_by(user_id = personid).first()
        s = str(principal.first_name) + " " + str(principal.last_name)
        return render_template('principal.html', title='Principal', s = s)
    else:
        return render_template('error.html', title='Error Page')


@app.route("/teacher/<personid>")
@login_required
def teacher(personid):  
    if ((current_user.role == "Teacher") or (current_user.role == "Principal") or (current_user.role == 'Super User')) :
        teacher = Teacher.query.filter_by(user_id=personid).first()
        class_ = Class.query.filter_by(class_teacher = teacher.id).first()
        s = str(teacher.first_name) + " " + str(teacher.last_name)
        if teacher.is_ct:
            s1 = str(class_.grade) + " - " + str(class_.section)
        else:
            s1= 0

        return render_template('teacher.html', title='Teacher', t_ct = teacher.is_ct, personid=personid, s=s, s1=s1)
    else:
        return render_template('error.html', title='Error Page')


@app.route("/student/<personid>")
@login_required
def student(personid):    
    if ((current_user.role == "Student") or (current_user.role == "Super User")) :
        student = Student.query.filter_by(user_id=personid).first()
        class_ = Class.query.filter_by(id = student.class_id).first()
        s = str(student.first_name) + " " + str(student.last_name)
        s1 = str(class_.grade) + " - " + str(class_.section)
        return render_template('student.html', title='Student', s=s, s1=s1)
    else:
        return render_template('error.html', title='Error Page')



@app.route("/super_user")
@login_required
def super_user():
    if current_user.role == 'Super User':
        return render_template('super_user.html', title='Super User')







# ---------------------------------------RESET PASSWORD---------------------------------------------------------
def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='shikshanoreply@gmail.com', recipients=[user.email])
    msg.body = f'''Hello!
    
Greetings from team Shiksha!

According to the request made from your account with email id(username) {user.email}, we are processing your request for a change in passwod.
    
To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}


If you did not make this request, then simply ignore this email and no change will be made to your account details! :)

NOTE: This email was sent from a notification-only address that cannot accept incoming email. Please do not reply to this message.
 '''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        flash('You are already logged in. Kindly logout and then access forgot password.','info')
        return redirect(url_for('welcome'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
            flash('An email has been sent with instructions to reset your password','info')
            return redirect(url_for('login'))
        else:
            flash('This email id has not been registered. Enter valid mail id.','danger')
            return redirect(url_for('reset_request'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        flash('You are already logged in. Kindly logout and then access forgot password.','info')
        return redirect(url_for('welcome'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token','warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to login', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)








# ---------------------------------------------PRINCIPAL-------------------------------------------------------
# ---------------------------------------REGISTER FROM PRINCIPAL BULK USERS---------------------------------------------------------
def send_registered_email(user, role):
    subj = "Invitation to join Shiksha"
    msg = Message(subj, sender='shikshanoreply@gmail.com', recipients=[user.email])
    msg.body = f'''Hello!

Greetings from the team of Shiksha!

We’re happy to welcome you to Shiksha, your friendly assistant for managing classes online.

In this regard, we would like to inform you that you have been registered as a {role} to enjoy our services.
Given below are your login details:
username: {user.email}
password: password
(NOTE: The default password for your account has been set as 'password'. Kindly login and change the password from the 'Account' page in order to ensure safety and privacy of your account)

Hope you enjoy your journey with us! :)

NOTE: This email was sent from a notification-only address that cannot accept incoming email. Please do not reply to this message.'''
    #mail.send(msg)
    print(msg)


def check_phno_principal(data):
    count = 0
    for i in data.index:
        if len(str(data['Phone Number'][i])) != 10:
            count = count + 1
            data['Phone Status'][i] = 'Phone Length Number Error'
        try:
            val = int(data['Phone Number'][i])
        except ValueError:
            count = count + 1
            data['Phone Status'][i] = 'Invalid Phone Number'
    return count

def check_username_principal(data):
    count = 0
    username = User.query.with_entities(User.email).all()
    username_list = [value for (value,) in username]
    email = list(data['Username'])
    
    # Check with existing users
    for i in range(len(email)):
        if email[i] in username_list:
            data['Email Status'][i] = 'Username Already Taken'
            count = count + 1

    # Check within given file
    email_set = set()
    for i in range(len(email)):
        if email[i] in email_set:
            data['Email Status'][i] = 'Username Already Taken'
            count = count + 1
        else:
            email_set.add(email[i])
    
    return count

def check_dob(data):
    count = 0
    for i in data.index:
        date = data['DOB'][i]
        date_format = '%Y-%m-%d'
        try:
            dob = datetime.strptime(date, date_format)
        except ValueError:
            data['DOB Status'][i] = 'Invalid data format'
            count += 1
    return count

def insert_teachers(data):
    for i in data.index:
        hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
        user = User(email=data['Username'][i], password=hashed_password, role='Teacher')
        db.session.add(user)

        user = User.query.filter_by(email = data['Username'][i]).first()
        user_id = user.id
        teacher = Teacher(first_name = data['First Name'][i], last_name = data['Last Name'][i], gender = data['Gender'][i], phone = int(data['Phone Number'][i]), dob = datetime.strptime((data['DOB'][i]),"%Y-%m-%d"), user_id = user_id, is_ct=False)
        send_registered_email(user,user.role)
        db.session.add(teacher)
        db.session.commit()


@app.route('/upload_teachers', methods=['GET', 'POST'])
@login_required
def upload_teachers():
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        instructions = 'First Name,Last Name,Phone Number,DOB,Username,Gender'
        form = UploadForm()
        if form.validate_on_submit():
            try:
                input_data = pd.read_csv(request.files['input_file'])
                output_data = input_data.copy()
                output_data['Phone Status'] = 'OK'
                output_data['Email Status'] = 'OK'
            except pd.errors.ParserError:
                flash('There are errors in the file. Please try again', 'danger')
                return redirect(url_for('upload_teachers')) 
            else:
                error_count = 0
                cols = list(input_data.columns)
                if (len(cols) != 6):
                    flash('The file does not match the given template. Please try again', 'danger')
                    return redirect(url_for('upload_teachers'))
                if input_data.isnull().values.any():
                    flash('Please fill in all the fields', 'danger')
                    return redirect(url_for('upload_teachers'))
                if (check_phno_principal(output_data)):
                    error_count = error_count + 1
                if (check_username_principal(output_data)):
                    error_count = error_count + 1
                if check_dob(output_data):
                    error_count += 1
                if error_count > 0:
                    # give file
                    errors = output_data.to_csv(index=False)
                    errors = str(errors)
                    response = make_response(errors)
                    cd = 'attachment; filename=error_file.csv'
                    response.headers['Content-Disposition'] = cd 
                    response.mimetype='text/csv' 
                    return response
                    
                else:
                    insert_teachers(input_data)
                    flash('Teachers have been registered!', 'success')
                    return redirect(url_for('manage_teachers'))   
        return render_template('upload.html', instructions = instructions , title='Upload Teachers', form=form)
    else:
        return render_template('error.html', title='Error Page')





# ---------------------------------------MANAGE TEACHERS---------------------------------------------------------
@app.route("/manage_teachers")
def manage_teachers():
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        teachers_list = []
        teachers = Teacher.query.all()
        for i in teachers:
            principal = Principal.query.filter_by(user_id = i.user_id).first()
            if not (principal):
                teachers_list.append(i)

        return render_template('manage_teachers.html', title='Teacher Details', teachers=teachers_list)
    else:
        return render_template('error.html', title='Error Page')



# -------------------------------------------------ADD TEACHER-------------------------------------------------
@app.route("/add_teacher", methods=['GET', 'POST'])
@login_required
def add_teacher():
    if (current_user.role == "Principal" or current_user.role == "Super User") :
        form = RegistrationForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
            user = User(email = form.username.data, role = 'Teacher', password=hashed_password)
            db.session.add(user)
            db.session.commit()
            user = User.query.filter_by(email = form.username.data).first()
            user_id = user.id
            teacher = Teacher(first_name = form.first_name.data, last_name = form.last_name.data, phone = form.phone_number.data, dob = form.dob.data, user_id = user_id, is_ct=False, gender = form.gender.data)
            send_registered_email(user,user.role)
            db.session.add(teacher)
            db.session.commit()
            
            flash('Teacher has been added', 'success')
            return redirect(url_for('manage_teachers'))
        return render_template('register.html', title='Add Teacher', form=form)
    else:
        return render_template('error.html', title='Error Page')



# -------------------------------------------------EDIT TEACHER-------------------------------------------------
@app.route("/edit_teacher/<teacherid>", methods=['GET', 'POST'])
@login_required
def edit_teacher(teacherid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        teacher = Teacher.query.filter_by(id = teacherid).first()
        user = User.query.filter_by(id = teacher.user_id).first()
        form = EditUserForm()
        if form.validate_on_submit():
            email_checker = User.query.filter_by(email=form.username.data).first()
            if email_checker:
                if email_checker.email == user.email:
                    teacher.first_name = form.first_name.data
                    teacher.last_name = form.last_name.data
                    teacher.dob = form.dob.data
                    teacher.phone = form.phone_number.data
                    teacher.gender = form.gender.data
                    user.email = form.username.data
                    flash('Changes have been updated', 'success')
                else:
                    flash('Email id is already registered', 'danger')
                    return render_template('edit_teacher.html', title='Edit Teacher', form = form, teacherid = teacherid)
            else:
                teacher.first_name = form.first_name.data
                teacher.last_name = form.last_name.data
                teacher.dob = form.dob.data
                teacher.phone = form.phone_number.data
                teacher.gender = form.gender.data
                user.email = form.username.data
                flash('Changes have been updated', 'success')
        elif request.method == 'GET':
            form.username.data = user.email
            form.first_name.data = teacher.first_name
            form.last_name.data = teacher.last_name 
            form.dob.data = teacher.dob
            form.phone_number.data = teacher.phone
            form.gender.data = teacher.gender
        db.session.commit()
        return render_template('edit_teacher.html', title='Edit Teacher', form = form, teacherid = teacherid)   
    else:
        return render_template('error.html', title='Error Page')




#--------------------------------------------------PROMOTE AS PRINCIPAL----------------------------------------------------------------------
@app.route("/promote_as_principal/<teacherid>", methods=['GET', 'POST'])
@login_required
def promote_as_principal(teacherid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        teacher = Teacher.query.filter_by(id = teacherid).first()
        user = User.query.filter_by(id = teacher.user_id).first()
        principal_user = User.query.filter_by(role = 'Principal').first()
        principal = Principal.query.filter_by(user_id = principal_user.id).first()
        new_principal = Principal(first_name = teacher.first_name, last_name = teacher.last_name, user_id = teacher.user_id, dob = teacher.dob, gender = teacher.gender, phone = teacher.phone)
    
        user.role= "Principal"
        principal_user.role = 'Teacher'
        db.session.delete(principal)
        db.session.add(new_principal)
        
        db.session.commit()
        flash("You have been demoted as Teacher. Log in again to continue as Teacher",'info')
        return redirect(url_for('logout'))
    else:
        return render_template('error.html', title='Error Page')




# -------------------------------------------------DELETE TEACHER-------------------------------------------------
@app.route("/delete_teacher", methods=['POST','GET'])
@login_required
def delete_teacher():
    if request.method == 'POST':
        to_delete = request.form.getlist('mycheckbox')
        flag = 0
        for i in range(len(to_delete)):
            teacher_id = int(to_delete[i])
            teacher = Teacher.query.get_or_404(teacher_id)
            class_teacher = Class.query.filter_by(class_teacher = teacher_id).first()
            subject = Subject_handler.query.filter_by(teacher_id = teacher_id).first()
            name = str(teacher.first_name) + ' ' + str(teacher.last_name)

            if class_teacher is None and subject is None:
                user_id = teacher.teacher_user.id
                user = User.query.get_or_404(user_id)
                if user.role == 'Principal':
                    principal = Principal.query.filter_by(user_id = user.id).first()
                    db.session.delete(principal)
                    db.session.delete(teacher)
                    db.session.delete(user)
                    db.session.commit()
                    flag = 1
                else:
                    db.session.delete(teacher)
                    db.session.delete(user)
                    db.session.commit()
                string =  name + ' has been deleted'
                flash( string , 'success')    
            else:  
                if class_teacher is None:
                    string = name + ' is assigned to a subject. Please reassign before deleting.'
                    flash(string,'danger')
                else:
                    string =  name + '  is a class teacher. Please reassign before deleting.'
                    flash(string ,'danger')
        if flag == 1:
            return redirect(url_for('logout'))
    return redirect(url_for('manage_teachers'))








#--------------------------------------------------REGISTER CLASS----------------------------------------------------------------------
#---------------------------------------------BULK REGISTER CLASS-----------------------------------------------------------------------------------------
def check_class_bulk(data):
    count = 0
    file_grade = list(data['Grade'])
    file_section = list(data['Section'])
    
    # Check with existing classes
    for i in range(len(file_grade)):
        classes = Class.query.filter_by(grade = int(file_grade[i])).all()
        for j in classes:
            if j.section == file_section[i]:
                data['Class Status'][i] = 'Class Already Registered'
                count += 1
    
         
    #Check within same file
    class_set = set()
    for i in range(len(file_grade)):
        for j in range(i+1, len(file_grade)):
            if file_grade[i] == file_grade[j]:
                if file_section[i] == file_section[j]:
                    data['Class Status'][i] = 'DUPLICATES FOUND'
                    count = count + 1

    return count




def insert_class(data):
    for i in data.index:
        data['Section'][i] = str(data['Section'][i]).strip(' ')
        data['Section'][i] = str(data['Section'][i]).upper()
        class_ = Class(grade=int(data['Grade'][i]), section=str(data['Section'][i]), class_teacher=0)
        db.session.add(class_)
        db.session.commit()


@app.route('/upload_class', methods=['GET', 'POST'])
@login_required
def upload_class():
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        instructions = 'Grade,Section'
        form = UploadForm()
        if form.validate_on_submit():
            try:
                input_data = pd.read_csv(request.files['input_file'])
                output_data = input_data.copy()
                output_data['Class Status'] = 'OK'

            except pd.errors.ParserError:
                flash('There are errors in the file. Please try again', 'danger')
                return redirect(url_for('upload_class')) 
            else:
                error_count = 0
                cols = list(input_data.columns)
                if (len(cols) != 2):
                    flash('The file does not match the given template. Please try again', 'danger')
                    return redirect(url_for('upload_class'))
                if input_data.isnull().values.any():
                    flash('Please fill in all the fields', 'danger')
                    return redirect(url_for('upload_class'))
                if input_data['Grade'].dtypes != 'int64':
                    flash('Invalid Grade type', 'danger')
                    return redirect(url_for('upload_class'))
                
                if (check_class_bulk(output_data)):
                    error_count = error_count + 1

                if error_count > 0:
                    # give file
                    errors = output_data.to_csv(index=False)
                    errors = str(errors)
                    response = make_response(errors)
                    cd = 'attachment; filename=error_file.csv'
                    response.headers['Content-Disposition'] = cd 
                    response.mimetype='text/csv'
                    return response
                else:
                    insert_class(input_data)
                    flash('Classes have been registered!', 'success')
                    return redirect(url_for('manage_section'))   
        return render_template('upload.html', instructions = instructions , title='Upload Class', form=form)
    else:
        return render_template('error.html', title='Error Page')






#---------------------------------------------VIEW GRADE-----------------------------------------------------------------------------------
def make_sec_num(section_):
    for i in range(1,13):
        num = Class.query.filter_by(grade = i).count()
        section_.append(num)

@app.route("/view_grade", methods=['GET', 'POST'])
@login_required
def view_grade():
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        section_ = []
        num = 14
        classes = Class.query.all()
        make_sec_num(section_)
        return render_template('view_grade.html', title='View Grade', section_=section_, num=num, classes=classes)

    else:
        return render_template('error.html', title='Error Page')








#---------------------------------------------MANAGE SECTIONS-----------------------------------------------------------------------------------
@app.route("/manage_section", methods=['GET', 'POST'])
@login_required
def manage_section():
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        form = ClassForm()
        sections = 0
        class_query = Class.query.distinct(Class.grade).group_by(Class.grade).all()
        grade_list = [(0,'--Select--')]
        for i in class_query:
            one = (i.grade,i.grade)
            grade_list.append(one)

        form.grade_opts.choices = grade_list
        current_grade = 0
        if request.method=='POST':
            current_grade = form.grade_opts.data
            sections = Class.query.filter_by(grade = current_grade).order_by(Class.section.asc()).all()
            return render_template('manage_section.html', title='Teacher Details', form=form, sections = sections, current_grade = current_grade)
        elif request.method == "GET":
            form.grade_opts.data = str(current_grade)
        return render_template('manage_section.html', title='Teacher Details', form=form, sections = sections, current_grade = current_grade)
        
    else:
        return render_template('error.html', title='Error Page')


@app.route("/manage_sections/<grade>", methods=['GET', 'POST'])
@login_required
def manage_sections(grade):
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        form = ClassForm()
        class_query = Class.query.distinct(Class.grade).group_by(Class.grade)
        grade_list = []
        for i in class_query:
            one = (i.grade,i.grade)
            grade_list.append(one)
        form.grade_opts.choices = grade_list
        sections = Class.query.filter_by(grade = grade).order_by(Class.section.asc()).all()
        current_grade = grade
        if request.method=='POST':
            current_grade= form.grade_opts.data
            sections = Class.query.filter_by(grade = current_grade).order_by(Class.section.asc()).all()
        elif request.method == "GET":
            form.grade_opts.data = str(grade)
        return render_template('manage_section.html', title='Teacher Details', form=form, sections = sections, current_grade = current_grade)
    else:
        return render_template('error.html', title='Error Page')



#---------------------------------------------ADD SECTION-----------------------------------------------------------------------------------
@app.route("/add_section/<current_grade>", methods=['GET', 'POST'])
@login_required
def add_section(current_grade):
    if (current_user.role == "Principal" or current_user.role == "Super User"):
        form = SectionForm()
        error = 0
        if form.validate_on_submit():
            section = form.section.data
            section = section.strip(' ')
            section = section.upper()
            classes = Class.query.filter_by(grade = current_grade).all()
            for i in classes:
                if (i.section == section):
                    error = 1
                    flash("Section already exists.", 'danger')
                    return redirect(url_for('add_section', current_grade = current_grade))
            if error == 0:
                new_class = Class(grade = current_grade, section = section, class_teacher = 0)
                db.session.add(new_class)
                db.session.commit()
                flash("Section added!", 'success')
                return redirect(url_for('manage_sections', grade = current_grade))
        return render_template('add_section.html', title='Add Class', form=form, current_grade=current_grade)
    else:
        return render_template('error.html', title='Error Page')


#---------------------------------------------EDIT SECTION-------------------------------------------------------------------------------------
@app.route("/edit_section/<classid>", methods=['GET', 'POST'])
@login_required
def edit_section(classid):
    if (current_user.role == "Principal" or current_user.role == "Super User"):
        class_ = Class.query.filter_by(id = classid).first()
        form = SectionForm()
        error = 0
        if form.validate_on_submit():
            section = form.section.data
            section = section.strip(' ')
            section = section.upper()
            classes = Class.query.filter_by(grade = class_.grade).all()
            for i in classes:
                if (i.section == section):
                    if (class_.section != section):
                        error = 1
                        flash("Section already exists.", 'danger')
                        return redirect(url_for('edit_section', classid=class_.id))
                if error == 0:
                    class_.section = section
                    db.session.commit()
                    flash("Section added!", 'success')
                    return redirect(url_for('manage_sections', grade = class_.grade))
        elif request.method == 'GET':
            form.section.data = class_.section
        return render_template('add_section.html', title='Edit Class', form=form, current_grade=class_.grade)
    else:
        return render_template('error.html', title='Error Page')



#---------------------------------------------DELETE SECTION-------------------------------------------------------------------------------------
@app.route("/delete_section/<current_grade>", methods=['POST','GET'])
@login_required
def delete_section(current_grade):
    if (current_user.role == "Principal" or current_user.role == "Super User"):
    #  delete all dependendcies
        
        delete_class = Class.query.filter_by(grade = current_grade).order_by(Class.section.desc()).first()
        students = Student.query.filter_by(class_id = delete_class.id).all()
        if not students:
            subjects = Subjects.query.filter_by(class_id = delete_class.id).first()
            if subjects:
                db.session.delete(subjects)
                sub_hand = Subject_handler.query.filter_by(class_id = delete_class.id).all()
                for i in sub_hand:
                    db.session.delete(i)
            if delete_class.class_teacher:
                ct = Teacher.query.filter_by(id = delete_class.class_teacher).first()
                ct.is_ct = 0
            
            db.session.delete(delete_class)
            db.session.commit()
            name = str(current_grade) + ' - ' + str(delete_class.section)
            message = name +" has been deleted!"
            flash(message ,'success')
        else:
            name = str(current_grade) + ' - ' + str(delete_class.section)
            message = "There are students registered to " +  name
            flash( message,'danger')
        return redirect(url_for('manage_sections', grade = current_grade))
    else:
        return render_template('error.html', title='Error Page')







#------------------------------------------------------BULK UPLOAD CLASS TEACHERS-----------------------------------------------------------------

def check_class_teacher_bulk(data):

    count = 0
    file_grade = list(data['Grade'])
    file_section = list(data['Section'])
    file_ct_username = list(data['Class Teacher Username'])

    #Check if all the classes are valid
    #Check if those classes already have teachers
    for i in range(len(file_grade)):
        file_section[i] = str(file_section[i]).strip(' ')
        file_section[i] = file_section[i].upper()
        current_class = Class.query.filter_by(grade=int(file_grade[i]), section=file_section[i]).first()
        if current_class:
            user = User.query.filter_by(email = data['Class Teacher Username'][i]).first()
            if user is None:
                data['Status'][i] = 'Class Teacher Not Registered'
                count+=1
            else:    
                
                current_class_teacher = Teacher.query.filter_by(user_id = user.id).first()
                current_class_teacher_id = current_class_teacher.id

                if current_class_teacher.is_ct == True:
                    data['Status'][i] = 'Teacher is already a Class Teacher'
                    count = count + 1

                '''assigned_class_teachers = Class.query.with_entities(Class.class_teacher).all()
                assigned_class_teachers_list = [value for (value,) in assigned_class_teachers]
                remaining_teachers = Teacher.query.with_entities(Teacher.id).filter(~Teacher.id.in_(assigned_class_teachers_list)).all()
                remaining_teachers_list = [value for (value,) in remaining_teachers]

                if(current_class_teacher_id not in remaining_teachers_list):
                    data['Status'][i] = 'Teacher is already a Class Teacher'
                    count+=1'''
                   
        else:
            data['Status'][i] = 'Class Not Registered'
            count+=1

    #Check if they are teacher or principal
    for i in range(len(file_grade)):
        user = User.query.filter_by(email=file_ct_username[i]).first()
        if user:
            if user.role != 'Teacher' and user.role != 'Principal':
                data['Status'][i] = 'Class Teacher Username Does Not Belong To Teacher Or Principal'
                count+=1

    #Check class within same file
    class_set = set()
    for i in range(len(file_grade)):
        for j in range(i+1, len(file_grade)):
            if file_grade[i] == file_grade[j]:
                if file_section[i] == file_section[j]:
                    data['Status'][i] = 'Class Duplicates Found'
                    count = count + 1    

    #Check teacher within same file
    teacher_set = set()
    for i in range(len(file_grade)):
        for j in range(i+1, len(file_grade)):
            if file_ct_username[i] == file_ct_username[j]:  
                data['Status'][i] = 'Teacher Duplicates Found'
                count = count + 1  

    return count



def insert_class_teacher(data):
    file_grade = list(data['Grade'])
    file_section = list(data['Section'])
    file_ct_username = list(data['Class Teacher Username'])

    for i in data.index:
        data['Section'][i] = str(data['Section'][i]).strip(' ')
        data['Section'][i] = data['Section'][i].upper()
        user = User.query.filter_by(email = data['Class Teacher Username'][i]).first()
        
        assigned_class_teachers = Class.query.with_entities(Class.class_teacher).all()
        assigned_class_teachers_list = [value for (value,) in assigned_class_teachers]
        
        remaining_teachers = Teacher.query.with_entities(Teacher.id).filter(~Teacher.id.in_(assigned_class_teachers_list)).all()
    
        remaining_teachers_list = [value for (value,) in remaining_teachers]

        teacher = Teacher.query.filter_by(user_id = user.id).first()
        current_class_teacher = teacher.id

        
        if(current_class_teacher in remaining_teachers_list):
            current_class = Class.query.filter_by(grade=int(file_grade[i]), section=file_section[i]).first()
            if(current_class.class_teacher == 0):
                print("hi1")
                current_class.class_teacher = current_class_teacher
                teacher.is_ct = True
            else:
                print("hi2")
                old_class_teacher_id  = current_class.class_teacher
                old_class_teacher = Teacher.query.filter_by(id = old_class_teacher_id).first()
                old_class_teacher.is_ct = False
                current_class.class_teacher = current_class_teacher
                teacher.is_ct = True
            db.session.commit()


@app.route('/upload_class_teacher', methods=['GET', 'POST'])
@login_required
def upload_class_teacher():
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        instructions = "Grade,Section,Class Teacher Username"
        form = UploadForm()
        if form.validate_on_submit():
            try:
                input_data = pd.read_csv(request.files['input_file'])
                output_data = input_data.copy()
                output_data['Status'] = 'OK'

            except pd.errors.ParserError:
                flash('There are errors in the file. Please try again', 'danger')
                return redirect(url_for('upload_class_teacher')) 
            else:
                error_count = 0
                cols = list(input_data.columns)
                if (len(cols) != 3):
                    flash('The file does not match the given template. Please try again', 'danger')
                    return redirect(url_for('upload_class_teacher'))
                
                if input_data.isnull().values.any():
                    flash('Please fill in all the fields', 'danger')
                    return redirect(url_for('upload_class_teacher'))
                
                if input_data['Grade'].dtypes != 'int64':
                    flash('Invalid Grade type', 'danger')
                    return redirect(url_for('upload_class_teacher'))
                
                if (check_class_teacher_bulk(output_data)):
                    error_count = error_count + 1

                if error_count > 0:
                    # give file
                    errors = output_data.to_csv(index=False)
                    errors = str(errors)
                    response = make_response(errors)
                    cd = 'attachment; filename=error_file.csv'
                    response.headers['Content-Disposition'] = cd 
                    response.mimetype='text/csv'
                    return response
                else:
                    insert_class_teacher(input_data)
                    flash('Class Teachers have been registered!', 'success')
                    return redirect(url_for('upload_class_teacher'))   
        return render_template('upload.html', instructions = instructions , title='Upload Class Teacher', form=form)
    else:
        return render_template('error.html', title='Error Page')



#------------------------------------------------------MANAGE CLASS TEACHERS-----------------------------------------------------------------
@app.route("/manage_class_teacher", methods=['GET', 'POST'])
@login_required
def manage_class_teacher():
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        form = ClassForm()
        sections = ''
        current_grade = ''
    
        class_query = Class.query.distinct(Class.grade).group_by(Class.grade).all()
        grade_list = [(0,'--Select--')]
        for i in class_query:
            one = (i.grade,i.grade)
            grade_list.append(one)

        form.grade_opts.choices = grade_list

        class_teacher_username = []
        class_teachers = []
        if request.method=='POST':
            current_grade = form.grade_opts.data
            sections = Class.query.filter_by(grade = current_grade).order_by(Class.section.asc()).all()
            for section in sections:
                class_ = Class.query.filter_by(grade = current_grade, section=section.section).first()
                teacher_id = class_.class_teacher
                if not teacher_id :
                    class_teachers.append('-')
                    class_teacher_username.append('-')
                else:
                    teacher = Teacher.query.filter_by(id=teacher_id).first()
                    first_name = teacher.first_name
                    last_name = teacher.last_name
                    name = first_name + ' ' + last_name
                    class_teachers.append(name)
                    user_id = teacher.user_id
                    user = User.query.filter_by(id=user_id).first()
                    class_teacher_username.append(user.email)
            return render_template('manage_class_teacher.html', title='Class Teacher Details',length = len(sections), form=form, sections = sections, grade = current_grade, class_teachers=class_teachers, class_teacher_username=class_teacher_username)
        else:
            return render_template('manage_class_teacher.html', title='Class Teacher Details',length = 0, form=form, sections = 0, grade = 0, class_teachers=0, class_teacher_username=0)
    else:
        return render_template('error.html', title='Error Page')




@app.route("/manage_class_teachers/<grade>", methods=['GET', 'POST'])
@login_required
def manage_class_teachers(grade):
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        form = ClassForm()
        sections = ''
        current_grade = ''
    
        class_query = Class.query.distinct(Class.grade).group_by(Class.grade).all()
        grade_list = [(0,'--Select--')]
        for i in class_query:
            one = (i.grade,i.grade)
            grade_list.append(one)

        form.grade_opts.choices = grade_list

        class_teacher_username = []
        class_teachers = []
        sections = Class.query.filter_by(grade = grade).order_by(Class.section.asc()).all()
        for section in sections:
            class_ = Class.query.filter_by(grade = grade, section=section.section).first()
            teacher_id = class_.class_teacher
            if not teacher_id :
                class_teachers.append('-')
                class_teacher_username.append('-')
            else:
                teacher = Teacher.query.filter_by(id=teacher_id).first()
                first_name = teacher.first_name
                last_name = teacher.last_name
                name = first_name + ' ' + last_name
                class_teachers.append(name)
                user_id = teacher.user_id
                user = User.query.filter_by(id=user_id).first()
                class_teacher_username.append(user.email)
            
        if request.method=='POST':
            class_teacher_username = []
            class_teachers = []
            current_grade = form.grade_opts.data
            sections = Class.query.filter_by(grade = current_grade).order_by(Class.section.asc()).all()
            for section in sections:
                class_ = Class.query.filter_by(grade = current_grade, section=section.section).first()
                teacher_id = class_.class_teacher
                if not teacher_id :
                    class_teachers.append('-')
                    class_teacher_username.append('-')
                else:
                    teacher = Teacher.query.filter_by(id=teacher_id).first()
                    first_name = teacher.first_name
                    last_name = teacher.last_name
                    name = first_name + ' ' + last_name
                    class_teachers.append(name)
                    user_id = teacher.user_id
                    user = User.query.filter_by(id=user_id).first()
                    class_teacher_username.append(user.email)
            return render_template('manage_class_teacher.html', title='Class Teacher Details',length = len(sections), form=form, sections = sections, grade = current_grade, class_teachers=class_teachers, class_teacher_username=class_teacher_username)
        elif  request.method == 'GET':
            form.grade_opts.data = str(grade)
            return render_template('manage_class_teacher.html', title='Class Teacher Details',length = len(sections), form=form, sections = sections, grade = grade, class_teachers=class_teachers, class_teacher_username=class_teacher_username)
    else:
        return render_template('error.html', title='Error Page')






#---------------------------------------------EDIT CLASS TEACHER-------------------------------------------------------------------------------------
@app.route("/edit_class_teacher/<classid>", methods=['GET', 'POST'])
@login_required
def edit_class_teacher(classid):
    if (current_user.role == "Principal" or current_user.role == "Super User"):
        form = ClassTeacherForm()
        class_teacher_list =[(0,"--Select--")]
        teachers = Teacher.query.filter_by(is_ct = False).all()
        for i in teachers:
            one = (i.id , str(i.first_name) + ' ' + str(i.last_name))
            if one not in class_teacher_list:
                class_teacher_list.append(one)
        form.class_teacher_opts.choices = class_teacher_list
        class_ = Class.query.filter_by(id = classid).first()
        
        if class_.class_teacher != 0:
            current_class_teacher = Teacher.query.filter_by(id = class_.class_teacher).first()
        else:
            current_class_teacher = 0

        if request.method == 'POST':
            if form.class_teacher_opts.data != '0':
                if current_class_teacher: 
                    current_class_teacher.is_ct = False
                new_class_teacher_id = form.class_teacher_opts.data
                new_class_teacher = Teacher.query.filter_by(id = new_class_teacher_id).first()
                new_class_teacher.is_ct = True
                class_.class_teacher = new_class_teacher_id
                db.session.commit()
                flash("Class teacher updated!", 'success')
                return redirect(url_for('manage_class_teachers', grade=class_.grade))
            else:
                return redirect(url_for('edit_class_teacher', classid = classid))
        elif request.method == 'GET':
            if class_.class_teacher == 0:
                form.class_teacher_opts.data = '0'
            else:
                if current_class_teacher:
                    name = str(current_class_teacher.first_name) + ' ' + str(current_class_teacher.last_name)
                    form.class_teacher_opts.choices.append((str(current_class_teacher.id),name))
                    form.class_teacher_opts.data = str(current_class_teacher.id)
                 

        return render_template('add_class_teacher.html', title='Edit Class Teacher', form=form, current_grade=class_.grade, current_section = class_.section)
    else:
        return render_template('error.html', title='Error Page')



#---------------------------------------------DELETE CLASS TEACHER-------------------------------------------------------------------------------------
@app.route("/delete_class_teacher/<grade>", methods=['POST','GET'])
@login_required
def delete_class_teacher(grade):
    if request.method == 'POST':
        to_delete = request.form.getlist('mycheckbox')
        if (to_delete):
            for i in range(len(to_delete)):
                class_id = int(to_delete[i])
                current_class = Class.query.filter_by(id = class_id).first()
                current_class_teacher_id = current_class.class_teacher
                current_class_teacher = Teacher.query.filter_by(id = current_class_teacher_id).first()
                if current_class_teacher:
                    current_class_teacher.is_ct = False
                    current_class.class_teacher = 0
                    grade = current_class.grade

                db.session.commit()
                flash("Class teacher removed!", 'success')
        return redirect(url_for('manage_class_teachers', grade=grade))
    else:
        return render_template('error.html', title='Error Page')


















#------------------------------------------------------SUBJECT MASTER------------------------------------------------------------------------
def check_code(data):
    count = 0
    for i in data.index:
        if len(str(data['Code'][i])) > 5:
            code = str(data['Code'][i])
            data['Code'][i] = code.strip(' ')
            data['Code Status'][i] = 'Code length should be <= 5'
            count = count + 1
    return count

def check_duplicate_code(data):
    count = 0
    for i in data.index:
        code = str(data['Code'][i])
        data['Code'][i] = code.strip(' ')     
        subject = Subject_master.query.filter_by(code = data['Code'][i]).first()
        if subject:
            data['Code Status'][i] = 'Code already registered'
            count = count + 1
    
    # Check within given file
    code_set = set()
    for i in data.index:
        code = str(data['Code'][i])
        data['Code'][i] = code.strip(' ')
        if data['Code'][i] in code_set:
            data['Code Status'][i] = 'Code already registered'
            count = count + 1
        else:
            code_set.add(data['Code'][i])
    
    return count

def check_description(data):
    count = 0
    desc = ['CORE', 'FIRST LANGUAGE', 'SECOND LANGUAGE', 'THIRD LANGUAGE', 'ELECTIVE']
    for i in data.index:
        d = str(data['Description'][i]).upper()
        d = d.lstrip()
        d = d.rstrip()
        if d not in desc:
            data['Description Status'][i] = 'Invalid Description'
            count  += 1
    return count

def insert_subject_master(data):
    for i in data.index:
        data['Description'][i] = str(data['Description'][i]).upper()
        data['Description'][i] = data['Description'][i].strip(" ")
        sm = Subject_master(code=data['Code'][i], name=data['Name'][i], description=data['Description'][i])
        db.session.add(sm)
        db.session.commit()


@app.route("/upload_subject_master", methods = ['GET','POST'])
@login_required
def upload_subject_master():
    if (current_user.role == "Principal" or current_user.role == "Super User"):
        instructions = "Code,Name,Description"
        form = UploadForm()
        if form.validate_on_submit():
            try:
                input_data = pd.read_csv(request.files['input_file'])
                output_data = input_data.copy()
                output_data['Code Status'] = 'OK'
                output_data['Description Status'] = 'OK'

            except pd.errors.ParserError:
                flash('There are errors in the file. Please try again', 'danger')
                return redirect(url_for('upload_subject_master')) 
            else:
                error_count = 0
                cols = list(input_data.columns)
                if (len(cols) != 3):
                    flash('The file does not match the given template. Please try again', 'danger')
                    return redirect(url_for('upload_subject_master'))
                if input_data.isnull().values.any():
                    flash('Please fill in all the fields', 'danger')
                    return redirect(url_for('upload_subject_master'))  
                if check_description(output_data):
                    error_count = error_count + 1

                if (check_code(output_data)):
                    error_count = error_count + 1
                if check_duplicate_code(output_data):
                    error_count = error_count + 1

                if error_count > 0:
                    # give file
                    errors = output_data.to_csv(index=False)
                    errors = str(errors)
                    response = make_response(errors)
                    cd = 'attachment; filename=error_file.csv'
                    response.headers['Content-Disposition'] = cd 
                    response.mimetype='text/csv'
                    return response
                else:
                    insert_subject_master(input_data)
                    flash('Subjects have been registered!', 'success')
                    return redirect(url_for('manage_subject_master'))
        return render_template('upload.html', instructions = instructions , title='Upload Subject Master', form=form)
    else:
        return render_template('error.html', title='Error Page')




#------------------------------------------------VIEW SUBJECT MASTER-----------------------------------------------------------------------
@app.route("/manage_subject_master", methods = ['GET','POST'])
@login_required
def manage_subject_master():
    if (current_user.role == "Principal" or current_user.role == "Super User"):
        subjects = Subject_master.query.all()
        return render_template("manage_subject_master.html", title = "Manage Subject Master", subjects = subjects)
    else:
        return render_template('error.html', title='Error Page')



@app.route("/add_subject_master", methods = ['GET','POST'])
@login_required
def add_subject_master():
    if (current_user.role == "Principal" or current_user.role == "Super User"):
        form = AddSubjectMasterForm()
        if form.validate_on_submit():
            code = str(form.code.data)
            code = code.strip(' ')
            if len(str(code)) > 5:
                flash ('Code length must be less than 5','danger')
                return redirect(url_for('add_subject_master'))

            desc = ['CORE', 'FIRST LANGUAGE', 'SECOND LANGUAGE', 'THIRD LANGUAGE', 'ELECTIVE']
            description = str(form.description.data)
            description = description.upper()
            description = description.lstrip(' ')
            description = description.rstrip(' ')
            if description not in desc:
                flash ('Invalid Subject Description','danger')
                return redirect(url_for('add_subject_master'))  
            subject = Subject_master.query.filter_by(code = code).first()
            if subject:
                flash("Code already registered", "danger")
                return redirect(url_for('add_subject_master'))
            sm = Subject_master(code = code, name = form.name.data, description = description)
            db.session.add(sm)
            db.session.commit()
            flash("Subject registered", "success")
            return redirect(url_for('manage_subject_master'))
        return render_template("add_subject_master.html", title = "Add Subject", form=form)
    else:
        return render_template('error.html', title='Error Page')


@app.route("/edit_subject_master/<subjectcode>", methods = ['GET','POST'])
@login_required
def edit_subject_master(subjectcode):
    if (current_user.role == "Principal" or current_user.role == "Super User"):
        form = EditSubjectMasterForm()
        if form.validate_on_submit():
            desc = ['CORE', 'FIRST LANGUAGE', 'SECOND LANGUAGE', 'THIRD LANGUAGE', 'ELECTIVE']
            description = str(form.description.data)
            description = description.upper()
            description = description.lstrip(' ')
            description = description.rstrip(' ')
            if description not in desc:
                flash ('Invalid Subject Description','danger')
                return redirect(url_for('edit_subject_master', subjectcode = subjectcode)) 
    
            subject = Subject_master.query.filter_by(code = subjectcode).first()
            subject.description = description
            subject.name = form.name.data
            db.session.commit()
            flash("Edit Successful", "success")
            return redirect(url_for('manage_subject_master'))
        elif request.method == 'GET':
            subject = Subject_master.query.filter_by(code = subjectcode).first()
            form.description.data = subject.description
            form.name.data = subject.name
        return render_template("edit_subject_master.html", title = "Edit Subject", form=form, code=subjectcode)
    else:
        return render_template('error.html', title='Error Page')



@app.route("/delete_subject_master", methods = ['GET','POST'])
@login_required
def delete_subject_master():
    if (current_user.role == "Principal" or current_user.role == "Super User"):
        if request.method == 'POST':
            to_delete = request.form.getlist('mycheckbox')
            for i in range(len(to_delete)):
                subject_code = str(to_delete[i])
                subject_handle = Subject_handler.query.filter_by(subject_code = subject_code).all()
                subject = Subject_master.query.filter_by(code = subject_code).first()
                name = str(subject.code) + ' ' + str(subject.name)
                if not (subject_handle):
                    db.session.delete(subject)
                    db.session.commit()
                    string =  name + ' has been deleted'
                    flash( string , 'success')    
                else:
                    string = name + ' has been assigned to classes. Please check before deleting'
                    flash(string,'danger')
        return redirect(url_for('manage_subject_master'))
    else:
        return render_template('error.html', title='Error Page')








#------------------------------------------------REGISTER SUBJECTS CLASSWISE-----------------------------------------------------------------------
@app.route("/register_subjects_classwise", methods=['GET', 'POST'])
@login_required
def register_subjects_classwise():
    if (current_user.role == "Principal" or current_user.role == "Super User"):
        form1 = SelectGradeSection()
        class_list =[(0,"--Select--")]
        classes = Class.query.order_by(Class.grade.asc(), Class.section.asc()).all()
        for i in classes:
            one = (i.id , str(i.grade) + ' - ' + str(i.section))
            if one not in class_list:
                class_list.append(one)
        form1.class_opts.choices = class_list
        if request.method == "POST":
            if request.form['action'] == "Go":
                form2 = RegisterSubjectsForm()
                class_id = form1.class_opts.data
                check_class = Subjects.query.filter_by(class_id = class_id).first()
                if check_class:
                    flash("Subjects already registered for this class!", "danger")
                    return redirect(url_for('register_subjects_classwise'))
                else:
                    return redirect(url_for('add_subjects_to_table_classwise', classid = class_id))
        return render_template('register_subject_classwise.html', title='Regsiter Subjects', form1=form1)
    else:
        return render_template('error.html', title='Error Page')


@app.route("/add_subjects_to_table_classwise/<classid>", methods=['GET', 'POST'])
def add_subjects_to_table_classwise(classid):
    class_ = Class.query.filter_by(id = classid).first()
    form1 = SelectGradeSection(class_opts = classid)
    form2 = RegisterSubjectsForm()

    class_list =[(0,"--Select--")]
    classes = Class.query.order_by(Class.grade.asc(), Class.section.asc()).all()
    for i in classes:
        one = (i.id , str(i.grade) + ' - ' + str(i.section))
        if one not in class_list:
            class_list.append(one)
    form1.class_opts.choices = class_list
    if request.method == "POST":
        if request.form['action'] == "Go":
            form2 = RegisterSubjectsForm()
            class_id = form1.class_opts.data
            class_ = Subjects.query.filter_by(class_id = class_id).first()
            if class_:
                flash("Subjects already registered for this class!", "danger")
                return redirect(url_for('register_subjects_classwise'))
            else:
                return redirect(url_for('add_subjects_to_table_classwise', classid = class_id))
            
        if request.form['action'] == "Submit":

            subject_list = []
        
            if form2.core1.data:
                core1 = form2.core1.data.code
                subject_list.append(core1)
            else:
                flash("Choose a core1 subject",'danger')
                return redirect(url_for('add_subjects_to_table_classwise', classid = class_.id))

            if form2.core2.data:
                core2 = form2.core2.data.code
                subject_list.append(core2)
            else:
                flash("Choose a core2 subject",'danger')
                return redirect(url_for('add_subjects_to_table_classwise', classid = class_.id))

            if form2.core3.data:
                core3 = form2.core3.data.code
                subject_list.append(core3)
            else:
                flash("Choose a core3 subject",'danger')
                return redirect(url_for('add_subjects_to_table_classwise', classid = class_.id))

            if form2.first_lang.data:
                first_language = form2.first_lang.data.code
                subject_list.append(first_language)
            else:
                flash("Choose a first language subject",'danger')
                return redirect(url_for('add_subjects_to_table_classwise', classid = class_.id))

            
            if form2.second_lang1.data:
                second_language1 = form2.second_lang1.data.code
                subject_list.append(second_language1)
            else:
                second_language1 = '-'

            if form2.second_lang2.data:
                second_language2 = form2.second_lang2.data.code
                subject_list.append(second_language2)
            else:
                second_language2 = '-'

            if form2.second_lang3.data:
                second_language3 = form2.second_lang3.data.code
                subject_list.append(second_language3)
            else:
                second_language3 = '-'

            if form2.third_lang1.data:
                third_language1 = form2.third_lang1.data.code
                subject_list.append(third_language1)
            else:
                third_language1 = '-'

            if form2.third_lang2.data:
                third_language2 = form2.third_lang2.data.code
                subject_list.append(third_language2)
            else:
                third_language2 = '-'
            
            if form2.third_lang3.data:
                third_language3 = form2.third_lang3.data.code
                subject_list.append(third_language3)
            else:
                third_language3 = '-'
            
            if form2.elective1.data:
                elective1 = form2.elective1.data.code
                subject_list.append(elective1)
            else:
                elective1 = '-'   
            
            if form2.elective2.data:
                elective2 = form2.elective2.data.code
                subject_list.append(elective2)
            else:
                elective2 = '-'  
            
            
            if(len(subject_list)) == len(set(subject_list)):
                subject_handle = Subject_handler(class_id = class_.id, subject_code = core1, teacher_id=0 )
                db.session.add(subject_handle)
                subject_handle = Subject_handler(class_id = class_.id, subject_code = core2, teacher_id=0 )
                db.session.add(subject_handle)
                subject_handle = Subject_handler(class_id = class_.id, subject_code = core3, teacher_id=0 )
                db.session.add(subject_handle)
                subject_handle = Subject_handler(class_id = class_.id, subject_code = first_language, teacher_id=0 )
                db.session.add(subject_handle)
                if second_language1 != '-':
                    subject_handle = Subject_handler(class_id = class_.id, subject_code = second_language1, teacher_id=0)
                    db.session.add(subject_handle)
                if second_language2 != '-':
                    subject_handle = Subject_handler(class_id = class_.id, subject_code = second_language2, teacher_id=0)
                    db.session.add(subject_handle)
                if second_language3 != '-':
                    subject_handle = Subject_handler(class_id = class_.id, subject_code = second_language3, teacher_id=0)
                    db.session.add(subject_handle)
                if third_language1 != '-':
                    subject_handle = Subject_handler(class_id = class_.id, subject_code = third_language1, teacher_id=0)
                    db.session.add(subject_handle)
                if third_language2 != '-':
                    subject_handle = Subject_handler(class_id = class_.id, subject_code = third_language2, teacher_id=0)
                    db.session.add(subject_handle)
                if third_language3 != '-':
                    subject_handle = Subject_handler(class_id = class_.id, subject_code = third_language3, teacher_id=0)
                    db.session.add(subject_handle)
                if elective1 != '-':
                    subject_handle = Subject_handler(class_id = class_.id, subject_code = elective1, teacher_id=0 )
                    db.session.add(subject_handle)
                if elective2 != '-':
                    subject_handle = Subject_handler(class_id = class_.id, subject_code = elective2, teacher_id=0 )
                    db.session.add(subject_handle)



                subject_list_new = Subjects(class_id = classid, core1= core1, core2 = core2, core3 = core3, first_language=first_language, second_language1=second_language1, second_language2=second_language2, second_language3=second_language3, third_language1=third_language1, third_language2=third_language2, third_language3=third_language3, elective1=elective1, elective2=elective2 )
                db.session.add(subject_list_new)
                db.session.commit()
                flash("Subjects have been registered",'success')
                return redirect(url_for('register_subjects_classwise'))
            else:
                flash('Duplicates found!','danger')
                return redirect(url_for('add_subjects_to_table_classwise', classid=classid))
    return render_template('register_subject_classwise.html', title='Regsiter Subjects', form1=form1, form2=form2, grade = class_.grade)








# ---------------------------------------------REGISTER SUBJECT TEACHERS BULK UPLOAD--------------------------------------------------------------------------
def check_class(data):
    count = 0
    for i in data.index:
        try: 
            grade = int(data['Grade'][i])
        except ValueError:
            data['Class Status'] = 'Class not registered'
            count = count + 1 
        else:
            section = data['Section'][i]
            class_ = Class.query.filter_by(grade=grade, section=section).first()
            if not class_:
                data['Class Status'] = 'Class not registered'
                count = count + 1   
    return count

def check_subject(data):
    count = 0
    for i in data.index:
        try:
            grade = int(data['Grade'][i])
        except ValueError:
            data['Subject Status'] = 'Class not registered'
            count = count + 1 
        else:
            section = data['Section'][i]
            class_ = Class.query.filter_by(grade=grade, section=section).first()
            if class_:
                subject = Subjects.query.filter_by(class_id = class_.id).first()
                if subject:
                    subject_list = [subject.core1, subject.core2, subject.core3, subject.first_language, subject.second_language1, subject.second_language2, subject.second_language3, subject.third_language1, subject.third_language2, subject.third_language3, subject.elective1, subject.elective2]
                    if data['Subject Code'][i] not in subject_list:
                        data['Subject Status'][i] = 'Subject Not Registered'
                        count = count + 1
                else:
                    count = -1
    return count


def check_teacher(data):
    count = 0
    for i in data.index:
        user = User.query.filter_by(email = data['Teacher Username'][i]).first()
        if not user:
            data['Teacher Status'][i] = "Teacher not registered"
            count = count + 1
        elif user.role =="Student":
            data['Teacher Status'][i] = "Teacher not registered"
            count = count + 1
    return count

def insert_subject_teachers(data):
    for i in data.index:
        grade = int(data['Grade'][i])
        section = data['Section'][i]
        class_ = Class.query.filter_by(grade=grade, section=section).first()
        user = User.query.filter_by(email = data['Teacher Username'][i]).first()
        teacher = Teacher.query.filter_by(user_id = user.id).first()
        subject = Subject_handler.query.filter_by(class_id = class_.id, subject_code = data['Subject Code'][i]).first()
        subject.teacher_id = teacher.id
        db.session.commit()



@app.route("/upload_subject_teachers", methods=['GET', 'POST'])
def upload_subject_teachers():
    if (current_user.role == "Principal" or current_user.role == "Super User"): 
        instructions = "Grade,Section,Subject Code,Teacher Username"
        form = UploadForm()
        if form.validate_on_submit():
            try:
                input_data = pd.read_csv(request.files['input_file'])
                output_data = input_data.copy()
                output_data['Class Status'] = 'OK'
                output_data['Subject Status'] = 'OK'
                output_data['Teacher Status'] = 'OK'
            except pd.errors.ParserError:
                flash('There are errors in the file. Please try again', 'danger')
                return redirect(url_for('upload_subject_teachers')) 
            else:
                error_count = 0
                cols = list(input_data.columns)
                if (len(cols) != 4):
                    flash('The file does not match the given template. Please try again', 'danger')
                    return redirect(url_for('upload_subject_teachers'))
                if input_data.isnull().values.any():
                    flash('Please fill in all the fields', 'danger')
                    return redirect(url_for('upload_subject_teachers'))
                if check_class(output_data):
                    error_count = error_count + 1
                x = check_subject(output_data)
                if x == -1:
                    flash('Please register subjects for this class!', 'danger')
                    return redirect(url_for('manage_subject_teachers'))
                elif x > 0:
                    error_count += 1
                if check_teacher(output_data):
                    error_count = error_count + 1
                if error_count > 0:
                    # give file
                    errors = output_data.to_csv(index=False)
                    errors = str(errors)
                    response = make_response(errors)
                    cd = 'attachment; filename=error_file.csv'
                    response.headers['Content-Disposition'] = cd 
                    response.mimetype='text/csv'
                    return response
                else:
                    insert_subject_teachers(input_data)
                    flash('Subject teachers have been registered!', 'success')
                    return redirect(url_for('manage_subject_teachers'))
        return render_template('upload.html', instructions = instructions , title='Upload Subject Teachers', form=form) 
    else:
        return render_template('error.html', title='Error Page') 










# -----------------------------------------------------MANAGE CLASS SUBJECTS--------------------------------------------------------------------
@app.route("/manage_class_subjects", methods=['POST', 'GET'])
def manage_class_subjects():
    if (current_user.role == "Principal" or current_user.role == "Super User"):
        form = SelectGradeSection()
        class_list =[(0,"--Select--")]
        classes = Class.query.order_by(Class.grade.asc(), Class.section.asc()).all()
        for i in classes:
            one = (i.id , str(i.grade) + ' - ' + str(i.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        class_id = 0
        class_subjects = []
        grade = 0
        if request.method == "POST":
            class_id = form.class_opts.data
            if class_id != '0':
                class_ = Class.query.filter_by(id = class_id).first()
                grade = class_.grade
                subjects = Subjects.query.filter_by(class_id = class_.id).first()
                if subjects:
                    if subjects.core1 and subjects.core1 != '-' :
                        class_subjects.append([subjects.core1_subject.code, subjects.core1_subject.name, subjects.core1_subject.description])
                    if subjects.core2 and subjects.core2 != '-' :
                        class_subjects.append([subjects.core2_subject.code, subjects.core2_subject.name, subjects.core2_subject.description])
                    if subjects.core3 and subjects.core3 != '-' :
                        class_subjects.append([subjects.core3_subject.code, subjects.core3_subject.name, subjects.core3_subject.description])
                    if subjects.first_language and subjects.first_language != '-':
                        class_subjects.append([subjects.first_language_subject.code, subjects.first_language_subject.name, subjects.first_language_subject.description])
                    if subjects.second_language1 and subjects.second_language1 != '-':
                        class_subjects.append([subjects.second_language1_subject.code, subjects.second_language1_subject.name, subjects.second_language1_subject.description])
                    if subjects.second_language2 and subjects.second_language2 != '-':
                        class_subjects.append([subjects.second_language2_subject.code, subjects.second_language2_subject.name, subjects.second_language2_subject.description])
                    if subjects.second_language3 and subjects.second_language3 != '-':
                        class_subjects.append([subjects.second_language3_subject.code, subjects.second_language3_subject.name, subjects.second_language3_subject.description])
                    if subjects.third_language1 and subjects.third_language1 != '-':
                        class_subjects.append([subjects.third_lang_subject1.code, subjects.third_lang_subject1.name, subjects.third_lang_subject1.description])
                    if subjects.third_language2 and subjects.third_language2 != '-':
                        class_subjects.append([subjects.third_lang_subject2.code, subjects.third_lang_subject2.name, subjects.third_lang_subject2.description])
                    if subjects.third_language3 and subjects.third_language3 != '-':
                        class_subjects.append([subjects.third_lang_subject3.code, subjects.third_lang_subject3.name, subjects.third_lang_subject3.description])
                    if subjects.elective1 and subjects.elective1 != '-':
                        class_subjects.append([subjects.elective_subject1.code, subjects.elective_subject1.name, subjects.elective_subject1.description])
                    if subjects.elective2 and subjects.elective2 != '-':
                        class_subjects.append([subjects.elective_subject2.code, subjects.elective_subject2.name, subjects.elective_subject2.description])
                else:
                    flash('Subjects are not registered for this class!', 'danger')
        return render_template('manage_class_subjects.html', title='Manage Subjects for Classes', form=form, class_subjects=class_subjects, classid = class_id)
    else:
        return render_template('error.html', title='Error Page')




@app.route("/manage_class_subject/<classid>", methods=['POST', 'GET'])
def manage_class_subject(classid):
    if (current_user.role == "Principal" or current_user.role == "Super User"):
        form = SelectGradeSection()
        class_list =[(0,"--Select--")]
        classes = Class.query.order_by(Class.grade.asc(), Class.section.asc()).all()
        for i in classes:
            one = (i.id , str(i.grade) + ' - ' + str(i.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        class_id = classid
        class_ = Class.query.filter_by(id = classid).first()
        subjects = Subjects.query.filter_by(class_id = classid).first()
        class_subjects = []
        if subjects:
            if subjects.core1 and subjects.core1 != '-' :
                class_subjects.append([subjects.core1_subject.code, subjects.core1_subject.name, subjects.core1_subject.description])
            if subjects.core2 and subjects.core2 != '-' :
                class_subjects.append([subjects.core2_subject.code, subjects.core2_subject.name, subjects.core2_subject.description])
            if subjects.core3 and subjects.core3 != '-' :
                class_subjects.append([subjects.core3_subject.code, subjects.core3_subject.name, subjects.core3_subject.description])
            if subjects.first_language and subjects.first_language != '-':
                class_subjects.append([subjects.first_language_subject.code, subjects.first_language_subject.name, subjects.first_language_subject.description])
            if subjects.second_language1 and subjects.second_language1 != '-':
                class_subjects.append([subjects.second_language1_subject.code, subjects.second_language1_subject.name, subjects.second_language1_subject.description])
            if subjects.second_language2 and subjects.second_language2 != '-':
                class_subjects.append([subjects.second_language2_subject.code, subjects.second_language2_subject.name, subjects.second_language2_subject.description])
            if subjects.second_language3 and subjects.second_language3 != '-':
                class_subjects.append([subjects.second_language3_subject.code, subjects.second_language3_subject.name, subjects.second_language3_subject.description])
            if subjects.third_language1 and subjects.third_language1 != '-':
                class_subjects.append([subjects.third_lang_subject1.code, subjects.third_lang_subject1.name, subjects.third_lang_subject1.description])
            if subjects.third_language2 and subjects.third_language2 != '-':
                class_subjects.append([subjects.third_lang_subject2.code, subjects.third_lang_subject2.name, subjects.third_lang_subject2.description])
            if subjects.third_language3 and subjects.third_language3 != '-':
                class_subjects.append([subjects.third_lang_subject3.code, subjects.third_lang_subject3.name, subjects.third_lang_subject3.description])
            if subjects.elective1 and subjects.elective1 != '-':
                class_subjects.append([subjects.elective_subject1.code, subjects.elective_subject1.name, subjects.elective_subject1.description])
            if subjects.elective2 and subjects.elective2 != '-':
                class_subjects.append([subjects.elective_subject2.code, subjects.elective_subject2.name, subjects.elective_subject2.description])

        else:
            flash("Subjects not assigned to this class", "danger")

        
        if request.method == "POST":
            class_subjects = []
            class_id = form.class_opts.data
            subjects = Subjects.query.filter_by(class_id = class_id).first()
            if subjects.core1 and subjects.core1 != '-' :
                class_subjects.append([subjects.core1_subject.code, subjects.core1_subject.name, subjects.core1_subject.description])
            if subjects.core2 and subjects.core2 != '-' :
                class_subjects.append([subjects.core2_subject.code, subjects.core2_subject.name, subjects.core2_subject.description])
            if subjects.core3 and subjects.core3 != '-' :
                class_subjects.append([subjects.core3_subject.code, subjects.core3_subject.name, subjects.core3_subject.description])
            if subjects.first_language and subjects.first_language != '-':
                class_subjects.append([subjects.first_language_subject.code, subjects.first_language_subject.name, subjects.first_language_subject.description])
            if subjects.second_language1 and subjects.second_language1 != '-':
                class_subjects.append([subjects.second_language1_subject.code, subjects.second_language1_subject.name, subjects.second_language1_subject.description])
            if subjects.second_language2 and subjects.second_language2 != '-':
                class_subjects.append([subjects.second_language2_subject.code, subjects.second_language2_subject.name, subjects.second_language2_subject.description])
            if subjects.second_language3 and subjects.second_language3 != '-':
                class_subjects.append([subjects.second_language3_subject.code, subjects.second_language3_subject.name, subjects.second_language3_subject.description])
            if subjects.third_language1 and subjects.third_language1 != '-':
                class_subjects.append([subjects.third_lang_subject1.code, subjects.third_lang_subject1.name, subjects.third_lang_subject1.description])
            if subjects.third_language2 and subjects.third_language2 != '-':
                class_subjects.append([subjects.third_lang_subject2.code, subjects.third_lang_subject2.name, subjects.third_lang_subject2.description])
            if subjects.third_language3 and subjects.third_language3 != '-':
                class_subjects.append([subjects.third_lang_subject3.code, subjects.third_lang_subject3.name, subjects.third_lang_subject3.description])
            if subjects.elective1 and subjects.elective1 != '-':
                class_subjects.append([subjects.elective_subject1.code, subjects.elective_subject1.name, subjects.elective_subject1.description])
            if subjects.elective2 and subjects.elective2 != '-':
                class_subjects.append([subjects.elective_subject2.code, subjects.elective_subject2.name, subjects.elective_subject2.description])
        elif request.method == "GET":
            form.class_opts.data = str(classid)
        return render_template('manage_class_subjects.html', title='Class Subjects', form=form, class_subjects=class_subjects, classid = classid)
    else:
        return render_template('error.html', title='Error Page')






# -------------------------------------------------ADD CLASS SUBJECT-------------------------------------------------
@app.route("/add_class_subject/<class_id>", methods=['GET', 'POST'])
@login_required
def add_class_subject(class_id):
    if (current_user.role == "Principal" or current_user.role == "Super User") :
        form = AddClassSubject()
        class_ = Class.query.filter_by(id = class_id).first()
        grade = class_.grade
        description_choices = [(0,'--Select--'),('Core','Core'), ('First Language','First Language'), ('Second Language','Second Language')]
        if grade < 9:
          description_choices.append(('Third Language','Third Language'))
        elif grade > 10:
          description_choices.append(('Elective','Elective'))
        form.description.choices = description_choices
        if request.method == 'POST':
            class_subjects = Subjects.query.filter_by(class_id = class_id).first()
            subject_code = Subject_master.query.filter_by(code = form.name.data).first()
            subject_code = subject_code.code
            description = form.description.data
            if description == 'Core':
                if class_subjects.core1 == '-':
                    class_subjects.core1 = subject_code
                    db.session.commit()
                elif class_subjects.core2 == '-':
                    class_subjects.core2 = subject_code
                    db.session.commit()
                elif class_subjects.core3 == '-':
                    class_subjects.core3 = subject_code
                    db.session.commit()
            elif description == 'First Language':
                if class_subjects.first_language == '-':
                    class_subjects.first_language = subject_code
                    db.session.commit()
            elif description == 'Second Language':
                if class_subjects.second_language1 == '-':
                    class_subjects.second_language1 = subject_code
                    db.session.commit()
                elif class_subjects.second_language2 == '-':
                    class_subjects.second_language2 = subject_code
                    db.session.commit()
                elif class_subjects.second_language3 == '-':
                    class_subjects.second_language3 = subject_code
                    db.session.commit()
            elif description == 'Third Language':
                if class_subjects.third_language1 == '-':
                    class_subjects.third_language1 = subject_code
                    db.session.commit()
                elif class_subjects.third_language2 == '-':
                    class_subjects.third_language2 = subject_code
                    db.session.commit()
                elif class_subjects.third_language3 == '-':
                    class_subjects.third_language3 = subject_code
                    db.session.commit()
            elif description == 'Elective':
                if class_subjects.elective1 == '-':
                    class_subjects.elective1 = subject_code
                    db.session.commit()
                elif class_subjects.elective2 == '-':
                    class_subjects.elective2 = subject_code
                    db.session.commit()
            sh = Subject_handler(class_id=class_id, subject_code=subject_code, teacher_id=0)            
            db.session.add(sh)
            db.session.commit()
            s = Subject_master.query.filter_by(code = form.name.data).first()
            s1 = s.code + " , " + s.name + " has been added!"
            flash(s1, "success")
            return redirect(url_for('manage_class_subject', classid = class_id))
        return render_template('add_class_subject.html', title='Add Subject Teacher', form=form, classid = class_id)
    else:
        return render_template('error.html', title='Error Page')


@app.route('/select_subject/<description>/<classid>', methods = ["GET","POST"])
def select_subject(description,classid):
    description = str(description).upper()
    subjects = Subject_master.query.filter_by(description = description).all()
    
    sub1 = Subjects.query.filter_by(class_id = classid).first()
    sub_list = [sub1.core1, sub1.core2, sub1.core3, sub1.first_language, sub1.second_language1, sub1.second_language2, sub1.second_language3, sub1.third_language1, sub1.third_language2, sub1.third_language3, sub1.elective1, sub1.elective2]
    
    subject_Array = []
    for sub in subjects:
        if sub.code not in sub_list:
            subObj = {}
            subObj['id'] = sub.code
            subObj['subject'] = sub.name 
            subject_Array.append(subObj)
    if subject_Array == []:
        subObj = {}
        subObj['id'] = '0'
        subObj['subject'] = 'All subjects are registered' 
        subject_Array.append(subObj)
    return jsonify( { 'subjects' : subject_Array } )


 
  

# -------------------------------------------------DELETE CLASS SUBJECT-------------------------------------------------
@app.route("/delete_class_subject/<class_id>", methods=['POST','GET'])
@login_required
def delete_class_subject(class_id):
    if request.method == 'POST':
        to_delete = request.form.getlist('mycheckbox')
        for i in range(len(to_delete)):
            subject_code = (to_delete[i])
            subject = Subject_handler.query.filter_by(class_id = class_id, subject_code = subject_code).first()
            
            student_sl = Student.query.filter_by(class_id = class_id, second_language = subject_code).all()
            student_tl = Student.query.filter_by(class_id = class_id, third_language = subject_code).all()
            student_el = Student.query.filter_by(class_id = class_id, elective = subject_code).all()
            
            materials = Material.query.filter_by(sub_hand_id = subject.id).all()
            if subject.teacher_id:
              flash('Teacher is assigned to the subject', 'danger')
              return redirect(url_for('manage_class_subject', classid=class_id))
            elif student_sl or student_tl or student_el:
                string = subject_code + " has been assigned to students. Please check before deleting"
                flash(string , "danger")
                return redirect(url_for('manage_class_subject', classid=class_id))
            elif materials:
                string = subject_code + " has materials related to it. Please check before deleting"
                flash(string , "danger")
                return redirect(url_for('manage_class_subject', classid=class_id))
            else:
                db.session.delete(subject)
                db.session.commit()
                s = Subject_master.query.filter_by(code = subject_code).first()
                s1 = s.code + " , " + s.name + " has been added!"
                flash(s1, "success")
            
                sub = Subjects.query.filter_by(class_id = class_id).first()
                if sub.core1 == subject_code:
                    sub.core1 = '-'
                    db.session.commit()
                elif sub.core2 == subject_code:
                    sub.core2 = '-'
                    db.session.commit()
                elif sub.core3 == subject_code:
                    sub.core3 = '-'
                    db.session.commit()
                elif sub.first_language == subject_code:
                    sub.first_language = '-'
                    db.session.commit()
                elif sub.second_language1 == subject_code:
                    sub.second_language1 = '-'
                    db.session.commit()
                elif sub.second_language2 == subject_code:
                    sub.second_language2 = '-'
                    db.session.commit()
                elif sub.second_language3 == subject_code:
                    sub.second_language3 = '-'
                    db.session.commit()
                elif sub.third_language1 == subject_code:
                    sub.third_language1 = '-'
                    db.session.commit()
                elif sub.third_language2 == subject_code:
                    sub.third_language2 = '-'
                    db.session.commit()
                elif sub.third_language3 == subject_code:
                    sub.third_language3 = '-'
                    db.session.commit()
                elif sub.elective1 == subject_code:
                    sub.elective1 = '-'
                    db.session.commit()
                elif sub.elective2 == subject_code:
                    sub.elective2 = '-'
                    db.session.commit()
                
                if ( sub.core1 == '-' and sub.core2 == '-' and sub.core3 == '-' and sub.first_language == '-' and sub.second_language1 == '-' and sub.second_language2 == '-' and sub.second_language3 == '-' and sub.third_language1 == '-' and sub.third_language2 == '-' and sub.third_language3 == '-' and sub.elective1 == '-' and sub.elective2 == '-'):
                    db.session.delete(sub)
                    db.session.commit()
            
    return redirect(url_for('manage_class_subject', classid=class_id))















# ------------------------------------------------------MANAGE SUBJECT TEACHER---------------------------------------------------------------
@app.route("/manage_subject_teachers", methods=['POST', 'GET'])
def manage_subject_teachers():
    if (current_user.role == "Principal" or current_user.role == "Super User"):
        form = SelectGradeSection()
        class_list =[(0,"--Select--")]
        classes = Class.query.order_by(Class.grade.asc(), Class.section.asc()).all()
        for i in classes:
            one = (i.id , str(i.grade) + ' - ' + str(i.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        subject_teachers = 0
        class_id = 0
        if request.method == "POST":
            class_id = form.class_opts.data
            subject_teachers = Subject_handler.query.filter_by(class_id = class_id).order_by(Subject_handler.subject_code.asc()).all()
            if not subject_teachers :
                flash("Subjects are not registered for this class",'danger')
        return render_template('manage_subject_teachers.html', title='Manage Subject Teachers', subject_teachers=subject_teachers, form=form, class_id = class_id)
    else:
        return render_template('error.html', title='Error Page')




@app.route("/manage_subject_teacher/<classid>", methods=['POST', 'GET'])
def manage_subject_teacher(classid):
    if (current_user.role == "Principal" or current_user.role == "Super User"):
        form = SelectGradeSection()
        class_list =[(0,"--Select--")]
        classes = Class.query.order_by(Class.grade.asc(), Class.section.asc()).all()
        for i in classes:
            one = (i.id , str(i.grade) + ' - ' + str(i.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        subject_teachers = Subject_handler.query.filter_by(class_id = classid).order_by(Subject_handler.subject_code.asc()).all()
        class_id = classid
        if request.method == "POST": 
            class1_id = form.class_opts.data
            subject_teachers = Subject_handler.query.filter_by(class_id = class1_id).order_by(Subject_handler.subject_code.asc()).all()
            if not subject_teachers :
                flash("Subjects are not registered for this class",'danger')
            return render_template('manage_subject_teachers.html', title='Manage Subject Teachers', subject_teachers=subject_teachers, form=form, class_id = class1_id)
        elif request.method == "GET":
            form.class_opts.data = str(classid)
        return render_template('manage_subject_teachers.html', title='Manage Subject Teachers', subject_teachers=subject_teachers, form=form, class_id = class_id)
    else:
        return render_template('error.html', title='Error Page')







# -------------------------------------------------EDIT SUBJECT TEACHER-------------------------------------------------
@app.route("/edit_subject_teacher/<subjectid>", methods=['GET', 'POST'])
@login_required
def edit_subject_teacher(subjectid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        subject = Subject_handler.query.filter_by(id = subjectid).first()
        form = UpdateSubjectTeacherForm()
        if form.validate_on_submit():
            subject = Subject_handler.query.filter_by(id= subjectid).first()
            if not form.teacher.data:
                subject.teacher_id = 0
                db.session.commit()
            else:
                teacher_query = form.teacher.data
                subject.teacher_id = teacher_query.id
                db.session.commit()           
            flash("Teacher Updated sucessfully",'success')
            return redirect(url_for('manage_subject_teacher', classid = subject.class_id))
        elif request.method == 'GET':
            teacher = Teacher.query.filter_by(id = subject.teacher_id).first()
            form.teacher.data = teacher
        return render_template('edit_subject_teacher.html', title='Edit Subject Teacher', form = form, subject = subject)   
    else:
        return render_template('error.html', title='Error Page')








# -------------------------------------------------DELETE SUBJECT TEACHER-------------------------------------------------
@app.route("/delete_subject_teacher/<class_id>", methods=['POST','GET'])
@login_required
def delete_subject_teacher(class_id):
    if request.method == 'POST':
        to_delete = request.form.getlist('mycheckbox')
        for i in range(len(to_delete)):
            subject_id = int(to_delete[i])
            current_sub_hand = Subject_handler.query.filter_by(id = subject_id).first()
            if current_sub_hand.teacher_id :
                teacher = Teacher.query.filter_by(id = current_sub_hand.teacher_id).first()
                string = str(teacher.first_name) + ' ' + str(teacher.last_name) + ' has been removed for ' + str(current_sub_hand.subject_code)        
                flash(string ,'success')
                current_sub_hand.teacher_id = '0'
                db.session.commit()
    return redirect(url_for('manage_subject_teacher', classid=class_id))




#--------------------------------------------------------------------TEACHER REPORT GENERATION------------------------------------------------------------
@app.route("/report_principal", methods = ['GET','POST'])

@login_required
def report_principal():
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        teachers = Teacher.query.all()
        data_list = []

        for i in teachers:
            classes = Subject_handler.query.filter_by(teacher_id = i.id).all()

            t = [i]
            if i.is_ct:
                class_query = Class.query.filter_by(class_teacher = i.id).first()
                t.append(class_query)
            else:
                t.append(0)
                
            '''if classes:
                for j in classes:
                    t.append(j)'''
            
            if classes:
                class_dict = {}
                
                for j in classes:
                    c = Class.query.filter_by(id = j.class_id).first()
                    key = str(c.grade) + '-' + str(c.section)
                    if key not in class_dict.keys():
                        class_dict[key] = [j]
                    else:
                        class_dict[key].append(j)
                
                t.append(class_dict)
            

            else:
                t.append('NULL')
            data_list.append(t)


        rendered = render_template('pdf_template.html', data_list = data_list)
        pdf = pdfkit.from_string(rendered, False)

        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'inline; filename=output.pdf'

        return response
    else:
        return render_template('error.html', title='Error Page')





#----------------------------------------------------------------------------CLASS HOMEWORKS REPORT FOR PRINCIPAL-----------------------------------------------------------------------------
@app.route("/class_test_report_principal", methods = ['GET','POST'])

@login_required
def class_test_report_principal():
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        form = ViewMaterialsForm();
        class_list = [(0,'--Select--')]
        class_query = Class.query.all()
        for i in class_query:
            one = (i.id , str(i.grade) + ' - ' + str(i.section))
            class_list.append(one)
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        if request.method == "POST":
            if form.subject_opts.data:
                curr_class = form.class_opts.data
                curr_class_query = Class.query.filter_by(id=curr_class).first()
                current_sub = form.subject_opts.data
                sub_hand_query = Subject_handler.query.filter_by(class_id = curr_class, subject_code = current_sub).first()
                sub_master_query = Subject_master.query.filter_by(code = current_sub).first()

                if sub_hand_query.teacher_id:
                    curr_teacher = sub_hand_query.teacher_id
                    curr_teacher_query = Teacher.query.filter_by(id = curr_teacher).first()
                    current_materials = Material.query.filter_by(sub_hand_id = sub_hand_query.id, material_type = "Test").all()
                    
                    data_list = []
            
                    for material in current_materials:
                        t = [material]
                        all_students = Submitted_attendance.query.filter_by(material_id = material.id).all()
                        submitted_students = []
                        not_submitted_students = []
                        for s in all_students:
                            student_dict = {}
                            stud_name_query = Student.query.filter_by(id = s.student_id).first()
                            stud_fname = stud_name_query.first_name
                            stud_lname = stud_name_query.last_name
                            student_dict['id'] = s.student_id
                            student_dict['fname'] = stud_fname
                            student_dict['lname'] = stud_lname
                            if s.submitted:
                                submitted_students.append(student_dict)
                            else:
                                not_submitted_students.append(student_dict)

                        t.append(submitted_students)
                        t.append(not_submitted_students)

                        
                        data_list.append(t)
                    
                    rendered = render_template('pdf_template_test_class.html', data_list = data_list, grade = curr_class_query.grade, section = curr_class_query.section, subject = sub_master_query.name, fteacher = curr_teacher_query.first_name, lteacher = curr_teacher_query.last_name)
                    pdf = pdfkit.from_string(rendered, False)
                
                    response = make_response(pdf)
                    response.headers['Content-Type'] = 'application/pdf'
                    response.headers['Content-Disposition'] = 'inline; filename=output.pdf'
                    
                    return response

                else:
                    flash("Teacher not assigned for the chosen subject!","danger")
                    return redirect(url_for('class_report_principal'))
            else:
                flash("Subjects not assigned for the chosen class!","danger")
                return redirect(url_for('class_report_principal'))

        return render_template('pdf_select_principal.html', title='Class Report', form = form)
    else:
        return render_template('error.html', title='Error Page')


@app.route('/subject_select/<classid>', methods = ["GET","POST"])
def subject_select(classid):
    
    subjects = Subject_handler.query.filter_by(class_id=classid).all()
    subject_Array = []
    for i in subjects:
        sub = Subject_master.query.filter_by(code = i.subject_code).first()
        subObj = {}
        subObj['id'] = sub.code
        subObj['subject'] = sub.name 
        subject_Array.append(subObj)
    return jsonify( { 'subjects' : subject_Array } )





#----------------------------------------------------------------------------CLASS TESTS REPORT FOR PRINCIPAL-----------------------------------------------------------------------------
@app.route("/class_hw_report_principal", methods = ['GET','POST'])

@login_required
def class_hw_report_principal():
    if ((current_user.role == "Principal") or (current_user.role == "Super User")) :
        form = ViewMaterialsForm();
        class_list = [(0,'--Select--')]
        class_query = Class.query.all()
        for i in class_query:
            one = (i.id , str(i.grade) + ' - ' + str(i.section))
            class_list.append(one)
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        if request.method == "POST":
            if form.subject_opts.data:
                curr_class = form.class_opts.data
                curr_class_query = Class.query.filter_by(id=curr_class).first()
                current_sub = form.subject_opts.data
                sub_hand_query = Subject_handler.query.filter_by(class_id = curr_class, subject_code = current_sub).first()
                sub_master_query = Subject_master.query.filter_by(code = current_sub).first()

                if sub_hand_query.teacher_id:
                    curr_teacher = sub_hand_query.teacher_id
                    curr_teacher_query = Teacher.query.filter_by(id = curr_teacher).first()
                    current_materials = Material.query.filter_by(sub_hand_id = sub_hand_query.id, material_type = "Homework").all()
                    
                    data_list = []
            
                    for material in current_materials:
                        t = [material]
                        all_students = Submitted_attendance.query.filter_by(material_id = material.id).all()
                        submitted_students = []
                        not_submitted_students = []
                        for s in all_students:
                            student_dict = {}
                            stud_name_query = Student.query.filter_by(id = s.student_id).first()
                            stud_fname = stud_name_query.first_name
                            stud_lname = stud_name_query.last_name
                            student_dict['id'] = s.student_id
                            student_dict['fname'] = stud_fname
                            student_dict['lname'] = stud_lname
                            if s.submitted:
                                submitted_students.append(student_dict)
                            else:
                                not_submitted_students.append(student_dict)

                        t.append(submitted_students)
                        t.append(not_submitted_students)

                        
                        data_list.append(t)
                    
                    rendered = render_template('pdf_template_hw_class.html', data_list = data_list, grade = curr_class_query.grade, section = curr_class_query.section, subject = sub_master_query.name, fteacher = curr_teacher_query.first_name, lteacher = curr_teacher_query.last_name)
                    pdf = pdfkit.from_string(rendered, False)
                
                    response = make_response(pdf)
                    response.headers['Content-Type'] = 'application/pdf'
                    response.headers['Content-Disposition'] = 'inline; filename=output.pdf'
                    
                    return response

                else:
                    flash("Teacher not assigned for the chosen subject!","danger")
                    return redirect(url_for('class_report_principal'))
            else:
                flash("Subjects not assigned for the chosen class!","danger")
                return redirect(url_for('class_report_principal'))

        return render_template('pdf_select_principal.html', title='Class Report', form = form)
    else:
        return render_template('error.html', title='Error Page')




























































# ------------------------------------------------TEACHER--------------------------------------------------------------
# --------------------------------------------REGISTER STUDENTS BULK---------------------------------------------------
def check_phno_teacher(data):
    count = 0
    for i in data.index:
        if len(str(data['Phone Number'][i])) != 10:
            count = count + 1
            data['Phone Status'][i] = 'Phone Length Number Error'
        try:
            val = int(data['Phone Number'][i])
        except ValueError:
            count = count + 1
            data['Phone Status'][i] = 'Invalid Phone Number'
    return count

def check_username_teacher(data):
    count = 0
    username = User.query.with_entities(User.email).all()
    username_list = [value for (value,) in username]
    email = list(data['Username'])
    
    # Check with existing users
    for i in range(len(email)):
        if email[i] in username_list:
            data['Email Status'][i] = 'Username Already Taken'
            count = count + 1

    # Check within given file
    email_set = set()
    for i in range(len(email)):
        if email[i] in email_set:
            data['Email Status'][i] = 'Username Already Taken'
            count = count + 1
        else:
            email_set.add(email[i])
    
    return count

def check_dob_1(data):
    count = 0
    for i in data.index:
        date = data['DOB'][i]
        date_format = '%Y-%m-%d'
        try:
            dob = datetime.strptime(date, date_format)
        except ValueError:
            data['DOB Status'][i] = 'Invalid data format'
            count += 1
    return count


def insert_students(data, personid):
    for i in data.index:
        hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
        user = User(email=data['Username'][i], password=hashed_password, role='Student')
        db.session.add(user)

        user_teacher = User.query.filter_by(id = personid).first()
        teacher = Teacher.query.filter_by(user_id = user_teacher.id).first()
        class_ = Class.query.filter_by(class_teacher = teacher.id).first()
        student = Student(first_name = data['First Name'][i], last_name = data['Last Name'][i], gender = data['Gender'][i], phone = int(data['Phone Number'][i]), dob = datetime.strptime((data['DOB'][i]),"%Y-%m-%d"), user_id = user.id, class_id = class_.id, second_language='-', third_language='-', elective='-')
        send_registered_email(user,user.role)
        db.session.add(student)
        db.session.commit()


@app.route('/upload_students/<personid>', methods=['GET', 'POST'])
@login_required
def upload_students(personid):
    if ((current_user.role == "Teacher") or (current_user.role == "Super User") or (current_user.role == "Principal")) :
        instructions = "First Name,Last Name,Phone Number,DOB,Username,Gender"
        form = UploadForm()
        t = Teacher.query.filter_by(user_id = personid).first()
        if form.validate_on_submit():
            try:
                input_data = pd.read_csv(request.files['input_file'])
                output_data = input_data.copy()
                output_data['Phone Status'] = 'OK'
                output_data['Email Status'] = 'OK'
            except pd.errors.ParserError:
                flash('There are errors in the file. Please try again', 'danger')
                return redirect(url_for('upload_students', personid=personid)) 
            else:
                error_count = 0
                cols = list(input_data.columns)
                if (len(cols) != 6):
                    flash('The file does not match the given template. Please try again', 'danger')
                    return redirect(url_for('upload_students', personid=personid))
                if input_data.isnull().values.any():
                    flash('Please fill in all the fields', 'danger')
                    return redirect(url_for('upload_students', personid=personid))
                if (check_phno_teacher(output_data)):
                    error_count = error_count + 1
                if (check_username_teacher(output_data)):
                    error_count = error_count + 1
                if check_dob_1(output_data):
                    error_count += 1
                if error_count > 0:
                    # give file
                    errors = output_data.to_csv(index=False)
                    errors = str(errors)
                    response = make_response(errors)
                    cd = 'attachment; filename=error_file.csv'
                    response.headers['Content-Disposition'] = cd 
                    response.mimetype='text/csv'
                    return response
                else:
                    insert_students(input_data, personid)
                    flash('Students have been registered!', 'success')
                    return redirect(url_for('upload_students', personid=personid))   
        return render_template('upload_teacher.html', instructions = instructions, title='Upload Students', form=form, t_ct = t.is_ct, personid = personid)
    else:
        return render_template('error.html', title='Error Page')









# --------------------------------------------REGISTER SUBJECTS FOR STUDENTS BULK---------------------------------------------------
def check_student_username(data):
    count = 0
    user = User.query.filter_by(role = "Student").all()
    email = list(data['Student Username'])
    email_list =[]
    for i in user:
        email_list.append(i.email)

    # Check with existing users
    for i in range(len(email)):
        if email[i] not in email_list:
            data['Student Status'][i] = 'Username not found'
            count = count + 1

    # Check within given file
    email_set = set()
    for i in range(len(email)):
        if email[i] in email_set:
            data['Student Status'][i] = 'Duplicates found'
            count = count + 1
        else:
            email_set.add(email[i])   
    return count

def check_subject_student(data, personid):
    count = 0
    class_ = Class.query.filter_by(class_teacher = personid).first()
    subjects = Subjects.query.filter_by(class_id = class_.id).first()
    subject_sl = []
    subject_tl = []
    subject_el = []
    if subjects:
        subject_sl = [subjects.second_language1, subjects.second_language2, subjects.second_language3]
        subject_tl = [subjects.third_language1, subjects.third_language2, subjects.third_language3]
        subject_el = [ subjects.elective1, subjects.elective2]
    for i in data.index:
        sl = data['Second Language'][i]
        tl = data['Third Language'][i]
        el = data['Elective'][i]
        if sl != '-' and sl not in subject_sl:
            data['Subject Status'][i] = 'Subject not registered'
            count = count +  1
        if tl != '-' and tl not in subject_tl:
            data['Subject Status'][i] = 'Subject not registered'
            count = count +  1
        if el != '-' and el not in subject_el:
            data['Subject Status'][i] = 'Subject not registered'
            count = count +  1
    return count



def insert_subjects_students(data):
    for i in data.index:
        user = User.query.filter_by(email = data['Student Username'][i], role="Student").first()
        student = Student.query.filter_by(user_id = user.id).first()
        student.second_language = data['Second Language'][i]
        student.third_language = data['Third Language'][i]
        student.elective = data['Elective'][i]
        db.session.add(student)
        db.session.commit()




@app.route('/upload_subject_students/<personid>', methods=['GET', 'POST'])
@login_required
def upload_subject_students(personid):
    if ((current_user.role == "Teacher") or (current_user.role == "Super User") or (current_user.role == "Principal")) :
        instructions = "Student Username,Second Language,Third Language,Elective"
        form = UploadForm()
        t = Teacher.query.filter_by(user_id = personid).first()
        if form.validate_on_submit():
            try:
                input_data = pd.read_csv(request.files['input_file'])
                output_data = input_data.copy()
                output_data['Student Status'] = 'OK'
                output_data['Subject Status'] = 'OK'
            except pd.errors.ParserError:
                flash('There are errors in the file. Please try again', 'danger')
                return redirect(url_for('upload_students', personid=personid)) 
            else:
                error_count = 0
                cols = list(input_data.columns)
                if (len(cols) != 4):
                    flash('The file does not match the given template. Please try again', 'danger')
                    return redirect(url_for('upload_students', personid=personid))
                if input_data.isnull().values.any():
                    flash('Please fill in all the fields', 'danger')
                    return redirect(url_for('upload_students', personid=personid))
                if (check_student_username(output_data)):
                    error_count = error_count + 1
                if (check_subject_student(output_data, t.id)):
                    error_count = error_count + 1
                if error_count > 0:
                    # give file
                    errors = output_data.to_csv(index=False)
                    errors = str(errors)
                    response = make_response(errors)
                    cd = 'attachment; filename=error_file.csv'
                    response.headers['Content-Disposition'] = cd 
                    response.mimetype='text/csv'
                    return response
                else:
                    insert_subjects_students(input_data)
                    flash('Students have been registered!', 'success')
                    return redirect(url_for('upload_subject_students', personid=personid))   
        return render_template('upload_teacher.html', instructions = instructions, title='Upload Subjects for Students', form=form, t_ct = t.is_ct, personid = personid)
    else:
        return render_template('error.html', title='Error Page')









# --------------------------------------------MANAGE STUDENTS---------------------------------------------------
@app.route("/manage_class_students/<personid>", methods=['GET', 'POST'])
def manage_class_students(personid):
    if ((current_user.role == "Teacher") or (current_user.role == "Super User") or (current_user.role == "Principal")) :
        teacher = Teacher.query.filter_by(user_id = personid).first()
        class_ = Class.query.filter_by(class_teacher = teacher.id).first()
        grade = class_.grade
        students = Student.query.filter_by(class_id = class_.id).all()
        if  not (students):
            flash("No students registered!", "danger")
            return redirect(url_for('welcome'))
        subjects = Subjects.query.filter_by(class_id = class_.id).first()
        if subjects:
            return render_template('manage_class_students.html', title='Manage Class Students', t_ct = teacher.is_ct, students=students, grade=grade, personid=personid, subjects = subjects)
        else:
            return render_template('manage_class_students.html', title='Manage Class Students', t_ct = teacher.is_ct, students=students, grade=grade, personid=personid, subjects = 0)
    else:
        return render_template('error.html', title='Error Page')





# -------------------------------------------------ADD CLASS STUDENT-------------------------------------------------
@app.route("/add_class_student/<personid>", methods=['GET', 'POST'])
@login_required
def add_class_student(personid):
    if (current_user.role == "Principal" or current_user.role == "Super User" or current_user.role == "Teacher") :
        form = RegistrationForm()
        t = Teacher.query.filter_by(user_id = personid).first()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
            user = User(email = form.username.data, role = 'Student', password=hashed_password)
            db.session.add(user)
            db.session.commit()
            user_teacher = User.query.filter_by(id = personid).first()
            teacher = Teacher.query.filter_by(user_id = user_teacher.id).first()
            class_ = Class.query.filter_by(class_teacher = teacher.id).first()
            student = Student(first_name = form.first_name.data, last_name = form.last_name.data, gender = form.gender.data, phone = int(form.phone_number.data), dob = form.dob.data, user_id = user.id, class_id = class_.id)
            send_registered_email(user,user.role)
            db.session.add(student)
            db.session.commit()
            
            flash('Student has been added', 'success')
            return redirect(url_for('manage_class_students', personid=personid))
        return render_template('register_teacher.html', title='Add Student', form=form, t_ct = t.is_ct, personid=personid)
    else:
        return render_template('error.html', title='Error Page')



# -------------------------------------------------EDIT CLASS STUDENT-------------------------------------------------
@app.route("/edit_class_student/<studentid>/<personid>", methods=['GET', 'POST'])
@login_required
def edit_class_student(studentid, personid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        t = Teacher.query.filter_by(user_id = personid).first()
        student = Student.query.filter_by(id = studentid).first()
        class_ = Class.query.filter_by(id = student.class_id).first()
        user = User.query.filter_by(id = student.user_id).first()
        form = EditStudentSubjectForm()
        subjects = Subjects.query.filter_by(class_id = student.class_id).first()
        subject_sl = [subjects.second_language1, subjects.second_language2, subjects.second_language3]
        subject_tl = [subjects.third_language1, subjects.third_language2, subjects.third_language3]
        subject_el = [ subjects.elective1, subjects.elective2]
        sl = [('-',"--Select--")]
        tl = [('-',"--Select--")]
        el = [('-',"--Select--")]
        for i in subject_sl:
            if i != '-':
                s = Subject_master.query.filter_by(code= i).first()
                one = (s.code,s.name)
                sl.append(one)
        for i in subject_tl:
            if i != '-':
                s = Subject_master.query.filter_by(code= i).first()
                one = (s.code,s.name)
                tl.append(one)
        for i in subject_el:
            if i != '-':
                s = Subject_master.query.filter_by(code= i).first()
                one = (s.code,s.name)
                el.append(one)
        form.second_lang.choices = sl
        form.third_lang.choices = tl
        form.elective.choices = el
        
        if request.method == "POST":
            count = 0
            if (len(form.email.data) > 10 and len(form.email.data)<50):
                count += 1

            if "@gmail.com" in form.email.data:
                count+=1

            if count<2:
                flash('Invalid e-mail id','danger')     
                return redirect(url_for('edit_class_student', personid=personid, studentid = studentid))

            check_user = User.query.filter_by(email=form.email.data).first()
            if check_user:
                if user.email != check_user.email:
                    flash('User already registered','danger')     
                    return redirect(url_for('edit_class_student', personid=personid, studentid = studentid))
            student.student_user.email = form.email.data
            student.second_language = form.second_lang.data
            student.third_language = form.third_lang.data
            student.elective = form.elective.data
            db.session.commit()
            flash('Changes have been updated', 'success')
            return redirect(url_for('manage_class_students', personid=personid))
        elif request.method == 'GET':
            print("HI 123")
            form.email.data = student.student_user.email
            form.second_lang.data = student.second_language
            form.third_lang.data = student.third_language
            form.elective.data = student.elective
        return render_template('edit_class_student.html', title='Edit Student', form = form, student = student, personid=personid, grade = class_.grade, t_ct = t.is_ct)   
    else:
        return render_template('error.html', title='Error Page')




# -------------------------------------------------DELETE STUDENT-------------------------------------------------
@app.route("/delete_class_students/<personid>", methods=['POST','GET'])
@login_required
def delete_class_students(personid):
    if request.method == 'POST':
        to_delete = request.form.getlist('mycheckbox')
        for i in range(len(to_delete)):
            student_id = int(to_delete[i])
            student = Student.query.filter_by(id = student_id).first()
            name = str(student.first_name) + ' ' + str(student.last_name)
            user = User.query.filter_by(id = student.user_id).first()

            # DELETE IN ATTENDANCE
            att = Submitted_attendance.query.filter_by(student_id = student_id).all()
            if att:
              for i in att:
                  db.session.delete(i)
                  db.session.commit()
            db.session.delete(student)
            db.session.delete(user)
            db.session.commit()
            string =  name + '  has been deleted.'
            flash(string ,'success')
    return redirect(url_for('manage_class_students', personid=personid))
    




# ----------------------------------------VIEW SUBJECT WISE STUDENTS--------------------------------------
@app.route("/view_subjectwise_students/<personid>", methods = ["GET","POST"])
@login_required
def view_subjectwise_students(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        form = ViewSubjectStudents()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        class_list =[(0,"--Select--")]
        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        class_list = sorted(class_list, key = lambda x: x[0])
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        
        students = []
        if request.method == "POST":
            selected_class = form.class_opts.data
            selected_sub = form.subject_opts.data
            if selected_class != '0' and selected_sub != '0':
                student = Student.query.filter_by(class_id=form.class_opts.data).all()
                subject = Subject_master.query.filter_by(code = selected_sub).first()
                if (subject.description == "CORE" or subject.description == "FIRST LANGUAGE"):
                    for i in student:
                        students.append(i)
                elif subject.description == "SECOND LANGUAGE":
                    for i in student:
                        if subject.code == i.second_language:
                            students.append(i)
                elif subject.description == "THIRD LANGUAGE":
                    for i in student:
                        if subject.code == i.third_language:
                            students.append(i)
                elif subject.description == "ELECTIVE":
                    for i in student:
                        if subject.code == i.elective:
                            students.append(i)
                if not students:
                    flash('No students registered for this course', 'danger')
                    return render_template("view_subject_student_details.html",t_ct = teacher.is_ct, form=form, students=students, personid=personid, class_=selected_class, sub=selected_sub)
                form.class_opts.data = '0'
                return render_template("view_subject_student_details.html",t_ct = teacher.is_ct, form=form, students=students, personid=personid, class_=selected_class, sub=selected_sub) 
        elif request.method == "GET":
            form.class_opts.data = '0'      
        return render_template("view_subject_student_details.html", t_ct = teacher.is_ct, form=form, students=0, personid=personid, class_=0, sub=0 )
    else:
        return render_template("error.html", title='Error Page')



@app.route('/subject/<personid>/<classid>', methods = ["GET","POST"])
def choose_subjects(personid, classid):
    teacher = Teacher.query.filter_by(user_id=personid).first()
    subjects = Subject_handler.query.filter_by(teacher_id=teacher.id, class_id=classid).all()
    subject_Array = []
    subObj = {}
    subObj['id'] = '0'
    subObj['subject'] = "--Select--"
    subject_Array.append(subObj)
    for i in subjects:
        sub = Subject_master.query.filter_by(code = i.subject_code).first()
        subObj = {}
        subObj['id'] = sub.code
        subObj['subject'] = sub.name 
        subject_Array.append(subObj)
    return jsonify( { 'subjects' : subject_Array } )




# ----------------------------------------------------ONLINE CLASS--------------------------------------------------------------
# ----------------------------------------------------ADD ONLINE CLASS--------------------------------------------------------------
def send_online_class_email(user, subject):
    subj = str(subject) + " - Online Class"
    msg = Message(subj, sender='shikshanoreply@gmail.com', recipients=[user.email])
    msg.body = f'''Hello!

Greetings from the team of Shiksha!

This is a notification for the addition of a new online class link for the subject {subject}. Kindly login and check the same.
We request you to use the time table provided by the school and the use the above mentioned link, which will be available in your login in our webiste hereafter,whenever you are expected to attend the classes of the respective subject.
    
Thank you!
Hope you enjoy your journey with us! :)

NOTE: This email was sent from a notification-only address that cannot accept incoming email. Please do not reply to this message.'''
    #mail.send(msg)
    print(msg)


@app.route("/add_online_class/<personid>", methods = ["GET","POST"])
def add_online_class(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        form = AddOnlineClass()
        teacher = Teacher.query.filter_by(user_id = personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        
        class_list =[(0,"--Select--")]
        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        class_list = sorted(class_list, key = lambda x: x[0])
        form.class_opts.choices = class_list

        form.subject_opts.choices = [(0,'--Select--')]
        if request.method == "POST":
            class_ = Class.query.filter_by(id = form.class_opts.data).first()
            subject = Subject_master.query.filter_by(code = form.subject_opts.data).first()
            sub_handle = Subject_handler.query.filter_by(class_id=class_.id, subject_code=subject.code, teacher_id=teacher.id).first()
            if sub_handle.online_class_link:
                s1 = str(class_.grade) + " - " + str(class_.section)
                s2 = str(subject.name)
                s = "Online Class already registered for " + s1 + " , " + s2
                flash(s, "danger") 
                return redirect(url_for('add_online_class', personid=personid))
            #sub_handle.online_class_link = form.link.data
            #db.session.commit()


            subject = subject.code
            students = Student.query.filter_by (class_id = form.class_opts.data).all()
            
            if students:
                class_subjects = Subjects.query.filter_by(class_id = form.class_opts.data).first()
                core_subjects = [ class_subjects.core1, class_subjects.core2, class_subjects.core3, class_subjects.first_language]
                
                
                if subject in core_subjects:
                    sub_handle.online_class_link = form.link.data
                    db.session.commit()
                    for i in students:
                        user_id = i.user_id
                        user = User.query.filter_by(id = user_id).first()
                        sub_code = form.subject_opts.data
                        sub = Subject_master.query.filter_by(code = sub_code).first()
                        sub = sub.name.capitalize()
                        send_online_class_email(user, sub)
                    
                else:
                    count = 0
                    for i in students:
                        subjects_i = [i.second_language, i.third_language, i.elective]
                        if subject in subjects_i:                            
                            count+=1
                    if count > 0:
                        sub_handle.online_class_link = form.link.data
                        db.session.commit()
                        for i in students:
                            subjects_i = [i.second_language, i.third_language, i.elective]
                            if subject in subjects_i:
                                user_id = i.user_id
                                user = User.query.filter_by(id = user_id).first()
                                sub_code = form.subject_opts.data
                                sub = Subject_master.query.filter_by(code = sub_code).first()
                                sub = sub.name.capitalize()
                                send_online_class_email(user, sub)
                    
                    
                    elif count == 0:
                        flash("Please register students for the given subject","danger")
                        return redirect(url_for('add_online_class', title = "Add Online Class", personid=personid))

                teacher = Teacher.query.filter_by(user_id=personid).first()
                flash('Online Class uploaded', 'success')
                return redirect(url_for('add_online_class', title = "Add Online Class",personid=personid))
            
            else:
                flash("Please register students for the given class","danger")
                return redirect(url_for('add_online_class', title = "Add Online Class",personid=personid))

        t = Teacher.query.filter_by(user_id = personid).first()
        return render_template('add_online_class.html', title='Add Online Class', form=form, personid=personid, t_ct=teacher.is_ct)
    else:
        return render_template('error.html', title='Error Page')
    



# ------------------------------------------MANAGE ONLINE CLASSS------------------------------------
@app.route("/manage_online_class/<personid>", methods = ["GET","POST"])
def manage_online_class(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        teacher = Teacher.query.filter_by(user_id = personid).first()
        subjecthandle = 0
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        return render_template('manage_online_class.html', title='Manage Online Class', subjecthandle=subjecthandle, personid=personid, t_ct=teacher.is_ct)
    else:
        return render_template('error.html', title='Error Page')











# -----------------------------------------------EDIT ONLINE CLASS----------------------------------------------------
@app.route("/edit_online_class/<sub_hand_id>/<personid>", methods = ["GET","POST"])
def edit_online_class(sub_hand_id, personid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        form = LinkSubmission()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        subject_handler = Subject_handler.query.filter_by(id = sub_hand_id).first()
        if request.method == "POST":
            subject_handler.online_class_link = form.link.data
            db.session.commit()
            s1 = str(subject_handler.class_sub.grade) + " - " + str(subject_handler.class_sub.section)
            s2 = str(subject_handler.class_subjects.name)
            s = "Online class link for " + s1 + " , " + s2 + " has been updated!"
            flash(s, "success")
            return redirect(url_for('manage_online_class', personid=personid))
        elif request.method == "GET":
            form.link.data = subject_handler.online_class_link
        
        return render_template('edit_online_class.html', title='Edit Online Class', form=form, subhandler = subject_handler, t_ct=teacher.is_ct)

    else:
        return render_template('error.html', title='Error Page')


# ---------------------------------------------------DELETE ONLINE CLASS-------------------------------------------------------
@app.route("/delete_online_class/<personid>", methods=['POST','GET'])
@login_required
def delete_online_class(personid):
    if request.method == 'POST':
        to_delete = request.form.getlist('mycheckbox')
        flag = 0
        for i in range(len(to_delete)):
            subject_handler_id = int(to_delete[i])
            subject_handler = Subject_handler.query.filter_by(id = subject_handler_id).first()
            s1 = str(subject_handler.class_sub.grade) + " - " + str(subject_handler.class_sub.section)
            s2 = str(subject_handler.class_subjects.name)
            s = "Online class link for " + s1 + " , " + s2 + " has been deleted!"
            subject_handler.online_class_link = ''
            db.session.commit()
            flash(s, "success")
    return redirect(url_for('manage_online_class', personid=personid))











#--------------------------------------------------------------------UPLOAD STUDY MATERIAL------------------------------------------------------------------------
def send_study_material_email(user, subject):
    subj = str(subject) + " - Study Material"
    msg = Message(subj, sender='shikshanoreply@gmail.com', recipients=[user.email])
    msg.body = f'''Hello!

Greetings from the team of Shiksha!

This is a notification for the addition of a new study material for the subject {subject}. Kindly login and check the same.
We request you to refer to the study materials provided in your login in our website for the respective subjects as per the guidance of your teacher.
    
Thank you!
Hope you enjoy your journey with us! :)

NOTE: This email was sent from a notification-only address that cannot accept incoming email. Please do not reply to this message.'''
    #mail.send(msg)
    print(msg)



@app.route("/upload_study_material/<personid>", methods = ["GET","POST"])
@login_required
def upload_study_material(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        form = StudyMaterialForm()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        class_list =[(0,"--Select--")]
        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        if request.method == 'POST':
            print("HERE")
            
            class_id = form.class_opts.data
            subject = form.subject_opts.data
            current_teacher_tuple = Teacher.query.with_entities(Teacher.id).filter_by(user_id = personid).all()
            current_teacher_list = [value for (value,) in current_teacher_tuple]
            teacher_id = current_teacher_list[0]
            current_subject_handler = Subject_handler.query.filter_by(class_id = class_id, subject_code = subject, teacher_id = teacher_id).first()
            subject_handler_id = current_subject_handler.id
            material = Material(name=form.name.data, link=form.link.data, sub_hand_id=subject_handler_id, material_type = "Study Material", report_gen=0)
            # db.session.add(material)
            # db.session.commit()

            students = Student.query.filter_by (class_id = class_id).all()
            
            if students:
                class_subjects = Subjects.query.filter_by(class_id = class_id).first()
                core_subjects = [ class_subjects.core1, class_subjects.core2, class_subjects.core3, class_subjects.first_language]
                
                
                if subject in core_subjects:
                    db.session.add(material)
                    db.session.commit()
                    for i in students:
                        user_id = i.user_id
                        user = User.query.filter_by(id = user_id).first()
                        sub_code = form.subject_opts.data
                        sub = Subject_master.query.filter_by(code = sub_code).first()
                        sub = sub.name.capitalize()
                        send_study_material_email(user, sub)
                    
                else:
                    count = 0
                    for i in students:
                        subjects_i = [i.second_language, i.third_language, i.elective]
                        if subject in subjects_i:                            
                            count+=1
                    if count > 0:
                        db.session.add(material)
                        db.session.commit()
                        for i in students:
                            subjects_i = [i.second_language, i.third_language, i.elective]
                            if subject in subjects_i:
                                user_id = i.user_id
                                user = User.query.filter_by(id = user_id).first()
                                sub_code = form.subject_opts.data
                                sub = Subject_master.query.filter_by(code = sub_code).first()
                                sub = sub.name.capitalize()
                                send_study_material_email(user, sub)
                    
                    
                    elif count == 0:
                        flash("Please register students for the given subject","danger")
                        return redirect(url_for('upload_study_material', title = "Upload Study Material", personid=personid))

                teacher = Teacher.query.filter_by(user_id=personid).first()
                flash('Study Material uploaded', 'success')
                return redirect(url_for('upload_study_material', title = "Upload Study Material",personid=personid))
            
            else:
                flash("Please register students for the given class","danger")
                return redirect(url_for('upload_study_material', title = "Upload Study Material",personid=personid))

        t = Teacher.query.filter_by(user_id = personid).first()
        return render_template("upload_study_material.html", form=form, personid=personid, t_ct = t.is_ct)
    else:
        return render_template('error.html', title='Error Page')



@app.route('/subjects/<class_id>/<personid>', methods = ["GET","POST"])
def assign_subjects(class_id, personid): 
    teacher = Teacher.query.filter_by(user_id=personid).first()
    subjects = Subject_handler.query.filter_by(teacher_id=teacher.id, class_id=class_id).all()
    subject_Array = []
    for i in subjects:
        subObj = {}
        subObj['id'] = i.subject_code
        subject_name_query = Subject_master.query.filter_by(code = i.subject_code).first()
        subObj['subject'] = subject_name_query.name
        subject_Array.append(subObj)

    return jsonify( { 'subjects' : subject_Array } )






#----------------------------------------------------------------------VIEW STUDY MATERIALS--------------------------------------------------------------------------------------------------------
@app.route("/view_study_materials/<personid>", methods = ["GET","POST"])
@login_required
def view_study_materials(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        form = ViewMaterialsForm()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        class_list =[(0,"--Select--")]

        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        materials = ''
        if request.method == 'POST':
            class_id = form.class_opts.data
            subject = form.subject_opts.data
            if class_id != '0' and subject != '0':
                current_teacher_tuple = Teacher.query.with_entities(Teacher.id).filter_by(user_id = personid).all()
                current_teacher_list = [value for (value,) in current_teacher_tuple]
                teacher_id = current_teacher_list[0]
                current_subject_handler = Subject_handler.query.filter_by(class_id = class_id, subject_code = subject, teacher_id = teacher_id).first()
                subject_handler_id = current_subject_handler.id
                

                materials = Material.query.filter_by(sub_hand_id = subject_handler_id, material_type="Study Material").all()
                if not materials:
                    flash('No materials uploaded!', 'danger')

                return render_template('view_study_materials.html', form = form, t_ct = teacher.is_ct, materials=materials, sub_hand_id = subject_handler_id, personid=personid, classid = class_id, subjectcode = subject)

        return render_template("view_study_materials.html", form=form, t_ct = teacher.is_ct, materials = materials, personid=personid)
    else:
        return render_template('error.html', title='Error Page')




@app.route("/view_study_material/<personid>/<subjectcode>/<classid>", methods = ["GET","POST"])
@login_required
def view_study_material(personid,subjectcode,classid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        form = ViewMaterialsForm()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        class_list =[(0,"--Select--")]

        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        materials = ''
        current_teacher_tuple = Teacher.query.with_entities(Teacher.id).filter_by(user_id = personid).all()
        current_teacher_list = [value for (value,) in current_teacher_tuple]
        teacher_id = current_teacher_list[0]
        current_subject_handler = Subject_handler.query.filter_by(class_id = int(classid), subject_code = subjectcode, teacher_id = teacher_id).first()
        subject_handler_id = current_subject_handler.id
        materials = Material.query.filter_by(sub_hand_id = subject_handler_id, material_type="Study Material").all()
            
        if request.method == 'POST':
            class_id = form.class_opts.data
            subject = form.subject_opts.data
            if class_id != '0' and subject != '0':
                current_teacher_tuple = Teacher.query.with_entities(Teacher.id).filter_by(user_id = personid).all()
                current_teacher_list = [value for (value,) in current_teacher_tuple]
                teacher_id = current_teacher_list[0]
                current_subject_handler = Subject_handler.query.filter_by(class_id = class_id, subject_code = subject, teacher_id = teacher_id).first()
                subject_handler_id = current_subject_handler.id

                materials = Material.query.filter_by(sub_hand_id = subject_handler_id, material_type="Study Material").all()
                if not materials:
                    flash('No materials uploaded!', 'danger')
                return render_template('view_materials.html', form = form, t_ct = teacher.is_ct, materials=materials, sub_hand_id = subject_handler_id, personid=personid)
        elif request.method == 'GET':
            form.class_opts.data = str(classid)
            form.subject_opts.data = subjectcode
        return render_template("view_study_materials.html", form=form, materials = materials,subjectcode = subjectcode, t_ct = teacher.is_ct, sub_hand_id = subject_handler_id, personid=personid, classid= classid)
    else:
        return render_template('error.html', title='Error Page')


# -----------------------------------------EDIT STUDY MATERIALS---------------------------------------------------------------------------------------
@app.route("/edit_study_material/<materialid>/<personid>", methods=['GET', 'POST'])
@login_required
def edit_study_material(materialid, personid):
    if ((current_user.role == "Principal") or (current_user.role == "Teacher") or (current_user.role == "Super User")) :
        material = Material.query.filter_by(id = materialid).first()
        form = UpdateStudyMaterialsForm()
        current_sub_hand_id = material.sub_hand_id
        sub_hand = Subject_handler.query.filter_by(id = current_sub_hand_id).first()
        current_class_id = sub_hand.class_id
        current_sub_code = sub_hand.subject_code
        current_sub_name = Subject_master.query.filter_by(code = current_sub_code).first()
        current_class = Class.query.filter_by(id=current_class_id).first()
        t = Teacher.query.filter_by(user_id = personid).first()
        if form.validate_on_submit():

            material.name = form.name.data
            material.link = form.link.data
            

            db.session.commit()

            flash("Study material updated successfully!", "success")
            return redirect(url_for('view_study_material', personid=personid, classid = current_class_id, subjectcode = current_sub_code))
        elif request.method == 'GET':
            form.name.data = material.name
            form.link.data = material.link
           

        return render_template('edit_study_material.html', title='Edit Homework', t_ct = t.is_ct, form = form, classid = current_class, subject = current_sub_name.name, personid = personid)   
    else:
        return render_template('error.html', title='Error Page')
        


# -------------------------------------------------ADD STUDY MATERIAL---------------------------------------------------------------------------------------
@app.route("/add_study_material_single/<subject_handler_id>/<personid>", methods=['GET', 'POST'])
@login_required
def add_study_material_single(subject_handler_id, personid):
    if ((current_user.role == "Principal") or (current_user.role == "Teacher") or (current_user.role == "Super User")) :
        form = UpdateStudyMaterialsForm()
        t = Teacher.query.filter_by(user_id = personid).first()
        if request.method == 'POST':
            material = Material(name=form.name.data, link=form.link.data, sub_hand_id=subject_handler_id, material_type = "Study Material")
            db.session.add(material)
            db.session.commit()
            sub = Subject_handler.query.filter_by(id = subject_handler_id).first()
            class_id = sub.class_id
            subject = sub.subject_code
            
            sub_mast = Subject_master.query.filter_by(code = subject).first()
            students = []
            if sub_mast.description == "CORE":
                students = Student.query.filter_by(class_id = class_id).all()
            elif sub_mast.description == "FIRST LANGUAGE":
                students = Student.query.filter_by(class_id = class_id).all()
            elif sub_mast.description == "SECOND LANGUAGE":
                students = Student.query.filter_by(class_id = class_id, second_language = subject).all()
            elif sub_mast.description == "THIRD LANGUAGE":
                students = Student.query.filter_by(class_id = class_id, third_language = subject).all()
            elif sub_mast.description == "ELECTIVE":
                students = Student.query.filter_by(class_id = class_id, elective = subject).all()
            
            if students == []:
                flash("Please register students!","danger")
                return redirect(url_for('view_study_material', personid=personid, classid = class_id, subjectcode=subject))
            else:
                for i in students:
                    user = User.query.filter_by(id = i.user_id).first()
                    s = sub_mast.name.capitalize()
                    send_study_material_email(user, s)
                flash("Material successfully added!", "success")
                return redirect(url_for('view_study_material', personid=personid, classid = class_id, subjectcode=subject))
        
        return render_template('add_study_material_single.html', title='Add Study Material', t_ct = t.is_ct, form = form,personid=personid)   
    else:
        return render_template('error.html', title='Error Page')





# -------------------------------------------------DELETE STUDY MATERIAL---------------------------------------------------------------------------------------

@app.route("/delete_study_material/<personid>/<classid>/<subjectcode>", methods=['GET', 'POST'])
@login_required
def delete_study_material(personid, classid, subjectcode):
    if ((current_user.role == "Principal") or (current_user.role == "Teacher") or (current_user.role == "Super User")):
        if request.method == 'POST':
            to_delete = request.form.getlist('mycheckbox')
            if len(to_delete):
                material = Material.query.filter_by(id = to_delete[0]).first()
                for i in range(len(to_delete)):
                    material = Material.query.filter_by(id = to_delete[i]).first()
                    name = material.name
                    string = 'Material name: ' + str(name) + ' has been deleted! '
                    db.session.delete(material)
                    db.session.commit()       
                    flash(string ,'success')
        return redirect(url_for('view_study_material', personid = personid, classid = classid, subjectcode = subjectcode))
    else:
        return render_template('error.html', title='Error Page')




#--------------------------------------------------------------UPLOAD HOMEWORK---------------------------------------------------------------------
def send_homework_email(user,name, subject, sd, st, ed, et):
    subj = str(subject) + " - homework"
    msg = Message(subj, sender='shikshanoreply@gmail.com', recipients=[user.email])
    msg.body = f'''Hello!

Greetings from the team of Shiksha!

This is a notification for the addition of a new homework, {name} for the subject {subject}.
The homework will be available in your login for referance and submission between the below specified period:
Starting date: {sd}          Starting time: {st}
Ending date: {ed}            Ending time: {et}
Kindly login and check the same and make sure you make the submission in the form of drive link before the deadline to avoid late submission.

Thank you!
Hope you enjoy your journey with us! :)

NOTE: This email was sent from a notification-only address that cannot accept incoming email. Please do not reply to this message.'''
    #mail.send(msg)
    print(msg)


@app.route("/upload_homework/<personid>", methods = ["GET","POST"])
@login_required
def upload_homework(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        form = MaterialForm()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        class_list =[(0,"--Select--")]
        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        if request.method == 'POST':
            print("HERE")
            if not (form.start_date.data <= form.end_date.data):
                flash("Invalid dates!", "danger")  
                return redirect(url_for('upload_homework', personid=personid))
            elif (form.start_date.data == form.end_date.data):
                if not (form.start_time.data < form.end_time.data):
                    flash("Invalid timings!", "danger")  
                    return redirect(url_for('upload_homework', personid=personid))
            elif (form.end_date.data < datetime.date(datetime.now())):
                flash("Enter a valid end date!", "danger")  
                return redirect(url_for('upload_homework', personid=personid))
            elif (form.end_date.data == datetime.date(datetime.now())):
                if (form.end_time.data < datetime.time(datetime.now())):
                    flash("Enter a valid end time!", "danger")  
                    return redirect(url_for('upload_homework', personid=personid))
            class_id = form.class_opts.data
            subject = form.subject_opts.data
            current_teacher_tuple = Teacher.query.with_entities(Teacher.id).filter_by(user_id = personid).all()
            current_teacher_list = [value for (value,) in current_teacher_tuple]
            teacher_id = current_teacher_list[0]
            print(class_id)
            print(subject)
            print(teacher_id)
            current_subject_handler = Subject_handler.query.filter_by(class_id = class_id, subject_code = subject, teacher_id = teacher_id).first()
            print(current_subject_handler)
            subject_handler_id = current_subject_handler.id
            material = Material(name=form.name.data, link=form.link.data, sub_hand_id=subject_handler_id, start_time=form.start_time.data, end_time=form.end_time.data, start_date=form.start_date.data, end_date=form.end_date.data, material_type = "Homework")

            
            students = Student.query.filter_by (class_id = class_id).all()
            
        
            if students:
                class_subjects = Subjects.query.filter_by(class_id = class_id).first()
                core_subjects = [ class_subjects.core1, class_subjects.core2, class_subjects.core3, class_subjects.first_language]
                
                
                if subject in core_subjects:
                    db.session.add(material)
                    db.session.commit()
                    material1 = Material.query.filter_by(name=form.name.data, link=form.link.data, sub_hand_id=subject_handler_id, start_time=form.start_time.data, end_time=form.end_time.data, start_date=form.start_date.data, end_date=form.end_date.data, material_type ="Homework").first()
                    for i in students:
                        user_id = i.user_id
                        user = User.query.filter_by(id = user_id).first()
                        sub_code = form.subject_opts.data
                        sub = Subject_master.query.filter_by(code = sub_code).first()
                        sub = sub.name.capitalize()
                        send_homework_email(user, form.name.data, sub, form.start_date.data, form.start_time.data, form.end_date.data, form.end_time.data)
                        a = Submitted_attendance(student_id = i.id , material_id = material1.id)
                        db.session.add(a)
                        db.session.commit()
                    
                else:
                    count = 0
                    for i in students:
                        subjects_i = [i.second_language, i.third_language, i.elective]
                        if subject in subjects_i:                            
                            count+=1
                    if count > 0:
                        db.session.add(material)
                        db.session.commit()
                        material1 = Material.query.filter_by(name=form.name.data, link=form.link.data, sub_hand_id=subject_handler_id, start_time=form.start_time.data, end_time=form.end_time.data, start_date=form.start_date.data, end_date=form.end_date.data, material_type = "Homework").first()
                                
                        for i in students:
                            subjects_i = [i.second_language, i.third_language, i.elective]
                            if subject in subjects_i:
                                user_id = i.user_id
                                user = User.query.filter_by(id = user_id).first()
                                sub_code = form.subject_opts.data
                                sub = Subject_master.query.filter_by(code = sub_code).first()
                                sub = sub.name.capitalize()
                                send_homework_email(user, form.name.data,sub, form.start_date.data, form.start_time.data, form.end_date.data, form.end_time.data)
                                a = Submitted_attendance(student_id = i.id , material_id = material1.id)
                                db.session.add(a)
                                db.session.commit() 
                    
                    
                    elif count == 0:
                        flash("Please register students for the given subject","danger")
                        return redirect(url_for('upload_homework', title = "Upload Homework", personid=personid))

                flash('Homework uploaded', 'success')
                return redirect(url_for('upload_homework', title = "Upload Homework",personid=personid))
            
            else:
                flash("Please register students for the given class","danger")
                return redirect(url_for('upload_homework', title = "Upload Homework",personid=personid))


        t = Teacher.query.filter_by(user_id = personid).first()
        return render_template("upload_homework.html", title = "Upload Homework",form=form, personid=personid, t_ct = t.is_ct)
    else:
        return render_template('error.html', title='Error Page')





#-------------------------------------------------------------------VIEW HOMEWORKS----------------------------------------------------------------------
@app.route("/view_homeworks/<personid>", methods = ["GET","POST"])
@login_required
def view_homeworks(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        form = ViewMaterialsForm()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        class_list =[(0,"--Select--")]

        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        materials = ''
        if request.method == 'POST':
            class_id = form.class_opts.data
            subject = form.subject_opts.data
            if class_id != '0' and subject != '0':
                current_teacher_tuple = Teacher.query.with_entities(Teacher.id).filter_by(user_id = personid).all()
                current_teacher_list = [value for (value,) in current_teacher_tuple]
                teacher_id = current_teacher_list[0]
                current_subject_handler = Subject_handler.query.filter_by(class_id = class_id, subject_code = subject, teacher_id = teacher_id).first()
                subject_handler_id = current_subject_handler.id
                
                materials = Material.query.filter_by(sub_hand_id = subject_handler_id, material_type ="Homework").all()
                if not materials:
                    flash('No materials uploaded!', 'danger')

                return render_template('view_homeworks.html', form = form, t_ct = teacher.is_ct, materials=materials, sub_hand_id = subject_handler_id, personid=personid, classid = class_id, subjectcode = subject)

        return render_template("view_homeworks.html", form=form, t_ct = teacher.is_ct, materials = materials, personid=personid)
    else:
        return render_template('error.html', title='Error Page')




@app.route("/view_homework/<personid>/<subjectcode>/<classid>", methods = ["GET","POST"])
@login_required
def view_homework(personid,subjectcode,classid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        form = ViewMaterialsForm()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        class_list =[(0,"--Select--")]

        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        materials = ''
        current_teacher_tuple = Teacher.query.with_entities(Teacher.id).filter_by(user_id = personid).all()
        current_teacher_list = [value for (value,) in current_teacher_tuple]
        teacher_id = current_teacher_list[0]
        current_subject_handler = Subject_handler.query.filter_by(class_id = int(classid), subject_code = subjectcode, teacher_id = teacher_id).first()
        subject_handler_id = current_subject_handler.id
        materials = Material.query.filter_by(sub_hand_id = subject_handler_id, material_type = "Homework").all()
            
        if request.method == 'POST':
            class_id = form.class_opts.data
            subject = form.subject_opts.data
            if class_id != '0' and subject != '0':
                current_teacher_tuple = Teacher.query.with_entities(Teacher.id).filter_by(user_id = personid).all()
                current_teacher_list = [value for (value,) in current_teacher_tuple]
                teacher_id = current_teacher_list[0]
                current_subject_handler = Subject_handler.query.filter_by(class_id = class_id, subject_code = subject, teacher_id = teacher_id).first()
                subject_handler_id = current_subject_handler.id

                materials = Material.query.filter_by(sub_hand_id = subject_handler_id, material_type = "Homework").all()
                if not materials:
                    flash('No materials uploaded!', 'danger')
                return render_template('view_homeworks.html', form = form, t_ct = teacher.is_ct, materials=materials, sub_hand_id = subject_handler_id, personid=personid)
        elif request.method == 'GET':
            form.class_opts.data = str(classid)
            form.subject_opts.data = subjectcode
        return render_template("view_homeworks.html", form=form, materials = materials,subjectcode = subjectcode, t_ct = teacher.is_ct, sub_hand_id = subject_handler_id, personid=personid, classid= classid)
    else:
        return render_template('error.html', title='Error Page')



# -----------------------------------------EDIT HOMEWORKS---------------------------------------------------------------------------------------
@app.route("/edit_homework/<materialid>/<personid>", methods=['GET', 'POST'])
@login_required
def edit_homework(materialid, personid):
    if ((current_user.role == "Principal") or (current_user.role == "Teacher") or (current_user.role == "Super User")) :
        material = Material.query.filter_by(id = materialid).first()
        form = UpdateMaterialsForm()
        current_sub_hand_id = material.sub_hand_id
        sub_hand = Subject_handler.query.filter_by(id = current_sub_hand_id).first()
        current_class_id = sub_hand.class_id
        current_sub_code = sub_hand.subject_code
        current_sub_name = Subject_master.query.filter_by(code = current_sub_code).first()
        current_class = Class.query.filter_by(id=current_class_id).first()
        t = Teacher.query.filter_by(user_id = personid).first()
        if form.validate_on_submit():

            material.name = form.name.data
            material.link = form.link.data
            material.start_date = form.start_date.data
            material.start_time = form.start_time.data
            material.end_date = form.end_date.data
            material.end_time = form.end_time.data

            db.session.commit()

            flash("Homework updated successfully!", "success")
            return redirect(url_for('view_homework', personid=personid, classid = current_class_id, subjectcode = current_sub_code))
        elif request.method == 'GET':
            form.name.data = material.name
            form.link.data = material.link
            form.start_date.data = material.start_date
            form.start_time.data = material.start_time
            form.end_date.data = material.end_date
            form.end_time.data = material.end_time

        return render_template('edit_homework.html', title='Edit Homework', t_ct = t.is_ct, form = form, classid = current_class, subject = current_sub_name.name, personid = personid)   
    else:
        return render_template('error.html', title='Error Page')




# -------------------------------------------------ADD HOMEWORK---------------------------------------------------------------------------------------
@app.route("/add_homework_single/<subject_handler_id>/<personid>", methods=['GET', 'POST'])
@login_required
def add_homework_single(subject_handler_id, personid):
    if ((current_user.role == "Principal") or (current_user.role == "Teacher") or (current_user.role == "Super User")) :
        form = UpdateMaterialsForm()
        t = Teacher.query.filter_by(user_id = personid).first()
        if form.validate_on_submit():
            
            if not (form.start_date.data <= form.end_date.data):
                flash("Invalid dates!", "danger")  
                return redirect(url_for('add_homework_single', subject_handler_id = subject_handler_id, personid=personid))
            elif (form.start_date.data == form.end_date.data and form.start_time.data >= form.end_time.data):
                flash("Invalid timings!", "danger")  
                return redirect(url_for('add_homework_single', subject_handler_id = subject_handler_id, personid=personid))
            elif (form.end_date.data < datetime.date(datetime.now())):
                flash("Enter a valid end date!", "danger")  
                return redirect(url_for('add_homework_single', subject_handler_id = subject_handler_id, personid=personid))
            elif (form.end_date.data == datetime.date(datetime.now()) and form.end_time.data < datetime.time(datetime.now())):
                flash("Enter a valid end time!", "danger")  
                return redirect(url_for('add_homework_single', subject_handler_id = subject_handler_id, personid=personid))

            sub = Subject_handler.query.filter_by(id = subject_handler_id).first()
            class_id = sub.class_id
            students = Student.query.filter_by (class_id = class_id).all()
            class_subjects = Subjects.query.filter_by(class_id = class_id).first()
            all_subjects = [ class_subjects.core1, class_subjects.core2, class_subjects.core3, class_subjects.first_language, class_subjects.second_language1, class_subjects.second_language2, class_subjects.second_language3, class_subjects.third_language1, class_subjects.third_language2, class_subjects.third_language3, class_subjects.elective1, class_subjects.elective2 ]
            subject = sub.subject_code
            
            count = 0
            if subject in all_subjects:
                core_subjects = [ class_subjects.core1, class_subjects.core2, class_subjects.core3, class_subjects.first_language]
                if subject in core_subjects:
                    if students:
                        count +=1
                        
                else:
                    if students:
                        for i in students:
                            selective_list = [ i.second_language, i.third_language, i.elective]
                            if subject in selective_list:
                                count+=1
                                break
            if count == 0 :
                flash("Please register students for the given subject","danger")
                return redirect(url_for('add_homework_single', subject_handler_id = subject_handler_id, personid=personid))

            material = Material(name=form.name.data, link=form.link.data, sub_hand_id=subject_handler_id, start_time=form.start_time.data, end_time=form.end_time.data, start_date=form.start_date.data, end_date=form.end_date.data, material_type = "Homework")
            db.session.add(material)
            db.session.commit()
            material = Material.query.filter_by(name=form.name.data, link=form.link.data, sub_hand_id=subject_handler_id, start_time=form.start_time.data, end_time=form.end_time.data, start_date=form.start_date.data, end_date=form.end_date.data, material_type = "Homework").first()
            sub_hand = Subject_handler.query.filter_by(id = subject_handler_id).first()
            sub_name = sub_hand.class_subjects.name
            if subject in all_subjects:
                core_subjects = [ class_subjects.core1, class_subjects.core2, class_subjects.core3, class_subjects.first_language]
                if subject in core_subjects:
                    for i in students:
                        user = User.query.filter_by(id = i.user_id).first()
                        sub_name = sub_name.capitalize()
                        send_homework_email(user,form.name.data, sub_name, form.start_date.data, form.start_time.data, form.end_date.data, form.end_time.data)
                        
                        attendance = Submitted_attendance(student_id = i.id , material_id = material.id)
                        db.session.add(attendance)

                else:
                    for i in students:
                        selective_list = [ i.second_language, i.third_language, i.elective]
                        if subject in selective_list:
                            user = User.query.filter_by(id = i.user_id).first()
                            sub_name = sub_name.capitalize()
                            send_homework_email(user,form.name.data ,sub_name, form.start_date.data, form.start_time.data, form.end_date.data, form.end_time.data)
                        
                            attendance = Submitted_attendance(student_id = i.id , material_id = material.id)
                            db.session.add(attendance)
                db.session.commit()
            
            

            flash("Homework successfully added!", "success")
            return redirect(url_for('view_homework', personid=personid, classid = class_id, subjectcode=subject))
            
        return render_template('add_homework_single.html', title='Add Homework', t_ct = t.is_ct, form = form, personid=personid)   
    else:
        return render_template('error.html', title='Error Page')


# -------------------------------------------------DELETE HOMEWORK---------------------------------------------------------------------------------------

@app.route("/delete_homework/<personid>/<classid>/<subjectcode>", methods=['GET', 'POST'])
@login_required
def delete_homework(personid, classid, subjectcode):
    if ((current_user.role == "Principal") or (current_user.role == "Teacher") or (current_user.role == "Super User")) :
        if request.method == 'POST':
            to_delete = request.form.getlist('mycheckbox')
            if len(to_delete):
                material = Material.query.filter_by(id = to_delete[0]).first()
                for i in range(len(to_delete)):
                    material = Material.query.filter_by(id = to_delete[i]).first()
                    attendance = Submitted_attendance.query.filter_by(material_id = material.id).all()
                    for j in attendance:
                        db.session.delete(j)
                    name = material.name
                    string = 'Material name: ' + str(name) + ' has been deleted! '
                    db.session.delete(material)
                    db.session.commit()       
                    flash(string ,'success')
        return redirect(url_for('view_homework', personid = personid, classid = classid, subjectcode = subjectcode))
    else:
        return render_template('error.html', title='Error Page')






@app.route('/matname/<personid>/<class_id>/<subject_code>/<mat_type>', methods = ["GET","POST"])
def choose_name(personid, class_id, subject_code, mat_type):
    teacher = Teacher.query.filter_by(user_id=personid).first()
    sub_handler = Subject_handler.query.filter_by(teacher_id=teacher.id, class_id=class_id, subject_code=subject_code).first()
    materials = Material.query.filter_by(sub_hand_id = sub_handler.id, material_type = mat_type).all()
    material_Array = []
    for mat in materials:
        matObj = {}
        matObj['id'] = mat.id
        matObj['name'] = mat.name 
        material_Array.append(matObj)
    if material_Array == []:
        matObj = {}
        matObj['id'] = '0'
        matObj['name'] = 'There are no materials' 
        material_Array.append(matObj)
    return jsonify( { 'materials' : material_Array } ) 


#-------------------------------------------------VIEW HOMEWORK SUBMISSIONS-------------------------------------------------------
@app.route("/view_hw_submissions/<personid>", methods = ["GET","POST"])
def view_hw_submissions(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        form = ViewSubmissionsForm()

        teacher = Teacher.query.filter_by(user_id=personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        class_list =[(0,"--Select--")]
        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        form.name_opts.choices = [(0,'--Select--')]
        if request.method == "POST":
            classid = form.class_opts.data
            sub_code = form.subject_opts.data
            mat_id = form.name_opts.data
            submitted = Submitted_attendance.query.filter_by(material_id=mat_id).all()
            return render_template('view_hw_submissions.html', title='Homework Submissions', form=form, submitted=submitted, personid=personid, t_ct=teacher.is_ct)
        return render_template('view_hw_submissions.html', title='Homework Submissions', form=form, submitted=0, personid=personid, t_ct=teacher.is_ct)

    else:
        return render_template('error.html', title='Error Page')


#--------------------------------------------------------------UPLOAD TEST---------------------------------------------------------------------
def send_test_email(user, name, subject, sd, st, ed, et):
    subj = str(subject) + " - test"
    msg = Message(subj, sender='shikshanoreply@gmail.com', recipients=[user.email])
    msg.body = f'''Hello!

Greetings from the team of Shiksha!

This is a notification for the addition of a new test, {name} for the subject {subject}.
The test will be available in your login for referance and submission between the below specified period:
Starting date: {sd}          Starting time: {st}
Ending date: {ed}            Ending time: {et}
Kindly login and check the same and make sure you make the submission in the form of drive link before the deadline to avoid late submission.

Thank you!
Hope you enjoy your journey with us! :)

NOTE: This email was sent from a notification-only address that cannot accept incoming email. Please do not reply to this message.'''
    #mail.send(msg)
    print(msg)


@app.route("/upload_test/<personid>", methods = ["GET","POST"])
@login_required
def upload_test(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        form = MaterialForm()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        class_list =[(0,"--Select--")]
        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        if request.method == 'POST':
            print("HERE")
            if not (form.start_date.data <= form.end_date.data):
                flash("Invalid dates!", "danger")  
                return redirect(url_for('upload_test', personid=personid))
            elif (form.start_date.data == form.end_date.data):
                if not (form.start_time.data < form.end_time.data):
                    flash("Invalid timings!", "danger")  
                    return redirect(url_for('upload_test', personid=personid))
            elif (form.end_date.data < datetime.date(datetime.now())):
                flash("Enter a valid end date!", "danger")  
                return redirect(url_for('upload_test', personid=personid))
            elif (form.end_date.data == datetime.date(datetime.now())):
                if (form.end_time.data < datetime.time(datetime.now())):
                    flash("Enter a valid end time!", "danger")  
                    return redirect(url_for('upload_test', personid=personid))
            class_id = form.class_opts.data
            subject = form.subject_opts.data
            current_teacher_tuple = Teacher.query.with_entities(Teacher.id).filter_by(user_id = personid).all()
            current_teacher_list = [value for (value,) in current_teacher_tuple]
            teacher_id = current_teacher_list[0]
            print(class_id)
            print(subject)
            print(teacher_id)
            current_subject_handler = Subject_handler.query.filter_by(class_id = class_id, subject_code = subject, teacher_id = teacher_id).first()
            print(current_subject_handler)
            subject_handler_id = current_subject_handler.id
            material = Material(name=form.name.data, link=form.link.data, sub_hand_id=subject_handler_id, start_time=form.start_time.data, end_time=form.end_time.data, start_date=form.start_date.data, end_date=form.end_date.data, material_type = "Test")
            #db.session.add(material)
            #db.session.commit()
            
            
            students = Student.query.filter_by (class_id = class_id).all()
            
        
            if students:
                class_subjects = Subjects.query.filter_by(class_id = class_id).first()
                core_subjects = [ class_subjects.core1, class_subjects.core2, class_subjects.core3, class_subjects.first_language]
                
                
                if subject in core_subjects:
                    db.session.add(material)
                    db.session.commit()
                    material1 = Material.query.filter_by(name=form.name.data, link=form.link.data, sub_hand_id=subject_handler_id, start_time=form.start_time.data, end_time=form.end_time.data, start_date=form.start_date.data, end_date=form.end_date.data, material_type ="Test").first()
                    for i in students:
                        user_id = i.user_id
                        user = User.query.filter_by(id = user_id).first()
                        sub_code = form.subject_opts.data
                        sub = Subject_master.query.filter_by(code = sub_code).first()
                        sub = sub.name
                        sub = sub.capitalize()
                        send_test_email(user, form.name.data, sub, form.start_date.data, form.start_time.data, form.end_date.data, form.end_time.data)
                        a = Submitted_attendance(student_id = i.id , material_id = material1.id)
                        db.session.add(a)
                        db.session.commit()
                    
                else:
                    count = 0
                    for i in students:
                        subjects_i = [i.second_language, i.third_language, i.elective]
                        if subject in subjects_i:                            
                            count+=1
                    if count > 0:
                        db.session.add(material)
                        db.session.commit()
                        material1 = Material.query.filter_by(name=form.name.data, link=form.link.data, sub_hand_id=subject_handler_id, start_time=form.start_time.data, end_time=form.end_time.data, start_date=form.start_date.data, end_date=form.end_date.data, material_type = "Test").first()
                                
                        for i in students:
                            subjects_i = [i.second_language, i.third_language, i.elective]
                            if subject in subjects_i:
                                user_id = i.user_id
                                user = User.query.filter_by(id = user_id).first()
                                sub_code = form.subject_opts.data
                                sub = Subject_master.query.filter_by(code = sub_code).first()
                                sub = sub.name
                                sub = sub.capitalize()
                                send_test_email(user,form.name.data, sub, form.start_date.data, form.start_time.data, form.end_date.data, form.end_time.data)
                                a = Submitted_attendance(student_id = i.id , material_id = material1.id)
                                db.session.add(a)
                                db.session.commit() 
                    
                    
                    elif count == 0:
                        flash("Please register students for the given subject","danger")
                        return redirect(url_for('upload_test',personid=personid))

                flash('Test uploaded', 'success')
                return redirect(url_for('upload_test', personid=personid))
            
            else:
                flash("Please register students for the given class","danger")
                return redirect(url_for('upload_test', personid=personid))


        t = Teacher.query.filter_by(user_id = personid).first()
        return render_template("upload_homework.html",title = "Upload Test", form=form, personid=personid, t_ct = t.is_ct)
    else:
        return render_template('error.html', title='Error Page')


#-------------------------------------------------------------------VIEW TESTS----------------------------------------------------------------------
@app.route("/view_tests/<personid>", methods = ["GET","POST"])
@login_required
def view_tests(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        form = ViewMaterialsForm()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        class_list =[(0,"--Select--")]

        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        materials = ''
        if request.method == 'POST':
            class_id = form.class_opts.data
            subject = form.subject_opts.data
            if class_id != '0' and subject != '0':
                current_teacher_tuple = Teacher.query.with_entities(Teacher.id).filter_by(user_id = personid).all()
                current_teacher_list = [value for (value,) in current_teacher_tuple]
                teacher_id = current_teacher_list[0]
                current_subject_handler = Subject_handler.query.filter_by(class_id = class_id, subject_code = subject, teacher_id = teacher_id).first()
                subject_handler_id = current_subject_handler.id
                
                materials = Material.query.filter_by(sub_hand_id = subject_handler_id, material_type ="Test").all()
                if not materials:
                    flash('No tests uploaded!', 'danger')

                return render_template('view_tests.html', form = form, t_ct = teacher.is_ct, materials=materials, sub_hand_id = subject_handler_id, personid=personid, classid = class_id, subjectcode = subject)

        return render_template("view_tests.html", form=form, t_ct = teacher.is_ct, materials = materials, personid=personid)
    else:
        return render_template('error.html', title='Error Page')




@app.route("/view_test/<personid>/<subjectcode>/<classid>", methods = ["GET","POST"])
@login_required
def view_test(personid,subjectcode,classid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        form = ViewMaterialsForm()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        class_list =[(0,"--Select--")]

        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        materials = ''
        current_teacher_tuple = Teacher.query.with_entities(Teacher.id).filter_by(user_id = personid).all()
        current_teacher_list = [value for (value,) in current_teacher_tuple]
        teacher_id = current_teacher_list[0]
        current_subject_handler = Subject_handler.query.filter_by(class_id = int(classid), subject_code = subjectcode, teacher_id = teacher_id).first()
        subject_handler_id = current_subject_handler.id
        materials = Material.query.filter_by(sub_hand_id = subject_handler_id, material_type = "Test").all()
            
        if request.method == 'POST':
            class_id = form.class_opts.data
            subject = form.subject_opts.data
            if class_id != '0' and subject != '0':
                current_teacher_tuple = Teacher.query.with_entities(Teacher.id).filter_by(user_id = personid).all()
                current_teacher_list = [value for (value,) in current_teacher_tuple]
                teacher_id = current_teacher_list[0]
                current_subject_handler = Subject_handler.query.filter_by(class_id = class_id, subject_code = subject, teacher_id = teacher_id).first()
                subject_handler_id = current_subject_handler.id

                materials = Material.query.filter_by(sub_hand_id = subject_handler_id, material_type = "Test").all()
                if not materials:
                    flash('No materials uploaded!', 'danger')
                return render_template('view_tests.html', form = form, t_ct = teacher.is_ct, materials=materials, sub_hand_id = subject_handler_id, personid=personid)
        elif request.method == 'GET':
            form.class_opts.data = str(classid)
            form.subject_opts.data = subjectcode
        return render_template("view_tests.html", form=form, materials = materials,subjectcode = subjectcode, t_ct = teacher.is_ct, sub_hand_id = subject_handler_id, personid=personid, classid= classid)
    else:
        return render_template('error.html', title='Error Page')




# -----------------------------------------EDIT TESTS---------------------------------------------------------------------------------------
@app.route("/edit_test/<materialid>/<personid>", methods=['GET', 'POST'])
@login_required
def edit_test(materialid, personid):
    if ((current_user.role == "Principal") or (current_user.role == "Teacher") or (current_user.role == "Super User")) :
        material = Material.query.filter_by(id = materialid).first()
        form = UpdateMaterialsForm()
        current_sub_hand_id = material.sub_hand_id
        sub_hand = Subject_handler.query.filter_by(id = current_sub_hand_id).first()
        current_class_id = sub_hand.class_id
        current_sub_code = sub_hand.subject_code
        current_sub_name = Subject_master.query.filter_by(code = current_sub_code).first()
        current_class = Class.query.filter_by(id=current_class_id).first()
        t = Teacher.query.filter_by(user_id = personid).first()
        if form.validate_on_submit():

            material.name = form.name.data
            material.link = form.link.data
            material.start_date = form.start_date.data
            material.start_time = form.start_time.data
            material.end_date = form.end_date.data
            material.end_time = form.end_time.data

            db.session.commit()

            flash("Test updated successfully!", "success")
            return redirect(url_for('view_test', personid=personid, classid = current_class_id, subjectcode = current_sub_code))
        elif request.method == 'GET':
            form.name.data = material.name
            form.link.data = material.link
            form.start_date.data = material.start_date
            form.start_time.data = material.start_time
            form.end_date.data = material.end_date
            form.end_time.data = material.end_time

        return render_template('edit_homework.html', title='Edit Test', t_ct = t.is_ct, form = form, classid = current_class, subject = current_sub_name.name, personid = personid)   
    else:
        return render_template('error.html', title='Error Page')




# -------------------------------------------------ADD TEST---------------------------------------------------------------------------------------
@app.route("/add_test_single/<subject_handler_id>/<personid>", methods=['GET', 'POST'])
@login_required
def add_test_single(subject_handler_id, personid):
    if ((current_user.role == "Principal") or (current_user.role == "Teacher") or (current_user.role == "Super User")) :
        form = UpdateMaterialsForm()
        t = Teacher.query.filter_by(user_id = personid).first()
        if form.validate_on_submit():

            if not (form.start_date.data <= form.end_date.data):
                flash("Invalid dates!", "danger")  
                return redirect(url_for('add_test_single', subject_handler_id = subject_handler_id, personid=personid))
            elif (form.start_date.data == form.end_date.data and form.start_time.data >= form.end_time.data):
                flash("Invalid timings!", "danger")  
                return redirect(url_for('add_test_single', subject_handler_id = subject_handler_id, personid=personid))
            elif (form.end_date.data < datetime.date(datetime.now())):
                flash("Enter a valid end date!", "danger")  
                return redirect(url_for('add_test_single', subject_handler_id = subject_handler_id, personid=personid))
            elif (form.end_date.data == datetime.date(datetime.now()) and form.end_time.data < datetime.time(datetime.now())):
                flash("Enter a valid end time!", "danger")  
                return redirect(url_for('add_test_single', subject_handler_id = subject_handler_id, personid=personid))


            sub = Subject_handler.query.filter_by(id = subject_handler_id).first()
            class_id = sub.class_id
            material = Material.query.filter_by(name=form.name.data, link=form.link.data, sub_hand_id=subject_handler_id, start_time=form.start_time.data, end_time=form.end_time.data, start_date=form.start_date.data, end_date=form.end_date.data, material_type = "Test").first()
            students = Student.query.filter_by (class_id = class_id).all()
            class_subjects = Subjects.query.filter_by(class_id = class_id).first()
            all_subjects = [ class_subjects.core1, class_subjects.core2, class_subjects.core3, class_subjects.first_language, class_subjects.second_language1, class_subjects.second_language2, class_subjects.second_language3, class_subjects.third_language1, class_subjects.third_language2, class_subjects.third_language3, class_subjects.elective1, class_subjects.elective2 ]
            subject = sub.subject_code

            count = 0
            if subject in all_subjects:
                core_subjects = [ class_subjects.core1, class_subjects.core2, class_subjects.core3, class_subjects.first_language]
                if subject in core_subjects:
                    if students:
                        count +=1
                        
                else:
                    if students:
                        for i in students:
                            selective_list = [ i.second_language, i.third_language, i.elective]
                            if subject in selective_list:
                                count+=1
                                break
            if count == 0 :
                flash("Please register students for the given subject","danger")
                return redirect(url_for('add_test_single', subject_handler_id = subject_handler_id, personid=personid))
            
            material = Material(name=form.name.data, link=form.link.data, sub_hand_id=subject_handler_id, start_time=form.start_time.data, end_time=form.end_time.data, start_date=form.start_date.data, end_date=form.end_date.data, material_type = "Test")
            db.session.add(material)
            db.session.commit()
            material = Material.query.filter_by(name=form.name.data, link=form.link.data, sub_hand_id=subject_handler_id, start_time=form.start_time.data, end_time=form.end_time.data, start_date=form.start_date.data, end_date=form.end_date.data, material_type = "Test").first()
            sub_hand = Subject_handler.query.filter_by(id = subject_handler_id).first()
            sub_name = sub_hand.class_subjects.name
            if subject in all_subjects:
                core_subjects = [ class_subjects.core1, class_subjects.core2, class_subjects.core3, class_subjects.first_language]
                if subject in core_subjects:
                    for i in students:
                        user = User.query.filter_by(id = i.user_id).first()
                        sub_name = sub_name.capitalize()
                        send_test_email(user, form.name.data, sub_name, form.start_date.data, form.start_time.data, form.end_date.data, form.end_time.data)
                        
                        attendance = Submitted_attendance(student_id = i.id , material_id = material.id)
                        db.session.add(attendance)

                else:
                    for i in students:
                        selective_list = [ i.second_language, i.third_language, i.elective]
                        if subject in selective_list:
                            user = User.query.filter_by(id = i.user_id).first()
                            sub_name = sub_name.capitalize()
                            send_test_email(user, sub_name, form.start_date.data, form.start_time.data, form.end_date.data, form.end_time.data)
                            attendance = Submitted_attendance(student_id = i.id , material_id = material.id)
                            db.session.add(attendance)
                db.session.commit()
            flash("Test successfully added!", "success")
            return redirect(url_for('view_test', personid=personid, classid = class_id, subjectcode=subject))
            
        return render_template('add_homework_single.html', title='Add Test', t_ct = t.is_ct, form = form, personid=personid)   
    else:
        return render_template('error.html', title='Error Page')


# -------------------------------------------------DELETE TEST---------------------------------------------------------------------------------------

@app.route("/delete_test/<personid>/<classid>/<subjectcode>", methods=['GET', 'POST'])
@login_required
def delete_test(personid, classid, subjectcode):
    if ((current_user.role == "Principal") or (current_user.role == "Teacher") or (current_user.role == "Super User")) :
        if request.method == 'POST':
            to_delete = request.form.getlist('mycheckbox')
            if len(to_delete):
                material = Material.query.filter_by(id = to_delete[0]).first()
                for i in range(len(to_delete)):
                    material = Material.query.filter_by(id = to_delete[i]).first()
                    attendance = Submitted_attendance.query.filter_by(material_id = material.id).all()
                    for j in attendance:
                        db.session.delete(j)
                    name = material.name
                    string = 'Material name: ' + str(name) + ' has been deleted! '
                    db.session.delete(material)
                    db.session.commit()       
                    flash(string ,'success')
        return redirect(url_for('view_test', personid = personid, classid = classid, subjectcode = subjectcode))
    else:
        return render_template('error.html', title='Error Page')



#-------------------------------------------------VIEW TEST SUBMISSIONS-------------------------------------------------------
@app.route("/view_test_submissions/<personid>", methods = ["GET","POST"])
def view_test_submissions(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Super User") or (current_user.role == "Teacher")) :
        form = ViewSubmissionsForm()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        class_list =[(0,"--Select--")]
        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        form.name_opts.choices = [(0,'--Select--')]
        if request.method == "POST":
            classid = form.class_opts.data
            sub_code = form.subject_opts.data
            mat_id = form.name_opts.data
            submitted = Submitted_attendance.query.filter_by(material_id=mat_id).all()
            return render_template('view_test_submissions.html', title='Test Submissions', form=form, submitted=submitted, personid=personid, t_ct=teacher.is_ct)
        return render_template('view_test_submissions.html', title='Test Submissions', form=form, submitted=0, personid=personid, t_ct=teacher.is_ct)

    else:
        return render_template('error.html', title='Error Page')











#--------------------------------------------------------------------SUBJECT STUDENTS HOMEWORK REPORT GENERATION------------------------------------------------------------
@app.route("/homework_report_subject/<personid>", methods = ['GET','POST'])

@login_required
def homework_report_subject(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Teacher") or (current_user.role == "Super User")):
        form = ViewSubjectStudents()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        class_list =[(0,"--Select--")]
        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        class_list = sorted(class_list, key = lambda x: x[0])
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        if request.method == "POST":
            current_class = form.class_opts.data
            current_subject = form.subject_opts.data
            if current_class != '0' and current_subject != '0':


                class_query = Class.query.filter_by(id = current_class).first()
                subject_query = Subject_master.query.filter_by(code = current_subject).first()

                grade = class_query.grade
                section = class_query.section
                subject = subject_query.name

                current_subject_handler = Subject_handler.query.filter_by(class_id = current_class, subject_code = current_subject, teacher_id = teacher.id).first()

                current_materials = Material.query.filter_by(sub_hand_id = current_subject_handler.id, material_type = "Homework").all()

                data_list = []
                for material in current_materials:
                    t = [material]
                    all_students = Submitted_attendance.query.filter_by(material_id = material.id).all()
                    submitted_students = []
                    not_submitted_students = []
                    for s in all_students:
                        student_dict = {}
                        stud_name_query = Student.query.filter_by(id = s.student_id).first()
                        stud_fname = stud_name_query.first_name
                        stud_lname = stud_name_query.last_name
                        student_dict['id'] = s.student_id
                        student_dict['fname'] = stud_fname
                        student_dict['lname'] = stud_lname
                        if s.submitted:
                            submitted_students.append(student_dict)
                        else:
                            not_submitted_students.append(student_dict)

                    t.append(submitted_students)
                    t.append(not_submitted_students)

                    
                    data_list.append(t)
                print(data_list)     
                rendered = render_template('pdf_template_hw_subject.html', grade=grade, section=section, subject=subject, data_list = data_list)
                pdf = pdfkit.from_string(rendered, False)

                response = make_response(pdf)
                response.headers['Content-Type'] = 'application/pdf'
                response.headers['Content-Disposition'] = 'inline; filename=output.pdf'

                return response
        t = Teacher.query.filter_by(id = personid).first()
        return render_template('pdf_template_select.html', title='Subject Report', t_ct = t.is_ct, form = form, personid=personid)
    else:
        return render_template('error.html', title='Error Page')




#--------------------------------------------------------------------SUBJECT STUDENTS TEST REPORT GENERATION------------------------------------------------------------
@app.route("/test_report_subject/<personid>", methods = ['GET','POST'])

@login_required
def test_report_subject(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Teacher") or (current_user.role == "Super User")):
        form = ViewSubjectStudents()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        subjecthandle = Subject_handler.query.filter_by(teacher_id=teacher.id).all()
        class_list =[(0,"--Select--")]
        for i in subjecthandle:
            one = (i.class_id , str(i.class_sub.grade) + ' - ' + str(i.class_sub.section))
            if one not in class_list:
                class_list.append(one)
        class_list = sorted(class_list, key = lambda x: x[0])
        form.class_opts.choices = class_list
        form.subject_opts.choices = [(0,'--Select--')]
        if request.method == "POST":
            current_class = form.class_opts.data
            current_subject = form.subject_opts.data
            if current_class != '0' and current_subject != '0':


                class_query = Class.query.filter_by(id = current_class).first()
                subject_query = Subject_master.query.filter_by(code = current_subject).first()

                grade = class_query.grade
                section = class_query.section
                subject = subject_query.name

                current_subject_handler = Subject_handler.query.filter_by(class_id = current_class, subject_code = current_subject, teacher_id = teacher.id).first()

                current_materials = Material.query.filter_by(sub_hand_id = current_subject_handler.id, material_type = "Test").all()

                data_list = []
                for material in current_materials:
                    t = [material]
                    all_students = Submitted_attendance.query.filter_by(material_id = material.id).all()
                    submitted_students = []
                    not_submitted_students = []
                    for s in all_students:
                        student_dict = {}
                        stud_name_query = Student.query.filter_by(id = s.student_id).first()
                        stud_fname = stud_name_query.first_name
                        stud_lname = stud_name_query.last_name
                        student_dict['id'] = s.student_id
                        student_dict['fname'] = stud_fname
                        student_dict['lname'] = stud_lname
                        if s.submitted:
                            submitted_students.append(student_dict)
                        else:
                            not_submitted_students.append(student_dict)

                    t.append(submitted_students)
                    t.append(not_submitted_students)

                    
                    data_list.append(t)
                print(data_list)     
                rendered = render_template('pdf_template_test_subject.html', grade=grade, section=section, subject=subject, data_list = data_list)
                pdf = pdfkit.from_string(rendered, False)

                response = make_response(pdf)
                response.headers['Content-Type'] = 'application/pdf'
                response.headers['Content-Disposition'] = 'inline; filename=output.pdf'

                return response
        t = Teacher.query.filter_by(id = personid).first()
        return render_template('pdf_template_select.html', title='Subject Test Report', t_ct = t.is_ct, form = form, personid=personid)
    else:
        return render_template('error.html', title='Error Page')




#-------------------------------------------------------------------CLASS STUDENTS HOMEWORKS REPORT GENERATION--------------------------------------------------------------------------
@app.route("/homework_report_class/<personid>", methods = ['GET','POST'])
@login_required
def homework_report_class(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Teacher") or (current_user.role == "Super User")) :
        form = StudentSubjects()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        curr_class = Class.query.filter_by(class_teacher = teacher.id).first()
        class_ = str(curr_class.grade) +  "  -  " + curr_class.section

        form.subject_opts.choices = [(0,'--Select--')]

        subs = Subject_handler.query.filter_by(class_id = curr_class.id).all()
        subjects_list = []
        for i in range(len(subs)):
            query = Subject_master.query.filter_by(code = subs[i].subject_code).first()
            s = (subs[i].subject_code,query.name)
            subjects_list.append(s)
        form.subject_opts.choices = subjects_list
        if request.method == "POST":

            current_sub = form.subject_opts.data

            sub_hand_query = Subject_handler.query.filter_by(class_id = curr_class.id, subject_code = current_sub).first()
            sub_master_query = Subject_master.query.filter_by(code = current_sub).first()

            if sub_hand_query.teacher_id:
                curr_teacher = sub_hand_query.teacher_id
                curr_teacher_query = Teacher.query.filter_by(id = curr_teacher).first()
                current_materials = Material.query.filter_by(sub_hand_id = sub_hand_query.id, material_type = "Homework").all()
                
                data_list = []
        
                for material in current_materials:
                    t = [material]
                    all_students = Submitted_attendance.query.filter_by(material_id = material.id).all()
                    submitted_students = []
                    not_submitted_students = []
                    for s in all_students:
                        student_dict = {}
                        stud_name_query = Student.query.filter_by(id = s.student_id).first()
                        stud_fname = stud_name_query.first_name
                        stud_lname = stud_name_query.last_name
                        student_dict['id'] = s.student_id
                        student_dict['fname'] = stud_fname
                        student_dict['lname'] = stud_lname
                        if s.submitted:
                            submitted_students.append(student_dict)
                        else:
                            not_submitted_students.append(student_dict)

                    t.append(submitted_students)
                    t.append(not_submitted_students)

                    
                    data_list.append(t)
                print(data_list)            

                rendered = render_template('pdf_template_hw_class.html',data_list = data_list, grade = curr_class.grade, section = curr_class.section, subject = sub_master_query.name, fteacher = curr_teacher_query.first_name, lteacher = curr_teacher_query.last_name, t_ct = teacher.is_ct)
                pdf = pdfkit.from_string(rendered, False)

                response = make_response(pdf)
                response.headers['Content-Type'] = 'application/pdf'
                response.headers['Content-Disposition'] = 'inline; filename=output.pdf'

                return response

            else:
                flash("Teacher not assigned for the chosen subject!","danger")
                return redirect(url_for('report_class', personid = personid))

        return render_template('pdf_template_select_class.html', title='Class Report', form = form, personid=personid, class_ = class_, t_ct = teacher.is_ct)

    else:
        return render_template('error.html', title='Error Page')







#-------------------------------------------------------------------CLASS STUDENTS TESTS REPORT GENERATION--------------------------------------------------------------------------
@app.route("/test_report_class/<personid>", methods = ['GET','POST'])
@login_required
def test_report_class(personid):
    if ((current_user.role == "Principal") or (current_user.role == "Teacher") or (current_user.role == "Super User")) :
        form = StudentSubjects()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        curr_class = Class.query.filter_by(class_teacher = teacher.id).first()
        class_ = str(curr_class.grade) +  "  -  " + curr_class.section

        form.subject_opts.choices = [(0,'--Select--')]

        subs = Subject_handler.query.filter_by(class_id = curr_class.id).all()
        subjects_list = []
        for i in range(len(subs)):
            query = Subject_master.query.filter_by(code = subs[i].subject_code).first()
            s = (subs[i].subject_code,query.name)
            subjects_list.append(s)
        form.subject_opts.choices = subjects_list
        if request.method == "POST":

            current_sub = form.subject_opts.data
            sub_hand_query = Subject_handler.query.filter_by(class_id = curr_class.id, subject_code = current_sub).first()
            sub_master_query = Subject_master.query.filter_by(code = current_sub).first()

            if sub_hand_query.teacher_id:
                curr_teacher = sub_hand_query.teacher_id
                curr_teacher_query = Teacher.query.filter_by(id = curr_teacher).first()
                current_materials = Material.query.filter_by(sub_hand_id = sub_hand_query.id, material_type = "Test").all()
                
                data_list = []
        
                for material in current_materials:
                    t = [material]
                    all_students = Submitted_attendance.query.filter_by(material_id = material.id).all()
                    submitted_students = []
                    not_submitted_students = []
                    for s in all_students:
                        student_dict = {}
                        stud_name_query = Student.query.filter_by(id = s.student_id).first()
                        stud_fname = stud_name_query.first_name
                        stud_lname = stud_name_query.last_name
                        student_dict['id'] = s.student_id
                        student_dict['fname'] = stud_fname
                        student_dict['lname'] = stud_lname
                        if s.submitted:
                            submitted_students.append(student_dict)
                        else:
                            not_submitted_students.append(student_dict)

                    t.append(submitted_students)
                    t.append(not_submitted_students)

                    
                    data_list.append(t)
                print(data_list)            

                rendered = render_template('pdf_template_test_class.html',data_list = data_list, grade = curr_class.grade, section = curr_class.section, subject = sub_master_query.name, fteacher = curr_teacher_query.first_name, lteacher = curr_teacher_query.last_name, t_ct = teacher.is_ct)
                pdf = pdfkit.from_string(rendered, False)

                response = make_response(pdf)
                response.headers['Content-Type'] = 'application/pdf'
                response.headers['Content-Disposition'] = 'inline; filename=output.pdf'

                return response

            else:
                flash("Teacher not assigned for the chosen subject!","danger")
                return redirect(url_for('report_class', personid = personid))

        return render_template('pdf_template_select_class.html', title='Class Report', form = form, personid=personid, class_ = class_, t_ct = teacher.is_ct)

    else:
        return render_template('error.html', title='Error Page')



























































# -----------------------------------------------STUDENT-----------------------------------------------------
# ----------------------------------------- SUBJECTS ENROLLED ---------------------------------------------------------
@app.route("/subject_taken")
@login_required
def subject_taken():   
    if ((current_user.role == "Student") or (current_user.role == "Super User")) :
        user_student = User.query.filter_by(id = current_user.id).first()
        student =  Student.query.filter_by(user_id = user_student.id).first()
        class_id = student.class_id
        subjects = Subjects.query.filter_by(class_id = class_id).first()
        subject_code_list = [ subjects.core1, subjects.core2, subjects.core3, subjects.first_language, student.second_language, student.third_language, student.elective ]
        subjects_list = []
        for i in subject_code_list:
            if i and i != '-':
                subject = Subject_handler.query.filter_by(class_id = class_id, subject_code = i).first()
                subjects_list.append(subject)
        return render_template('subjects_taken.html', title='Subjects', subjects_list = subjects_list)
    else:
        return render_template('error.html', title='Error Page')



# ----------------------------------------- STUDY MATERIALS ---------------------------------------------------------
@app.route("/study_materials", methods=['GET', 'POST'])
@login_required
def study_materials():   
    if ((current_user.role == "Student") or (current_user.role == "Super User")) :
        form = StudentSubjects()
        user_student = User.query.filter_by(id = current_user.id).first()
        student =  Student.query.filter_by(user_id = user_student.id).first()
        class_id = student.class_id
        subjects = Subjects.query.filter_by(class_id = class_id).first()
        
        subject_code_list = [ subjects.core1, subjects.core2, subjects.core3, subjects.first_language, student.second_language, student.third_language, student.elective ]
        subject_choices =[('0', '--Select--')]
        for i in subject_code_list:
            if i and i != '-':
                query = Subject_master.query.filter_by(code = i).first()
                one = (i , query.name)
                subject_choices.append(one)
        form.subject_opts.choices = subject_choices
        
        
        if request.method == "POST":
            material_list = []
            select_subject = form.subject_opts.data
            if select_subject != '0':
                print(form.subject_opts.data)
                print(class_id)
                sub_hand = Subject_handler.query.filter_by(class_id = class_id, subject_code = select_subject).first()
                print(sub_hand)
                material = Material.query.filter_by(sub_hand_id = sub_hand.id, material_type = "Study Material").all() 
                print(material)
                for i in material:
                    material_list.append(i)
                return render_template('study_materials.html', title='Subject Materials', material_list = material_list, form = form, sub=1)
        return render_template('study_materials.html', title='Subject Materials', form = form, material_list=1, sub=0 )
    else:
        return render_template('error.html', title='Error Page')







# ----------------------------------------------- HOMEWORKS ---------------------------------------------------------
# -------------------------------------------- ACTIVE HOMEWORKS ---------------------------------------------------------
@app.route("/active_homework", methods=['GET', 'POST'])
@login_required
def active_homework():   
    if ((current_user.role == "Student") or (current_user.role == "Super User")) :
        form = StudentSubjects()
        user_student = User.query.filter_by(id = current_user.id).first()
        student =  Student.query.filter_by(user_id = user_student.id).first()
        class_id = student.class_id
        subjects = Subjects.query.filter_by(class_id = class_id).first()
        
        subject_code_list = [ subjects.core1, subjects.core2, subjects.core3, subjects.first_language, student.second_language, student.third_language, student.elective ]
        subject_choices =[]
        for i in subject_code_list:
            if i and i != '-':
                query = Subject_master.query.filter_by(code = i).first()
                one = (i , query.name)
                subject_choices.append(one)
        form.subject_opts.choices = subject_choices
        
        if request.method == "POST":
            material_list = []
            attendance_list = []
            report_gen_list = []
            select_subject = form.subject_opts.data
            sub_hand = Subject_handler.query.filter_by(class_id = class_id, subject_code = select_subject).first()
            material = Material.query.filter_by(sub_hand_id = sub_hand.id, material_type = "Homework").all() 
           
            for i in material:
                
                
                
                #print(i.report_gen)
                if i.report_gen == 0 or i.report_gen == -1:
                    attendance = Submitted_attendance.query.filter_by(student_id = student.id, material_id = i.id).first()
                    print(attendance)
                    if attendance.submitted:
                        attendance_list.append(1)

                    else:
                        attendance_list.append(0)

                    if i.report_gen == 0:
                        report_gen_list.append(0)
                        material_list.append(i)
                    elif i.report_gen == -1:
                        report_gen_list.append(-1)
                        material_list.append(i)
            if not material_list:
                material_list = 1
            print(attendance_list)
            return render_template('active_homework.html', title='Homeworks', material_list = material_list, form = form, attendance_list = attendance_list, report_gen_list=report_gen_list)
        return render_template('active_homework.html', title='Homeworks', form = form, material_list = 0 )
    else:
        return render_template('error.html', title='Error Page')





@app.route("/upload_homeworks/<material_id>", methods=['GET', 'POST'])
@login_required
def upload_homeworks(material_id):
    if ((current_user.role == "Student") or (current_user.role == "Super User")) :
        user_student = User.query.filter_by(id = current_user.id).first()
        student =  Student.query.filter_by(user_id = user_student.id).first()
        material = Material.query.filter_by(id = material_id).first()
        a = Submitted_attendance.query.filter_by(student_id = student.id, material_id = material_id).first()
        form = LinkSubmission()
        if form.validate_on_submit():
            link = form.link.data
          
            if not a.submitted:
                a.submitted = link
                db.session.commit()
                flash("Homework successfully uploaded!","success")
                return redirect(url_for('active_homework'))
            else:
                return redirect(url_for('active_homework'))
            
        return render_template("upload_homeworks.html", title = "Upload Homework", material = material, form = form)
    else:
        return render_template('error.html', title='Error Page')




# -----------------------------------------COMPLETED HOMEWORKS ---------------------------------------------------------
@app.route("/completed_homework", methods=['GET', 'POST'])
@login_required
def completed_homework():   
    if ((current_user.role == "Student") or (current_user.role == "Super User")) :
        form = StudentSubjects()
        user_student = User.query.filter_by(id = current_user.id).first()
        student =  Student.query.filter_by(user_id = user_student.id).first()
        class_id = student.class_id
        subjects = Subjects.query.filter_by(class_id = class_id).first()
        
        subject_code_list = [ subjects.core1, subjects.core2, subjects.core3, subjects.first_language, student.second_language, student.third_language, student.elective ]
        subject_choices =[]
        for i in subject_code_list:
            if i and i != '-':
                query = Subject_master.query.filter_by(code = i).first()
                one = (i , query.name)
                subject_choices.append(one)
        form.subject_opts.choices = subject_choices
        
        if request.method == "POST":
            material_list = []
            select_subject = form.subject_opts.data
            sub_hand = Subject_handler.query.filter_by(class_id = class_id, subject_code = select_subject).first()
            material = Material.query.filter_by(sub_hand_id = sub_hand.id, material_type = "Homework", report_gen = 1).all() 
            # for i in material:
            #     sub = Submitted_attendance.query.filter_by(material_id=i, student_id=student.id).first()
            #     print(sub)
            #     if sub.submitted:
            #         material_list.append(i)
            print(material)
            attendance_list = []
            for i in material:
                print(i)
                material_list.append(i)
                attendance = Submitted_attendance.query.filter_by(student_id = student.id, material_id = i.id).first()
                print(attendance)
                if attendance.submitted:
                    attendance_list.append(1)
                else:
                    attendance_list.append(0)
            print(attendance_list)
            if material_list == []:
                material_list = 1
            return render_template('completed_homework.html', title='Completed Works', material_list = material_list, form = form, attendance_list=attendance_list)
        return render_template('completed_homework.html', title='Completed Works', form = form, material_list = 0 )
    else:
        return render_template('error.html', title='Error Page')



# -------------------------------------------------- TESTS ---------------------------------------------------------
# ----------------------------------------------- ACTIVE TESTS ---------------------------------------------------------
@app.route("/active_tests", methods=['GET', 'POST'])
@login_required
def active_tests():   
    if ((current_user.role == "Student") or (current_user.role == "Super User")) :
        form = StudentSubjects()
        user_student = User.query.filter_by(id = current_user.id).first()
        student =  Student.query.filter_by(user_id = user_student.id).first()
        class_id = student.class_id
        subjects = Subjects.query.filter_by(class_id = class_id).first()
        
        subject_code_list = [ subjects.core1, subjects.core2, subjects.core3, subjects.first_language, student.second_language, student.third_language, student.elective ]
        subject_choices =[]
        for i in subject_code_list:
            if i and i != '-':
                query = Subject_master.query.filter_by(code = i).first()
                one = (i , query.name)
                subject_choices.append(one)
        form.subject_opts.choices = subject_choices
        
        if request.method == "POST":
            material_list = []
            attendance_list = []
            report_gen_list = []
            select_subject = form.subject_opts.data
            sub_hand = Subject_handler.query.filter_by(class_id = class_id, subject_code = select_subject).first()
            material = Material.query.filter_by(sub_hand_id = sub_hand.id, material_type = "Test").all() 
            for i in material:
                #print(i.report_gen)
                if i.report_gen == 0 or i.report_gen == -1:
                    attendance = Submitted_attendance.query.filter_by(student_id = student.id, material_id = i.id).first()
                    print(attendance)
                    if attendance.submitted:
                        attendance_list.append(1)

                    else:
                        attendance_list.append(0)

                    if i.report_gen == 0:
                        report_gen_list.append(0)
                        material_list.append(i)
                    elif i.report_gen == -1:
                        report_gen_list.append(-1)
                        material_list.append(i)
            if material_list == []:
                material_list = 1
            return render_template('active_test.html', title='Tests', material_list = material_list, form = form, attendance_list = attendance_list, report_gen_list=report_gen_list)
        return render_template('active_test.html', title='Tests', form = form, material_list = 0 )
    else:
        return render_template('error.html', title='Error Page')




@app.route("/upload_tests/<material_id>", methods=['GET', 'POST'])
@login_required
def upload_tests(material_id):
    if ((current_user.role == "Student") or (current_user.role == "Super User")) :
        user_student = User.query.filter_by(id = current_user.id).first()
        student =  Student.query.filter_by(user_id = user_student.id).first()
        material = Material.query.filter_by(id = material_id).first()
        a = Submitted_attendance.query.filter_by(student_id = student.id, material_id = material_id).first()
        form = LinkSubmission()
        if form.validate_on_submit():
            link = form.link.data
           
            if not a.submitted:
                a.submitted = link
                db.session.commit()
                flash("Test successfully uploaded!","success")
                return redirect(url_for('active_tests'))
            else:
                return redirect(url_for('active_tests'))
            
        return render_template("upload_tests.html", title = "Upload Test", material = material, form = form)
    else:
        return render_template('error.html', title='Error Page')





# -----------------------------------------COMPLETED TESTS ---------------------------------------------------------
@app.route("/completed_tests", methods=['GET', 'POST'])
@login_required
def completed_tests():   
    if ((current_user.role == "Student") or (current_user.role == "Super User")) :
        form = StudentSubjects()
        user_student = User.query.filter_by(id = current_user.id).first()
        student =  Student.query.filter_by(user_id = user_student.id).first()
        class_id = student.class_id
        subjects = Subjects.query.filter_by(class_id = class_id).first()
        
        subject_code_list = [ subjects.core1, subjects.core2, subjects.core3, subjects.first_language, student.second_language, student.third_language, student.elective ]
        subject_choices =[]
        for i in subject_code_list:
            if i and i != '-':
                query = Subject_master.query.filter_by(code = i).first()
                one = (i , query.name)
                subject_choices.append(one)
        form.subject_opts.choices = subject_choices
        
        if request.method == "POST":
            material_list = []
            select_subject = form.subject_opts.data
            sub_hand = Subject_handler.query.filter_by(class_id = class_id, subject_code = select_subject).first()
            material = Material.query.filter_by(sub_hand_id = sub_hand.id, material_type = "Test", report_gen=1).all() 
            attendance_list = []
            for i in material:
                print(i)
                material_list.append(i)
                attendance = Submitted_attendance.query.filter_by(student_id = student.id, material_id = i.id).first()
                print(attendance)
                if attendance.submitted:
                    attendance_list.append(1)
                else:
                    attendance_list.append(0)
            if material_list == []:
                material_list = 1
            return render_template('completed_tests.html', title='Completed Works', material_list = material_list, form = form, attendance_list=attendance_list)
        return render_template('completed_tests.html', title='Completed Works', form = form, material_list = 0 )
    else:
        return render_template('error.html', title='Error Page')






def send_all_email(user, message):
    subj = "Information"
    msg = Message(subj, sender='shikshanoreply@gmail.com', recipients=[user.email])
    msg.body = message
    #mail.send(msg)
    print(msg)

#---------------------------------------------------MAIL--------------------------------------------------------
# -------------------------------------------------MAIL TEACHER-------------------------------------------------
@app.route("/mail_teacher", methods=['GET', 'POST'])
@login_required
def mail_teacher():  
    if (current_user.role == "Principal" or current_user.role == "Super User") :
        form = MailForm()
        if form.validate_on_submit():
            message = form.message.data
            teachers = Teacher.query.all()
            for teacher in teachers:
                user = User.query.filter_by(id = teacher.user_id).first()
                send_all_email(user,message)
            flash('Message has been sent to all the teachers', 'success')
            return redirect(url_for('manage_teachers'))
        return render_template('mail_teacher.html', title='Mail Teacher', form=form)
    else:
        return render_template('error.html', title='Error Page')


# -------------------------------------------------MAIL CLASS STUDENTS-------------------------------------------------
@app.route("/mail_class_students/<personid>", methods=['GET', 'POST'])
@login_required
def mail_class_students(personid): 
    if (current_user.role == "Teacher" or current_user.role == "Super User" or current_user.role == "Principal") :
        form = MailForm()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        if form.validate_on_submit():
            message = form.message.data
            class_ = Class.query.filter_by(class_teacher=teacher.id).first()
            students = Student.query.filter_by(class_id = class_.id).all()
            for student in students:
                user = User.query.filter_by(id = student.user_id).first()
                send_all_email(user,message)
            flash('Message has been sent to all the students', 'success')
            return redirect(url_for('manage_class_students', personid=personid))
        return render_template('mail_class_students.html', title='Mail Class Students', form=form, t_ct=teacher.is_ct, personid=personid)
    else:
        return render_template('error.html', title='Error Page')

# -------------------------------------------------MAIL SUBJECT STUDENTS-------------------------------------------------
@app.route("/mail_subject_students/<personid>/<class_>/<sub>", methods=['GET', 'POST'])
@login_required
def mail_subject_students(personid,class_,sub): 
    if (current_user.role == "Teacher" or current_user.role == "Super User" or current_user.role == "Principal") :
        form = MailForm()
        teacher = Teacher.query.filter_by(user_id=personid).first()
        print(teacher)
        if form.validate_on_submit():
            message = form.message.data
            class_obj = Class.query.filter_by(id=class_).first()
            print(class_obj)

            students = Student.query.filter_by (class_id = class_).all()
            class_subjects = Subjects.query.filter_by(class_id = class_).first()
            all_subjects = [ class_subjects.core1, class_subjects.core2, class_subjects.core3, class_subjects.first_language, class_subjects.second_language1, class_subjects.second_language2, class_subjects.second_language3, class_subjects.third_language1, class_subjects.third_language2, class_subjects.third_language3, class_subjects.elective1, class_subjects.elective2 ]
            subject = sub
            if subject in all_subjects:
                core_subjects = [ class_subjects.core1, class_subjects.core2, class_subjects.core3, class_subjects.first_language]
                if subject in core_subjects:
                    for i in students:
                        user = User.query.filter_by(id=i.user_id).first()
                        send_all_email(user,message)
                else:
                    for i in students:
                        selective_list = [ i.second_language, i.third_language, i.elective]
                        if subject in selective_list:
                            user = User.query.filter_by(id=i.user_id).first()
                            send_all_email(user,message)
            flash('Message has been sent to all the subject students', 'success')
            return redirect(url_for('view_subjectwise_students', personid=personid))
        return render_template('mail_subject_students.html', title='Mail Subject Students', form=form, t_ct=teacher.is_ct, personid=personid)
    else:
        return render_template('error.html', title='Error Page')

























































# ----------------------------------------------SUPER USER----------------------------------------------------------------
# -------------------------------------------REGISTER PRINCIPAL---------------------------------------------------------
@app.route("/register_principal", methods=['GET', 'POST'])
@login_required
def register_principal():
    if (current_user.role == "Super User") :
        form = RegistrationForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
            user = User(email = form.username.data, role = 'Principal', password=hashed_password)
            db.session.add(user)
            db.session.commit()
            new_user = User.query.filter_by(email = form.username.data).first()

            principal = Principal(first_name = form.first_name.data, last_name = form.last_name.data, phone = form.phone_number.data, dob = form.dob.data, user_id = new_user.id, gender = form.gender.data)
            send_registered_email(user,user.role)
            db.session.add(principal)
            teacher = Teacher(first_name = form.first_name.data, last_name = form.last_name.data, phone = form.phone_number.data, dob = form.dob.data, user_id = new_user.id, is_ct=False, gender = form.gender.data)                
            db.session.add(teacher)
            db.session.commit()
            
            flash('Principal has been created', 'success')
            return redirect(url_for('choose_user'))
        return render_template('register.html', title='Register Principal', form=form)
    else:
        return render_template('error.html', title='Error Page')






# ----------------------------------------------------CHOOSE USER-------------------------------------------------------------------
@app.route("/choose_user", methods=['GET', 'POST'])
@login_required
def choose_user():
    form = SelectRole()
    form.person_opts.choices = [(0,'--Select--')]
    if form.validate_on_submit:
        role = form.role_opts.data
        person_user_id = form.person_opts.data
        if person_user_id:
            if role == 'Principal':
                return redirect(url_for('principal_select_role', personid = person_user_id))
            elif role == 'Teacher':
                return redirect(url_for('teacher', personid = person_user_id))
    return render_template('choose_user.html', title='Super User', form=form)


@app.route('/select_people/<role>', methods = ["GET","POST"])
def select_people(role):
    if role == "Principal":
        people = Principal.query.all()
    elif role == "Teacher":
        people = Teacher.query.all()
    peopleArray = []
    for i in people:
        user = User.query.filter_by(id = i.user_id).first()
        peopleObj = {}
        peopleObj['id'] = user.id
        peopleObj['username'] = user.email
        peopleArray.append(peopleObj)
    return jsonify( { 'people' : peopleArray } )










































# -----------------------------------------------PROFILE-----------------------------------------------------
# ---------------------------------------UPDATE PROFILE ---------------------------------------------------------
@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    if not current_user.role == "Super User":
        form = UpdateAccountForm()
        user = User.query.filter_by(id = current_user.id).first()
        if form.validate_on_submit():
            if user.role == "Principal":
                person1 = Principal.query.filter_by(user_id = user.id).first()
                person2 = Teacher.query.filter_by(user_id = user.id).first()
                
                person1.first_name = form.first_name.data
                person1.last_name = form.last_name.data
                person1.dob = form.dob.data
                person1.phone = form.phone_number.data
                person1.gender = form.gender.data

                person2.first_name = form.first_name.data
                person2.last_name = form.last_name.data
                person2.dob = form.dob.data
                person2.phone = form.phone_number.data
                person2.gender = form.gender.data
            else:
                if user.role == "Teacher":
                    person = Teacher.query.filter_by(user_id = user.id).first()
                elif user.role == "Student":
                    person = Student.query.filter_by(user_id = user.id).first()
                person.first_name = form.first_name.data
                person.last_name = form.last_name.data
                person.dob = form.dob.data
                person.phone = form.phone_number.data
                person.gender = form.gender.data
            db.session.commit()
            flash('Your account has been updated!', 'success')
            return redirect(url_for('profile'))
        
        elif request.method == 'GET':
            user = User.query.filter_by(id = current_user.id).first()
            if user.role == "Principal":
                person = Principal.query.filter_by(user_id = user.id).first()
            elif user.role == "Teacher":
                person = Teacher.query.filter_by(user_id = user.id).first()
            elif user.role == "Student":
                person = Student.query.filter_by(user_id = user.id).first()
            form.first_name.data = person.first_name
            form.last_name.data = person.last_name 
            form.dob.data = person.dob
            form.phone_number.data = person.phone
            form.gender.data = person.gender
            return render_template('profile.html', title='Profile', form=form, user=user)
        return render_template('profile.html', title='Profile', form=form, user=user)
    else:
        return render_template('error.html', title='Error')



@app.route("/change_password", methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePassword()
    if form.validate_on_submit():
        user = User.query.filter_by(id = current_user.id).first()
        if bcrypt.check_password_hash(user.password, form.old_password.data):
            hashed_password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
            user.password = hashed_password
            db.session.commit()        
            flash('Your password has been updated! You are now able to login', 'success')
            return redirect(url_for('logout'))
        else:
            flash('Your old password is incorrect. Please try again!', 'danger')
            return redirect(url_for('change_password'))
    return render_template('change_password.html', title='Change Password', form=form)



























# --------------------------------------------LOGOUT---------------------------------------------------------
@app.route("/logout")
@login_required
def logout():
    if current_user.role != "Super User":
        logout_user()
        return redirect(url_for('home'))
    else:
        logout_user()
        return redirect(url_for('home'))
