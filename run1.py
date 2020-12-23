from application import app
from flask_apscheduler import APScheduler
from application.tables import Material, Subject_handler, Teacher
from datetime import datetime
from application import db
from twilio.rest import Client
from alembic import op

scheduler = APScheduler()


def check_report_gen(material):
    if(material.report_gen == 0):
        ### after the end time
        #nd > ed
        c1 = datetime.date(datetime.now()) > material.end_date
        #nd = ed & nt > et
        c2 = datetime.date(datetime.now()) == material.end_date and datetime.time(datetime.now()) > material.end_time
        if(c1 or c2):
            return 1
    
    if(material.report_gen == -1):
        ### between the available time
        #sd < nd < ed
        c1 = material.start_date < datetime.date(datetime.now()) and datetime.date(datetime.now()) < material.end_date
        #sd = nd & nd != ed & st < nt
        c2 = material.start_date == datetime.date(datetime.now()) and datetime.date(datetime.now()) != material.end_date and material.start_time < datetime.time(datetime.now())
        #nd = ed & nd != sd & nt < et 
        c3 = material.start_date != datetime.date(datetime.now()) and datetime.date(datetime.now()) == material.end_date and datetime.time(datetime.now()) < material.end_time
        #nd = sd = ed & st < nt < et
        c4 = material.start_date == datetime.date(datetime.now()) and datetime.date(datetime.now()) == material.end_date and material.start_time < datetime.time(datetime.now()) and datetime.time(datetime.now()) < material.end_time 
        if(c1 or c2 or c3 or c4):
            return 0

        ### after the end time
        #nd > ed
        c5 = datetime.date(datetime.now()) > material.end_date
        #nd = ed & nt > et
        c6 = datetime.date(datetime.now()) == material.end_date and datetime.time(datetime.now()) > material.end_time
        if(c5 or c6):
            return 1
        
    return material.report_gen


def task():
    mats = Material.query.all()
    for mat in mats:
        if str(mat.material_type) != "Study Material":
            if mat.report_gen == -1 or mat.report_gen == 0:
                final = check_report_gen(mat)
                #print(final)
                if int(final) == 1:
                    sub_hand_id = mat.sub_hand_id
                    subject_handler = Subject_handler.query.filter_by(id = sub_hand_id).first()
                    teacher_id = subject_handler.teacher_id
                    teacher = Teacher.query.filter_by(id = teacher_id).first()
                    phone_no = teacher.phone
                    phone_no = "+91" + str(phone_no)
                    #print(phone_no)
                    
                    '''account_sid = "AC9608e221c0e4a7a9a10c1ec3f6cd7b9c"
                    auth_token = "f02beeed1c753d6aa68ca4fb2c42e6e0"
                    client = Client(account_sid, auth_token)
                    sms = client.messages.create(
                            body="Hey",
                            from_="+17402004853",
                            to=phone_no
                        )
                    print(sms.sid)'''
                mat.report_gen = int(final)
                db.session.commit()


if __name__ == '__main__':
    scheduler.add_job(id='Task', func=task, trigger='interval', seconds=60)
    scheduler.start()
    app.run(debug=True, use_reloader=False) 
    #app.run(debug=True) 
