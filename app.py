#!venv/bin/python
import json
import os
from random import randrange

from datetime import timedelta
from datetime import datetime
from flask import Flask, url_for, redirect, render_template, request, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user
from flask_security.utils import hash_password
import flask_admin
from flask_admin import BaseView, expose, AdminIndexView
from flask_admin.contrib import sqla
from flask_admin import helpers as admin_helpers


import datetime
# Create Flask application
app = Flask(__name__)
from geopy.geocoders import Nominatim
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)

# Define models
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __str__(self):
        return self.name

class Building(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    floors = db.Column(db.Integer)
    owner = db.Column(db.String(255))
    comment = db.Column(db.String(255))
    address = db.Column(db.String(255))
    city = db.Column(db.String(255))
    state = db.Column(db.String(255))
    zip_code = db.Column(db.Integer)
    confirmed_at = db.Column(db.DateTime())

    def to_dict(self):
        return {c.name: getattr(self, c.name, None) for c in self.__table__.columns}


class SensorNode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    floor = db.Column(db.Integer)
    room = db.Column(db.String(255))
    cluster_id = db.Column(db.Integer,db.ForeignKey('cluster_node.id'))
    ip = db.Column(db.String(255))
    type = db.Column(db.String(255))
    status = db.Column(db.String(255))

    def to_dict(self):
        return {c.name: getattr(self, c.name, None) for c in self.__table__.columns}


class ClusterNode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    floor = db.Column(db.Integer)
    building_id = db.Column(db.Integer, db.ForeignKey('building.id'))
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    ip = db.Column(db.String(255))
    comment = db.Column(db.String(255))

    def to_dict(self):
        return {c.name: getattr(self, c.name, None) for c in self.__table__.columns}

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    def __str__(self):
        return self.email


class SensorData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sensor_id = db.Column(db.Integer, db.ForeignKey('sensor_node.id'))
    building_id = db.Column(db.Integer, db.ForeignKey('building.id'))
    cluster_id = db.Column(db.Integer, db.ForeignKey('cluster_node.id'))
    temperature = db.Column(db.Float)
    floor = db.Column(db.Integer)
    room = db.Column(db.String(255))
    date = db.Column(db.Date)
    time = db.Column(db.Time)
    status = db.Column(db.String(255))

    def to_dict(self):
        return {c.name: getattr(self, c.name, None) for c in self.__table__.columns}



# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


# Create customized model view class
class MyModelView(sqla.ModelView):
    def is_accessible(self):
        if not current_user.is_active or not current_user.is_authenticated:
            return False
        if current_user.has_role('superuser'):
            return True
        return False

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permmission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))


    # can_edit = True
    edit_modal = True
    create_modal = True
    can_export = True
    can_view_details = True
    details_modal = True


class UserView(sqla.ModelView):

    def is_accessible(self):
        if not current_user.is_active or not current_user.is_authenticated:
            return False
        if current_user.has_role('superuser'):
            return True
        return False

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permmission denied
                abort(403)
            else:
                column_list = ['email', 'first_name', 'last_name']
                can_create = False
                can_edit = False
                can_delete = False
                column_searchable_list = column_list
                column_exclude_list = ['password']
                form_excluded_columns = column_exclude_list
                column_details_exclude_list = column_exclude_list
                # column_filters = column_editable_list


class SensorView(sqla.ModelView):

    def is_accessible(self):
        if not current_user.is_active or not current_user.is_authenticated:
            return False
        if current_user.has_role('superuser') or current_user.has_role('manager'):
            return True
        return False

    # TODO: change number to enums
    def get_access_level(self):
        if not current_user.is_active or not current_user.is_authenticated:
            return 0
        if current_user.has_role('superuser'):
            return 3
        if current_user.has_role('manager'):
            return 2
        if current_user.has_role('user'):
            return 1
        return 1

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        print("access level",self.get_access_level())
        access_level = self.get_access_level()

        if access_level == 3:
            column_list = ["id", "floor", "ip", "cluster_id", "type", "status"]
            column_searchable_list = column_list
            can_create = True
            can_edit = True
            can_delete = True
        elif access_level == 2:
            column_list = ["id", "floor", "ip", "cluster_id", "type", "status"]
            column_searchable_list = column_list
            can_create = False
            can_edit = False
            can_delete = False
        elif access_level == 1:
            print("user access")
            column_list = ["id", "floor", "ip", "cluster_id", "type", "status"]
            column_searchable_list = column_list
            can_create = False
            can_edit = False
            can_delete = False


        else:
            # login
            return redirect(url_for('security.login', next=request.url))




class BillingView(BaseView):
    def is_accessible(self):
        if not current_user.is_active or not current_user.is_authenticated:
            return False
        if current_user.has_role('superuser'):
            return True
        return False

    @expose('/')
    def index(self):
        count = SensorNode.query.count()
        return self.render('admin/billing.html',count=count)

class MapView(BaseView):

    def is_accessible(self):
        if not current_user.is_active or not current_user.is_authenticated:
            return False
        if current_user.has_role('superuser') or current_user.has_role('manager'):
            return True
        return False

    @expose('/')
    def index(self):
        # TODO: finish the user roles to clean this part
        # pass in the list of buildings
        buildings = Building.query.all()
        return self.render('admin/map.html', buildings=buildings)


class DataView(BaseView):
    @expose('/')
    def index(self):
        buildings = []
        floors = []
        rooms = []
        sensor_logs = SensorData.query.all()
        for sensor_data in sensor_logs:
            if str(sensor_data.building_id) not in buildings:
                buildings.append(str(sensor_data.building_id))
            if str(sensor_data.floor) not in floors:
                floors.append(str(sensor_data.floor))
            if str(sensor_data.room) not in rooms:
                rooms.append(str(sensor_data.room))
            buildings.sort(key=int)
            floors.sort(key=int)
            rooms.sort(key=int)
        return self.render('admin/data_view.html',entries=sensor_logs, buildings=buildings, floors=floors, rooms=rooms)


@app.route('/data_request', methods=['POST','GET'])
def data_request():
    if request.method == "POST":
        filters = request.form
        print('data_request',filters)

        s_query = SensorData.query.all()
        result = []

        # filter query result
        for sensor_data in s_query:
                if filters['building']:
                    if not str(filters['building']) == str(sensor_data.building_id):
                        continue
                if filters['floor']:
                    if not str(filters['floor']) == str(sensor_data.floor):
                        continue
                if filters['room']:
                    if not str(filters['room']) == str(sensor_data.room):
                        continue
                if filters['start_date']:
                    start_date = datetime.datetime.strptime(filters['start_date'], "%Y-%m-%d").date()
                    if not start_date < sensor_data.date:
                        continue
                if filters['end_date']:
                    end_date = datetime.datetime.strptime(filters['end_date'], "%Y-%m-%d").date()
                    if not end_date > sensor_data.date:
                        continue
                temp = sensor_data.to_dict()
                temp['date'] = temp['date'].strftime('%Y-%m-%d')
                temp['time'] = temp['time'].strftime('%H:%S')
                result.append(temp)
        print("result is", result)

        return json.dumps(result)

# handles all requests going around map view
@app.route('/map_request',methods=['POST','GET'])
def map_request():

    if request.method == 'POST':
        packet = request.form.to_dict()
        if 'type' not in packet.keys() :
            print("weird packet!")
            return ""
        print("map_request", request.form['type'])
        operation = packet['type']  # determines operations to do
        # init vars for easier access
        try:
            building_id = packet['building_id']
        except KeyError:
            pass
        try:
            floor = packet['floor']
        except KeyError:
            pass
        try:
            ip = packet['ip']
        except KeyError:
            pass
        try:
            address = packet['address']
        except KeyError:
            pass
        try:
            city = packet['city']
        except KeyError:
            pass
        try:
            state = packet['state']
        except KeyError:
            pass
        try:
            zip_code = packet['zip']
        except KeyError:
            pass
        try:
            cluster_ip = packet['cluster_ip']
        except KeyError:
            pass
        try:
            sensor_ip = packet['sensor_ip']
        except KeyError:
            pass
        try:
            cluster_id = packet['cluster_id']
        except KeyError:
            pass
        try:
            new_name = packet['new_name']
        except KeyError:
            pass
        try:
            new_building_id = packet['new_building_id']
        except KeyError:
            pass
        try:
            new_floor = packet['new_floor']
        except KeyError:
            pass
        try:
            new_ip = packet['new_ip']
        except KeyError:
            pass
        try:
            new_sensor_ip = packet['new_sensor_ip']
        except KeyError:
            pass
        try:
            new_cluster_ip = packet['new_cluster_ip']
        except KeyError:
            pass
        try:
            status = packet['status']
        except KeyError:
            pass
        # TODO finish adding sensors, then get_sensor
        if operation == "add_sensor":
            cluster = ClusterNode.query.filter_by(ip=cluster_ip,building_id=building_id).first()
            print("add_sensor:",cluster)
            new_sensor = SensorNode(ip=sensor_ip,cluster_id=cluster.id,status=status)
            print("new_sensor:",new_sensor.id)
            db.session.add(new_sensor)
            # more here
            db.session.commit()
            pass
        elif operation == "add_cluster":
            db.session.add(ClusterNode(building_id=building_id,floor=floor,ip=ip))
            db.session.commit()
        elif operation == "add_building":
            building_address = ' '.join((address, city, state, zip_code))
            geolocator = Nominatim(user_agent="my-application")
            location = geolocator.geocode(building_address)
            if not location:  # fake address
                lat, lng = 0, 0
            else:
                lat, lng = location.latitude, location.longitude
                print(location.latitude, location.longitude)
            b = Building(name=packet['building_name'], address=address,city=city,
                         state=state, zip_code=zip_code, lat=lat, lng=lng)
            db.session.add(b)
            db.session.commit()
        elif operation == "edit_building":
            building = Building.query.get(building_id)
            if new_name:
                building.name = new_name
            if address:
                building.address = address
            if city:
                building.city = city
            if state:
                building.state = state
            if zip_code:
                building.zip_code = zip_code
            db.session.commit()
        elif operation == "remove_building":
            Building.query.filter_by(id=building_id).delete()
            db.session.commit()
            return json.dumps({"time": str(datetime.datetime.now())})
        elif operation == "remove_cluster":
            ClusterNode.query.filter_by(building_id=building_id,floor=floor, ip=ip).delete()
            db.session.commit()
            return json.dumps({"time": str(datetime.datetime.now())})
        elif operation == "remove_sensor":
            cluster = ClusterNode.query.filter_by(building_id=building_id, floor=floor, ip=cluster_ip).first()
            SensorNode.query.filter_by(cluster_id=cluster.id, ip=sensor_ip).delete()
            db.session.commit()
        elif operation == "edit_cluster":
            cluster = ClusterNode.query.filter_by(building_id=building_id,floor=floor, ip=ip).first()
            print("cluster_id is",cluster.id)
            if new_building_id:
                cluster.building_id = building_id
            if new_floor:
                cluster.floor = new_floor
            if new_ip:
                cluster.ip = new_ip
            db.session.commit()
        elif operation == "edit_sensor":
            cluster = ClusterNode.query.filter_by(building_id=building_id, floor=floor, ip=ip).first()
            sensor = SensorNode.query.filter_by(cluster_id=cluster.id).first()
            if new_building_id and new_floor:
                if new_cluster_ip:
                    new_cluster = ClusterNode.query.filter_by(building_id=new_building_id, floor=new_floor, cluster_ip=new_cluster_ip).first()
                else:
                    new_cluster = ClusterNode.query.filter_by(building_id=new_building_id, floor=new_floor).first()
                sensor.cluster_id = new_cluster.id
                db.session.commit()

        elif operation == "get_cluster":
            clusters = ClusterNode.query.filter_by(building_id=building_id).order_by(ClusterNode.floor).all()
            print("clusters", clusters)
            result = [r.to_dict() for r in clusters]
            print("result is",result)
            return json.dumps(result)
        elif operation == "get_sensor":
            sensors = SensorNode.query.filter_by(cluster_id=cluster_id).all()
            result = [r.to_dict() for r in sensors]
            return json.dumps(result)
        else:
            return json.dumps({"time":str(datetime.datetime.now()),"you":"got_pranked"})

    elif request.method == 'GET':
        return json.dumps({"time":str(datetime.datetime.now())})

# Flask views
# @app.route('/')
# def index():
#     return render_template('index.html')


class MyIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        print("wtf")
        id_list = []
        c_id_list = []
        b_id_list = []
        active = 0
        for sensor in SensorData.query.all():
            if sensor.sensor_id not in id_list:
                id_list.append(sensor.sensor_id)
                if sensor.status == 'ON':
                  active += 1
            if sensor.cluster_id not in c_id_list:
                c_id_list.append(sensor.cluster_id)
            if sensor.building_id not in b_id_list:
                b_id_list.append(sensor.building_id)

        buildings = Building.query.all()
        print("b1:",buildings)
        return self.render('admin/index.html',arg1=len(id_list), arg2=active, arg3=len(c_id_list), arg4=len(b_id_list), buildings=buildings)


# Create admin
admin = flask_admin.Admin(
    app,
    'GreenBuilding',
    base_template='my_master.html',
    template_mode='bootstrap3',
    index_view=MyIndexView( ),
    url="/",
)

# redirect page to admin index
@app.route("/")
def index():
    return redirect(url_for('admin.index'))

# Add model views
admin.add_view(MyModelView(Role, db.session, menu_icon_type='fa', menu_icon_value='fa-server', name="Roles"))

admin.add_view(UserView(User, db.session, menu_icon_type='fa', menu_icon_value='fa-users', name="Users"))

admin.add_view(MapView(name="Map View", endpoint='map', menu_icon_type='fa', menu_icon_value='fa-connectdevelop'))

admin.add_view(SensorView(SensorNode, db.session, name="Sensor View",endpoint='sensor', menu_icon_type='fa', menu_icon_value='fa-connectdevelop'))

admin.add_view(BillingView(name="Billing View", endpoint='billing', menu_icon_type='glyph', menu_icon_value='glyphicon-home'))

admin.add_view(DataView(name="Data View", endpoint='data_view', menu_icon_type='glyph', menu_icon_value='glyphicon-home'))

# define a context processor for merging flask-admin's template context into the
# flask-security views.
@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template=admin.base_template,
        admin_view=admin.index_view,
        h=admin_helpers,
        get_url=url_for
    )

def random_date(start, end):
    """
    This function will return a random datetime between two datetime
    objects.
    """
    delta = end - start
    int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
    random_second = randrange(int_delta)
    return start + timedelta(seconds=random_second)


def build_sample_db():
    """
    Populate a small db with some example entries.
    """
    import string
    import random

    db.drop_all()
    db.create_all()

    with app.app_context():
        user_role = Role(name='user')
        manager_role = Role(name='manager')
        super_user_role = Role(name='superuser')

        db.session.add(user_role)
        db.session.add(manager_role)
        db.session.add(super_user_role)

        b1 = Building(id=1,name="Waycrest Manor",lat=37.335480, lng=-121.893028, address="1500 Joseph Street")
        b2 = Building(id=2,name="Sethraliss Temple",lat=40,lng=-70, address="402 Wilson Road")
        b3 = Building(id=3, name="Black Rook Hold", lat=47, lng=-122,address="32 Custer Drive")

        c1 = ClusterNode(id=1, building_id=1, floor=2, ip='192.168.1.122')
        c2 = ClusterNode(id=2, building_id=2, floor=3, ip='192.168.1.12')
        c3 = ClusterNode(id=3, building_id=3, floor=1, ip='192.168.3.52')
        c4 = ClusterNode(id=4, building_id=3, floor=4, ip='192.168.5.23')


        s1 = SensorNode(id=1, cluster_id=1, ip="10.0.1.4")
        s2 = SensorNode(id=2, cluster_id=1, ip="10.0.1.45")
        s3 = SensorNode(id=3, cluster_id=1, ip="10.0.1.4")
        s4 = SensorNode(id=4, cluster_id=3, ip="10.0.5.3")
        s5 = SensorNode(id=5, cluster_id=2, ip="10.0.2.125")

        s6 = SensorNode(id=6, cluster_id=2, ip="10.0.1.4")

        s_id = 1
        c_id = 1
        d1 = datetime.datetime.strptime('1/1/1995 1:30 PM', '%m/%d/%Y %I:%M %p')
        d2 = datetime.datetime.strptime('1/1/2018 12:50 PM', '%m/%d/%Y %I:%M %p')
        for building in range(1,6):
            for level in range(1,11):
                for room in range(1,21):
                    for i in range(5):
                        dt = random_date(d1, d2)
                        status = "ON"
                        if random.uniform(0,1)>0.8:
                            status = "OFF"
                        s_data = SensorData(sensor_id=s_id,building_id=building,cluster_id=c_id,floor=level,room=room,
                                        temperature=round(random.uniform(16.0, 30.0),2),
                                        date=dt.date(),time=dt.time(),status=status)
                        db.session.add(s_data)
                    s_id += 1
                c_id +=1

        db.session.add(c1)
        db.session.add(c2)
        db.session.add(c3)
        db.session.add(c4)

        db.session.add(s1)
        db.session.add(s2)
        db.session.add(s3)
        db.session.add(s4)
        db.session.add(s5)
        db.session.add(s6)

        db.session.add(b1)
        db.session.add(b2)
        db.session.add(b3)


        db.session.commit()
        db.session.add(c1)
        db.session.add(c2)
        db.session.add(c3)
        db.session.add(c4)

        db.session.add(s1)
        db.session.add(s2)
        db.session.add(s3)
        db.session.add(s4)
        db.session.add(s5)
        db.session.add(s6)

        db.session.add(b1)
        db.session.add(b2)
        db.session.add(b3)


        db.session.commit()

        test_user = user_datastore.create_user(
            first_name='Admin',
            email='admin',
            password=hash_password('admin'),
            roles=[user_role, super_user_role]
        )

        first_names = [
            'Harry', 'Amelia', 'Oliver', 'Jack', 'Isabella', 'Charlie', 'Sophie', 'Mia',
            'Jacob', 'Thomas', 'Emily', 'Lily', 'Ava', 'Isla', 'Alfie', 'Olivia', 'Jessica',
            'Riley', 'William', 'James', 'Geoffrey', 'Lisa', 'Benjamin', 'Stacey', 'Lucy'
        ]
        last_names = [
            'Brown', 'Smith', 'Patel', 'Jones', 'Williams', 'Johnson', 'Taylor', 'Thomas',
            'Roberts', 'Khan', 'Lewis', 'Jackson', 'Clarke', 'James', 'Phillips', 'Wilson',
            'Ali', 'Mason', 'Mitchell', 'Rose', 'Davis', 'Davies', 'Rodriguez', 'Cox', 'Alexander'
        ]

        for i in range(len(first_names)):
            tmp_email = first_names[i].lower() + "." + last_names[i].lower() + "@example.com"
            tmp_pass = ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(10))
            user_datastore.create_user(
                first_name=first_names[i],
                last_name=last_names[i],
                email=tmp_email,
                password=hash_password(tmp_pass),
                roles=[user_role, ]
            )
        db.session.commit()
    return

if __name__ == '__main__':

    # Build a sample db on the fly, if one does not exist yet.
    app_dir = os.path.realpath(os.path.dirname(__file__))
    database_path = os.path.join(app_dir, app.config['DATABASE_FILE'])
    if not os.path.exists(database_path):
        build_sample_db()

    # Start app
    app.run(debug=True, port=80)