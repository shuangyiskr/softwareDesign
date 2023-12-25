from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from flask import Flask

app = Flask('sayhello')
app.secret_key = 'your_secret_key'
app.config.from_pyfile('settings.py')
app.jinja_env.trim_blocks = True  # 删除Jinjia2语句后的第一个空行
app.jinja_env.lstrip_blocks = True  # 删除Jinjia2语句所在行之前的空格和制表符

db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
moment = Moment(app)


from sayhello import views, errors
