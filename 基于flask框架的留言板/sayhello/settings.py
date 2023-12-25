import os
#配置文件
SECRET_KEY = os.getenv('SECRET_KEY', '123456789') #密钥
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URI', 'mysql+pymysql://root:gjb134679@127.0.0.1:3306/liuyan')
