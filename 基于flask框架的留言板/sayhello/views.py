from sayhello import app, db
from sayhello.forms import HelloForm,ReplyForm
from sayhello.models import Message,Reply
from flask import flash, render_template, request, redirect, session, url_for, make_response, jsonify
from flask_paginate import Pagination, get_page_args
import functools

users = [
    {'username': 'gjb', 'password': '123456', 'role': 'admin'},
    {'username': 'bao', 'password': '666666', 'role': 'user'},
    # ...
]

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # 验证用户名和密码
        for user in users:
            if user['username'] == username and user['password'] == password:
                # 将用户信息存储在会话中
                session['username'] = username
                session['password'] = password
                # session['role'] = user['role']
                if user['role'] == 'admin':
                    return redirect('/index')  # 管理员跳转至index.html
                elif user['role'] == 'user':
                    return redirect('/index1')  # 普通用户跳转至index1.html
        # 用户名或密码不正确时的处理
        return render_template('login.html', error='用户名或密码错误')
    # GET 请求时渲染登录页面
    return render_template('login.html')

# 装饰器函数，用于检查用户是否已登录

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'username' not in session:
            return redirect('/login')
        return view(*args, **kwargs)
    return wrapped_view


@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    form = HelloForm()
    if form.validate_on_submit():
        name = form.name.data
        body = form.body.data
        message = Message(body=body, name=name)  # 实例化模型类，创建记录
        db.session.add(message)  # 添加记录到数据库回会话
        db.session.commit()  # 提交会话
        flash('留言成功！')
        return redirect('/index')  # 重定向到index视图

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = db.session.query(Message).count()
    messages = db.session.query(Message).order_by(Message.timestamp.desc()).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')
    return render_template('index.html', form=form, messages=messages, pagination=pagination)

@app.route('/index1', methods=['GET', 'POST'])
@login_required
def index1():
    form = HelloForm()
    if form.validate_on_submit():
        name = form.name.data
        body = form.body.data
        message = Message(body=body, name=name)  # 实例化模型类，创建记录
        db.session.add(message)  # 添加记录到数据库回会话
        db.session.commit()  # 提交会话
        flash('留言成功！')
        return redirect('/index1')  # 重定向到index视图

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    total = db.session.query(Message).count()
    messages = db.session.query(Message).order_by(Message.timestamp.desc()).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')
    return render_template('index1.html', form=form, messages=messages, pagination=pagination)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

@app.route('/delete/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    message = Message.query.get(message_id)
    if message:
        db.session.delete(message)
        db.session.commit()
        flash('Message deleted successfully!')
    return redirect('/')

from faker import Faker
@app.route('/generate_messages', methods=['GET'])
def generate_messages():
    fake = Faker('zh-CN')
    for _ in range(10):  # 生成 10 条测试留言
        name = fake.name()
        body = fake.text(max_nb_chars=200)
        message = Message(name=name, body=body)
        db.session.add(message)
    db.session.commit()
    flash('Generated test messages!')
    return redirect('/index')


@app.route('/view_message/<int:message_id>', methods=['GET', 'POST'])
def view_message(message_id):
    message = Message.query.get_or_404(message_id)

    if request.method == 'POST':
        if 'reply_body' in request.form:  # 处理回复
            reply_body = request.form.get('reply_body')

            if reply_body:
                reply = Reply(body=reply_body, message=message)
                db.session.add(reply)
                db.session.commit()
                flash('Your reply has been posted.')
        elif 'delete_reply' in request.form:  # 处理删除回复
            reply_id = request.form.get('delete_reply')
            reply = Reply.query.get_or_404(reply_id)
            db.session.delete(reply)
            db.session.commit()
            flash('Reply deleted.')

            # 将当前位置存储在 Cookie 中
        response = redirect(url_for('view_message', message_id=message.id))
        response.set_cookie('last_visited', f'/view_message/{message.id}',
                                max_age=60 * 60 * 24)  # 设置 Cookie 的有效期为一天
        return response
    for user in users:
        if user['name'] == session.get('name'):
            if user['role'] == 'admin':
                return redirect('/index')
            elif user['role'] == 'user':
                return redirect('/index1')
            else:
                return redirect('/')


@app.route('/like/<int:message_id>', methods=['POST'])
def like_message(message_id):
    message = Message.query.get_or_404(message_id)
    message.likes += 1
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/admin_index')
@login_required
def admin_index():
    # 管理员界面的处理逻辑
    return render_template('index.html')
def get_current_user(f):
    return 0;
@app.route('/user_index')
@login_required
def user_index():
    # 普通用户界面的处理逻辑
    return render_template('index1.html')


@app.route('/search_messages', methods=['GET', 'POST'])
def search_messages():
    form = HelloForm()
    process_messages(form)

    keyword = request.args.get('keyword', '')  # 获取用户输入的关键词
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')

    # 根据关键词进行留言的筛选
    filtered_messages = Message.query.filter(
        (Message.name.contains(keyword)) | (Message.body.contains(keyword))
    ).order_by(Message.timestamp.desc()).offset(offset).limit(per_page).all()

    total = len(filtered_messages)  # 获取筛选后的总数

    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    return render_template('index.html', form=form, messages=filtered_messages, pagination=pagination)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        print("POST")
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            return render_template('register.html', error='两次密码输入的不一致')
        for user in users:
            if user['username'] == username:
                return render_template('register.html', error='该用户名已被使用')
        else:
            users.append({'username': username, 'password': password})
            return redirect(url_for('login'))
    else:
        return render_template('register.html')

# 封禁用户接口
@app.route('/ban_user/<int:user_id>', methods=['POST'])
def ban_user(user_id):
    # 获取当前用户信息，假设通过某种方式获取当前用户信息
    current_user = get_current_user()

    # 检查当前用户是否为管理员
    if not current_user or not current_user['is_admin']:
        return jsonify({'message': 'Permission denied'}), 403

    # 查找要封禁的用户
    user_to_ban = next((user for user in users if user['id'] == user_id), None)

    # 如果找到用户并且不是管理员，封禁或解封用户
    if user_to_ban and not user_to_ban['is_admin']:
        user_to_ban['is_banned'] = not user_to_ban['is_banned']
        return jsonify({'message': 'User banned successfully'}), 200

    return jsonify({'message': 'User not found or cannot be banned'}), 404


# 解封用户接口
@app.route('/unban_user/<int:user_id>', methods=['POST'])
def unban_user(user_id):
    # 获取当前用户信息，假设通过某种方式获取当前用户信息
    current_user = get_current_user()

    # 检查当前用户是否为管理员
    if not current_user or not current_user['is_admin']:
        return jsonify({'message': 'Permission denied'}), 403

    # 查找要解封的用户
    user_to_unban = next((user for user in users if user['id'] == user_id), None)

    # 如果找到用户并且已被封禁，解封用户
    if user_to_unban and user_to_unban['is_banned']:
        user_to_unban['is_banned'] = False
        return jsonify({'message': 'User unbanned successfully'}), 200

    return jsonify({'message': 'User not found or cannot be unbanned'}), 404