from flask import Flask, render_template, request, url_for, redirect, flash, jsonify
from flask import session as login_session
import random, string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import datetime

app = Flask(__name__)

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from database import Base, User, Category, Item

engine = create_engine('sqlite:///catalog.db')
DBSession = sessionmaker(bind = engine)
session = DBSession()

CLIENT_ID = json.loads(
		open('client_secretive.json', 'r').read()
	)['web']['client_id']

def respond(msg, err):
	res = make_response(json.dumps(msg), err)
	res.headers['Content-Type'] = 'application/json'
	return res

def getUserByEmail(email):
	try:
		user = session.query(User).filter_by(email = email).one()
		return user
	except:
		return None

def getUserID(email):
	try:
		user = session.query(User).filter_by(email = email).one()
		return user.id
	except:
		return None

def getUserByID(user_id):
	user = session.query(User).filter_by(id = user_id).one()
	return user

def createUser(login_session):
	newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'])
	session.add(newUser)
	session.commit()
	user = session.query(User).filter_by(email = login_session['email']).one()
	return user.id

def standard_date(date):
	return date.strftime('%b %d, %Y')

app.jinja_env.filters['standard_date'] = standard_date

@app.route('/login', methods = ['GET','POST'])
def login():
	state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
	login_session['state'] = state
	return render_template('login.html', state = state)

@app.route('/gconnect', methods = ['POST'])
def gconnect():
	if request.args.get('state') != login_session['state']:
		response = respond('Invalid state parameter', 401)
		return response
	
	code = request.data

	try:
		oauth_flow = flow_from_clientsecrets('client_secretive.json', scope='')
		oauth_flow.redirect_uri = 'postmessage'
		credentials = oauth_flow.step2_exchange(code).to_json()
	except FlowExchangeError:
		reponse = respond('Failed to upgrade the authorization code', 401)
		return response

	access_token = json.loads(credentials)['access_token']
	url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
	h = httplib2.Http()
	result = json.loads(h.request(url, 'GET')[1])

	if result.get('error') is not None:
		return respond(result.get('error'),500)

	gplus_id = json.loads(credentials)['id_token']['sub']
	if result['user_id'] != gplus_id:
		return respond("Token's user ID doesn't match given user ID.", 400)

	if result['issued_to'] != CLIENT_ID:
		return respond("Token's client ID doesn't match app's", 401)

	stored_credentials = login_session.get('credentials')
	stored_gplus_id = login_session.get('gplus_id')
	if stored_credentials is not None and gplus_id == stored_gplus_id:
		return respond("Current user is already connected.", 200)

	login_session['credentials'] = credentials
	login_session['gplus_id'] = gplus_id

	userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
	params = { 'access_token': access_token, 'alt': 'json' }
	answer = requests.get(userinfo_url, params = params)

	data = answer.json()

	login_session['provider'] = 'google'
	login_session['username'] = data['name']
	login_session['picture'] = data['picture']
	login_session['email'] = data['email']

	# see if user exists by email
	user_id = getUserID(login_session['email'])
	if not user_id:
		user_id = createUser(login_session)
	login_session['user_id'] = user_id

	return 'You are now logged in as %s, redirecting...' % login_session['username']

@app.route('/fbconnect', methods = ['GET', 'POST'])
def fbconnect():
	if request.args.get('state') != login_session['state']:
		return respond('Error', 401)

	access_token = request.data

	app_id = json.loads(open('fbclient_secretive.json', 'r').read())['web']['app_id']
	app_secret = json.loads(open('fbclient_secretive.json', 'r').read())['web']['app_secret']

	url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)

	h = httplib2.Http()
	result = h.request(url, 'GET')[1]

	# strip expire tag from access token
	token = result.split("&")[0]
	
	url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]

	data = json.loads(result)

	login_session['provider'] = 'facebook'
	login_session['username'] = data['name']
	login_session['email'] = data['email']
	login_session['facebook_id'] = data['id']
	login_session['access_token'] = token

	# get user picture in a separate call
	url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]
	data = json.loads(result)
	login_session['picture'] = data['data']['url']

	# see if user exists by email
	user_id = getUserID(login_session['email'])
	if not user_id:
		user_id = createUser(login_session)
	login_session['user_id'] = user_id

	return 'You are now logged in as %s, Redirecting...' % login_session['username']

@app.route('/disconnect', methods = ['GET', 'POST'])
def disconnect():
	if login_session['provider'] == 'google':
		credentials = login_session.get('credentials')
		if credentials is None:
			return render_template('error.html', message = 'Current user not connected, 401')

		access_token = json.loads(credentials)['access_token']

		url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
		h = httplib2.Http()
		result = h.request(url, 'GET')[0]
		print result['status']

		if result['status'] == '200':
			session_list = ['credentials', 'gplus_id', 'username', 'email', 'picture', 'user_id']
			for s in session_list:
				del login_session[s]
			flash('Logged out using Google')
			return redirect(url_for('showCategory'))
		else:
			return render_template('error.html', message = 'Failed to revoke token for given user., 400')

	else:
		facebook_id = login_session['facebook_id']
		access_token = login_session['access_token']
		url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
		h = httplib2.Http()
		result = h.request(url, 'DELETE')[1]
		session_list = ['facebook_id', 'username', 'email', 'picture', 'user_id', 'access_token']
		for s in session_list:
			del login_session[s]
		flash('Logged out using Facebook')
		return redirect(url_for('showCategory'))

@app.route('/', methods = ['GET'])
def showCategory():
	if 'username' in login_session:
		user = getUserByEmail(login_session['email'])
	else:
		user = None
	categories = session.query(Category).all()
	full_categories = []
	for c in categories:
		item_count = session.query(Item).filter_by(category_id = c.id).all()
		if len(item_count) != 0:
			full_categories.append(c)
	items = session.query(Item).order_by(Item.date_added).all()
	return render_template('showcategory.html', categories = full_categories, user = user, items = items)

@app.route('/showusercategory/<int:category_id>', methods = ['GET'])
def showUserCategory(category_id):
	if 'username' in login_session:
		user = getUserByEmail(login_session['email'])
		categories = session.query(Category).filter_by(user_id = user.id).all()
		if category_id != 0:
			items = session.query(Item).filter_by(category_id = category_id).all()
			category = session.query(Category).filter_by(id = category_id).one()
		else:
			items = None
			category = None
		return render_template('showusercategory.html', categories = categories, category = category, user = user, items = items)

@app.route('/addcategory', methods = ['GET', 'POST'])
def addCategory():
	if 'username' in login_session:
		user = getUserByEmail(login_session['email'])
		if request.method == 'POST':
			name = request.form['name']
			category = Category(name = name, user_id = user.id)
			session.add(category)
			session.commit()
			flash('Successfully added category!')
			categories = session.query(Category).filter_by(user_id = user.id).all()
			# return redirect(url_for('showUserCategory'))
			return render_template('showusercategory.html', categories = categories, user = user)
		return render_template('addcategory.html', user = user)
	else:
		return redirect(url_for('login'))

@app.route('/editcategory/<int:category_id>', methods = ['GET', 'POST'])
def editCategory(category_id):
	if 'username' in login_session:
		category = session.query(Category).filter_by(id = category_id).one()
		user = getUserByEmail(login_session['email'])
		if request.method == 'POST':
			category.name = request.form['name']
			if category.user_id == user.id:
				session.add(category)
				session.commit()
				return redirect(url_for('showUserCategory', category_id = 0))
			else:
				return render_template('error.html', message = 'Error: wrong user', user = user)
		return render_template('editcategory.html', category = category, user = user)
	else:
		return redirect(url_for('login'))

@app.route('/deletecategory/<int:category_id>', methods = ['GET', 'POST'])
def deleteCategory(category_id):
	if 'username' in login_session:
		user = getUserByEmail(login_session['email'])
		category = session.query(Category).filter_by(id = category_id).one()
		if request.method == 'POST':
			if category.user_id == user.id:
				session.delete(category)
				return redirect(url_for('showUserCategory', category_id = 0))
			else:
				return render_template('error.html', message = 'Error: wrong user', user = user)
		return render_template('deletecategory.html', category = category, user = user)
	else:
		return redirect(url_for('login'))

@app.route('/showItems/<int:category_id>', methods = ['GET'])
def showItems(category_id):
	items = session.query(Item).filter_by(category_id = category_id).all()
	category = session.query(Category).filter_by(id = category_id).one()
	categories = session.query(Category).all()
	if category:
		author = session.query(User).filter_by(id = category.user_id).one()
	else:
		author = None
	full_categories = []
	for c in categories:
		item_count = session.query(Item).filter_by(category_id = c.id).all()
		if len(item_count) != 0:
			full_categories.append(c)
	if 'username' in login_session:
		user = getUserByEmail(login_session['email'])
	else:
		user = None
	return render_template('showitems.html', items = items, category = category, user = user, categories = full_categories, author = author)

@app.route('/addItem/<int:category_id>', methods = ['GET', 'POST'])
def addItem(category_id):
	if 'username' in login_session:
		user = getUserByEmail(login_session['email'])
	else:
		user = None
	category = session.query(Category).filter_by(id = category_id).one()
	if request.method == 'POST':
		if user.id == category.user_id:
			item = Item(name = request.form['name'], description = request.form['description'], picture = request.form['picture'], date_added = datetime.datetime.now(), category_id = category_id, user_id = user.id)
			session.add(item)
			session.commit()
			return redirect(url_for('showUserCategory', category_id = category_id))
		else:
			return render_template('error.html', message = 'Error: unable to add item, wrong user logged in', user = user)
	return render_template('additem.html', category = category, user = user)

@app.route('/editItem/<int:item_id>', methods = ['GET', 'POST'])
def editItem(item_id):
	if 'username' in login_session:
		user = getUserByEmail(login_session['email'])
	else:
		user = None
	item = session.query(Item).filter_by(id = item_id).one()
	if request.method == 'POST':
		if user.id == item.user_id:
			item.name = request.form['name']
			item.description = request.form['description']
			item.picture = request.form['picture']
			session.add(item)
			session.commit()
			return redirect(url_for('showUserCategory', category_id = item.category_id))
		else:
			return render_template('error.html', message = 'Error: unable to edit item, wrong user logged in', user = user)
	return render_template('edititem.html', item = item, user = user)

@app.route('/deleteItem/<int:item_id>', methods = ['GET', 'POST'])
def deleteItem(item_id):
	if 'username' in login_session:
		user = getUserByEmail(login_session['email'])
	else:
		user = None
	item = session.query(Item).filter_by(id = item_id).one()
	if request.method == 'POST':
		if user.id == item.user_id:
			session.delete(item)
			session.commit()
			return redirect(url_for('showUserCategory', category_id = item.category_id))
		else:
			return render_template('error.html', message = 'Error: unable to delete item, wrong user logged in', user = user)
	return render_template('deleteitem.html', item = item)

@app.route('/showitem/<int:item_id>', methods = ['GET'])
def showItem(item_id):
	if 'username' in login_session:
		user = getUserByEmail(login_session['email'])
	else:
		user = None
	item = session.query(Item).filter_by(id = item_id).one()
	author = session.query(User).filter_by(id = item.user_id).one()
	return render_template('showitem.html', item = item, item_author = author.name, user = user)

@app.route('/showcategory/<int:category_id>/json', methods = ['GET'])
def showJsonCategory(category_id):
	items = session.query(Item).filter_by(category_id = category_id).all()
	return jsonify(Items = [i.serialize for i in items])	

if __name__ == '__main__':
	app.secret_key = 'Sikrett'
	app.debug = True
	app.run(host = '0.0.0.0', port = 8000)
