from flask import Flask, render_template, request, redirect, jsonify
from flask import url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from application_db_setup import Base, Sport, RecentlyAdded, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from oauth2client.client import AccessTokenCredentials
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
            open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///application.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
          'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    #login_session['provider'] = 'google'
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id
    response = make_response(json.dumps('Successfully connected user', 200))

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    #login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ''' " style = "width: 300px; height: 300px;border-radius:
                        150px;-webkit-border-radius: 150px;-moz-border-radius:
                        150px;"> '''
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    user = session.query(User).filter_by(email=email).one()
    return user.id


# DISCONNECT - Revoke a current user's token and reset their login_session

@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
          json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Sports Recently Added Information
@app.route('/sport/<int:sport_id>/RecentlyAdded/JSON')
def sportRecentlyAddedJSON(sport_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    items = session.query(RecentlyAdded).filter_by(
        sport_id=sport_id).all()
    return jsonify(Sports=[i.serialize for i in items])


# JSON APIs to view Sports
@app.route('/sport/JSON')
def sportJSON():
    sport = session.query(Sport).all()
    return jsonify(sport=[s.serialize for s in sport])


# Show all Sports
@app.route('/')
@app.route('/sport/')
def showSport():
    sport = session.query(Sport).order_by(asc(Sport.name))
    if 'username' not in login_session:
        return render_template('publicSport.html', sport=sport)
    else:
        return render_template('sports.html', sport=sport)

# Create a new Sport

@app.route('/sport/new/', methods=['GET', 'POST'])
def newSport():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newSport = Sport(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newSport)
        flash('New Sport %s Successfully Created' % newSport.name)
        session.commit()
        return redirect(url_for('showSport'))
    else:
        return render_template('newSport.html')


# Edit a Sport
@app.route('/sport/<int:sport_id>/edit/', methods=['GET', 'POST'])
def editSport(sport_id):
    editedSport = session.query(
        Sport).filter_by(id=sport_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedSport.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this field. Please create your own sport in order to edit.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedSport.name = request.form['name']
            flash('Sport Successfully Edited %s' % editedSport.name)
        return redirect(url_for('showSport'))
    else:
        return render_template('editSport.html', sport=editedSport)


# Delete a Sport
@app.route('/sport/<int:sport_id>/delete/', methods=['GET', 'POST'])
def deleteSport(sport_id):
    sportToDelete = session.query(Sport).filter_by(id=sport_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if sportToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this sport. Please create your own sport in order to delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(sportToDelete)
        flash('%s Successfully Deleted' % sportToDelete.name)
        session.commit()
        return redirect(url_for('showSport', sport_id=sport_id))
    else:
        return render_template('deleteSport.html', sport=sportToDelete)


# Show items in a sport Recently Added
@app.route('/sport/<int:sport_id>/')
@app.route('/sport/<int:sport_id>/RecentlyAdded/')
def showRecentlyAdded(sport_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    creator = getUserInfo(sport.user_id)
    items = session.query(RecentlyAdded).filter_by(sport_id=sport_id).all()
    if 'username' not in login_session or creator.id != (login_session
                                                         ['user_id']):
        return render_template('PublicRecentlyAdded.html', items=items,
                               sport=sport, creator=creator)
    else:
        return render_template('recentlyAdded.html', items=items,
                               sport=sport, creator=creator)


# Create a new Recently Addded Item
@app.route('/sport/<int:sport_id>/RecentlyAdded/new/', methods=['GET', 'POST'])
def newRecentlyAdded(sport_id):
    if 'username' not in login_session:
        return redirect('/login')
    sport = session.query(Sport).filter_by(id=sport_id).one()
    if login_session['user_id'] != sport.user_id:
        return "<script>function myFunction(){alert('You are not authorized to contribute recently added items to this sport. Please create your own sport in order to add items.');} </script><body onload='myFunction()'>"
    if request.method == 'POST':
        newRecentlyAdded = RecentlyAdded(name=request.form['name'],
                                         description=request.form
                                         ['description'],
                                         price=request.form['price'],
                                         sport_id=sport_id,
                                         user_id=sport.user_id)
        session.add(newRecentlyAdded)
        session.commit()
        flash('New Recently Added %s Item Successfully Created' % (newRecentlyAdded.name))
        return redirect(url_for('showSport', sport_id=sport_id))
    else:
        return render_template('newRecentlyAdded.html', sport_id=sport_id)


# Edit a RecentlyAdded item
@app.route('/sport/<int:sport_id>/RecentlyAdded/<int:recently_added_id>/edit',
           methods=['GET', 'POST'])
def editRecentlyAdded(sport_id, recently_added_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = (session.query(RecentlyAdded)
                  .filter_by(id=recently_added_id)
                  .one())
    sport = session.query(Sport).filter_by(id=sport_id).one()
    if login_session['user_id'] != sport.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit items for this sport. Please create your own sport in order to edit items.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
            
        session.add(editedItem)
        session.commit()
        flash('Recently Added Item Successfully Edited')
        return redirect(url_for('showSport', sport_id=sport_id))
    else:
        return render_template('editRecentlyAdded.html', sport_id=sport_id,
                               recently_added_id=recently_added_id,
                               item=editedItem)


# Delete a recently added sport item
@app.route('/sport/<int:sport_id>/RecentlyAdded/<int:recently_added_id>/delete',
           methods=['GET', 'POST'])
def deleteRecentlyAdded(sport_id, recently_added_id):
    if 'username' not in login_session:
        return redirect('/login')
    sport = session.query(Sport).filter_by(id=sport_id).one()
    iToDel = session.query(RecentlyAdded).filter_by(id=recently_added_id).one()
    if login_session['user_id'] != sport.user_id:
        return "<script>function myFunction() {alert('You are not authorized to delete items from this sport. Please create your own sport in order to delete items.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(iToDel)
        session.commit()
        flash('Recently Added Item Successfully Deleted')
        return redirect(url_for('showRecentlyAdded', sport_id=sport_id))
    else:
        return render_template('deleteRecentlyAdded.html', item=iToDel)


# Disconnect based on provider



if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
