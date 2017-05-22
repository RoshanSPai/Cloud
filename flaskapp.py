#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, redirect,session, url_for, send_from_directory, current_app, make_response
import sys
import re
import boto3
import boto
from passlib.hash import sha256_crypt
from boto.s3.connection import S3Connection

conn = S3Connection(aws_access_key_id='AKIAIIMYVX2YNQJYWYTQ',aws_secret_access_key='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')
bucket_name= 'roshanassign3'
bucket=conn.get_bucket(bucket_name,validate=True)
app = Flask(__name__)
app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'

# Get the service resource.
dynamodb = boto3.resource('dynamodb',aws_access_key_id='AKIAIIMYVX2YNQJYWYTQ',aws_secret_access_key='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',region_name='us-west-2')
table=dynamodb.Table('users')
photoTable = dynamodb.Table('photo')
commentTable=dynamodb.Table('commentTable')
#login page
@app.route('/')
def login():
    if 'username' in session:
      username = session['username']
      response2 = photoTable.scan()
      plist=[]
      for item in response2['Items']:
           photoURL = item['url']
           owner=item['owner']
           pdict={}
           pdict['url']=photoURL
           pdict['owner']=owner
           plist.append(pdict)
      return render_template("index.html",uname=username,lists=plist)
    out=''
    return render_template("login.html", contents=out)

#logout
@app.route('/logoutUser', methods=['POST'])
def logoutUser():
    session.pop('username', None)
    out=''
    return render_template("login.html", contents=out)    

#create new user
#@app.route('/create',methods=["POST"])
#def create():
#    newuser = request.form['newuser']
#    ulist=[]
#    with open('/home/ubuntu/flaskapp/authenticate.txt', 'a+') as data:
#      for line in data:
#          ulist.append(line.strip())
#      if newuser.strip() in ulist:
#          out = "User exists. Please login to continue"
#          return render_template("login.html",contents=out)
#      else:
#          data.write('\n'+newuser)      
#          out = "User created. Please login to continue"
#          return render_template("login.html",contents=out)

# login
@app.route('/userlogin', methods=['GET','POST'])
def Hello(): 
    userName = request.form['uname']  
    password = request.form['psw']   
    #hashedPass = sha256_crypt.encrypt(password)
    response= table.get_item(
      Key={
          'username':userName
          }
      )
    item=response['Item']
    if sha256_crypt.verify(password,item['password']):
        session['username']=userName
        response2 = photoTable.scan()
        plist=[]
        for item in response2['Items']:
             photoURL = item['url']
             owner=item['owner']
             pdict={}
             pdict['url']=photoURL
             pdict['owner']=owner
             plist.append(pdict)
        return render_template("index.html",uname=session['username'],lists=plist)
    else:
        out="Username or password invalid. Please try again"
        return render_template("login.html",contents=out)

#new user creation
@app.route('/newUser', methods=['GET','POST'])
def register():
    return render_template("register.html")

@app.route('/create', methods=['GET','POST'])
def newUser():
    userName = request.form['uname']  
    password = request.form['psw']
    hashedPass = sha256_crypt.encrypt(password)
    table.put_item(
        Item={
              'username':userName,
              'password':hashedPass
        }
    ) 
    return render_template("login.html")
        

#back button
@app.route('/back',methods=['GET', 'POST'])
def Back():
    file_list=[]
    for files in bucket.get_all_keys():
        file_list.append(files.key)
    return render_template("index.html",nlist=file_list)        

#upload a new image
@app.route('/upload',methods=['GET', 'POST'])
def Upload():
    uname = session['username']
    upload_file = request.files['file']
    file_name = uname + upload_file.filename
    file_contents = upload_file.read()
    k = bucket.new_key(bucket_name)
    k.key = file_name
    k.content_type='image/png' 
    k.content_disposition='inline'
    k.set_contents_from_string(file_contents)
    k.set_acl('public-read')
    secure_https_url = 'https://s3-us-west-2.amazonaws.com/{bucket}/{key}'.format(
    bucket=bucket_name,
    key=file_name)
    photoTable.put_item(
        Item={
              'url':secure_https_url,
              'owner':uname
        }
    ) 
    out = "success"
    response2 = photoTable.scan()
    plist=[]
    for item in response2['Items']:
         photoURL = item['url']
         owner=item['owner']
         pdict={}
         pdict['url']=photoURL
         pdict['owner']=owner
         plist.append(pdict)
    return render_template("index.html",contents=out,uname=uname,lists=plist)

#upload a new image
@app.route('/uploadComment',methods=['GET', 'POST'])
def UploadComment():
    comment = request.form['comment']
    photo=request.form.get("photo","")
    commentTable.put_item(
        Item={
              'comment':comment,
              'photo':photo,
              'uname':session['username']
        }
    )
    response2 = photoTable.scan()
    plist=[]
    for item in response2['Items']:
         photoURL = item['url']
         owner=item['owner']
         pdict={}
         pdict['url']=photoURL
         pdict['owner']=owner
         plist.append(pdict)
    return render_template("index.html",contents=out,uname=uname,lists=plist)

#list all files
#@app.route('/list',methods=['POST'])
#def List():
#    dlist=[]
#    for files in bucket.get_all_keys():
#        file_name = files.key
#        size = files.size
#        last_modified = files.last_modified
#        dvar={}
#        dvar['file_name']=file_name
#        dvar['size']=size
#        dvar['last_modified']=last_modified
#        dlist.append(dvar)
#    return render_template("list.html",lists=dlist)               

#download a file
@app.route('/download', methods=['GET','POST'])
def download():
    s3 = boto3.resource('s3',aws_access_key_id, aws_secret_access_key , region_name= 'us-west-2')
    bucket = s3.Bucket(bucket_name)
    file_selected=request.form['filename']
    for files in bucket.objects.all():
        if file_selected == files.key:
            file_contents = files.get()['Body'].read()
            response = make_response(file_contents)
            response.headers["Content-Disposition"] = "attachment; filename=" + file_selected
    return response

#delete a file
@app.route('/delete', methods=['GET','POST'])
def delete():
    file_selected = request.form['filedelete']  
    for files in bucket.get_all_keys():
        if files.key == file_selected:
            files.delete()
            out = "file deleted"
    return render_template("uploadfile.html",contents=out)


if __name__ == '__main__':
    app.run()