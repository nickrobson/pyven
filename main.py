#!/usr/bin/env python

import hashlib
import json
import os
import re

from flask import Flask, request, session, redirect, url_for, abort, \
                    flash, render_template, Blueprint, g, send_file


class Repo(object):

    def __init__(self, data):
        super(Repo, self).__init__()
        self.data = data
        self.browse = data.get('browse', True)
        self.auth = data.get('auth', None)

    def has_auth(self):
        return self.auth is not None

    def is_auth(self, username, password):
        if not self.has_auth():
            return True
        if username is None or password is None:
            return False
        return self.auth.get(username) == password


app = Flask('pyven')

with open('config.json', 'r') as f:
    app.config.update(json.loads(f.read()))

bp = Blueprint('main', __name__)
app.secret_key = app.config['secret']
prefix = app.config.get('prefix', '')
valid_gid = re.compile(r'[a-zA-Z0-9.]+')
valid_aid = re.compile(r'[a-zA-Z0-9]+')
valid_vid = re.compile(r'[0-9]+(?:\.[0-9]+)*')

cfg_repos = app.config['repositories']
repos = dict()
for repo in cfg_repos:
    repos[repo] = Repo(cfg_repos[repo])


@bp.route('/')
def get_index():
    return render_template('index.html')


@bp.route('/content/')
@bp.route('/upload/')
@bp.route('/login/')
def get_repos():
    return render_template('repos.html', repos=repos)


@bp.route('/content/<repo>/')
@bp.route('/content/<repo>/<path:url>')
def get_file(repo, url=''):
    if '..' in url or url.startswith('/'):
        abort(404)
    rep = repos[repo]
    if not rep:
        abort(404)
    fname = os.path.join('artifacts', repo, url)
    if os.path.isfile(fname):
        ext = fname[fname.rfind('.')+1:]
        mime = 'text/plain'
        return send_file(fname, mime)
    elif os.path.isdir(fname):
        if rep.browse or (session.get('repo') == repo and session.get('username')):
            ls = os.listdir(fname)
            files = []
            if not url.startswith('/'):
                url = '/' + url
            if not url.endswith('/'):
                url += '/'
            for file in ls:
                fn = os.path.join(fname, file)
                info = dict()
                stat = os.stat(fn)
                info['name'] = file
                info['link'] = url_for('.get_file', repo=repo, url=url[1:] + file)
                if os.path.isdir(fn):
                    info['type'] = 'directory'
                    info['name'] += '/'
                    info['link'] += '/'
                elif os.path.isfile(fn):
                    info['type'] = 'file'
                    info['size'] = stat.st_size
                files.append(info)
            files = sorted(files, key=lambda f: f['type'])
            if url != '/':
                parent = url[1:-1]
                if '/' in parent:
                    parent = parent[:parent.rfind('/')]
                else:
                    parent = ''
                finfo = {
                            'name': '../',
                            'link': url_for('.get_file', repo=repo, url=parent)
                        }
                if finfo['link'] != url_for('.get_file', repo=repo, url=''):
                    finfo['link'] += '/'
                files.insert(0, finfo)
            return render_template('dir.html', dir=url, files=files)
        abort(403)
    abort(404)


def make_md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    hash_md5 = hash_md5.hexdigest()
    with open(fname + '.md5', "w+") as f:
        f.write(hash_md5)


def make_sha1(fname):
    hash_sha1 = hashlib.sha1()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
    hash_sha1 = hash_sha1.hexdigest()
    with open(fname + '.sha1', "w+") as f:
        f.write(hash_sha1)


@bp.route('/upload/<repo>/', methods=['GET', 'POST'])
def upload(repo):
    if not repos[repo]:
        abort(404)
    if not session.get('username') or session.get('repo') != repo:
        return redirect(url_for('.login', repo=repo))
    if request.method == 'GET':
        return render_template('upload.html')
    jar = request.files.get('jar')
    pom = request.files.get('pom')
    gid = request.form.get('groupId')
    aid = request.form.get('artifactId')
    vid = request.form.get('version')
    if jar and pom and gid and aid and vid:
        vg = valid_gid.match(gid)
        va = valid_aid.match(aid)
        vv = valid_vid.match(vid)
        if vg and va and vv:
            p = os.path.join(*gid.split('.'))
            path = os.path.join('artifacts', repo, p, aid, vid)
            jarpath = os.path.join(path, '%s-%s.jar' % (aid, vid))
            pompath = os.path.join(path, '%s-%s.pom' % (aid, vid))
            if not os.path.exists(os.path.dirname(jarpath)):
                os.makedirs(os.path.dirname(jarpath))
            with open(jarpath, "wb+") as f:
                jar.save(f)
            with open(pompath, "wb+") as f:
                pom.save(f)
            make_md5(jarpath)
            make_sha1(jarpath)
            make_md5(pompath)
            make_sha1(pompath)
            return '{}'
        res = []
        if not vg:
            res.append('groupId')
        if not va:
            res.append('artifactId')
        if not vv:
            res.append('version')
        return '{"invalid":%s}' % json.dumps(res)
    return '{"invalid":"missing params"}'


@bp.route('/login/<repo>/', methods=['GET', 'POST'])
def login(repo):
    rep = repos[repo]
    if not rep:
        abort(404)
    if session.get(repo) == repo:
        return redirect(url_for('.get_file', repo=repo))
    if request.method == 'GET':
        return render_template('login.html')
    else:
        form = request.form
        user = form.get('username')
        pword = form.get('password')
        if user and pword:
            if rep.is_auth(user, pword):
                session['repo'] = repo
                session['username'] = user
                return redirect(url_for('.get_file', repo=repo))
            else:
                flash('Invalid username or password.')
                return redirect(url_for('.login', repo=repo))
        abort(400)


@bp.route('/logout/')
def logout():
    session.pop('repo', None)
    if session.pop('username', None):
        flash('You have been logged out.')
    return redirect(url_for('.show_all'))


@app.errorhandler(403)
def err_forbidden(e):
    return render_template('error403.html'), 403


@app.errorhandler(404)
def err_page_not_found(e):
    return render_template('error404.html'), 404


if __name__ == "__main__":
    app.register_blueprint(bp, url_prefix=prefix)
    app.run(host='0.0.0.0', port=app.config.get('port', 5000), debug=True)
