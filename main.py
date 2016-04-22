#!/usr/bin/env python

import hashlib
import json
import os
import re
import time

from flask import Flask, request, session, redirect, url_for, abort, \
                    flash, render_template, Blueprint, g, send_file


ARTIFACTS_DIR = 'artifacts'


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
    if not os.path.isdir(os.path.join(ARTIFACTS_DIR, repo)):
        os.makedirs(os.path.join(ARTIFACTS_DIR, repo))


@bp.route('/')
def get_index():
    return render_template('index.html')


@bp.route('/content/')
@bp.route('/upload/')
@bp.route('/login/')
def get_repos():
    return render_template('repos.html')


@bp.route('/content/<repo>/')
@bp.route('/content/<repo>/<path:url>')
def get_file(repo, url=''):
    if '..' in url or url.startswith('/'):
        abort(404)
    rep = repos.get(repo)
    if not rep:
        abort(404)
    fname = os.path.join(ARTIFACTS_DIR, repo, url)
    if os.path.isfile(fname):
        ext = fname[fname.rfind('.')+1:]
        mime = 'text/plain'
        if ext == 'xml':
            mime = 'text/xml'
        print ext, mime
        return send_file(fname, mime)
    elif os.path.isdir(fname):
        logged_in = session.get('repo') == repo and session.get('username')
        if rep.browse or logged_in:
            ls = os.listdir(fname)
            files = []
            if not url.startswith('/'):
                url = '/' + url
            if not url.endswith('/'):
                url += '/'
            furl = url[1:]
            for file in ls:
                fn = os.path.join(fname, file)
                info = dict()
                stat = os.stat(fn)
                info['name'] = file
                info['link'] = url_for('.get_file', repo=repo, url=furl+file)
                if os.path.isdir(fn):
                    info['type'] = 'directory'
                    info['name'] += '/'
                    info['link'] += '/'
                    info['size'] = '-'
                    info['date'] = '-'
                elif os.path.isfile(fn):
                    info['type'] = 'file'
                    info['size'] = stat.st_size
                    info['date'] = time.asctime(time.gmtime(stat.st_ctime))
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
                            'link': url_for('.get_file', repo=repo, url=parent),
                            'size': '-',
                            'date': '-'
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
    if not repos.get(repo):
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
            path = os.path.join(ARTIFACTS_DIR, repo, p, aid, vid)
            jarpath = os.path.join(path, '%s-%s.jar' % (aid, vid))
            pompath = os.path.join(path, '%s-%s.pom' % (aid, vid))
            mdpath = os.path.join(path, 'maven-metadata.xml')
            mdvpath = os.path.join(os.path.dirname(path), 'maven-metadata.xml')
            if not os.path.exists(os.path.dirname(jarpath)):
                os.makedirs(os.path.dirname(jarpath))
            with open(jarpath, 'wb+') as f:
                jar.save(f)
            with open(pompath, 'wb+') as f:
                pom.save(f)
            make_md5(jarpath)
            make_sha1(jarpath)
            make_md5(pompath)
            make_sha1(pompath)
            with open(mdpath, 'w+') as f:
                f.write('<metadata>')
                f.write('<groupId>%s</groupId>' % gid)
                f.write('<artifactId>%s</artifactId>' % aid)
                f.write('<version>%s</version>' % vid)
                f.write('</metadata>')
            make_md5(mdpath)
            make_sha1(mdpath)
            with open(mdvpath, 'w+') as f:
                f.write('<metadata>')
                f.write('<groupId>%s</groupId>' % gid)
                f.write('<artifactId>%s</artifactId>' % aid)
                f.write('<version>%s</version>' % vid)
                f.write('<versioning><versions>')
                dirname = os.path.dirname(path)
                for l in os.listdir(dirname):
                    if os.path.isdir(os.path.join(dirname, l)):
                        f.write('<version>%s</version>' % l)
                f.write('</versions>')
                ts = time.strftime('%Y%m%d%H%M%S', time.gmtime())
                f.write('<lastUpdated>%s</lastUpdated>' % ts)
                f.write('</versioning></metadata>')
            make_md5(mdvpath)
            make_sha1(mdvpath)
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
    rep = repos.get(repo)
    if not rep:
        abort(404)
    if session.get('repo') == repo:
        return redirect(url_for('.get_file', repo=repo))
    if request.method == 'GET':
        return render_template('login.html')
    form = request.form
    user = form.get('username')
    pword = form.get('password')
    if user and pword:
        if rep.is_auth(user, pword):
            session['repo'] = repo
            session['username'] = user
            return redirect(url_for('.get_file', repo=repo))
        flash('Invalid username or password.')
        return redirect(url_for('.login', repo=repo))
    abort(400)


@bp.route('/logout/')
def logout():
    session.pop('repo', None)
    if session.pop('username', None):
        flash('You have been logged out.')
    return redirect(url_for('.show_all'))


@app.errorhandler(400)
def err_bad_request(e):
    return render_template('error400.html'), 400


@app.errorhandler(403)
def err_forbidden(e):
    return render_template('error403.html'), 403


@app.errorhandler(404)
def err_page_not_found(e):
    return render_template('error404.html'), 404


@app.context_processor
def inject_vars():
    return {
        'repos': repos
    }

if __name__ == "__main__":
    app.register_blueprint(bp, url_prefix=prefix)
    app.run(host='0.0.0.0', port=app.config.get('port', 5000))
