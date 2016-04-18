#!/usr/bin/env python

import hashlib
import json
import os
import re

from flask import Flask, request, session, redirect, url_for, abort, \
                    flash, render_template, Blueprint, g, send_file


app = Flask('pyven')

with open('config.json', 'r') as f:
    app.config.update(json.loads(f.read()))

bp = Blueprint('main', __name__)
app.secret_key = app.config['secret']
prefix = app.config.get('prefix', '')
valid_gid = re.compile(r'[a-zA-Z0-9.]+')
valid_aid = re.compile(r'[a-zA-Z0-9]+')
valid_vid = re.compile(r'[0-9]+(?:\.[0-9]+)*')


@bp.route('/')
def get_index():
    return render_template('index.html')


@bp.route('/content/')
@bp.route('/content/<path:url>')
def get_file(url=''):
    if '..' in url or url.startswith('/'):
        abort(404)
    fname = os.path.join('artifacts', url)
    if os.path.isfile(fname):
        return send_file(fname)
    elif os.path.isdir(fname):
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
            info['link'] = url_for('.get_file', url=url[1:] + file)
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
                        'link': url_for('.get_file', url=parent)
                    }
            if finfo['link'] != url_for('.get_file', url=''):
                finfo['link'] += '/'
            files.insert(0, finfo)
        return render_template('dir.html', dir=url, files=files)
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


@bp.route('/upload/', methods=['GET', 'POST'])
def upload():
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
            path = '%s/%s/%s' % (gid.replace('.', '/'), aid, vid)
            path = os.path.join('artifacts', path)
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
        return '{"error":%s}' % json.dumps(res)
    return '{"error":"missing params"}'


@app.errorhandler(404)
def err_page_not_found(e):
    return render_template('error404.html'), 404


if __name__ == "__main__":
    app.register_blueprint(bp, url_prefix=prefix)
    app.run(host='0.0.0.0', port=app.config.get('port', 5000), debug=True)
