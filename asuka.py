#!/usr/bin/env python
"""
Asuka Virtualization Manager or Asuka-VTM is a tool for creating virtual
machines you can share with the web.
"""

__author__ = 'Naphtha Nepanthez'
__version__ = '0.0.1'
__license__ = 'AGPL-v3.0' # SEE LICENSE FILE

import vertibird, argparse, toml, sys, os, random, string, base64, time, bcrypt
import pickle, shlex, io, subprocess, asyncio, copy, threading, re, queue
import select as fselect

vertibird.VNC_FRAMERATE = 24

from captcha.audio import AudioCaptcha
from captcha.image import ImageCaptcha

from PIL import Image

from quart import (
    Quart, websocket, render_template, url_for, session, request,
    redirect, abort, Response, make_response
)
from pony.orm import *

app = Quart(__name__)

configfile_name = os.path.join(app.root_path, 'config.toml')
if not os.path.isfile(configfile_name):
    configfile = """
# This is the configuration file for Asuka.
# -----------------------------------------------------------------------------
# For improved scalability, you should configure a database server such as
# MySQL or PostgreSQL here.
# -----------------------------------------------------------------------------
# Never share this file with anyone.

{0}
[default_admin_account]
# This section is only ever used on first launch, and is used to define which
# account will be given administrator permissions when it is created.
username = "admin"

[database]
# This section allows you to pick which database engine you intend to use.
# The default is SQLite. The following engines are supported:
# - sqlite
# - mysql
# - postgres
engine = "sqlite"

[database.file]
# This section allows you to specify what file you would like to use for a
# local database system such as SQLite.
# You can even specify ":memory:" to use an in-memory database.
# This section will be ignored if you use a remote database system, such as
# MySQL or PostgreSQL.
file = "asuka.db"

[database.remote]
# These are the connection details for a remote database. These fields are
# required if you are using MySQL or PostgreSQL. They will be ignored if you
# are using SQLite.
host = ""
username = ""
password = ""
schema = ""

[site]
# These are configuration options for the site itself, particularly its
# appearance.
logo = "icon.svg"
secret_key = "{1}"

# Once you're done configuring Asuka through this file, you should change
# the site-wide options from within Asuka itself. You'll probably want to
# change things like the default copyright string, whether or not you want
# comments to be made, etc. You'll also want to read the Help page in the
# administrator menu too, as it will explain how to actually use Asuka.
    """.format(toml.dumps({
        'version': __version__
    }), os.urandom(32).hex())

    open(configfile_name, 'w').write(configfile)

    print("""The default Asuka configuration file has been created in
the current working directory. Please read and edit it before you
continue, as you will need to configure the default admin account and
the database options.""")

    sys.exit()

app.config['file'] = toml.load(configfile_name)
app.secret_key = bytes.fromhex(app.config['file']['site']['secret_key'])

root_vertibird = vertibird.Vertibird()
db = Database()
vb = (lambda: root_vertibird) # Can be switched out for session_generator
    
class Group(db.Entity):
    name     = PrimaryKey(str)
    priority = Required  (int)
    perms    = Required  (bytes)
    
class User(db.Entity):
    name     = PrimaryKey(str)
    auth     = Required  (bytes)
    groups   = Required  (bytes)
    token    = Required  (bytes)

class VirtualMachine(db.Entity):
    id       = PrimaryKey(str)
    name     = Required  (str)
    owner    = Required  (str)

class Captcha(db.Entity):
    id       = PrimaryKey(int, auto=True)
    code     = Required  (str)
    created  = Required  (int)
    
acceptable_username_set = set(
    string.ascii_lowercase
    + string.digits
    + '_-@!?./+'
)

if app.config['file']['database']['engine'] == 'sqlite':
    db.bind(
        provider  = app.config['file']['database']['engine'],
        filename  = app.config['file']['database']['file']['file'],
        create_db = True
    )
else:
    db.bind(
        provider  = app.config['file']['database']['engine'],
        host      = app.config['file']['database']['remote']['host'],
        user      = app.config['file']['database']['remote']['username'],
        passwd    = app.config['file']['database']['remote']['password'],
        db        = app.config['file']['database']['remote']['schema']
    )

db.generate_mapping(create_tables=True)

@db_session
def gen_captcha():
    # NOTE: This causes an invalid pointer or segfault on some systems.
    # See https://github.com/naphthasl/sakamoto/issues/7

    code = ''.join([random.choice(string.digits) for _ in range(4)])
    image = ImageCaptcha().generate(code).read()

    x = Captcha(
        code    = code,
        created = round(time.time())
    )

    commit()
    
    return (x.id, 'data:image/png;base64,{0}'.format(
        base64.b64encode(image).decode()
    ))

@db_session
def validate_captcha(cid: int, i: str) -> bool:
    try:
        if not (cid in select(p.id for p in Captcha)[:]):
            return False
    except:
        return False
    
    captcha = Captcha.get(id=cid)
    captcha_code = captcha.code
    captcha.delete()
    commit()
    
    if i.strip() != captcha_code:
        return False
        
    return True

@db_session
def cleanup_captcha():
    for x in (
            select(p for p in Captcha if (time.time() - p.created) > 3600)[:]
        ):

        x.delete()

    commit()
    
@db_session
def get_login():
    try:
        if not ('logged_in' in session):
            return False
        elif User.get(
            name = session['username']
        ).token != session['logged_in']:
            return False
    except AttributeError:
        return False
        
    return True
        
@db_session
def get_groups():
    if not get_login():
        return ['default',]
    else:
        return pickle.loads(User.get(name = session['username']).groups)
        
@db_session
def get_vms():
    ret = {}
    if not get_login():
        return ret
    else:
        i = select(
            p for p in VirtualMachine if p.owner == session['username']
        )[:]
    
        for x in i:
            ret[x.id] = x.name
            
        return ret
        
app.jinja_env.globals.update(get_login=get_login)
app.jinja_env.globals.update(get_groups=get_groups)
app.jinja_env.globals.update(get_vms=get_vms)
app.jinja_env.globals.update(vmif=vb)

@app.route('/')
async def index():
    cleanup_captcha()
    
    return await render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
async def login():
    if get_login():
        abort(401)
    
    error = None
    if request.method == 'POST':
        with db_session:
            form = await request.form
            if not validate_captcha(int(form['captchaid']), form['captcha']):
                error = 'Captcha input was incorrect.'
            elif len(
                    select(p for p in User if p.name == form['username'])[:]
                ) < 1:
                error = 'Incorrect username or password.'
            elif not bcrypt.checkpw(
                    form['password'].encode(),
                    User.get(name = form['username']).auth
                ):
                error = 'Incorrect username or password.'
            else:
                user = User.get(name = form['username'])
                session['logged_in'] = user.token
                session['username'] = form['username']
                commit()
                
                return redirect(url_for('index'))
    
    return await render_template(
        'login.html',
        captcha = gen_captcha(),
        error = error
    )

@app.route('/register', methods=['GET', 'POST'])
async def register():
    if get_login():
        abort(401)
    
    error = None
    if request.method == 'POST':
        with db_session:
            form = await request.form
            if not validate_captcha(int(form['captchaid']), form['captcha']):
                error = 'Captcha input was incorrect.'
            elif not acceptable_username_set.issuperset(form['username']):
                error = ('Usernames can only contain digits, ' +
                'lowercase letters, hyphens and underscores.')
            elif len(form['username']) > 32:
                error = 'Usernames must be under 32 characters long.'
            elif form['password'] != form['confirmpassword']:
                error = 'Passwords do not match.'
            elif len(
                    select(p for p in User if p.name == form['username'])[:]
                ) > 0:
                    
                error = 'User already exists!'
            else:
                groups = ['default', 'registered']
                if form['username'] == (
                        app.config['file']['default_admin_account']['username']
                    ):
                    
                    groups.append('admin')
                
                token = os.urandom(48)
                User(
                    name = form['username'],
                    auth = bcrypt.hashpw(
                        form['password'].encode(),
                        bcrypt.gensalt()
                    ),
                    groups = pickle.dumps(groups),
                    token = token
                )
                commit()
                
                session['logged_in'] = token
                session['username'] = form['username']
                return redirect(url_for('index'))
    
    return await render_template(
        'register.html',
        captcha = gen_captcha(),
        error = error
    )

@app.route('/logout')
async def logout():
    if not get_login():
        abort(401)
        
    with db_session:
        token = os.urandom(48)
        user = User.get(name = session['username'])
        user.token = token
        commit()
    
    session.clear()
    
    return redirect(url_for('index'))

@app.route('/password', methods=['GET', 'POST'])
async def password():
    if not get_login():
        abort(401)
    
    error = None
    if request.method == 'POST':
        with db_session:
            form = await request.form
            if not validate_captcha(int(form['captchaid']), form['captcha']):
                error = 'Captcha input was incorrect.'
            elif not bcrypt.checkpw(
                    form['currentpassword'].encode(),
                    User.get(name = session['username']).auth
                ):
                error = 'Incorrect username or password.'
            elif form['newpassword'] != form['confirmpassword']:
                error = 'Passwords do not match.'
            else:
                token = os.urandom(48)
                user = User.get(name = session['username'])
                user.auth = bcrypt.hashpw(
                    form['newpassword'].encode(),
                    bcrypt.gensalt()
                )
                user.token = token
                
                commit()
                
                session['logged_in'] = token
                return redirect(url_for('index'))
    
    return await render_template(
        'password.html',
        captcha = gen_captcha(),
        error = error
    )

@app.route('/dashboard', methods=['GET', 'POST'])
async def dashboard():
    if not get_login():
        abort(401)
    
    error = None
    if request.method == 'POST':
        with db_session:
            form = await request.form
            if not acceptable_username_set.issuperset(form['vmname']):
                error = ('Names can only contain digits, ' +
                'lowercase letters, hyphens and underscores.')
            elif len(form['vmname']) > 32:
                error = 'Names must be under 32 characters long.'
            else:
                vid = vb().create().id
                
                VirtualMachine(
                    id = vid,
                    name = form['vmname'],
                    owner = session['username']
                )
                commit()
    
    return await render_template(
        'dashboard.html',
        error = error
    )
    
@app.route('/vm/<vuuid>')
@app.route('/vm/<vuuid>/<error>')
async def vm(vuuid, error = None):
    if (not get_login()) or (vuuid not in get_vms().keys()):
        abort(401)
    
    return await render_template(
        'vm.html',
        vuuid = vuuid,
        vmname = get_vms()[vuuid],
        error = error
    )
    
@app.route('/vmd/<vuuid>')
async def vmd(vuuid):
    if (not get_login()) or (vuuid not in get_vms().keys()):
        abort(401)
    
    vb().remove(vuuid)
    
    with db_session:
        VirtualMachine.get(id = vuuid).delete()
        commit()
        
    return redirect(url_for('dashboard'))

@app.route('/vms/<action>/<vuuid>')
async def vms(action, vuuid):
    if (not get_login()) or (vuuid not in get_vms().keys()):
        abort(401)
    
    error = None
    try:
        vmexec = vb().get(vuuid)
        if action == 'start':
            vmexec.start()
        elif action == 'shutdown':
            vmexec.signal_shutdown()
        elif action == 'reset':
            vmexec.signal_reset()
        elif action == 'stop':
            vmexec.stop()
        else:
            error = 'Invalid action'
    except Exception as e:
        error = str(e)
        
    return redirect(url_for('vm', vuuid = vuuid, error = error))

@app.route('/interact/<vuuid>')
async def interact(vuuid):
    if (not get_login()) or (vuuid not in get_vms().keys()):
        abort(401)
        
    return await render_template(
        'interact.html',
        vuuid = vuuid
    )

@app.route('/display/<vuuid>')
@app.route('/display/<vuuid>/<palette>')
async def display(vuuid, palette = 'default'):
    if (not get_login()) or (vuuid not in get_vms().keys()):
        abort(401)
    
    async def async_generator():
        vmint = vb().get(vuuid)
        display = vmint.display
        start_shape = copy.deepcopy(display.shape)
            
        process = subprocess.Popen(
            shlex.split(('ffmpeg -f rawvideo -video_size {0}x{1} -vsync 0 '+
                '-pixel_format rgb24 -i - -i ./static/palette-{2}.png -map 0 '+
                '-vsync 0 -f gif -hide_banner -loglevel warning -nostats '+
                '-lavfi "scale={3}:-1:flags=fast_bilinear,'+
                'paletteuse=dither=bayer:diff_mode=rectangle" '+
                '-loop -1 -blocksize 4096 -flush_packets 1 -y -').format(
                    shlex.quote(str(display.shape[0])),
                    shlex.quote(str(display.shape[1])),
                    shlex.quote(re.sub('[^0-9a-zA-Z]+', '_', palette.lower())),
                    shlex.quote(str(display.shape[0] // 1.25))
                )),
            stdin  = subprocess.PIPE,
            stdout = subprocess.PIPE
        )
        
        read_queue = queue.Queue(maxsize = 1024)
        
        def writing_queue(disp, proc):
            last = None
            while proc.returncode is None:
                current = disp.capture().tobytes()
                
                if last != current:
                    try:
                        proc.stdin.write(current)
                    except:
                        break
                    
                    last = current
                else:
                    time.sleep(1 / vertibird.VNC_FRAMERATE)
        
            if proc.returncode is None:
                proc.kill()
        
        def reading_queue(q, proc, vmcls):
            while proc.returncode is None:
                if vmcls.state() != 'online':
                    break
                elif q.full():
                    break
                
                try:
                    q.put(os.read(proc.stdout.fileno(), 4096))
                except:
                    break
                
            if proc.returncode is None:
                proc.kill()
        
        threading.Thread(
            target = writing_queue,
            args = (display, process),
            daemon = True
        ).start()
        
        threading.Thread(
            target = reading_queue,
            args = (read_queue, process, vmint),
            daemon = True
        ).start()
        
        last = None
        while (process.returncode is None
            and vmint.state() == 'online'
            and display.shape == start_shape
        ):
            await asyncio.sleep(1 / vertibird.VNC_FRAMERATE)
                    
            while process.returncode is None:
                try:
                    get = read_queue.get_nowait()
                except queue.Empty:
                    break
                    
                yield get
                
        if process.returncode is None:
            process.stdin.close()
            process.stdout.close()
            process.kill()
    
    response = await make_response(async_generator())
    response.timeout = None
    response.mimetype = 'image/gif'
    return response

def main():
    parser = argparse.ArgumentParser(
        description = __doc__
    )

    parser.add_argument(
        '-H', '--host',
        type    = str,
        default = '0.0.0.0',
        help    = ('This is the IP that Asuka should be bound to.'
        + ' Defaults to 0.0.0.0.')
    )

    parser.add_argument(
        '-P', '--port',
        type    = int,
        default = 8080,
        help    = ('This is the port that Asuka should be bound to.'
        + ' Defaults to 8080.')
    )

    parser.add_argument(
        '-d', '--debug',
        action = 'store_true',
        help   = 'Enable debug mode and auto-reloader.'
    )

    args = parser.parse_args()

    if args.debug:
        app.config['ENV'] = 'development'
        app.config['TESTING'] = True
        app.config['DEBUG'] = True
        app.config['TEMPLATES_AUTO_RELOAD'] = True
        
        app.run(
            host=args.host,
            port=args.port,
            use_reloader=True,
            debug=True
        )
    else:
        app.run(
            host=args.host,
            port=args.port,
            use_reloader=False,
            debug=False
        )

if __name__ == '__main__':
    main()
