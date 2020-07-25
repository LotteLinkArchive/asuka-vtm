#!/usr/bin/env python
"""
Asuka Virtualization Manager or Asuka-VTM is a tool for creating virtual
machines you can share with the web.
"""

__author__ = 'Naphtha Nepanthez'
__version__ = '0.0.1'
__license__ = 'AGPL-v3.0' # SEE LICENSE FILE

import vertibird, argparse, toml, sys, os, random, string, base64, time, bcrypt
import pickle, shlex, io, subprocess, asyncio, copy, threading, re, queue, zlib
import hashlib, struct, math, itertools, xxhash, collections, traceback
import select as fselect

from vncdotool import client as vncapiclient

# Video options
vertibird.VNC_FRAMERATE = 32
WORKING_IMAGE_MODE = 'RGBA'
CHUNK_SIZE = 256
LOSSY_COLORS_AUTO = CHUNK_SIZE // 2
LOSSY_COLORS = LOSSY_COLORS_AUTO if LOSSY_COLORS_AUTO <= 256 else 256
TYPE_PICK_MODE = 'mixed'
ALPHA_CHECK = True

# Utility expressions
nonzero = lambda nsi: nsi if nsi > 0 else 1
nonneg = lambda nsi: nsi if nsi >= 0 else 0

from captcha.audio import AudioCaptcha
from captcha.image import ImageCaptcha

from PIL import Image, ImageOps, ImageMath, ImageDraw
import numpy as np

from quart import (
    Quart, websocket, render_template, url_for, session, request,
    redirect, abort, Response, make_response, app as gapp
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
app.jinja_env.globals.update(os=os)
app.jinja_env.globals.update(hashlib=hashlib)

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

@app.websocket('/operate/<username>/<password>/<vuuid>')
async def operate(username, password, vuuid):
    # USERNAME: 32-bit hex salt
    # PASSWORD: SHA-512 hex hash (UTF-8 -> hex of token + space + hex of salt)
    # These names were originally intended for websocket authorization, but it
    # appears to be broken in Quart :(
    
    # Used for initial handshake
    with db_session:
        user = None
        
        # TODO: Improve database performance by NOT iterating over the whole
        # user table.
        for acc in select(p for p in User):
            if hashlib.sha512('{0} {1}'.format(
                bytes(acc.token).hex(),
                username
            ).encode()).hexdigest() == (
                password
            ):
                
                user = acc
                
                # This helps a bit, but not if they're the last user in the
                # table...
                break
                    
        # Abort if user is invalid or token is invalid
        if user == None:
            abort(403)
            
        username = user.name
            
        vmo = VirtualMachine.get(owner = user.name, id = vuuid)
        
        # Abort if VM doesn't exist or user is not the owner
        if vmo == None:
            abort(403)
            
        # Convert DB VM Object to Vertibird Object
        vmi = vb().get(vmo.id)
        
    # Define command functions
    def get_display(world):
        display = world['context']['vm'].display
        
        # Capture the display on each call
        temp = display.capture().convert(WORKING_IMAGE_MODE)
        
        # Limit the size of the display just in case
        if math.prod(temp.size) > 2073600:
            temp = Image.new(WORKING_IMAGE_MODE, (640, 480))
            ImageDraw.Draw(temp).text(
                (8, 8),
                'Invalid signal! Consuming over 2073600 pixels!',
                (255, 255, 0)
            )
        
        newdisplay = lambda: Image.new(WORKING_IMAGE_MODE, temp.size)
        
        # Create a new cache/framebuffer if it doesn't exist or the display
        # size has changed.
        # (Split into multiple checks to prevent a keyerror)
        if 'framebuffer' not in world['context']:
            world['context']['framebuffer'] = newdisplay()
        elif display.shape != world['context']['framebuffer'].size:
            world['context']['framebuffer'] = newdisplay()
        
        if world['context']['framebuffer'] != temp:
            chunks = []
            for x, y in itertools.product(
                    range(math.ceil(temp.width / CHUNK_SIZE)),
                    range(math.ceil(temp.height / CHUNK_SIZE))
                ):
                x = x * CHUNK_SIZE
                y = y * CHUNK_SIZE
                x_end = x + CHUNK_SIZE
                y_end = y + CHUNK_SIZE
                
                temp_c = temp.crop((x, y, x_end, y_end))
                fb_c = world['context']['framebuffer'].crop(
                    (x, y, x_end, y_end))

                if temp_c != fb_c:
                    if ALPHA_CHECK == True:
                        downscale = (lambda i: i.resize(
                            size = (i.width // 4, i.height // 4),
                            resample = Image.BILINEAR
                        ))
                        
                        xsplit = downscale(fb_c).split()
                        ysplit = downscale(temp_c).split()
                        
                        #xsplit = fb_c.split()
                        #ysplit = temp_c.split()
                        mask = ImageOps.invert(ImageMath.eval(
                            '((abs(b - a) + abs(d - c) + abs(f - e)) * 127)',
                            a = xsplit[0], b = ysplit[0],
                            c = xsplit[1], d = ysplit[1],
                            e = xsplit[2], f = ysplit[2]
                        ).convert('L')).convert(
                            '1', dither = Image.NONE)
                            
                        mask = mask.resize(
                                size = temp_c.size,
                                resample = Image.NEAREST
                        )

                        final = Image.composite(
                            Image.new('RGBA', temp_c.size), temp_c, mask)
                        
                        bbox = final.getbbox()
                        if bbox == None:
                            continue
                        elif bbox != (0, 0, CHUNK_SIZE, CHUNK_SIZE):
                            final = final.crop(bbox)
                            x += bbox[0]
                            y += bbox[1]
                        
                        if final.width < 2 or final.height < 2:
                            continue
                    else:
                        final = temp_c
                    
                    chash = xxhash.xxh32(
                        final.resize(
                            size = (
                                nonzero(final.width // 2),
                                nonzero(final.height // 2)
                            ),
                            resample = Image.NEAREST
                        ).tobytes()
                    ).intdigest()
                    
                    if chash not in world['context']['chunkcache']:
                        if TYPE_PICK_MODE == 'guess':
                            data = io.BytesIO()
                            if final.getcolors(
                                maxcolors = LOSSY_COLORS) == None:
                                final.save(data, 'WEBP', quality = 15)
                            else:
                                final.save(
                                    data, 'WEBP', lossless = True)
                            data.seek(0)
                            
                            data = data.read()
                        elif TYPE_PICK_MODE == 'brute':
                            results = []
                            
                            data = io.BytesIO()
                            final.save(data, 'WEBP', quality = 15)
                            data.seek(0)
                            results.append(data.read())
                            
                            data = io.BytesIO()
                            final.save(data, 'WEBP', lossless = True)
                            data.seek(0)
                            results.append(data.read())
                            
                            data = min(results, key=len)
                        elif TYPE_PICK_MODE == 'mixed':
                            alpha = True
                            if not ImageOps.invert(final.split()[3]).getbbox():
                                alpha = False
                            
                            data = io.BytesIO()
                            if not alpha:
                                final.convert('RGB').save(
                                    data, 'JPEG', quality = 15)
                            elif final.getcolors(
                                maxcolors = LOSSY_COLORS) == None:
                                    
                                final.save(data, 'WEBP', quality = 15)
                            else:
                                final.save(data, 'WEBP', lossless = True)
                            data.seek(0)
                            
                            data = data.read()
                        elif TYPE_PICK_MODE == 'fastpng':
                            data = io.BytesIO()
                            final.save(
                                data, 'PNG', compression_level = 0
                            )
                            data.seek(0)
                            data = data.read()
                        elif TYPE_PICK_MODE == 'jpegonly':
                            data = io.BytesIO()
                            final.convert('RGB').save(
                                data, 'JPEG', quality = 80
                            )
                            data.seek(0)
                            data = data.read()
                        elif TYPE_PICK_MODE == 'webpd':
                            data = io.BytesIO()
                            final.save(data, 'WEBP', quality = 50,
                                allow_mixed = True, save_all = True)
                            data.seek(0)
                            data = data.read()

                        chunks.append(struct.pack(
                            '<I?IHH',
                            len(data),
                            False,
                            chash,
                            x,
                            y
                        ) + data)
                            
                        world['context']['chunkcache'].append(chash)
                    else:
                        chunks.append(struct.pack(
                            '<I?IHH', 0, True, chash, x, y))
                            
            chunks = b''.join(chunks)
            
            world['context']['framebuffer'] = temp
            
            # compressed = zlib.compress(chunks, level = 1)

            return (
                struct.pack(
                    '<?HHI', # 9 bytes
                    True,
                    temp.size[0],
                    temp.size[1],
                    len(chunks)
                ) +
                chunks
            )
        else:
            # Inform the client that nothing has changed whatsoever.
            return struct.pack('<?HHI', False, temp.size[0], temp.size[1], 0)
            
    async def clear_framebuffer(world):
        if 'framebuffer' in world['context']:
            del world['context']['framebuffer']
            
            return struct.pack('<?', True)
        else:
            return struct.pack('<?', False)
    
    async def get_display_size(world):
        return struct.pack('<HH', *world['context']['vm'].display.shape)
    
    async def move_mouse(world):
        world['context']['vm'].display.mouseMove(
            *struct.unpack('<HH', world['data'])
        )
        
        return struct.pack('<?', True)
        
    async def mouse_down(world):
        world['context']['vm'].display.mouseDown(
            *struct.unpack('<B', world['data'])
        )
        
        return struct.pack('<?', True)
        
    async def mouse_up(world):
        world['context']['vm'].display.mouseUp(
            *struct.unpack('<B', world['data'])
        )
        
        return struct.pack('<?', True)
        
    async def key_down(world):
        # Client format must be correct
        world['context']['vm'].display.keyDown(world['data'].decode())
        
        return struct.pack('<?', True)
    
    async def key_up(world):
        world['context']['vm'].display.keyUp(world['data'].decode())
        
        return struct.pack('<?', True)

    async def get_state(world):
        state_enc = world['context']['vm'].state().encode()
        
        return struct.pack('<B', len(state_enc)) + state_enc
    
    async def cleanup_keys(world):
        SPCHARS = list(vncapiclient.KEYMAP.keys())
        for key in (SPCHARS + [chr(x) for x in range(256)]):
            world['context']['vm'].display.keyUp(key)
    
        for button in range(32):
            world['context']['vm'].display.mouseUp(button + 1)
    
        return struct.pack('<?', True)
    
    async def get_buffered_frames(world):
        framewait, tobuffer = struct.unpack('<fB', world['data'])
        
        if (tobuffer > vertibird.VNC_FRAMERATE or tobuffer < 1):
            raise Exception('Invalid buffer size!')
        elif (framewait > 0.3 or framewait < 0.004):
            raise Exception('Invalid frame wait time!')
        
        frames = []
        for cframe in range(tobuffer):
            start_time = time.time()
            
            frame = await gapp.run_sync(get_display)(world)
            await asyncio.sleep(nonneg(framewait - (time.time() - start_time)))
            total_time = time.time() - start_time
            
            frames.append(struct.pack(
                '<fBBI', total_time, cframe, tobuffer, len(frame)) + frame)
                # 10 bytes
                
        return b''.join(frames)
    
    # Create command lookup table
    commands = {
        0 : get_display,
        1 : clear_framebuffer,
        2 : move_mouse,
        3 : get_display_size,
        4 : mouse_down,
        5 : mouse_up,
        6 : key_down,
        7 : key_up,
        8 : get_state,
        9 : cleanup_keys,
        10: get_buffered_frames
    }
    
    # Command execution module
    context = {
        'vm': vmi,
        'username': username,
        'chunkcache': collections.deque(maxlen = 4096)
    }
    try:
        while True:
            try:
                # Get command from user
                command = await websocket.receive()

                # If command isn't valid (e.g they're sending strings)
                if type(command) != bytes:
                    command = command.encode()
                   
                # Decode command
                header_pattern = '<BI'
                header_size = struct.calcsize(header_pattern)
                opcode, event, data = (
                    *struct.unpack(
                        header_pattern,
                        command[:header_size]
                    ),  command[header_size:]
                )
                
                # Execute command from lookup table
                await websocket.send(
                    command[:header_size] +
                    struct.pack('<?', True) +
                    bytes(await commands[opcode]({
                        'context': context,
                        'data'   : data   ,
                        'event'  : event
                    }))
                )
            except Exception as e:
                exception_header = lambda code: (
                    command[:header_size] +
                    struct.pack('<?H', False, code)
                )
                
                if type(e) == asyncio.CancelledError:
                    raise
                elif type(e) == KeyError and opcode not in commands:
                    await websocket.send(
                        exception_header(404) + 
                        'Opcode {0} not found'.format(opcode).encode()
                    )
                else:
                    traceback.print_exc()
                    
                    await websocket.send(
                        exception_header(500) + 
                        str(e).encode()
                    )
    except asyncio.CancelledError:
        await commands[9]({
            'context': context,
            'data'   : b'',
            'event'  : os.urandom(4)
        })
        
        raise 

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
