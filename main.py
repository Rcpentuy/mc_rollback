from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import subprocess

app = Flask(__name__)
socketio = SocketIO(app)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('execute_command')
def handle_command(command):
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        emit('command_output', result)
    except subprocess.CalledProcessError as e:
        emit('command_output', str(e))

if __name__ == '__main__':
    socketio.run(app,host='0.0.0.0', port=25566, debug=True)