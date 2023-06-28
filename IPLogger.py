from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    ip_address = request.remote_addr
    print("IP Address:", ip_address)
    return "Hello, World!"

if __name__ == '__main__':
    app.run()
