from flask import Flask, request
import maxminddb

app = Flask(__name__)
reader = maxminddb.open_database('path/to/GeoIP2-City.mmdb')  # Replace with the actual path to your GeoIP2 database file

@app.route('/')
def index():
    ip_address = request.remote_addr
    geolocation = get_geolocation(ip_address)
    print("IP Address:", ip_address)
    print("Geolocation:", geolocation)
    return "IP Address and Geolocation have been captured and stored"

def get_geolocation(ip_address):
    response = reader.get(ip_address)
    
    if response and 'city' in response and 'country' in response:
        city = response['city']['names']['en']
        country = response['country']['names']['en']
        return f"City: {city}, Country: {country}"
    
    return "Geolocation information not found."

if __name__ == '__main__':
    app.run()
