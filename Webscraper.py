import requests
from bs4 import BeautifulSoup

# Define the URL to scrape
base_url = 'https://weather.com/en-IN/weather/today/l/'

# Get the city from the user
city = input('Enter city name: ')

# Construct the full URL for the city
url = base_url + city.lower()

# Send a GET request to the URL and get the HTML content
response = requests.get(url)
html_content = response.content

# Parse the HTML content using Beautiful Soup
soup = BeautifulSoup(html_content, 'html.parser')

# Find the temperature and forecast on the page
temp = soup.find('span', {'class': 'CurrentConditions--tempValue--3KcTQ'}).text.strip()
forecast = soup.find('div', {'class': 'CurrentConditions--phraseValue--17s79'}).text.strip()

# Print the results
print('Temperature in', city.capitalize() + ':', temp)
print('Forecast in', city.capitalize() + ':', forecast)
