import requests

url = "http://127.0.0.1:8080"
response = requests.get(url)

print(response.status_code)
print(response.text)

