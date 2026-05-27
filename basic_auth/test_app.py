import requests

BASE_URL = "http://127.0.0.1:8000"

# ---------------------------------------------------
# V1 LOGIN (no session persistence)
# ---------------------------------------------------

print("\n--- Testing login_v1 ---")

r = requests.post(
    f"{BASE_URL}/login_v1",
    params={
        "username": "admin",
        "password": "admin123"
    }
)

print("Status:", r.status_code)
print("Response:", r.text)

# Try profile after login_v1
print("\nTrying /profile after login_v1...")

r = requests.get(f"{BASE_URL}/profile")

print("Status:", r.status_code)
print("Response:", r.text)

print("\nNotice:")
print("login_v1 does NOT persist authentication")
print("No cookie/session was created")


# ---------------------------------------------------
# V2 LOGIN (session cookie auth)
# ---------------------------------------------------

print("\n\n--- Testing login_v2 ---")

# requests.Session() automatically stores cookies
session = requests.Session()

r = session.post(
    f"{BASE_URL}/login_v2",
    params={
        "username": "admin",
        "password": "admin123"
    }
)

print("Status:", r.status_code)
print("Response:", r.json())

print("\nCookies stored in session:")
print(session.cookies.get_dict())


# ---------------------------------------------------
# Access protected profile endpoint
# ---------------------------------------------------

print("\n--- Accessing /profile ---")

r = session.get(f"{BASE_URL}/profile")

print("Status:", r.status_code)
print("Response:", r.json())


# ---------------------------------------------------
# Access another endpoint
# ---------------------------------------------------

print("\n--- Accessing /myfiles/test.txt ---")

r = session.get(f"{BASE_URL}/myfiles/test.txt")

print("Status:", r.status_code)
print("Response:", r.text)


# ---------------------------------------------------
# Simulate invalid/no-cookie request
# ---------------------------------------------------

print("\n--- Testing without cookies ---")

r = requests.get(f"{BASE_URL}/profile")

print("Status:", r.status_code)
print("Response:", r.text)