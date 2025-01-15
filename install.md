# Installation

## 1. Python

The EUDI rQES Wallet-Driven Wallet Tester application was tested with

- Python version 3.10.8

and should only be used with Python 3.10 or higher.

If you don't have it installed, please downlod it from <https://www.python.org/downloads/> and follow the [Python Developer's Guide](https://devguide.python.org/getting-started/).

## 2. Flask

The EUDI rQES Wallet-Driven Wallet Tester application was tested with

- Flask v. 2.3

and should only be used with Flask v. 2.3 or higher.

To install [Flask](https://flask.palletsprojects.com/en/2.3.x/), please follow the [Installation Guide](https://flask.palletsprojects.com/en/2.3.x/installation/).

## 3. Running the EUDI rQES Wallet-Driven Wallet Tester Application

To run the application, follow these simple steps (some of which may have already been completed when installing Flask) for Linux/macOS or Windows.

### Step 1: Clone the Repository

Clone the eudi-app-web-walletdriven-tester-py repository:

```shell
git clone <repository>
```

### Step 2: Create a Virtual Environment

Create a `.venv` folder within the cloned repository:

```shell
cd eudi-app-web-walletdriven-tester-py
python3 -m venv .venv
```

### Step 3: Activate the Virtual Environment

Linux/macOS

```shell
. .venv/bin/activate
```

Windows

```shell
. .venv\Scripts\Activate
```

### Step 4: Upgrade pip

Install or upgrade _pip_

```shell
python -m pip install --upgrade pip
```

### Step 5: Install Dependencies

Install Flask and other dependencies in virtual environment

```shell
pip install -r app/requirements.txt
```

### Step 6: Configure the Application

Copy \_config.py to config.py and modify the following configuration variables:

- **secret_key**: define a secure and random key
- **service_url**: the base URL of the Wallet Tester
- **AS**: the URL of the QTSP Authorization Server (AS)
- **RS**: the URL of the QTSP Resource Server (RS)
- **SCA**: the URL of the rQES External SCA Server
- **oauth_client_id**: the client ID of the Wallet Tester in the QTSP AS
- **oauth_client_secret**: the client secret of the Wallet Tester in the QTSP AS

### Step 7: Run the Application

Run the EUDI rQES Wallet-Driven Wallet Tester application (on <http://127.0.0.1:5000>)

```shell
flask --app app run
```
