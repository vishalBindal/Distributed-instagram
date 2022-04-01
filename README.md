# Distributed-instagram
Demo: https://youtu.be/TPRKj142P0g

## Running Instructions
- Installing requirements
    - `pip install -r requirements.txt`
- Make sure to run master and user at different systems since they have the same node.
- To run a master app
    - Start the redis server
    - `python USER_APP/user_app.py`
    - Then url will be given `http://10.17.5.95:8000/`
    - Open this to view the realtime state of system. It will show storage for different users and the different
      clusters of users
    - <img width="1227" alt="Screenshot 2022-04-01 at 11 24 56 PM" src="https://user-images.githubusercontent.com/31121102/161318360-0ab4dc08-0d11-4110-a4df-021d0a8241ad.png">

- To run a user app
    - Start the redis server
    - `python USER_APP/user_app.py`
    - Open the url. Now you can use the app, register
    - <img width="1227" alt="Screenshot 2022-04-01 at 11 28 20 PM" src="https://user-images.githubusercontent.com/31121102/161318379-99f1f312-91e9-48d5-a803-bb4e2fecea97.png">
    - <img width="1227" alt="Screenshot 2022-04-01 at 11 32 23 PM" src="https://user-images.githubusercontent.com/31121102/161318386-300492c8-ed2c-498c-a92f-a2c143626a5f.png">
