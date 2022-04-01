# Distributed-instagram

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
    - ![live_view](https://github.com/vishalBindal/Distributed-instagram/blob/main/screenshots/master_live_info.png?raw=true)
- To run a user app
    - Start the redis server
    - `python USER_APP/user_app.py`
    - Open the url. Now you can use the app, register
    - ![live_view](https://github.com/vishalBindal/Distributed-instagram/blob/main/screenshots/front_page.png?raw=true)
    - ![live_view](https://github.com/vishalBindal/Distributed-instagram/blob/main/screenshots/profile.png?raw=true)