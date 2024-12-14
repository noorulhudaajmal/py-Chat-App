# Flask Chat App

This project is a **Flask-based chat application** featuring real-time messaging using **Flask-SocketIO**.

## Features

1. **User Authentication**:
   - Secure login and registration using **Flask-Login**.
   - Password hashing with **Flask-Bcrypt**.

2. **Real-Time Messaging**:
   - Chat functionality powered by **SocketIO**.
   - Messages are broadcasted in real-time to all connected clients.
   - Supports multiple clients in the chat room.
   - User activity notifications (e.g., joined, left) are recorded and broadcasted.

3. **Message Storage**:
   - Message data is stored in a **SQLite database**.
   - Supports retrieval of chat history for new users joining the app.


## Installation and Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/noorulhudaajmal/py-Chat-App
   cd py-Chat-App
   ```
2. Create a virtual environment and install dependencies:
    ```
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
3. Set up the database by uncommenting the code in main.py:
    ```
    with app.app_context():
        db.create_all()
    ```
4. Run the application:
    ```
    python app.py

    ```

## Snapshots from the App
![Index](/screenshots/index.png)
![Auth](/screenshots/auth.png)
![Home](/screenshots/home.png)
