class Application:
    def __init__(self):
        self.config = load_config()
        self.authenticate()

    def authenticate(self):
        print("Initializing application")

    def main_menu(self):
        choice = input("1. Scan\n2. Reports\n3. Exit\n> ")
        return choice

def load_config():
    return {"debug": False}

def main():
    app = Application()
    app.main_menu()

if __name__ == "__main__":
    main()
