import sqlite3
import my_client as mct
import my_server as msr


if __name__ == "__main__":
    conn = sqlite3.connect('test.db')
    print("Opened database successfully")
    msr.main()
    # mct.main()
