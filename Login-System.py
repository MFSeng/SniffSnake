def main():
    while True:
        username = input("Enter the admin username: ")
        password = input("Enter the admin password: ")
        if (username == "admin" and password == "Admin1!"):
            break
        else:
            print ("Incorrect Username or Password!")
            continue
    
    print ("You entered the correct credentials")

main()