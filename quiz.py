import sqlite3
import hashlib
import re
import random
import os  
from time import sleep

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

conn = sqlite3.connect('quiz.db')
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT PRIMARY KEY, password_hash TEXT, high_score INTEGER DEFAULT 0)''')

c.execute('''CREATE TABLE IF NOT EXISTS scores
             (username TEXT, score INTEGER, date TEXT)''')

def register(username, password):
    clear_screen()
    length_regex = r'.{8,}'
    digit_regex = r'\d'
    lowercase_regex = r'[a-z]'
    uppercase_regex = r'[A-Z]'
    special_regex = r'[!@#$%^&*()-+]'

    if (re.search(length_regex, password) and
            re.search(digit_regex, password) and
            re.search(lowercase_regex, password) and
            re.search(uppercase_regex, password) and
            re.search(special_regex, password)):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        try:
            c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            conn.commit()
            print("Registration successful!")
            sleep(1)
            display_user_menu(username, 0, password)
        except sqlite3.IntegrityError:
            print("Username already exists!")
            
    else:
        print("Password does not meet the criteria.")
        
    
    

def login(username, password):
    clear_screen()
    c.execute("SELECT password_hash, high_score FROM users WHERE username=?", (username,))
    result = c.fetchone()
    if result:
        stored_password_hash, high_score = result
        entered_password_hash = hashlib.sha256(password.encode()).hexdigest()
        if stored_password_hash == entered_password_hash:
            print("Login successful!")
            return high_score
    print("Invalid username or password.")
    return None

def save_score(username, score):
    c.execute("INSERT INTO scores (username, score, date) VALUES (?, ?, datetime('now'))", (username, score))
    c.execute("SELECT high_score FROM users WHERE username=?", (username,))
    current_high_score = c.fetchone()[0]
    new_high_score = max(current_high_score, score)
    c.execute("UPDATE users SET high_score=? WHERE username=?", (new_high_score, username))
    conn.commit()

def display_leaderboard():
    clear_screen()
    c.execute("SELECT username, high_score FROM users ORDER BY high_score DESC")
    leaderboard = c.fetchall()
    if leaderboard:
        print("Leaderboard:")
        for rank, (username, high_score) in enumerate(leaderboard, 1):
            print(f"{rank}. {username}: {high_score}")
    else:
        print("No users found.")
    input("Press Enter to continue....")

def display_score_history(username):
    clear_screen()
    c.execute("SELECT score, date FROM scores WHERE username=? ORDER BY date DESC", (username,))
    scores = c.fetchall()
    if scores:
        print("Score History:")
        for score in scores:
            print(f"Score: {score[0]}, Date: {score[1]}")
    else:
        print("No score history available.")

def read_questions(filename):
    questions = []
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                question, *options, answer = line.split('|')
                question_dict = {
                    'question': question.strip().replace('@','\n'),
                    'options': [opt.strip() for opt in options],
                    'answer': answer.strip().lower()
                }
                questions.append(question_dict)
    return questions

def quiz(username):
    clear_screen()
    print("Welcome to the Quiz!")
    questions = read_questions('questions.txt')
    random.shuffle(questions) 
    questions = questions[:10]  
    score = 0
    total_questions = len(questions)
    opp = ['A','B','C','D']
    for i, question in enumerate(questions, 1):
        print(f"\nQuestion {i}: {question['question']}\n")
        j = 0
        for option in question['options']:
            print(opp[j],".",option)
            j+=1
        answer = input("Your answer (a/b/c/d): ").strip().lower()
        while answer not in ['a', 'b', 'c', 'd']:
            print("Invalid answer format. Please enter a/b/c/d only.")
            answer = input("Your answer (a/b/c/d): ").strip().lower()
        if answer == question['answer']:
            print("\nHurray!! Correct Answer.\n")
            score += 1
        else:
            print(f"\nOops!! Wrong Answer. The Correct Option was {question['answer']}\n")
    
    sleep(2)

    print(f"\nQuiz complete! Your final score is: {score}/{total_questions}")
    save_score(username, score)
    input("Press Enter to continue...")
    display_score_history(username)


def main_menu():
    clear_screen()
    print("Welcome to the Quiz!")
    while True:
        print("\nMain Menu:")
        print("1. Login")
        print("2. Register")
        print("3. Leaderboard")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            login_menu()
        elif choice == '2':
            register_menu()
        elif choice == '3':
            display_leaderboard()
        elif choice == '4':
            print("Exiting the quiz. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a valid option.")

def register_menu():
    clear_screen()
    print("\nRegister Menu:")
    print("Create a strong password of min. length 8 including lowercase, uppercase, numeric and special character\n")
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    register(username, password)

def login_menu():
    clear_screen()
    print("\nLogin Menu:")
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    high_score = login(username, password)
    if high_score is not None:
        display_user_menu(username, high_score, password)

def display_profile(username, high_score):
    clear_screen()
    print(f"Username:  {username}:")
    print(f"High Score: {high_score}")
    input("Press Enter to continue....")
    
def display_user_menu(username, high_score, password):
    while True:
        clear_screen()
        print(f"\nWelcome, {username}!")
        print("Your High Score:", high_score)
        print()
        print("User Menu:")
        print("1. Start Quiz")
        print("2. Change Password")
        print("3. Leaderboard")
        print("4. View Profile")
        print("5. Logout")
        choice = input("Enter your choice: ")
        
        if choice == '1':
            quiz(username)
            high_score = login(username, password)
        elif choice == '2':
            change_password(username)
        elif choice == '3':
            display_leaderboard()
        elif choice == '4':
            display_profile(username, high_score)
        elif choice == '5':
            print("Logging out...")
            sleep(1)
            break
        else:
            print("Invalid choice. Please enter a valid option.")



def change_password(username):
    clear_screen()
    print("Change Password:")
    old_password = input("Enter your old password: ")
    new_password = input("Enter your new password: ")

    # Validate old password
    c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    stored_password_hash = c.fetchone()[0]
    entered_password_hash = hashlib.sha256(old_password.encode()).hexdigest()
    if stored_password_hash != entered_password_hash:
        print("Old password is incorrect.")
        return

    # Update password in the database
    new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    c.execute("UPDATE users SET password_hash=? WHERE username=?", (new_password_hash, username))
    conn.commit()
    print("Password changed successfully!")
    input("Press Enter to continue...")



main_menu()
conn.close()
