# Password Generator and Manager


>**THIS PROJECT WAS NOT MADE BY A SECURITY PROFESSIONAL, IT MAY BE EASILY BREACHABLE! NO GUIDE WAS FOLLOWED IN THE MAKING OF THIS, DO NOT DEPLOY THIS PROGRAM!!!**

This program generates passwords, encrypts them and stroes them in a local SQLlite database. Access to passwords are protected by a master password and the encryption key is derived from the saem password. Additionally the master password (hashed), master salt (hashed) and password encryption key are held in separate binary files. In a deployment environment, these binary files would be stored in a secured directory.